/*
 * Copyright (C) 2015 NoBNC
 * Copyright (C) 2004-2015 ZNC, see the NOTICE file for details.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <no/nomodule.h>
#include <no/nodir.h>
#include <no/nofile.h>
#include <no/nouser.h>
#include <no/noprocess.h>
#include <no/noclient.h>
#include <no/nosocketmanager.h>

// Forward Declaration
class NoShellMod;

class NoShellSock : public NoProcess
{
public:
    NoShellSock(NoShellMod* pShellMod, NoClient* client, const NoString& sExec) : NoProcess()
    {
        enableReadLine();
        m_pParent = pShellMod;
        m_pClient = client;

        if (!execute(sExec)) {
            NoString s = "Failed to execute: ";
            s += strerror(errno);
            readLine(s);
            return;
        }

        // Get rid of that write fd, we aren't going to use it
        // (And clients expecting input will fail this way).
        ::close(writeDescriptor());
        setWriteDescriptor(open("/dev/null", O_WRONLY));
    }
    // These next two function's bodies are at the bottom of the file since they reference NoShellMod
    void readLine(const NoString& data) override;
    void onDisconnected() override;

    NoShellMod* m_pParent;

private:
    NoClient* m_pClient;
};

class NoShellMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoShellMod)
    {
        m_sPath = NoDir::home().path();
    }

    virtual ~NoShellMod()
    {
        std::vector<NoSocket*> vSocks = manager()->findSockets("SHELL");

        for (uint a = 0; a < vSocks.size(); a++) {
            manager()->removeSocket(vSocks[a]);
        }
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
#ifndef MOD_SHELL_ALLOW_EVERYONE
        if (!user()->isAdmin()) {
            message = "You must be admin to use the shell module";
            return false;
        }
#endif

        return true;
    }

    void onModCommand(const NoString& line) override
    {
        NoString command = No::token(line, 0);
        if (command.equals("cd")) {
            NoString arg = No::tokens(line, 1);
            NoString path = NoDir(m_sPath).filePath(arg.empty() ? NoString(NoDir::home().path()) : arg);
            NoFile Dir(path);

            if (Dir.IsDir()) {
                m_sPath = path;
            } else if (Dir.Exists()) {
                PutShell("cd: not a directory [" + path + "]");
            } else {
                PutShell("cd: no such directory [" + path + "]");
            }

            PutShell("znc$");
        } else {
            RunCommand(line);
        }
    }

    void PutShell(const NoString& msg)
    {
        NoString path = m_sPath.replace_n(" ", "_");
        NoString sSource = ":" + moduleNick() + "!shell@" + path;
        NoString line = sSource + " PRIVMSG " + client()->nick() + " :" + msg;
        client()->putClient(line);
    }

    void RunCommand(const NoString& command)
    {
        // TODO: who deletes the instance?
        NoShellSock* sock = new NoShellSock(this, client(), "cd " + m_sPath + " && " + command);
        manager()->addSocket(sock, "SHELL");
    }

private:
    NoString m_sPath;
};

void NoShellSock::readLine(const NoString& data)
{
    NoString line = data;

    line.trimRight("\r\n");
    line.replace("\t", "    ");

    m_pParent->setClient(m_pClient);
    m_pParent->PutShell(line);
    m_pParent->setClient(nullptr);
}

void NoShellSock::onDisconnected()
{
    // If there is some incomplete line in the buffer, read it
    // (e.g. echo echo -n "hi" triggered this)
    NoString& sBuffer = internalReadBuffer();
    if (!sBuffer.empty())
        readLine(sBuffer);

    m_pParent->setClient(m_pClient);
    m_pParent->PutShell("znc$");
    m_pParent->setClient(nullptr);
}

template <>
void no_moduleInfo<NoShellMod>(NoModuleInfo& info)
{
    info.setWikiPage("shell");
}

#ifdef MOD_SHELL_ALLOW_EVERYONE
USERMODULEDEFS(NoShellMod, "Gives shell access")
#else
USERMODULEDEFS(NoShellMod, "Gives shell access. Only ZNC admins can use it.")
#endif
