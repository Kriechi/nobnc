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
    NoShellSock(NoShellMod* pShellMod, NoClient* pClient, const NoString& sExec) : NoProcess()
    {
        EnableReadLine();
        m_pParent = pShellMod;
        m_pClient = pClient;

        if (!execute(sExec)) {
            NoString s = "Failed to execute: ";
            s += strerror(errno);
            readLine(s);
            return;
        }

        // Get rid of that write fd, we aren't going to use it
        // (And clients expecting input will fail this way).
        close(GetWSock());
        SetWSock(open("/dev/null", O_WRONLY));
    }
    // These next two function's bodies are at the bottom of the file since they reference NoShellMod
    void readLine(const NoString& sData) override;
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

    bool onLoad(const NoString& sArgs, NoString& sMessage) override
    {
#ifndef MOD_SHELL_ALLOW_EVERYONE
        if (!user()->isAdmin()) {
            sMessage = "You must be admin to use the shell module";
            return false;
        }
#endif

        return true;
    }

    void onModCommand(const NoString& sLine) override
    {
        NoString sCommand = No::token(sLine, 0);
        if (sCommand.equals("cd")) {
            NoString sArg = No::tokens(sLine, 1);
            NoString sPath = NoDir(m_sPath).filePath(sArg.empty() ? NoString(NoDir::home().path()) : sArg);
            NoFile Dir(sPath);

            if (Dir.IsDir()) {
                m_sPath = sPath;
            } else if (Dir.Exists()) {
                PutShell("cd: not a directory [" + sPath + "]");
            } else {
                PutShell("cd: no such directory [" + sPath + "]");
            }

            PutShell("znc$");
        } else {
            RunCommand(sLine);
        }
    }

    void PutShell(const NoString& sMsg)
    {
        NoString sPath = m_sPath.replace_n(" ", "_");
        NoString sSource = ":" + moduleNick() + "!shell@" + sPath;
        NoString sLine = sSource + " PRIVMSG " + client()->nick() + " :" + sMsg;
        client()->putClient(sLine);
    }

    void RunCommand(const NoString& sCommand)
    {
        // TODO: who deletes the instance?
        NoShellSock* sock = new NoShellSock(this, client(), "cd " + m_sPath + " && " + sCommand);
        manager()->addSocket(sock, "SHELL");
    }

private:
    NoString m_sPath;
};

void NoShellSock::readLine(const NoString& sData)
{
    NoString sLine = sData;

    sLine.trimRight("\r\n");
    sLine.replace("\t", "    ");

    m_pParent->setClient(m_pClient);
    m_pParent->PutShell(sLine);
    m_pParent->setClient(nullptr);
}

void NoShellSock::onDisconnected()
{
    // If there is some incomplete line in the buffer, read it
    // (e.g. echo echo -n "hi" triggered this)
    NoString& sBuffer = GetInternalReadBuffer();
    if (!sBuffer.empty())
        readLine(sBuffer);

    m_pParent->setClient(m_pClient);
    m_pParent->PutShell("znc$");
    m_pParent->setClient(nullptr);
}

template <>
void no_moduleInfo<NoShellMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("shell");
}

#ifdef MOD_SHELL_ALLOW_EVERYONE
USERMODULEDEFS(NoShellMod, "Gives shell access")
#else
USERMODULEDEFS(NoShellMod, "Gives shell access. Only ZNC admins can use it.")
#endif
