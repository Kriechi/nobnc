/*
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

#include <znc/nodir.h>
#include <znc/nofile.h>
#include <znc/nouser.h>
#include <znc/noapp.h>
#include <znc/noexecsock.h>

using std::vector;

// Forward Declaration
class NoShellMod;

class NoShellSock : public NoExecSock
{
public:
    NoShellSock(NoShellMod* pShellMod, NoClient* pClient, const NoString& sExec) : NoExecSock()
    {
        EnableReadLine();
        m_pParent = pShellMod;
        m_pClient = pClient;

        if (Execute(sExec) == -1) {
            NoString s = "Failed to execute: ";
            s += strerror(errno);
            ReadLine(s);
            return;
        }

        // Get rid of that write fd, we aren't going to use it
        // (And clients expecting input will fail this way).
        close(GetWSock());
        SetWSock(open("/dev/null", O_WRONLY));
    }
    // These next two function's bodies are at the bottom of the file since they reference NoShellMod
    void ReadLine(const NoString& sData) override;
    void Disconnected() override;

    NoShellMod* m_pParent;

private:
    NoClient* m_pClient;
};

class NoShellMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoShellMod) { m_sPath = NoApp::Get().GetHomePath(); }

    virtual ~NoShellMod()
    {
        vector<Csock*> vSocks = GetManager()->FindSocksByName("SHELL");

        for (unsigned int a = 0; a < vSocks.size(); a++) {
            GetManager()->DelSockByAddr(vSocks[a]);
        }
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
#ifndef MOD_SHELL_ALLOW_EVERYONE
        if (!GetUser()->IsAdmin()) {
            sMessage = "You must be admin to use the shell module";
            return false;
        }
#endif

        return true;
    }

    void OnModCommand(const NoString& sLine) override
    {
        NoString sCommand = sLine.Token(0);
        if (sCommand.Equals("cd")) {
            NoString sArg = sLine.Token(1, true);
            NoString sPath =
            NoDir::ChangeDir(m_sPath, (sArg.empty() ? NoString(NoApp::Get().GetHomePath()) : sArg), NoApp::Get().GetHomePath());
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
        NoString sPath = m_sPath.Replace_n(" ", "_");
        NoString sSource = ":" + GetModNick() + "!shell@" + sPath;
        NoString sLine = sSource + " PRIVMSG " + GetClient()->GetNick() + " :" + sMsg;
        GetClient()->PutClient(sLine);
    }

    void RunCommand(const NoString& sCommand)
    {
        GetManager()->AddSock(new NoShellSock(this, GetClient(), "cd " + m_sPath + " && " + sCommand), "SHELL");
    }

private:
    NoString m_sPath;
};

void NoShellSock::ReadLine(const NoString& sData)
{
    NoString sLine = sData;

    sLine.TrimRight("\r\n");
    sLine.Replace("\t", "    ");

    m_pParent->SetClient(m_pClient);
    m_pParent->PutShell(sLine);
    m_pParent->SetClient(nullptr);
}

void NoShellSock::Disconnected()
{
    // If there is some incomplete line in the buffer, read it
    // (e.g. echo echo -n "hi" triggered this)
    NoString& sBuffer = GetInternalReadBuffer();
    if (!sBuffer.empty()) ReadLine(sBuffer);

    m_pParent->SetClient(m_pClient);
    m_pParent->PutShell("znc$");
    m_pParent->SetClient(nullptr);
}

template <> void TModInfo<NoShellMod>(NoModInfo& Info) { Info.SetWikiPage("shell"); }

#ifdef MOD_SHELL_ALLOW_EVERYONE
USERMODULEDEFS(NoShellMod, "Gives shell access")
#else
USERMODULEDEFS(NoShellMod, "Gives shell access. Only ZNC admins can use it.")
#endif
