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

#include <no/nomodule.h>
#include <no/nofile.h>
#include <no/noircconnection.h>
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/nodebug.h>
#include <no/noapp.h>

class NoIdentFileModule : public NoModule
{
    NoString m_sOrigISpoof;
    NoFile* m_pISpoofLockFile;
    NoIrcConnection* m_pIRCSock;

public:
    MODCONSTRUCTOR(NoIdentFileModule)
    {
        AddHelpCommand();
        AddCommand("GetFile", static_cast<NoModCommand::ModCmdFunc>(&NoIdentFileModule::GetFile));
        AddCommand("SetFile", static_cast<NoModCommand::ModCmdFunc>(&NoIdentFileModule::SetFile), "<file>");
        AddCommand("GetFormat", static_cast<NoModCommand::ModCmdFunc>(&NoIdentFileModule::GetFormat));
        AddCommand("SetFormat", static_cast<NoModCommand::ModCmdFunc>(&NoIdentFileModule::SetFormat), "<format>");
        AddCommand("Show", static_cast<NoModCommand::ModCmdFunc>(&NoIdentFileModule::Show));

        m_pISpoofLockFile = nullptr;
        m_pIRCSock = nullptr;
    }

    virtual ~NoIdentFileModule() { ReleaseISpoof(); }

    void GetFile(const NoString& sLine) { PutModule("File is set to: " + GetNV("File")); }

    void SetFile(const NoString& sLine)
    {
        SetNV("File", sLine.Tokens(1));
        PutModule("File has been set to: " + GetNV("File"));
    }

    void SetFormat(const NoString& sLine)
    {
        SetNV("Format", sLine.Tokens(1));
        PutModule("Format has been set to: " + GetNV("Format"));
        PutModule("Format would be expanded to: " + ExpandString(GetNV("Format")));
    }

    void GetFormat(const NoString& sLine)
    {
        PutModule("Format is set to: " + GetNV("Format"));
        PutModule("Format would be expanded to: " + ExpandString(GetNV("Format")));
    }

    void Show(const NoString& sLine)
    {
        PutModule("m_pISpoofLockFile = " + NoString((long long)m_pISpoofLockFile));
        PutModule("m_pIRCSock = " + NoString((long long)m_pIRCSock));
        if (m_pIRCSock) {
            PutModule("user/network - " + m_pIRCSock->GetNetwork()->GetUser()->GetUserName() + "/" +
                      m_pIRCSock->GetNetwork()->GetName());
        } else {
            PutModule("identfile is free");
        }
    }

    void OnModCommand(const NoString& sCommand) override
    {
        if (GetUser()->IsAdmin()) {
            HandleCommand(sCommand);
        } else {
            PutModule("Access denied");
        }
    }

    void SetIRCSock(NoIrcConnection* pIRCSock)
    {
        if (m_pIRCSock) {
            NoApp::Get().ResumeConnectQueue();
        }

        m_pIRCSock = pIRCSock;

        if (m_pIRCSock) {
            NoApp::Get().PauseConnectQueue();
        }
    }

    bool WriteISpoof()
    {
        if (m_pISpoofLockFile != nullptr) {
            return false;
        }

        m_pISpoofLockFile = new NoFile;
        if (!m_pISpoofLockFile->TryExLock(GetNV("File"), O_RDWR | O_CREAT)) {
            delete m_pISpoofLockFile;
            m_pISpoofLockFile = nullptr;
            return false;
        }

        char buf[1024];
        memset((char*)buf, 0, 1024);
        m_pISpoofLockFile->Read(buf, 1024);
        m_sOrigISpoof = buf;

        if (!m_pISpoofLockFile->Seek(0) || !m_pISpoofLockFile->Truncate()) {
            delete m_pISpoofLockFile;
            m_pISpoofLockFile = nullptr;
            return false;
        }

        NoString sData = ExpandString(GetNV("Format"));

        // If the format doesn't contain anything expandable, we'll
        // assume this is an "old"-style format string.
        if (sData == GetNV("Format")) {
            sData.Replace("%", GetUser()->GetIdent());
        }

        DEBUG("Writing [" + sData + "] to ident spoof file [" + m_pISpoofLockFile->GetLongName() +
              "] for user/network [" + GetUser()->GetUserName() + "/" + GetNetwork()->GetName() + "]");

        m_pISpoofLockFile->Write(sData + "\n");

        return true;
    }

    void ReleaseISpoof()
    {
        DEBUG("Releasing ident spoof for user/network [" +
              (m_pIRCSock ? m_pIRCSock->GetNetwork()->GetUser()->GetUserName() + "/" + m_pIRCSock->GetNetwork()->GetName() : "<no user/network>") +
              "]");

        SetIRCSock(nullptr);

        if (m_pISpoofLockFile != nullptr) {
            if (m_pISpoofLockFile->Seek(0) && m_pISpoofLockFile->Truncate()) {
                m_pISpoofLockFile->Write(m_sOrigISpoof);
            }

            delete m_pISpoofLockFile;
            m_pISpoofLockFile = nullptr;
        }
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        m_pISpoofLockFile = nullptr;
        m_pIRCSock = nullptr;

        if (GetNV("Format").empty()) {
            SetNV("Format", "global { reply \"%ident%\" }");
        }

        if (GetNV("File").empty()) {
            SetNV("File", "~/.oidentd.conf");
        }

        return true;
    }

    ModRet OnIRCConnecting(NoIrcConnection* pIRCSock) override
    {
        if (m_pISpoofLockFile != nullptr) {
            DEBUG("Aborting connection, ident spoof lock file exists");
            PutModule(
            "Aborting connection, another user or network is currently connecting and using the ident spoof file");
            return HALTCORE;
        }

        if (!WriteISpoof()) {
            DEBUG("identfile [" + GetNV("File") + "] could not be written");
            PutModule("[" + GetNV("File") + "] could not be written, retrying...");
            return HALTCORE;
        }

        SetIRCSock(pIRCSock);
        return CONTINUE;
    }

    void OnIRCConnected() override
    {
        if (m_pIRCSock == GetNetwork()->GetIRCSock()) {
            ReleaseISpoof();
        }
    }

    void OnIRCConnectionError(NoIrcConnection* pIRCSock) override
    {
        if (m_pIRCSock == pIRCSock) {
            ReleaseISpoof();
        }
    }

    void OnIRCDisconnected() override
    {
        if (m_pIRCSock == GetNetwork()->GetIRCSock()) {
            ReleaseISpoof();
        }
    }
};

template <> void TModInfo<NoIdentFileModule>(NoModInfo& Info) { Info.SetWikiPage("identfile"); }

GLOBALMODULEDEFS(NoIdentFileModule, "Write the ident of a user to a file when they are trying to connect.")
