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
#include <no/nofile.h>
#include <no/noircsocket.h>
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/nodebug.h>
#include <no/noapp.h>
#include <no/noregistry.h>

class NoIdentFileModule : public NoModule
{
    NoString m_sOrigISpoof;
    NoFile* m_pISpoofLockFile;
    NoIrcSocket* m_pIRCSock;

public:
    MODCONSTRUCTOR(NoIdentFileModule)
    {
        AddHelpCommand();
        AddCommand("GetFile", static_cast<NoModuleCommand::ModCmdFunc>(&NoIdentFileModule::GetFile));
        AddCommand("SetFile", static_cast<NoModuleCommand::ModCmdFunc>(&NoIdentFileModule::SetFile), "<file>");
        AddCommand("GetFormat", static_cast<NoModuleCommand::ModCmdFunc>(&NoIdentFileModule::GetFormat));
        AddCommand("SetFormat", static_cast<NoModuleCommand::ModCmdFunc>(&NoIdentFileModule::SetFormat), "<format>");
        AddCommand("Show", static_cast<NoModuleCommand::ModCmdFunc>(&NoIdentFileModule::Show));

        m_pISpoofLockFile = nullptr;
        m_pIRCSock = nullptr;
    }

    virtual ~NoIdentFileModule() { ReleaseISpoof(); }

    void GetFile(const NoString& sLine) { PutModule("File is set to: " + NoRegistry(this).value("File")); }

    void SetFile(const NoString& sLine)
    {
        NoRegistry registry(this);
        registry.setValue("File", No::tokens(sLine, 1));
        PutModule("File has been set to: " + registry.value("File"));
    }

    void SetFormat(const NoString& sLine)
    {
        NoRegistry registry(this);
        registry.setValue("Format", No::tokens(sLine, 1));
        PutModule("Format has been set to: " + registry.value("Format"));
        PutModule("Format would be expanded to: " + ExpandString(registry.value("Format")));
    }

    void GetFormat(const NoString& sLine)
    {
        NoRegistry registry(this);
        PutModule("Format is set to: " + registry.value("Format"));
        PutModule("Format would be expanded to: " + ExpandString(registry.value("Format")));
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

    void onModCommand(const NoString& sCommand) override
    {
        if (GetUser()->IsAdmin()) {
            HandleCommand(sCommand);
        } else {
            PutModule("Access denied");
        }
    }

    void SetIRCSock(NoIrcSocket* pIRCSock)
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

        NoRegistry registry(this);

        m_pISpoofLockFile = new NoFile;
        if (!m_pISpoofLockFile->TryExLock(registry.value("File"), O_RDWR | O_CREAT)) {
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

        NoString sData = ExpandString(registry.value("Format"));

        // If the format doesn't contain anything expandable, we'll
        // assume this is an "old"-style format string.
        if (sData == registry.value("Format")) {
            sData.replace("%", GetUser()->GetIdent());
        }

        NO_DEBUG("Writing [" + sData + "] to ident spoof file [" + m_pISpoofLockFile->GetLongName() +
              "] for user/network [" + GetUser()->GetUserName() + "/" + GetNetwork()->GetName() + "]");

        m_pISpoofLockFile->Write(sData + "\n");

        return true;
    }

    void ReleaseISpoof()
    {
        NO_DEBUG("Releasing ident spoof for user/network [" +
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

        NoRegistry registry(this);
        if (registry.value("Format").empty()) {
            registry.setValue("Format", "global { reply \"%ident%\" }");
        }

        if (registry.value("File").empty()) {
            registry.setValue("File", "~/.oidentd.conf");
        }

        return true;
    }

    ModRet onIrcConnecting(NoIrcSocket* pIRCSock) override
    {
        if (m_pISpoofLockFile != nullptr) {
            NO_DEBUG("Aborting connection, ident spoof lock file exists");
            PutModule(
            "Aborting connection, another user or network is currently connecting and using the ident spoof file");
            return HALTCORE;
        }

        if (!WriteISpoof()) {
            NoRegistry registry(this);
            NO_DEBUG("identfile [" + registry.value("File") + "] could not be written");
            PutModule("[" + registry.value("File") + "] could not be written, retrying...");
            return HALTCORE;
        }

        SetIRCSock(pIRCSock);
        return CONTINUE;
    }

    void onIrcConnected() override
    {
        if (m_pIRCSock == GetNetwork()->GetIRCSock()) {
            ReleaseISpoof();
        }
    }

    void onIrcConnectionError(NoIrcSocket* pIRCSock) override
    {
        if (m_pIRCSock == pIRCSock) {
            ReleaseISpoof();
        }
    }

    void onIrcDisconnected() override
    {
        if (m_pIRCSock == GetNetwork()->GetIRCSock()) {
            ReleaseISpoof();
        }
    }
};

template <> void no_moduleInfo<NoIdentFileModule>(NoModuleInfo& Info) { Info.SetWikiPage("identfile"); }

GLOBALMODULEDEFS(NoIdentFileModule, "Write the ident of a user to a file when they are trying to connect.")
