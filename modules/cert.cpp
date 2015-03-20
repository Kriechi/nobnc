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

#define REQUIRESSL

#include <no/nomodule.h>
#include <no/nofile.h>
#include <no/nouser.h>
#include <no/noircconnection.h>

class NoCertMod : public NoModule
{
public:
    void Delete(const NoString& line)
    {
        if (NoFile::Delete(PemFile())) {
            PutModule("Pem file deleted");
        } else {
            PutModule("The pem file doesn't exist or there was a error deleting the pem file.");
        }
    }

    void Info(const NoString& line)
    {
        if (HasPemFile()) {
            PutModule("You have a certificate in: " + PemFile());
        } else {
            PutModule("You do not have a certificate. Please use the web interface to add a certificate");
            if (GetUser()->IsAdmin()) {
                PutModule("Alternatively you can either place one at " + PemFile());
            }
        }
    }

    MODCONSTRUCTOR(NoCertMod)
    {
        AddHelpCommand();
        AddCommand("delete",
                   static_cast<NoModCommand::ModCmdFunc>(&NoCertMod::Delete),
                   "",
                   "Delete the current certificate");
        AddCommand("info", static_cast<NoModCommand::ModCmdFunc>(&NoCertMod::Info));
    }

    NoString PemFile() const { return GetSavePath() + "/user.pem"; }

    bool HasPemFile() const { return (NoFile::Exists(PemFile())); }

    ModRet OnIRCConnecting(NoIrcConnection* pIRCSock) override
    {
        if (HasPemFile()) {
            pIRCSock->SetPemLocation(PemFile());
        }

        return CONTINUE;
    }

    NoString GetWebMenuTitle() override { return "Certificate"; }

    bool OnWebRequest(NoWebSock& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "index") {
            Tmpl["Cert"] = NoString(HasPemFile());
            return true;
        } else if (sPageName == "update") {
            NoFile fPemFile(PemFile());

            if (fPemFile.Open(O_WRONLY | O_TRUNC | O_CREAT)) {
                fPemFile.Write(WebSock.GetParam("cert", true, ""));
                fPemFile.Close();
            }

            WebSock.Redirect(GetWebPath());
            return true;
        } else if (sPageName == "delete") {
            NoFile::Delete(PemFile());
            WebSock.Redirect(GetWebPath());
            return true;
        }

        return false;
    }
};

template <> void TModInfo<NoCertMod>(NoModInfo& Info)
{
    Info.AddType(No::UserModule);
    Info.SetWikiPage("cert");
}

NETWORKMODULEDEFS(NoCertMod, "Use a ssl certificate to connect to a server")
