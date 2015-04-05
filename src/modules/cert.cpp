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

#define REQUIRESSL

#include <nobnc/nomodule.h>
#include <nobnc/nofile.h>
#include <nobnc/nouser.h>
#include <nobnc/noircsocket.h>
#include <nobnc/notemplate.h>
#include <nobnc/nowebsocket.h>

class NoCertMod : public NoModule
{
public:
    void Delete(const NoString& line)
    {
        if (NoFile::Delete(PemFile())) {
            putModule("Pem file deleted");
        } else {
            putModule("The pem file doesn't exist or there was a error deleting the pem file.");
        }
    }

    void info(const NoString& line)
    {
        if (HasPemFile()) {
            putModule("You have a certificate in: " + PemFile());
        } else {
            putModule("You do not have a certificate. Please use the web interface to add a certificate");
            if (user()->isAdmin()) {
                putModule("Alternatively you can either place one at " + PemFile());
            }
        }
    }

    MODCONSTRUCTOR(NoCertMod)
    {
        addHelpCommand();
        addCommand("delete",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoCertMod::Delete),
                   "",
                   "Delete the current certificate");
        addCommand("info", static_cast<NoModuleCommand::ModCmdFunc>(&NoCertMod::info));
    }

    NoString PemFile() const
    {
        return savePath() + "/user.pem";
    }

    bool HasPemFile() const
    {
        return (NoFile::Exists(PemFile()));
    }

    Return onIrcConnecting(NoIrcSocket* socket) override
    {
        if (HasPemFile()) {
            socket->setPemFile(PemFile());
        }

        return Continue;
    }

    NoString webMenuTitle() override
    {
        return "Certificate";
    }

    bool onWebRequest(NoWebSocket* socket, const NoString& page, NoTemplate& tmpl) override
    {
        if (page == "index") {
            tmpl["Cert"] = NoString(HasPemFile());
            return true;
        } else if (page == "update") {
            NoFile fPemFile(PemFile());

            if (fPemFile.Open(O_WRONLY | O_TRUNC | O_CREAT)) {
                fPemFile.Write(socket->param("cert", true, ""));
                fPemFile.Close();
            }

            socket->redirect(webPath());
            return true;
        } else if (page == "delete") {
            NoFile::Delete(PemFile());
            socket->redirect(webPath());
            return true;
        }

        return false;
    }
};

template <>
void no_moduleInfo<NoCertMod>(NoModuleInfo& info)
{
    info.addType(No::UserModule);
    info.setWikiPage("cert");
}

NETWORKMODULEDEFS(NoCertMod, "Use a ssl certificate to connect to a server")
