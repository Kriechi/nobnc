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
        addCommand("Delete",
                   static_cast<NoModule::CommandFunction>(&NoCertMod::Delete),
                   "",
                   "Delete the current certificate");
        addCommand("Info", static_cast<NoModule::CommandFunction>(&NoCertMod::info));
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
};

template <>
void no_moduleInfo<NoCertMod>(NoModuleInfo& info)
{
    info.addType(No::UserModule);
    info.setWikiPage("cert");
}

NETWORKMODULEDEFS(NoCertMod, "Use a ssl certificate to connect to a server")
