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
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/noapp.h>
#include <no/noclient.h>
#include <no/nowebsocket.h>
#include <no/nowebsession.h>

class NoSendRawMod : public NoModule
{
    void SendClient(const NoString& sLine)
    {
        NoUser* pUser = NoApp::Get().FindUser(No::token(sLine, 1));

        if (pUser) {
            NoNetwork* pNetwork = pUser->findNetwork(No::token(sLine, 2));

            if (pNetwork) {
                pNetwork->putUser(No::tokens(sLine, 3));
                putModule("Sent [" + No::tokens(sLine, 3) + "] to " + pUser->userName() + "/" + pNetwork->name());
            } else {
                putModule("Network [" + No::token(sLine, 2) + "] not found for user [" + No::token(sLine, 1) + "]");
            }
        } else {
            putModule("User [" + No::token(sLine, 1) + "] not found");
        }
    }

    void SendServer(const NoString& sLine)
    {
        NoUser* pUser = NoApp::Get().FindUser(No::token(sLine, 1));

        if (pUser) {
            NoNetwork* pNetwork = pUser->findNetwork(No::token(sLine, 2));

            if (pNetwork) {
                pNetwork->putIrc(No::tokens(sLine, 3));
                putModule("Sent [" + No::tokens(sLine, 3) + "] to IRC Server of " + pUser->userName() + "/" + pNetwork->name());
            } else {
                putModule("Network [" + No::token(sLine, 2) + "] not found for user [" + No::token(sLine, 1) + "]");
            }
        } else {
            putModule("User [" + No::token(sLine, 1) + "] not found");
        }
    }

    void CurrentClient(const NoString& sLine)
    {
        NoString sData = No::tokens(sLine, 1);
        client()->putClient(sData);
    }

public:
    bool onLoad(const NoString& sArgs, NoString& sErrorMsg) override
    {
        if (!user()->isAdmin()) {
            sErrorMsg = "You must have admin privileges to load this module";
            return false;
        }

        return true;
    }

    NoString webMenuTitle() override
    {
        return "Send Raw";
    }
    bool webRequiresAdmin() override
    {
        return true;
    }

    bool onWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "index") {
            if (WebSock.isPost()) {
                NoUser* pUser = NoApp::Get().FindUser(No::token(WebSock.param("network"), 0, "/"));
                if (!pUser) {
                    WebSock.session()->addError("User not found");
                    return true;
                }

                NoNetwork* pNetwork = pUser->findNetwork(No::token(WebSock.param("network"), 1, "/"));
                if (!pNetwork) {
                    WebSock.session()->addError("Network not found");
                    return true;
                }

                bool bToServer = WebSock.param("send_to") == "server";
                const NoString sLine = WebSock.param("line");

                Tmpl["user"] = pUser->userName();
                Tmpl[bToServer ? "to_server" : "to_client"] = "true";
                Tmpl["line"] = sLine;

                if (bToServer) {
                    pNetwork->putIrc(sLine);
                } else {
                    pNetwork->putUser(sLine);
                }

                WebSock.session()->addSuccess("Line sent");
            }

            const std::map<NoString, NoUser*>& msUsers = NoApp::Get().GetUserMap();
            for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it) {
                NoTemplate& l = Tmpl.addRow("UserLoop");
                l["Username"] = (*it->second).userName();

                std::vector<NoNetwork*> vNetworks = (*it->second).networks();
                for (std::vector<NoNetwork*>::const_iterator it2 = vNetworks.begin(); it2 != vNetworks.end(); ++it2) {
                    NoTemplate& NetworkLoop = l.addRow("NetworkLoop");
                    NetworkLoop["Username"] = (*it->second).userName();
                    NetworkLoop["Network"] = (*it2)->name();
                }
            }

            return true;
        }

        return false;
    }

    MODCONSTRUCTOR(NoSendRawMod)
    {
        addHelpCommand();
        addCommand("Client",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSendRawMod::SendClient),
                   "[user] [network] [data to send]",
                   "The data will be sent to the user's IRC client(s)");
        addCommand("Server",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSendRawMod::SendServer),
                   "[user] [network] [data to send]",
                   "The data will be sent to the IRC server the user is connected to");
        addCommand("Current",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSendRawMod::CurrentClient),
                   "[data to send]",
                   "The data will be sent to your current client");
    }
};

template <>
void no_moduleInfo<NoSendRawMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("send_raw");
}

USERMODULEDEFS(NoSendRawMod, "Lets you send some raw IRC lines as/to someone else")
