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
            NoNetwork* pNetwork = pUser->FindNetwork(No::token(sLine, 2));

            if (pNetwork) {
                pNetwork->PutUser(No::tokens(sLine, 3));
                PutModule("Sent [" + No::tokens(sLine, 3) + "] to " + pUser->GetUserName() + "/" + pNetwork->GetName());
            } else {
                PutModule("Network [" + No::token(sLine, 2) + "] not found for user [" + No::token(sLine, 1) + "]");
            }
        } else {
            PutModule("User [" + No::token(sLine, 1) + "] not found");
        }
    }

    void SendServer(const NoString& sLine)
    {
        NoUser* pUser = NoApp::Get().FindUser(No::token(sLine, 1));

        if (pUser) {
            NoNetwork* pNetwork = pUser->FindNetwork(No::token(sLine, 2));

            if (pNetwork) {
                pNetwork->PutIRC(No::tokens(sLine, 3));
                PutModule("Sent [" + No::tokens(sLine, 3) + "] to IRC Server of " + pUser->GetUserName() + "/" + pNetwork->GetName());
            } else {
                PutModule("Network [" + No::token(sLine, 2) + "] not found for user [" + No::token(sLine, 1) + "]");
            }
        } else {
            PutModule("User [" + No::token(sLine, 1) + "] not found");
        }
    }

    void CurrentClient(const NoString& sLine)
    {
        NoString sData = No::tokens(sLine, 1);
        GetClient()->PutClient(sData);
    }

public:
    bool OnLoad(const NoString& sArgs, NoString& sErrorMsg) override
    {
        if (!GetUser()->IsAdmin()) {
            sErrorMsg = "You must have admin privileges to load this module";
            return false;
        }

        return true;
    }

    NoString GetWebMenuTitle() override { return "Send Raw"; }
    bool WebRequiresAdmin() override { return true; }

    bool OnWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "index") {
            if (WebSock.IsPost()) {
                NoUser* pUser = NoApp::Get().FindUser(No::token(WebSock.GetParam("network"), 0, "/"));
                if (!pUser) {
                    WebSock.GetSession()->AddError("User not found");
                    return true;
                }

                NoNetwork* pNetwork = pUser->FindNetwork(No::token(WebSock.GetParam("network"), 1, "/"));
                if (!pNetwork) {
                    WebSock.GetSession()->AddError("Network not found");
                    return true;
                }

                bool bToServer = WebSock.GetParam("send_to") == "server";
                const NoString sLine = WebSock.GetParam("line");

                Tmpl["user"] = pUser->GetUserName();
                Tmpl[bToServer ? "to_server" : "to_client"] = "true";
                Tmpl["line"] = sLine;

                if (bToServer) {
                    pNetwork->PutIRC(sLine);
                } else {
                    pNetwork->PutUser(sLine);
                }

                WebSock.GetSession()->AddSuccess("Line sent");
            }

            const std::map<NoString, NoUser*>& msUsers = NoApp::Get().GetUserMap();
            for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it) {
                NoTemplate& l = Tmpl.AddRow("UserLoop");
                l["Username"] = (*it->second).GetUserName();

                std::vector<NoNetwork*> vNetworks = (*it->second).GetNetworks();
                for (std::vector<NoNetwork*>::const_iterator it2 = vNetworks.begin(); it2 != vNetworks.end(); ++it2) {
                    NoTemplate& NetworkLoop = l.AddRow("NetworkLoop");
                    NetworkLoop["Username"] = (*it->second).GetUserName();
                    NetworkLoop["Network"] = (*it2)->GetName();
                }
            }

            return true;
        }

        return false;
    }

    MODCONSTRUCTOR(NoSendRawMod)
    {
        AddHelpCommand();
        AddCommand("Client",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSendRawMod::SendClient),
                   "[user] [network] [data to send]",
                   "The data will be sent to the user's IRC client(s)");
        AddCommand("Server",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSendRawMod::SendServer),
                   "[user] [network] [data to send]",
                   "The data will be sent to the IRC server the user is connected to");
        AddCommand("Current",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSendRawMod::CurrentClient),
                   "[data to send]",
                   "The data will be sent to your current client");
    }
};

template <> void no_moduleInfo<NoSendRawMod>(NoModuleInfo& Info) { Info.SetWikiPage("send_raw"); }

USERMODULEDEFS(NoSendRawMod, "Lets you send some raw IRC lines as/to someone else")
