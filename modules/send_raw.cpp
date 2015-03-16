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

#include <znc/nouser.h>
#include <znc/nonetwork.h>

using std::vector;
using std::map;

class NoSendRawMod : public NoModule
{
    void SendClient(const NoString& sLine)
    {
        NoUser* pUser = CZNC::Get().FindUser(sLine.Token(1));

        if (pUser) {
            NoNetwork* pNetwork = pUser->FindNetwork(sLine.Token(2));

            if (pNetwork) {
                pNetwork->PutUser(sLine.Token(3, true));
                PutModule("Sent [" + sLine.Token(3, true) + "] to " + pUser->GetUserName() + "/" + pNetwork->GetName());
            } else {
                PutModule("Network [" + sLine.Token(2) + "] not found for user [" + sLine.Token(1) + "]");
            }
        } else {
            PutModule("User [" + sLine.Token(1) + "] not found");
        }
    }

    void SendServer(const NoString& sLine)
    {
        NoUser* pUser = CZNC::Get().FindUser(sLine.Token(1));

        if (pUser) {
            NoNetwork* pNetwork = pUser->FindNetwork(sLine.Token(2));

            if (pNetwork) {
                pNetwork->PutIRC(sLine.Token(3, true));
                PutModule("Sent [" + sLine.Token(3, true) + "] to IRC Server of " + pUser->GetUserName() + "/" + pNetwork->GetName());
            } else {
                PutModule("Network [" + sLine.Token(2) + "] not found for user [" + sLine.Token(1) + "]");
            }
        } else {
            PutModule("User [" + sLine.Token(1) + "] not found");
        }
    }

    void CurrentClient(const NoString& sLine)
    {
        NoString sData = sLine.Token(1, true);
        GetClient()->PutClient(sData);
    }

public:
    virtual ~NoSendRawMod() {}

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

    bool OnWebRequest(NoWebSock& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "index") {
            if (WebSock.IsPost()) {
                NoUser* pUser = CZNC::Get().FindUser(WebSock.GetParam("network").Token(0, false, "/"));
                if (!pUser) {
                    WebSock.GetSession()->AddError("User not found");
                    return true;
                }

                NoNetwork* pNetwork = pUser->FindNetwork(WebSock.GetParam("network").Token(1, false, "/"));
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

            const map<NoString, NoUser*>& msUsers = CZNC::Get().GetUserMap();
            for (map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it) {
                NoTemplate& l = Tmpl.AddRow("UserLoop");
                l["Username"] = (*it->second).GetUserName();

                vector<NoNetwork*> vNetworks = (*it->second).GetNetworks();
                for (vector<NoNetwork*>::const_iterator it2 = vNetworks.begin(); it2 != vNetworks.end(); ++it2) {
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
                   static_cast<NoModCommand::ModCmdFunc>(&NoSendRawMod::SendClient),
                   "[user] [network] [data to send]",
                   "The data will be sent to the user's IRC client(s)");
        AddCommand("Server",
                   static_cast<NoModCommand::ModCmdFunc>(&NoSendRawMod::SendServer),
                   "[user] [network] [data to send]",
                   "The data will be sent to the IRC server the user is connected to");
        AddCommand("Current",
                   static_cast<NoModCommand::ModCmdFunc>(&NoSendRawMod::CurrentClient),
                   "[data to send]",
                   "The data will be sent to your current client");
    }
};

template <> void TModInfo<NoSendRawMod>(NoModInfo& Info) { Info.SetWikiPage("send_raw"); }

USERMODULEDEFS(NoSendRawMod, "Lets you send some raw IRC lines as/to someone else")
