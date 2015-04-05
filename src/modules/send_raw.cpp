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

#include <nobnc/nomodule.h>
#include <nobnc/nouser.h>
#include <nobnc/nonetwork.h>
#include <nobnc/noapp.h>
#include <nobnc/noclient.h>
#include <nobnc/nowebsocket.h>
#include <nobnc/nowebsession.h>

class NoSendRawMod : public NoModule
{
    void SendClient(const NoString& line)
    {
        NoUser* user = noApp->findUser(No::token(line, 1));

        if (user) {
            NoNetwork* network = user->findNetwork(No::token(line, 2));

            if (network) {
                network->putUser(No::tokens(line, 3));
                putModule("Sent [" + No::tokens(line, 3) + "] to " + user->userName() + "/" + network->name());
            } else {
                putModule("network [" + No::token(line, 2) + "] not found for user [" + No::token(line, 1) + "]");
            }
        } else {
            putModule("User [" + No::token(line, 1) + "] not found");
        }
    }

    void SendServer(const NoString& line)
    {
        NoUser* user = noApp->findUser(No::token(line, 1));

        if (user) {
            NoNetwork* network = user->findNetwork(No::token(line, 2));

            if (network) {
                network->putIrc(No::tokens(line, 3));
                putModule("Sent [" + No::tokens(line, 3) + "] to IRC Server of " + user->userName() + "/" + network->name());
            } else {
                putModule("network [" + No::token(line, 2) + "] not found for user [" + No::token(line, 1) + "]");
            }
        } else {
            putModule("User [" + No::token(line, 1) + "] not found");
        }
    }

    void CurrentClient(const NoString& line)
    {
        NoString data = No::tokens(line, 1);
        client()->putClient(data);
    }

public:
    bool onLoad(const NoString& args, NoString& sErrorMsg) override
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

    bool onWebRequest(NoWebSocket* socket, const NoString& page, NoTemplate& tmpl) override
    {
        if (page == "index") {
            if (socket->isPost()) {
                NoUser* user = noApp->findUser(No::token(socket->param("network"), 0, "/"));
                if (!user) {
                    socket->session()->addError("User not found");
                    return true;
                }

                NoNetwork* network = user->findNetwork(No::token(socket->param("network"), 1, "/"));
                if (!network) {
                    socket->session()->addError("network not found");
                    return true;
                }

                bool bToServer = socket->param("send_to") == "server";
                const NoString line = socket->param("line");

                tmpl["user"] = user->userName();
                tmpl[bToServer ? "to_server" : "to_client"] = "true";
                tmpl["line"] = line;

                if (bToServer) {
                    network->putIrc(line);
                } else {
                    network->putUser(line);
                }

                socket->session()->addSuccess("Line sent");
            }

            const std::map<NoString, NoUser*>& msUsers = noApp->userMap();
            for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it) {
                NoTemplate& l = tmpl.addRow("UserLoop");
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
                   static_cast<NoModuleCommand::Function>(&NoSendRawMod::SendClient),
                   "[user] [network] [data to send]",
                   "The data will be sent to the user's IRC client(s)");
        addCommand("Server",
                   static_cast<NoModuleCommand::Function>(&NoSendRawMod::SendServer),
                   "[user] [network] [data to send]",
                   "The data will be sent to the IRC server the user is connected to");
        addCommand("Current",
                   static_cast<NoModuleCommand::Function>(&NoSendRawMod::CurrentClient),
                   "[data to send]",
                   "The data will be sent to your current client");
    }
};

template <>
void no_moduleInfo<NoSendRawMod>(NoModuleInfo& info)
{
    info.setWikiPage("send_raw");
}

USERMODULEDEFS(NoSendRawMod, "Lets you send some raw IRC lines as/to someone else")
