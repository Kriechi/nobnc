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

    MODCONSTRUCTOR(NoSendRawMod)
    {
        addHelpCommand();
        addCommand("Client",
                   static_cast<NoModule::CommandFunction>(&NoSendRawMod::SendClient),
                   "[user] [network] [data to send]",
                   "The data will be sent to the user's IRC client(s)");
        addCommand("Server",
                   static_cast<NoModule::CommandFunction>(&NoSendRawMod::SendServer),
                   "[user] [network] [data to send]",
                   "The data will be sent to the IRC server the user is connected to");
        addCommand("Current",
                   static_cast<NoModule::CommandFunction>(&NoSendRawMod::CurrentClient),
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
