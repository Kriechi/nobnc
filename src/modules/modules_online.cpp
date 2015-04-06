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

class NoFakeOnlineModule : public NoModule
{
public:
    MODCONSTRUCTOR(NoFakeOnlineModule)
    {
    }

    bool IsOnlineModNick(const NoString& nick)
    {
        const NoString& prefix = user()->statusPrefix();
        if (!nick.startsWith(prefix))
            return false;

        NoString sModNick = nick.substr(prefix.length());
        if (sModNick.equals("status") || network()->loader()->findModule(sModNick) ||
            user()->loader()->findModule(sModNick) || noApp->loader()->findModule(sModNick))
            return true;
        return false;
    }

    Return onUserRaw(NoString& line) override
    {
        // Handle ISON
        if (No::token(line, 0).equals("ison")) {
            NoStringVector::const_iterator it;

            // Get the list of nicks which are being asked for
            NoStringVector vsNicks = No::tokens(line, 1).trimLeft_n(":").split(" ", No::SkipEmptyParts);

            NoString sBNNoNicks;
            for (it = vsNicks.begin(); it != vsNicks.end(); ++it) {
                if (IsOnlineModNick(*it)) {
                    sBNNoNicks += " " + *it;
                }
            }
            // Remove the leading space
            sBNNoNicks.leftChomp(1);

            if (!network()->ircSocket()) {
                // if we are not connected to any IRC server, send
                // an empty or module-nick filled response.
                putUser(":irc.znc.in 303 " + client()->nick() + " :" + sBNNoNicks);
            } else {
                // We let the server handle this request and then act on
                // the 303 response from the IRC server.
                m_ISONRequests.push_back(sBNNoNicks);
            }
        }

        // Handle WHOIS
        if (No::token(line, 0).equals("whois")) {
            NoString nick = No::token(line, 1);

            if (IsOnlineModNick(nick)) {
                NoNetwork* network = NoModule::network();
                putUser(":znc.in 311 " + network->currentNick() + " " + nick + " " + nick + " znc.in * :" + nick);
                putUser(":znc.in 312 " + network->currentNick() + " " + nick + " *.znc.in :Bouncer");
                putUser(":znc.in 318 " + network->currentNick() + " " + nick + " :End of /WHOIS list.");

                return Halt;
            }
        }

        return Continue;
    }

    Return onRaw(NoString& line) override
    {
        // Handle 303 reply if m_Requests is not empty
        if (No::token(line, 1) == "303" && !m_ISONRequests.empty()) {
            NoStringVector::iterator it = m_ISONRequests.begin();

            line.trim();

            // Only append a space if this isn't an empty reply
            if (line.endsWith(":")) {
                line += " ";
            }

            // add BNC nicks to the reply
            line += *it;
            m_ISONRequests.erase(it);
        }

        return Continue;
    }

private:
    NoStringVector m_ISONRequests;
};

template <>
void no_moduleInfo<NoFakeOnlineModule>(NoModuleInfo& info)
{
    info.setWikiPage("modules_online");
}

NETWORKMODULEDEFS(NoFakeOnlineModule, "Make ZNC's *modules to be \"online\".")
