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
#include <nobnc/nonetwork.h>
#include <nobnc/nochannel.h>
#include <nobnc/nonick.h>

class NoKickClientOnIrcDisconnect : public NoModule
{
public:
    MODCONSTRUCTOR(NoKickClientOnIrcDisconnect)
    {
    }

    void onIrcDisconnected() override
    {
        const std::vector<NoChannel*>& channels = network()->channels();

        for (std::vector<NoChannel*>::const_iterator it = channels.begin(); it != channels.end(); ++it) {
            if ((*it)->isOn()) {
                putUser(":NoBNC!no@bnc.no KICK " + (*it)->name() + " " + network()->ircNick().nick() +
                        " :You have been disconnected from the IRC server");
            }
        }
    }
};

template <>
void no_moduleInfo<NoKickClientOnIrcDisconnect>(NoModuleInfo& info)
{
    info.setWikiPage("disconkick");
}

USERMODULEDEFS(NoKickClientOnIrcDisconnect,
               "Kicks the client from all channels when the connection to the IRC server is lost")
