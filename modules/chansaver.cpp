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
#include <no/nochannel.h>
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/noapp.h>
#include <no/nonick.h>

class NoChannelSaverMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoChannelSaverMod)
    {
    }

    bool onLoad(const NoString& sArgsi, NoString& sMessage) override
    {
        switch (type()) {
        case No::GlobalModule:
            LoadUsers();
            break;
        case No::UserModule:
            LoadUser(user());
            break;
        case No::NetworkModule:
            LoadNetwork(network());
            break;
        }
        return true;
    }

    void LoadUsers()
    {
        const std::map<NoString, NoUser*>& vUsers = noApp->userMap();
        for (const auto& user : vUsers) {
            LoadUser(user.second);
        }
    }

    void LoadUser(NoUser* user)
    {
        const std::vector<NoNetwork*>& vNetworks = user->networks();
        for (const NoNetwork* network : vNetworks) {
            LoadNetwork(network);
        }
    }

    void LoadNetwork(const NoNetwork* network)
    {
        const std::vector<NoChannel*>& channels = network->channels();
        for (NoChannel* channel : channels) {
            // If that channel isn't yet in the config,
            // we'll have to add it...
            if (!channel->inConfig()) {
                channel->setInConfig(true);
            }
        }
    }

    void onJoin(const NoNick& Nick, NoChannel& Channel) override
    {
        if (!Channel.inConfig() && network()->ircNick().equals(Nick.nick())) {
            Channel.setInConfig(true);
        }
    }

    void onPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage) override
    {
        if (Channel.inConfig() && network()->ircNick().equals(Nick.nick())) {
            Channel.setInConfig(false);
        }
    }
};

template <>
void no_moduleInfo<NoChannelSaverMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("chansaver");
    Info.addType(No::NetworkModule);
    Info.addType(No::GlobalModule);
}

USERMODULEDEFS(NoChannelSaverMod, "Keep config up-to-date when user joins/parts.")
