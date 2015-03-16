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

#include <znc/nochannel.h>
#include <znc/nouser.h>
#include <znc/nonetwork.h>

class NoChannelSaverMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoChannelSaverMod) {}

    virtual ~NoChannelSaverMod() {}

    bool OnLoad(const NoString& sArgsi, NoString& sMessage) override
    {
        switch (GetType()) {
        case NoModInfo::GlobalModule:
            LoadUsers();
            break;
        case NoModInfo::UserModule:
            LoadUser(GetUser());
            break;
        case NoModInfo::NetworkModule:
            LoadNetwork(GetNetwork());
            break;
        }
        return true;
    }

    void LoadUsers()
    {
        const std::map<NoString, NoUser*>& vUsers = NoApp::Get().GetUserMap();
        for (const auto& user : vUsers) {
            LoadUser(user.second);
        }
    }

    void LoadUser(NoUser* pUser)
    {
        const std::vector<NoNetwork*>& vNetworks = pUser->GetNetworks();
        for (const NoNetwork* pNetwork : vNetworks) {
            LoadNetwork(pNetwork);
        }
    }

    void LoadNetwork(const NoNetwork* pNetwork)
    {
        const std::vector<NoChannel*>& vChans = pNetwork->GetChans();
        for (NoChannel* pChan : vChans) {
            // If that channel isn't yet in the config,
            // we'll have to add it...
            if (!pChan->InConfig()) {
                pChan->SetInConfig(true);
            }
        }
    }

    void OnJoin(const NoNick& Nick, NoChannel& Channel) override
    {
        if (!Channel.InConfig() && GetNetwork()->GetIRNoNick().NickEquals(Nick.GetNick())) {
            Channel.SetInConfig(true);
        }
    }

    void OnPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage) override
    {
        if (Channel.InConfig() && GetNetwork()->GetIRNoNick().NickEquals(Nick.GetNick())) {
            Channel.SetInConfig(false);
        }
    }
};

template <> void TModInfo<NoChannelSaverMod>(NoModInfo& Info)
{
    Info.SetWikiPage("chansaver");
    Info.AddType(NoModInfo::NetworkModule);
    Info.AddType(NoModInfo::GlobalModule);
}

USERMODULEDEFS(NoChannelSaverMod, "Keep config up-to-date when user joins/parts.")
