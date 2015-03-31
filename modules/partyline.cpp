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
#include <no/noregistry.h>
#include <no/nonick.h>

// If you change these and it breaks, you get to keep the pieces
#define CHAN_PREFIX_1 "~"
#define CHAN_PREFIX_1C '~'
#define CHAN_PREFIX CHAN_PREFIX_1 "#"

#define NICK_PREFIX NoString("?")
#define NICK_PREFIX_C '?'

class NoPartylineChannel
{
public:
    NoPartylineChannel(const NoString& name)
    {
        m_sName = name.toLower();
    }

    const NoString& GetTopic() const
    {
        return m_sTopic;
    }
    const NoString& GetName() const
    {
        return m_sName;
    }
    const std::set<NoString>& GetNicks() const
    {
        return m_ssNicks;
    }

    void SetTopic(const NoString& s)
    {
        m_sTopic = s;
    }

    void AddNick(const NoString& s)
    {
        m_ssNicks.insert(s);
    }
    void DelNick(const NoString& s)
    {
        m_ssNicks.erase(s);
    }

    bool IsInChannel(const NoString& s)
    {
        return m_ssNicks.find(s) != m_ssNicks.end();
    }

protected:
    NoString m_sTopic;
    NoString m_sName;
    std::set<NoString> m_ssNicks;
};

class NoPartylineMod : public NoModule
{
public:
    void ListChannelsCommand(const NoString& line)
    {
        if (m_ssChannels.empty()) {
            putModule("There are no open channels.");
            return;
        }

        NoTable Table;

        Table.addColumn("Channel");
        Table.addColumn("Users");

        for (std::set<NoPartylineChannel*>::const_iterator a = m_ssChannels.begin(); a != m_ssChannels.end(); ++a) {
            Table.addRow();

            Table.setValue("Channel", (*a)->GetName());
            Table.setValue("Users", NoString((*a)->GetNicks().size()));
        }

        putModule(Table);
    }

    MODCONSTRUCTOR(NoPartylineMod)
    {
        addHelpCommand();
        addCommand("List",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoPartylineMod::ListChannelsCommand),
                   "",
                   "List all open channels");
    }

    virtual ~NoPartylineMod()
    {
        // Kick all clients who are in partyline channels
        for (std::set<NoPartylineChannel*>::iterator it = m_ssChannels.begin(); it != m_ssChannels.end(); ++it) {
            std::set<NoString> ssNicks = (*it)->GetNicks();

            for (std::set<NoString>::const_iterator it2 = ssNicks.begin(); it2 != ssNicks.end(); ++it2) {
                NoUser* user = noApp->findUser(*it2);
                std::vector<NoClient*> vClients = user->allClients();

                for (std::vector<NoClient*>::const_iterator it3 = vClients.begin(); it3 != vClients.end(); ++it3) {
                    NoClient* client = *it3;
                    client->putClient(":*" + moduleName() + "!znc@znc.in KICK " + (*it)->GetName() + " " +
                                       client->nick() + " :" + moduleName() + " unloaded");
                }
            }
        }

        while (!m_ssChannels.empty()) {
            delete *m_ssChannels.begin();
            m_ssChannels.erase(m_ssChannels.begin());
        }
    }

    bool onBoot() override
    {
        // The config is now read completely, so all Users are set up
        Load();

        return true;
    }

    bool onLoad(const NoString& args, NoString& sMessage) override
    {
        const std::map<NoString, NoUser*>& msUsers = noApp->userMap();

        for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it) {
            NoUser* user = it->second;
            for (std::vector<NoNetwork*>::const_iterator i = user->networks().begin(); i != user->networks().end(); ++i) {
                NoNetwork* network = *i;
                if (network->ircSocket()) {
                    if (!network->channelPrefixes().contains(CHAN_PREFIX_1)) {
                        network->putUser(":" + ircServer(network) + " 005 " + network->ircNick().nick() +
                                          " CHANTYPES=" + network->channelPrefixes() + CHAN_PREFIX_1
                                          " :are supported by this server.");
                    }
                }
            }
        }

        NoStringVector::const_iterator it;
        NoStringVector vsChans = args.split(" ", No::SkipEmptyParts);

        for (it = vsChans.begin(); it != vsChans.end(); ++it) {
            if (it->left(2) == CHAN_PREFIX) {
                m_ssDefaultChans.insert(it->left(32));
            }
        }

        Load();

        return true;
    }

    void Load()
    {
        NoString sAction, sKey;
        NoPartylineChannel* pChannel;
        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            if (key.contains(":")) {
                sAction = No::token(key, 0, ":");
                sKey = No::tokens(key, 1, ":");
            } else {
                // backwards compatibility for older NV data
                sAction = "fixedchan";
                sKey = key;
            }

            if (sAction == "fixedchan") {
                // Sorry, this was removed
            }

            if (sAction == "topic") {
                pChannel = FindChannel(sKey);
                NoString value = registry.value(key);
                if (pChannel && !value.empty()) {
                    PutChan(pChannel->GetNicks(), ":irc.znc.in TOPIC " + pChannel->GetName() + " :" + value);
                    pChannel->SetTopic(value);
                }
            }
        }

        return;
    }

    void SaveTopic(NoPartylineChannel* pChannel)
    {
        NoRegistry registry(this);
        if (!pChannel->GetTopic().empty())
            registry.setValue("topic:" + pChannel->GetName(), pChannel->GetTopic());
        else
            registry.remove("topic:" + pChannel->GetName());
    }

    ModRet onDeleteUser(NoUser& User) override
    {
        // Loop through each chan
        for (std::set<NoPartylineChannel*>::iterator it = m_ssChannels.begin(); it != m_ssChannels.end();) {
            NoPartylineChannel* channel = *it;
            // RemoveUser() might delete channels, so make sure our
            // iterator doesn't break.
            ++it;
            RemoveUser(&User, channel, "KICK", "User deleted", true);
        }

        return CONTINUE;
    }

    ModRet onRaw(NoString& line) override
    {
        if (No::token(line, 1) == "005") {
            NoString::size_type uPos = line.toUpper().find("CHANTYPES=");
            if (uPos != NoString::npos) {
                uPos = line.find(" ", uPos);

                if (uPos == NoString::npos)
                    line.append(CHAN_PREFIX_1);
                else
                    line.insert(uPos, CHAN_PREFIX_1);
                m_spInjectedPrefixes.insert(network());
            }
        }

        return CONTINUE;
    }

    void onIrcDisconnected() override
    {
        m_spInjectedPrefixes.erase(network());
    }

    void onClientLogin() override
    {
        NoUser* user = NoModule::user();
        NoClient* client = NoModule::client();
        NoNetwork* network = NoModule::network();
        if (m_spInjectedPrefixes.find(network) == m_spInjectedPrefixes.end() && network && !network->channelPrefixes().empty()) {
            client->putClient(":" + ircServer(network) + " 005 " + client->nick() + " CHANTYPES=" +
                               network->channelPrefixes() + CHAN_PREFIX_1 " :are supported by this server.");
        }

        // Make sure this user is in the default channels
        for (std::set<NoString>::iterator a = m_ssDefaultChans.begin(); a != m_ssDefaultChans.end(); ++a) {
            NoPartylineChannel* pChannel = GetChannel(*a);
            const NoString& nick = user->userName();

            if (pChannel->IsInChannel(nick))
                continue;

            NoString host = user->bindHost();
            const std::set<NoString>& ssNicks = pChannel->GetNicks();

            if (host.empty()) {
                host = "znc.in";
            }
            PutChan(ssNicks, ":" + NICK_PREFIX + nick + "!" + user->ident() + "@" + host + " JOIN " + *a, false);
            pChannel->AddNick(nick);
        }

        NoString sNickMask = client->nickMask();

        for (std::set<NoPartylineChannel*>::iterator it = m_ssChannels.begin(); it != m_ssChannels.end(); ++it) {
            const std::set<NoString>& ssNicks = (*it)->GetNicks();

            if ((*it)->IsInChannel(user->userName())) {

                client->putClient(":" + sNickMask + " JOIN " + (*it)->GetName());

                if (!(*it)->GetTopic().empty()) {
                    client->putClient(":" + ircServer(network) + " 332 " + client->nickMask() + " " +
                                       (*it)->GetName() + " :" + (*it)->GetTopic());
                }

                SendNickList(user, network, ssNicks, (*it)->GetName());
                PutChan(ssNicks,
                        ":*" + moduleName() + "!znc@znc.in MODE " + (*it)->GetName() + " +" +
                        NoString(user->isAdmin() ? "o" : "v") + " " + NICK_PREFIX + user->userName(),
                        false);
            }
        }
    }

    void onClientDisconnect() override
    {
        NoUser* user = NoModule::user();
        if (!user->isUserAttached() && !user->isBeingDeleted()) {
            for (std::set<NoPartylineChannel*>::iterator it = m_ssChannels.begin(); it != m_ssChannels.end(); ++it) {
                const std::set<NoString>& ssNicks = (*it)->GetNicks();

                if (ssNicks.find(user->userName()) != ssNicks.end()) {
                    PutChan(ssNicks,
                            ":*" + moduleName() + "!znc@znc.in MODE " + (*it)->GetName() + " -ov " + NICK_PREFIX +
                            user->userName() + " " + NICK_PREFIX + user->userName(),
                            false);
                }
            }
        }
    }

    ModRet onUserRaw(NoString& line) override
    {
        if (line.startsWith("WHO " CHAN_PREFIX_1)) {
            return HALT;
        } else if (line.startsWith("MODE " CHAN_PREFIX_1)) {
            return HALT;
        } else if (line.startsWith("TOPIC " CHAN_PREFIX)) {
            NoString sChannel = No::token(line, 1);
            NoString sTopic = No::tokens(line, 2);

            sTopic.trimPrefix(":");

            NoUser* user = NoModule::user();
            NoClient* client = NoModule::client();
            NoPartylineChannel* pChannel = FindChannel(sChannel);

            if (pChannel && pChannel->IsInChannel(user->userName())) {
                const std::set<NoString>& ssNicks = pChannel->GetNicks();
                if (!sTopic.empty()) {
                    if (user->isAdmin()) {
                        PutChan(ssNicks, ":" + client->nickMask() + " TOPIC " + sChannel + " :" + sTopic);
                        pChannel->SetTopic(sTopic);
                        SaveTopic(pChannel);
                    } else {
                        user->putUser(":irc.znc.in 482 " + client->nick() + " " + sChannel +
                                       " :You're not channel operator");
                    }
                } else {
                    sTopic = pChannel->GetTopic();

                    if (sTopic.empty()) {
                        user->putUser(":irc.znc.in 331 " + client->nick() + " " + sChannel + " :No topic is set.");
                    } else {
                        user->putUser(":irc.znc.in 332 " + client->nick() + " " + sChannel + " :" + sTopic);
                    }
                }
            } else {
                user->putUser(":irc.znc.in 442 " + client->nick() + " " + sChannel + " :You're not on that channel");
            }
            return HALT;
        }

        return CONTINUE;
    }

    ModRet onUserPart(NoString& sChannel, NoString& sMessage) override
    {
        if (sChannel.left(1) != CHAN_PREFIX_1) {
            return CONTINUE;
        }

        if (sChannel.left(2) != CHAN_PREFIX) {
            client()->putClient(":" + ircServer(network()) + " 401 " + client()->nick() + " " + sChannel +
                                " :No such channel");
            return HALT;
        }

        NoPartylineChannel* pChannel = FindChannel(sChannel);

        PartUser(user(), pChannel);

        return HALT;
    }

    void PartUser(NoUser* user, NoPartylineChannel* pChannel, const NoString& sMessage = "")
    {
        RemoveUser(user, pChannel, "PART", sMessage);
    }

    void RemoveUser(NoUser* user, NoPartylineChannel* pChannel, const NoString& command, const NoString& sMessage = "", bool bNickAsTarget = false)
    {
        if (!pChannel || !pChannel->IsInChannel(user->userName())) {
            return;
        }

        std::vector<NoClient*> vClients = user->allClients();

        NoString cmd = " " + command + " ";
        NoString sMsg = sMessage;
        if (!sMsg.empty())
            sMsg = " :" + sMsg;

        pChannel->DelNick(user->userName());

        const std::set<NoString>& ssNicks = pChannel->GetNicks();
        NoString host = user->bindHost();

        if (host.empty()) {
            host = "znc.in";
        }

        if (bNickAsTarget) {
            for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                NoClient* client = *it;

                client->putClient(":" + client->nickMask() + cmd + pChannel->GetName() + " " + client->nick() + sMsg);
            }

            PutChan(ssNicks,
                    ":" + NICK_PREFIX + user->userName() + "!" + user->ident() + "@" + host + cmd +
                    pChannel->GetName() + " " + NICK_PREFIX + user->userName() + sMsg,
                    false,
                    true,
                    user);
        } else {
            for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                NoClient* client = *it;

                client->putClient(":" + client->nickMask() + cmd + pChannel->GetName() + sMsg);
            }

            PutChan(ssNicks,
                    ":" + NICK_PREFIX + user->userName() + "!" + user->ident() + "@" + host + cmd + pChannel->GetName() + sMsg,
                    false,
                    true,
                    user);
        }

        if (!user->isBeingDeleted() && m_ssDefaultChans.find(pChannel->GetName()) != m_ssDefaultChans.end()) {
            JoinUser(user, pChannel);
        }

        if (ssNicks.empty()) {
            delete pChannel;
            m_ssChannels.erase(pChannel);
        }
    }

    ModRet onUserJoin(NoString& sChannel, NoString& sKey) override
    {
        if (sChannel.left(1) != CHAN_PREFIX_1) {
            return CONTINUE;
        }

        if (sChannel.left(2) != CHAN_PREFIX) {
            client()->putClient(":" + ircServer(network()) + " 403 " + client()->nick() + " " + sChannel +
                                " :Channels look like " CHAN_PREFIX "znc");
            return HALT;
        }

        sChannel = sChannel.left(32);
        NoPartylineChannel* pChannel = GetChannel(sChannel);

        JoinUser(user(), pChannel);

        return HALT;
    }

    void JoinUser(NoUser* user, NoPartylineChannel* pChannel)
    {
        if (pChannel && !pChannel->IsInChannel(user->userName())) {
            std::vector<NoClient*> vClients = user->allClients();

            const std::set<NoString>& ssNicks = pChannel->GetNicks();
            const NoString& nick = user->userName();
            pChannel->AddNick(nick);

            NoString host = user->bindHost();

            if (host.empty()) {
                host = "znc.in";
            }

            for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                NoClient* client = *it;
                client->putClient(":" + client->nickMask() + " JOIN " + pChannel->GetName());
            }

            PutChan(ssNicks, ":" + NICK_PREFIX + nick + "!" + user->ident() + "@" + host + " JOIN " + pChannel->GetName(), false, true, user);

            if (!pChannel->GetTopic().empty()) {
                for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                    NoClient* client = *it;
                    client->putClient(":" + ircServer(client->network()) + " 332 " + client->nickMask() + " " +
                                       pChannel->GetName() + " :" + pChannel->GetTopic());
                }
            }

            SendNickList(user, nullptr, ssNicks, pChannel->GetName());

            /* Tell the other clients we have op or voice, the current user's clients already know from NAMES list */

            if (user->isAdmin()) {
                PutChan(ssNicks,
                        ":*" + moduleName() + "!znc@znc.in MODE " + pChannel->GetName() + " +o " + NICK_PREFIX + user->userName(),
                        false,
                        false,
                        user);
            }

            PutChan(ssNicks,
                    ":*" + moduleName() + "!znc@znc.in MODE " + pChannel->GetName() + " +v " + NICK_PREFIX + user->userName(),
                    false,
                    false,
                    user);
        }
    }

    ModRet HandleMessage(const NoString& cmd, const NoString& sTarget, const NoString& sMessage)
    {
        if (sTarget.empty()) {
            return CONTINUE;
        }

        char cPrefix = sTarget[0];

        if (cPrefix != CHAN_PREFIX_1C && cPrefix != NICK_PREFIX_C) {
            return CONTINUE;
        }

        NoUser* user = NoModule::user();
        NoClient* client = NoModule::client();
        NoNetwork* network = NoModule::network();
        NoString host = user->bindHost();

        if (host.empty()) {
            host = "znc.in";
        }

        if (cPrefix == CHAN_PREFIX_1C) {
            if (FindChannel(sTarget) == nullptr) {
                client->putClient(":" + ircServer(network) + " 401 " + client->nick() + " " + sTarget +
                                   " :No such channel");
                return HALT;
            }

            PutChan(sTarget,
                    ":" + NICK_PREFIX + user->userName() + "!" + user->ident() + "@" + host + " " + cmd + " " +
                    sTarget + " :" + sMessage,
                    true,
                    false);
        } else {
            NoString nick = sTarget.leftChomp_n(1);
            NoUser* pTargetUser = noApp->findUser(nick);

            if (pTargetUser) {
                std::vector<NoClient*> vClients = pTargetUser->allClients();

                if (vClients.empty()) {
                    client->putClient(":" + ircServer(network) + " 401 " + client->nick() + " " + sTarget +
                                       " :User is not attached: " + nick + "");
                    return HALT;
                }

                for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                    NoClient* pTarget = *it;

                    pTarget->putClient(":" + NICK_PREFIX + user->userName() + "!" + user->ident() + "@" + host +
                                       " " + cmd + " " + pTarget->nick() + " :" + sMessage);
                }
            } else {
                client->putClient(":" + ircServer(network) + " 401 " + client->nick() + " " + sTarget +
                                   " :No such znc user: " + nick + "");
            }
        }

        return HALT;
    }

    ModRet onUserMsg(NoString& sTarget, NoString& sMessage) override
    {
        return HandleMessage("PRIVMSG", sTarget, sMessage);
    }

    ModRet onUserNotice(NoString& sTarget, NoString& sMessage) override
    {
        return HandleMessage("NOTICE", sTarget, sMessage);
    }

    ModRet onUserAction(NoString& sTarget, NoString& sMessage) override
    {
        return HandleMessage("PRIVMSG", sTarget, "\001ACTION " + sMessage + "\001");
    }

    ModRet onUserCtcp(NoString& sTarget, NoString& sMessage) override
    {
        return HandleMessage("PRIVMSG", sTarget, "\001" + sMessage + "\001");
    }

    ModRet onUserCtcpReply(NoString& sTarget, NoString& sMessage) override
    {
        return HandleMessage("NOTICE", sTarget, "\001" + sMessage + "\001");
    }

    const NoString ircServer(NoNetwork* network)
    {
        if (!network) {
            return "irc.znc.in";
        }

        const NoString& sServer = network->ircServer();
        if (!sServer.empty())
            return sServer;
        return "irc.znc.in";
    }

    bool PutChan(const NoString& sChan,
                 const NoString& line,
                 bool bIncludeCurUser = true,
                 bool bIncludeClient = true,
                 NoUser* user = nullptr,
                 NoClient* client = nullptr)
    {
        NoPartylineChannel* pChannel = FindChannel(sChan);

        if (pChannel != nullptr) {
            PutChan(pChannel->GetNicks(), line, bIncludeCurUser, bIncludeClient, user, client);
            return true;
        }

        return false;
    }

    void PutChan(const std::set<NoString>& ssNicks,
                 const NoString& line,
                 bool bIncludeCurUser = true,
                 bool bIncludeClient = true,
                 NoUser* user = nullptr,
                 NoClient* client = nullptr)
    {
        const std::map<NoString, NoUser*>& msUsers = noApp->userMap();

        if (!user)
            user = NoModule::user();
        if (!client)
            client = NoModule::client();

        for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it) {
            if (ssNicks.find(it->first) != ssNicks.end()) {
                if (it->second == user) {
                    if (bIncludeCurUser) {
                        it->second->putAllUser(line, nullptr, (bIncludeClient ? nullptr : client));
                    }
                } else {
                    it->second->putAllUser(line);
                }
            }
        }
    }

    void putUserIRCNick(NoUser* user, const NoString& sPre, const NoString& sPost)
    {
        const std::vector<NoClient*>& vClients = user->allClients();
        std::vector<NoClient*>::const_iterator it;
        for (it = vClients.begin(); it != vClients.end(); ++it) {
            (*it)->putClient(sPre + (*it)->nick() + sPost);
        }
    }

    void SendNickList(NoUser* user, NoNetwork* network, const std::set<NoString>& ssNicks, const NoString& sChan)
    {
        NoString sNickList;

        for (std::set<NoString>::const_iterator it = ssNicks.begin(); it != ssNicks.end(); ++it) {
            NoUser* pChanUser = noApp->findUser(*it);

            if (pChanUser == user) {
                continue;
            }

            if (pChanUser && pChanUser->isUserAttached()) {
                sNickList += (pChanUser->isAdmin()) ? "@" : "+";
            }

            sNickList += NICK_PREFIX + (*it) + " ";

            if (sNickList.size() >= 500) {
                putUserIRCNick(user, ":" + ircServer(network) + " 353 ", " @ " + sChan + " :" + sNickList);
                sNickList.clear();
            }
        }

        if (sNickList.size()) {
            putUserIRCNick(user, ":" + ircServer(network) + " 353 ", " @ " + sChan + " :" + sNickList);
        }

        std::vector<NoClient*> vClients = user->allClients();
        for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
            NoClient* client = *it;
            client->putClient(":" + ircServer(network) + " 353 " + client->nick() + " @ " + sChan + " :" +
                               ((user->isAdmin()) ? "@" : "+") + client->nick());
        }

        putUserIRCNick(user, ":" + ircServer(network) + " 366 ", " " + sChan + " :End of /NAMES list.");
    }

    NoPartylineChannel* FindChannel(const NoString& sChan)
    {
        NoString sChannel = sChan.toLower();

        for (std::set<NoPartylineChannel*>::iterator it = m_ssChannels.begin(); it != m_ssChannels.end(); ++it) {
            if ((*it)->GetName().toLower() == sChannel)
                return *it;
        }

        return nullptr;
    }

    NoPartylineChannel* GetChannel(const NoString& sChannel)
    {
        NoPartylineChannel* pChannel = FindChannel(sChannel);

        if (!pChannel) {
            pChannel = new NoPartylineChannel(sChannel.toLower());
            m_ssChannels.insert(pChannel);
        }

        return pChannel;
    }

private:
    std::set<NoPartylineChannel*> m_ssChannels;
    std::set<NoNetwork*> m_spInjectedPrefixes;
    std::set<NoString> m_ssDefaultChans;
};

template <>
void no_moduleInfo<NoPartylineMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("partyline");
    Info.setHasArgs(true);
    Info.setArgsHelpText("You may enter a list of channels the user joins, when entering the internal partyline.");
}

GLOBALMODULEDEFS(NoPartylineMod, "Internal channels and queries for users connected to znc")
