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
    NoPartylineChannel(const NoString& sName)
    {
        m_sName = sName.toLower();
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
    void ListChannelsCommand(const NoString& sLine)
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
                NoUser* pUser = NoApp::instance().findUser(*it2);
                std::vector<NoClient*> vClients = pUser->allClients();

                for (std::vector<NoClient*>::const_iterator it3 = vClients.begin(); it3 != vClients.end(); ++it3) {
                    NoClient* pClient = *it3;
                    pClient->putClient(":*" + moduleName() + "!znc@znc.in KICK " + (*it)->GetName() + " " +
                                       pClient->nick() + " :" + moduleName() + " unloaded");
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

    bool onLoad(const NoString& sArgs, NoString& sMessage) override
    {
        const std::map<NoString, NoUser*>& msUsers = NoApp::instance().userMap();

        for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it) {
            NoUser* pUser = it->second;
            for (std::vector<NoNetwork*>::const_iterator i = pUser->networks().begin(); i != pUser->networks().end(); ++i) {
                NoNetwork* pNetwork = *i;
                if (pNetwork->ircSocket()) {
                    if (!pNetwork->channelPrefixes().contains(CHAN_PREFIX_1)) {
                        pNetwork->putUser(":" + ircServer(pNetwork) + " 005 " + pNetwork->ircNick().nick() +
                                          " CHANTYPES=" + pNetwork->channelPrefixes() + CHAN_PREFIX_1
                                          " :are supported by this server.");
                    }
                }
            }
        }

        NoStringVector::const_iterator it;
        NoStringVector vsChans = sArgs.split(" ", No::SkipEmptyParts);

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
            NoPartylineChannel* pChan = *it;
            // RemoveUser() might delete channels, so make sure our
            // iterator doesn't break.
            ++it;
            RemoveUser(&User, pChan, "KICK", "User deleted", true);
        }

        return CONTINUE;
    }

    ModRet onRaw(NoString& sLine) override
    {
        if (No::token(sLine, 1) == "005") {
            NoString::size_type uPos = sLine.toUpper().find("CHANTYPES=");
            if (uPos != NoString::npos) {
                uPos = sLine.find(" ", uPos);

                if (uPos == NoString::npos)
                    sLine.append(CHAN_PREFIX_1);
                else
                    sLine.insert(uPos, CHAN_PREFIX_1);
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
        NoUser* pUser = user();
        NoClient* pClient = client();
        NoNetwork* pNetwork = network();
        if (m_spInjectedPrefixes.find(pNetwork) == m_spInjectedPrefixes.end() && pNetwork && !pNetwork->channelPrefixes().empty()) {
            pClient->putClient(":" + ircServer(pNetwork) + " 005 " + pClient->nick() + " CHANTYPES=" +
                               pNetwork->channelPrefixes() + CHAN_PREFIX_1 " :are supported by this server.");
        }

        // Make sure this user is in the default channels
        for (std::set<NoString>::iterator a = m_ssDefaultChans.begin(); a != m_ssDefaultChans.end(); ++a) {
            NoPartylineChannel* pChannel = GetChannel(*a);
            const NoString& sNick = pUser->userName();

            if (pChannel->IsInChannel(sNick))
                continue;

            NoString sHost = pUser->bindHost();
            const std::set<NoString>& ssNicks = pChannel->GetNicks();

            if (sHost.empty()) {
                sHost = "znc.in";
            }
            PutChan(ssNicks, ":" + NICK_PREFIX + sNick + "!" + pUser->ident() + "@" + sHost + " JOIN " + *a, false);
            pChannel->AddNick(sNick);
        }

        NoString sNickMask = pClient->nickMask();

        for (std::set<NoPartylineChannel*>::iterator it = m_ssChannels.begin(); it != m_ssChannels.end(); ++it) {
            const std::set<NoString>& ssNicks = (*it)->GetNicks();

            if ((*it)->IsInChannel(pUser->userName())) {

                pClient->putClient(":" + sNickMask + " JOIN " + (*it)->GetName());

                if (!(*it)->GetTopic().empty()) {
                    pClient->putClient(":" + ircServer(pNetwork) + " 332 " + pClient->nickMask() + " " +
                                       (*it)->GetName() + " :" + (*it)->GetTopic());
                }

                SendNickList(pUser, pNetwork, ssNicks, (*it)->GetName());
                PutChan(ssNicks,
                        ":*" + moduleName() + "!znc@znc.in MODE " + (*it)->GetName() + " +" +
                        NoString(pUser->isAdmin() ? "o" : "v") + " " + NICK_PREFIX + pUser->userName(),
                        false);
            }
        }
    }

    void onClientDisconnect() override
    {
        NoUser* pUser = user();
        if (!pUser->isUserAttached() && !pUser->isBeingDeleted()) {
            for (std::set<NoPartylineChannel*>::iterator it = m_ssChannels.begin(); it != m_ssChannels.end(); ++it) {
                const std::set<NoString>& ssNicks = (*it)->GetNicks();

                if (ssNicks.find(pUser->userName()) != ssNicks.end()) {
                    PutChan(ssNicks,
                            ":*" + moduleName() + "!znc@znc.in MODE " + (*it)->GetName() + " -ov " + NICK_PREFIX +
                            pUser->userName() + " " + NICK_PREFIX + pUser->userName(),
                            false);
                }
            }
        }
    }

    ModRet onUserRaw(NoString& sLine) override
    {
        if (sLine.startsWith("WHO " CHAN_PREFIX_1)) {
            return HALT;
        } else if (sLine.startsWith("MODE " CHAN_PREFIX_1)) {
            return HALT;
        } else if (sLine.startsWith("TOPIC " CHAN_PREFIX)) {
            NoString sChannel = No::token(sLine, 1);
            NoString sTopic = No::tokens(sLine, 2);

            sTopic.trimPrefix(":");

            NoUser* pUser = user();
            NoClient* pClient = client();
            NoPartylineChannel* pChannel = FindChannel(sChannel);

            if (pChannel && pChannel->IsInChannel(pUser->userName())) {
                const std::set<NoString>& ssNicks = pChannel->GetNicks();
                if (!sTopic.empty()) {
                    if (pUser->isAdmin()) {
                        PutChan(ssNicks, ":" + pClient->nickMask() + " TOPIC " + sChannel + " :" + sTopic);
                        pChannel->SetTopic(sTopic);
                        SaveTopic(pChannel);
                    } else {
                        pUser->putUser(":irc.znc.in 482 " + pClient->nick() + " " + sChannel +
                                       " :You're not channel operator");
                    }
                } else {
                    sTopic = pChannel->GetTopic();

                    if (sTopic.empty()) {
                        pUser->putUser(":irc.znc.in 331 " + pClient->nick() + " " + sChannel + " :No topic is set.");
                    } else {
                        pUser->putUser(":irc.znc.in 332 " + pClient->nick() + " " + sChannel + " :" + sTopic);
                    }
                }
            } else {
                pUser->putUser(":irc.znc.in 442 " + pClient->nick() + " " + sChannel + " :You're not on that channel");
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

    void PartUser(NoUser* pUser, NoPartylineChannel* pChannel, const NoString& sMessage = "")
    {
        RemoveUser(pUser, pChannel, "PART", sMessage);
    }

    void RemoveUser(NoUser* pUser, NoPartylineChannel* pChannel, const NoString& sCommand, const NoString& sMessage = "", bool bNickAsTarget = false)
    {
        if (!pChannel || !pChannel->IsInChannel(pUser->userName())) {
            return;
        }

        std::vector<NoClient*> vClients = pUser->allClients();

        NoString sCmd = " " + sCommand + " ";
        NoString sMsg = sMessage;
        if (!sMsg.empty())
            sMsg = " :" + sMsg;

        pChannel->DelNick(pUser->userName());

        const std::set<NoString>& ssNicks = pChannel->GetNicks();
        NoString sHost = pUser->bindHost();

        if (sHost.empty()) {
            sHost = "znc.in";
        }

        if (bNickAsTarget) {
            for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                NoClient* pClient = *it;

                pClient->putClient(":" + pClient->nickMask() + sCmd + pChannel->GetName() + " " + pClient->nick() + sMsg);
            }

            PutChan(ssNicks,
                    ":" + NICK_PREFIX + pUser->userName() + "!" + pUser->ident() + "@" + sHost + sCmd +
                    pChannel->GetName() + " " + NICK_PREFIX + pUser->userName() + sMsg,
                    false,
                    true,
                    pUser);
        } else {
            for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                NoClient* pClient = *it;

                pClient->putClient(":" + pClient->nickMask() + sCmd + pChannel->GetName() + sMsg);
            }

            PutChan(ssNicks,
                    ":" + NICK_PREFIX + pUser->userName() + "!" + pUser->ident() + "@" + sHost + sCmd + pChannel->GetName() + sMsg,
                    false,
                    true,
                    pUser);
        }

        if (!pUser->isBeingDeleted() && m_ssDefaultChans.find(pChannel->GetName()) != m_ssDefaultChans.end()) {
            JoinUser(pUser, pChannel);
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

    void JoinUser(NoUser* pUser, NoPartylineChannel* pChannel)
    {
        if (pChannel && !pChannel->IsInChannel(pUser->userName())) {
            std::vector<NoClient*> vClients = pUser->allClients();

            const std::set<NoString>& ssNicks = pChannel->GetNicks();
            const NoString& sNick = pUser->userName();
            pChannel->AddNick(sNick);

            NoString sHost = pUser->bindHost();

            if (sHost.empty()) {
                sHost = "znc.in";
            }

            for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                NoClient* pClient = *it;
                pClient->putClient(":" + pClient->nickMask() + " JOIN " + pChannel->GetName());
            }

            PutChan(ssNicks, ":" + NICK_PREFIX + sNick + "!" + pUser->ident() + "@" + sHost + " JOIN " + pChannel->GetName(), false, true, pUser);

            if (!pChannel->GetTopic().empty()) {
                for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                    NoClient* pClient = *it;
                    pClient->putClient(":" + ircServer(pClient->network()) + " 332 " + pClient->nickMask() + " " +
                                       pChannel->GetName() + " :" + pChannel->GetTopic());
                }
            }

            SendNickList(pUser, nullptr, ssNicks, pChannel->GetName());

            /* Tell the other clients we have op or voice, the current user's clients already know from NAMES list */

            if (pUser->isAdmin()) {
                PutChan(ssNicks,
                        ":*" + moduleName() + "!znc@znc.in MODE " + pChannel->GetName() + " +o " + NICK_PREFIX + pUser->userName(),
                        false,
                        false,
                        pUser);
            }

            PutChan(ssNicks,
                    ":*" + moduleName() + "!znc@znc.in MODE " + pChannel->GetName() + " +v " + NICK_PREFIX + pUser->userName(),
                    false,
                    false,
                    pUser);
        }
    }

    ModRet HandleMessage(const NoString& sCmd, const NoString& sTarget, const NoString& sMessage)
    {
        if (sTarget.empty()) {
            return CONTINUE;
        }

        char cPrefix = sTarget[0];

        if (cPrefix != CHAN_PREFIX_1C && cPrefix != NICK_PREFIX_C) {
            return CONTINUE;
        }

        NoUser* pUser = user();
        NoClient* pClient = client();
        NoNetwork* pNetwork = network();
        NoString sHost = pUser->bindHost();

        if (sHost.empty()) {
            sHost = "znc.in";
        }

        if (cPrefix == CHAN_PREFIX_1C) {
            if (FindChannel(sTarget) == nullptr) {
                pClient->putClient(":" + ircServer(pNetwork) + " 401 " + pClient->nick() + " " + sTarget +
                                   " :No such channel");
                return HALT;
            }

            PutChan(sTarget,
                    ":" + NICK_PREFIX + pUser->userName() + "!" + pUser->ident() + "@" + sHost + " " + sCmd + " " +
                    sTarget + " :" + sMessage,
                    true,
                    false);
        } else {
            NoString sNick = sTarget.leftChomp_n(1);
            NoUser* pTargetUser = NoApp::instance().findUser(sNick);

            if (pTargetUser) {
                std::vector<NoClient*> vClients = pTargetUser->allClients();

                if (vClients.empty()) {
                    pClient->putClient(":" + ircServer(pNetwork) + " 401 " + pClient->nick() + " " + sTarget +
                                       " :User is not attached: " + sNick + "");
                    return HALT;
                }

                for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                    NoClient* pTarget = *it;

                    pTarget->putClient(":" + NICK_PREFIX + pUser->userName() + "!" + pUser->ident() + "@" + sHost +
                                       " " + sCmd + " " + pTarget->nick() + " :" + sMessage);
                }
            } else {
                pClient->putClient(":" + ircServer(pNetwork) + " 401 " + pClient->nick() + " " + sTarget +
                                   " :No such znc user: " + sNick + "");
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

    const NoString ircServer(NoNetwork* pNetwork)
    {
        if (!pNetwork) {
            return "irc.znc.in";
        }

        const NoString& sServer = pNetwork->ircServer();
        if (!sServer.empty())
            return sServer;
        return "irc.znc.in";
    }

    bool PutChan(const NoString& sChan,
                 const NoString& sLine,
                 bool bIncludeCurUser = true,
                 bool bIncludeClient = true,
                 NoUser* pUser = nullptr,
                 NoClient* pClient = nullptr)
    {
        NoPartylineChannel* pChannel = FindChannel(sChan);

        if (pChannel != nullptr) {
            PutChan(pChannel->GetNicks(), sLine, bIncludeCurUser, bIncludeClient, pUser, pClient);
            return true;
        }

        return false;
    }

    void PutChan(const std::set<NoString>& ssNicks,
                 const NoString& sLine,
                 bool bIncludeCurUser = true,
                 bool bIncludeClient = true,
                 NoUser* pUser = nullptr,
                 NoClient* pClient = nullptr)
    {
        const std::map<NoString, NoUser*>& msUsers = NoApp::instance().userMap();

        if (!pUser)
            pUser = user();
        if (!pClient)
            pClient = client();

        for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it) {
            if (ssNicks.find(it->first) != ssNicks.end()) {
                if (it->second == pUser) {
                    if (bIncludeCurUser) {
                        it->second->putAllUser(sLine, nullptr, (bIncludeClient ? nullptr : pClient));
                    }
                } else {
                    it->second->putAllUser(sLine);
                }
            }
        }
    }

    void putUserIRCNick(NoUser* pUser, const NoString& sPre, const NoString& sPost)
    {
        const std::vector<NoClient*>& vClients = pUser->allClients();
        std::vector<NoClient*>::const_iterator it;
        for (it = vClients.begin(); it != vClients.end(); ++it) {
            (*it)->putClient(sPre + (*it)->nick() + sPost);
        }
    }

    void SendNickList(NoUser* pUser, NoNetwork* pNetwork, const std::set<NoString>& ssNicks, const NoString& sChan)
    {
        NoString sNickList;

        for (std::set<NoString>::const_iterator it = ssNicks.begin(); it != ssNicks.end(); ++it) {
            NoUser* pChanUser = NoApp::instance().findUser(*it);

            if (pChanUser == pUser) {
                continue;
            }

            if (pChanUser && pChanUser->isUserAttached()) {
                sNickList += (pChanUser->isAdmin()) ? "@" : "+";
            }

            sNickList += NICK_PREFIX + (*it) + " ";

            if (sNickList.size() >= 500) {
                putUserIRCNick(pUser, ":" + ircServer(pNetwork) + " 353 ", " @ " + sChan + " :" + sNickList);
                sNickList.clear();
            }
        }

        if (sNickList.size()) {
            putUserIRCNick(pUser, ":" + ircServer(pNetwork) + " 353 ", " @ " + sChan + " :" + sNickList);
        }

        std::vector<NoClient*> vClients = pUser->allClients();
        for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
            NoClient* pClient = *it;
            pClient->putClient(":" + ircServer(pNetwork) + " 353 " + pClient->nick() + " @ " + sChan + " :" +
                               ((pUser->isAdmin()) ? "@" : "+") + pClient->nick());
        }

        putUserIRCNick(pUser, ":" + ircServer(pNetwork) + " 366 ", " " + sChan + " :End of /NAMES list.");
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
