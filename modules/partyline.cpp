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

#include <no/nomodule.h>
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/noapp.h>
#include <no/noclient.h>

// If you change these and it breaks, you get to keep the pieces
#define CHAN_PREFIX_1 "~"
#define CHAN_PREFIX_1C '~'
#define CHAN_PREFIX CHAN_PREFIX_1 "#"

#define NICK_PREFIX NoString("?")
#define NICK_PREFIX_C '?'

class NoPartylineChannel
{
public:
    NoPartylineChannel(const NoString& sName) { m_sName = sName.toLower(); }

    const NoString& GetTopic() const { return m_sTopic; }
    const NoString& GetName() const { return m_sName; }
    const std::set<NoString>& GetNicks() const { return m_ssNicks; }

    void SetTopic(const NoString& s) { m_sTopic = s; }

    void AddNick(const NoString& s) { m_ssNicks.insert(s); }
    void DelNick(const NoString& s) { m_ssNicks.erase(s); }

    bool IsInChannel(const NoString& s) { return m_ssNicks.find(s) != m_ssNicks.end(); }

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
            PutModule("There are no open channels.");
            return;
        }

        NoTable Table;

        Table.AddColumn("Channel");
        Table.AddColumn("Users");

        for (std::set<NoPartylineChannel*>::const_iterator a = m_ssChannels.begin(); a != m_ssChannels.end(); ++a) {
            Table.AddRow();

            Table.SetCell("Channel", (*a)->GetName());
            Table.SetCell("Users", NoString((*a)->GetNicks().size()));
        }

        PutModule(Table);
    }

    MODCONSTRUCTOR(NoPartylineMod)
    {
        AddHelpCommand();
        AddCommand("List",
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
                NoUser* pUser = NoApp::Get().FindUser(*it2);
                std::vector<NoClient*> vClients = pUser->GetAllClients();

                for (std::vector<NoClient*>::const_iterator it3 = vClients.begin(); it3 != vClients.end(); ++it3) {
                    NoClient* pClient = *it3;
                    pClient->PutClient(":*" + GetModName() + "!znc@znc.in KICK " + (*it)->GetName() + " " +
                                       pClient->GetNick() + " :" + GetModName() + " unloaded");
                }
            }
        }

        while (!m_ssChannels.empty()) {
            delete *m_ssChannels.begin();
            m_ssChannels.erase(m_ssChannels.begin());
        }
    }

    bool OnBoot() override
    {
        // The config is now read completely, so all Users are set up
        Load();

        return true;
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        const std::map<NoString, NoUser*>& msUsers = NoApp::Get().GetUserMap();

        for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it) {
            NoUser* pUser = it->second;
            for (std::vector<NoNetwork*>::const_iterator i = pUser->GetNetworks().begin(); i != pUser->GetNetworks().end(); ++i) {
                NoNetwork* pNetwork = *i;
                if (pNetwork->GetIRCSock()) {
                    if (pNetwork->GetChanPrefixes().find(CHAN_PREFIX_1) == NoString::npos) {
                        pNetwork->PutUser(":" + GetIRCServer(pNetwork) + " 005 " + pNetwork->GetIRCNick().nick() +
                                          " CHANTYPES=" + pNetwork->GetChanPrefixes() + CHAN_PREFIX_1
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
        for (NoStringMap::iterator it = BeginNV(); it != EndNV(); ++it) {
            if (it->first.find(":") != NoString::npos) {
                sAction = No::token(it->first, 0, ":");
                sKey = No::tokens(it->first, 1, ":");
            } else {
                // backwards compatibility for older NV data
                sAction = "fixedchan";
                sKey = it->first;
            }

            if (sAction == "fixedchan") {
                // Sorry, this was removed
            }

            if (sAction == "topic") {
                pChannel = FindChannel(sKey);
                if (pChannel && !(it->second).empty()) {
                    PutChan(pChannel->GetNicks(), ":irc.znc.in TOPIC " + pChannel->GetName() + " :" + it->second);
                    pChannel->SetTopic(it->second);
                }
            }
        }

        return;
    }

    void SaveTopic(NoPartylineChannel* pChannel)
    {
        if (!pChannel->GetTopic().empty())
            SetNV("topic:" + pChannel->GetName(), pChannel->GetTopic());
        else
            DelNV("topic:" + pChannel->GetName());
    }

    ModRet OnDeleteUser(NoUser& User) override
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

    ModRet OnRaw(NoString& sLine) override
    {
        if (No::token(sLine, 1) == "005") {
            NoString::size_type uPos = sLine.toUpper().find("CHANTYPES=");
            if (uPos != NoString::npos) {
                uPos = sLine.find(" ", uPos);

                if (uPos == NoString::npos)
                    sLine.append(CHAN_PREFIX_1);
                else
                    sLine.insert(uPos, CHAN_PREFIX_1);
                m_spInjectedPrefixes.insert(GetNetwork());
            }
        }

        return CONTINUE;
    }

    void OnIRCDisconnected() override { m_spInjectedPrefixes.erase(GetNetwork()); }

    void OnClientLogin() override
    {
        NoUser* pUser = GetUser();
        NoClient* pClient = GetClient();
        NoNetwork* pNetwork = GetNetwork();
        if (m_spInjectedPrefixes.find(pNetwork) == m_spInjectedPrefixes.end() && pNetwork && !pNetwork->GetChanPrefixes().empty()) {
            pClient->PutClient(":" + GetIRCServer(pNetwork) + " 005 " + pClient->GetNick() + " CHANTYPES=" +
                               pNetwork->GetChanPrefixes() + CHAN_PREFIX_1 " :are supported by this server.");
        }

        // Make sure this user is in the default channels
        for (std::set<NoString>::iterator a = m_ssDefaultChans.begin(); a != m_ssDefaultChans.end(); ++a) {
            NoPartylineChannel* pChannel = GetChannel(*a);
            const NoString& sNick = pUser->GetUserName();

            if (pChannel->IsInChannel(sNick)) continue;

            NoString sHost = pUser->GetBindHost();
            const std::set<NoString>& ssNicks = pChannel->GetNicks();

            if (sHost.empty()) {
                sHost = "znc.in";
            }
            PutChan(ssNicks, ":" + NICK_PREFIX + sNick + "!" + pUser->GetIdent() + "@" + sHost + " JOIN " + *a, false);
            pChannel->AddNick(sNick);
        }

        NoString sNickMask = pClient->GetNickMask();

        for (std::set<NoPartylineChannel*>::iterator it = m_ssChannels.begin(); it != m_ssChannels.end(); ++it) {
            const std::set<NoString>& ssNicks = (*it)->GetNicks();

            if ((*it)->IsInChannel(pUser->GetUserName())) {

                pClient->PutClient(":" + sNickMask + " JOIN " + (*it)->GetName());

                if (!(*it)->GetTopic().empty()) {
                    pClient->PutClient(":" + GetIRCServer(pNetwork) + " 332 " + pClient->GetNickMask() + " " +
                                       (*it)->GetName() + " :" + (*it)->GetTopic());
                }

                SendNickList(pUser, pNetwork, ssNicks, (*it)->GetName());
                PutChan(ssNicks,
                        ":*" + GetModName() + "!znc@znc.in MODE " + (*it)->GetName() + " +" +
                        NoString(pUser->IsAdmin() ? "o" : "v") + " " + NICK_PREFIX + pUser->GetUserName(),
                        false);
            }
        }
    }

    void OnClientDisconnect() override
    {
        NoUser* pUser = GetUser();
        if (!pUser->IsUserAttached() && !pUser->IsBeingDeleted()) {
            for (std::set<NoPartylineChannel*>::iterator it = m_ssChannels.begin(); it != m_ssChannels.end(); ++it) {
                const std::set<NoString>& ssNicks = (*it)->GetNicks();

                if (ssNicks.find(pUser->GetUserName()) != ssNicks.end()) {
                    PutChan(ssNicks,
                            ":*" + GetModName() + "!znc@znc.in MODE " + (*it)->GetName() + " -ov " + NICK_PREFIX +
                            pUser->GetUserName() + " " + NICK_PREFIX + pUser->GetUserName(),
                            false);
                }
            }
        }
    }

    ModRet OnUserRaw(NoString& sLine) override
    {
        if (sLine.startsWith("WHO " CHAN_PREFIX_1)) {
            return HALT;
        } else if (sLine.startsWith("MODE " CHAN_PREFIX_1)) {
            return HALT;
        } else if (sLine.startsWith("TOPIC " CHAN_PREFIX)) {
            NoString sChannel = No::token(sLine, 1);
            NoString sTopic = No::tokens(sLine, 2);

            sTopic.trimPrefix(":");

            NoUser* pUser = GetUser();
            NoClient* pClient = GetClient();
            NoPartylineChannel* pChannel = FindChannel(sChannel);

            if (pChannel && pChannel->IsInChannel(pUser->GetUserName())) {
                const std::set<NoString>& ssNicks = pChannel->GetNicks();
                if (!sTopic.empty()) {
                    if (pUser->IsAdmin()) {
                        PutChan(ssNicks, ":" + pClient->GetNickMask() + " TOPIC " + sChannel + " :" + sTopic);
                        pChannel->SetTopic(sTopic);
                        SaveTopic(pChannel);
                    } else {
                        pUser->PutUser(":irc.znc.in 482 " + pClient->GetNick() + " " + sChannel +
                                       " :You're not channel operator");
                    }
                } else {
                    sTopic = pChannel->GetTopic();

                    if (sTopic.empty()) {
                        pUser->PutUser(":irc.znc.in 331 " + pClient->GetNick() + " " + sChannel + " :No topic is set.");
                    } else {
                        pUser->PutUser(":irc.znc.in 332 " + pClient->GetNick() + " " + sChannel + " :" + sTopic);
                    }
                }
            } else {
                pUser->PutUser(":irc.znc.in 442 " + pClient->GetNick() + " " + sChannel +
                               " :You're not on that channel");
            }
            return HALT;
        }

        return CONTINUE;
    }

    ModRet OnUserPart(NoString& sChannel, NoString& sMessage) override
    {
        if (sChannel.left(1) != CHAN_PREFIX_1) {
            return CONTINUE;
        }

        if (sChannel.left(2) != CHAN_PREFIX) {
            GetClient()->PutClient(":" + GetIRCServer(GetNetwork()) + " 401 " + GetClient()->GetNick() + " " + sChannel + " :No such channel");
            return HALT;
        }

        NoPartylineChannel* pChannel = FindChannel(sChannel);

        PartUser(GetUser(), pChannel);

        return HALT;
    }

    void PartUser(NoUser* pUser, NoPartylineChannel* pChannel, const NoString& sMessage = "")
    {
        RemoveUser(pUser, pChannel, "PART", sMessage);
    }

    void RemoveUser(NoUser* pUser, NoPartylineChannel* pChannel, const NoString& sCommand, const NoString& sMessage = "", bool bNickAsTarget = false)
    {
        if (!pChannel || !pChannel->IsInChannel(pUser->GetUserName())) {
            return;
        }

        std::vector<NoClient*> vClients = pUser->GetAllClients();

        NoString sCmd = " " + sCommand + " ";
        NoString sMsg = sMessage;
        if (!sMsg.empty()) sMsg = " :" + sMsg;

        pChannel->DelNick(pUser->GetUserName());

        const std::set<NoString>& ssNicks = pChannel->GetNicks();
        NoString sHost = pUser->GetBindHost();

        if (sHost.empty()) {
            sHost = "znc.in";
        }

        if (bNickAsTarget) {
            for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                NoClient* pClient = *it;

                pClient->PutClient(":" + pClient->GetNickMask() + sCmd + pChannel->GetName() + " " + pClient->GetNick() + sMsg);
            }

            PutChan(ssNicks,
                    ":" + NICK_PREFIX + pUser->GetUserName() + "!" + pUser->GetIdent() + "@" + sHost + sCmd +
                    pChannel->GetName() + " " + NICK_PREFIX + pUser->GetUserName() + sMsg,
                    false,
                    true,
                    pUser);
        } else {
            for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                NoClient* pClient = *it;

                pClient->PutClient(":" + pClient->GetNickMask() + sCmd + pChannel->GetName() + sMsg);
            }

            PutChan(ssNicks,
                    ":" + NICK_PREFIX + pUser->GetUserName() + "!" + pUser->GetIdent() + "@" + sHost + sCmd +
                    pChannel->GetName() + sMsg,
                    false,
                    true,
                    pUser);
        }

        if (!pUser->IsBeingDeleted() && m_ssDefaultChans.find(pChannel->GetName()) != m_ssDefaultChans.end()) {
            JoinUser(pUser, pChannel);
        }

        if (ssNicks.empty()) {
            delete pChannel;
            m_ssChannels.erase(pChannel);
        }
    }

    ModRet OnUserJoin(NoString& sChannel, NoString& sKey) override
    {
        if (sChannel.left(1) != CHAN_PREFIX_1) {
            return CONTINUE;
        }

        if (sChannel.left(2) != CHAN_PREFIX) {
            GetClient()->PutClient(":" + GetIRCServer(GetNetwork()) + " 403 " + GetClient()->GetNick() + " " +
                                   sChannel + " :Channels look like " CHAN_PREFIX "znc");
            return HALT;
        }

        sChannel = sChannel.left(32);
        NoPartylineChannel* pChannel = GetChannel(sChannel);

        JoinUser(GetUser(), pChannel);

        return HALT;
    }

    void JoinUser(NoUser* pUser, NoPartylineChannel* pChannel)
    {
        if (pChannel && !pChannel->IsInChannel(pUser->GetUserName())) {
            std::vector<NoClient*> vClients = pUser->GetAllClients();

            const std::set<NoString>& ssNicks = pChannel->GetNicks();
            const NoString& sNick = pUser->GetUserName();
            pChannel->AddNick(sNick);

            NoString sHost = pUser->GetBindHost();

            if (sHost.empty()) {
                sHost = "znc.in";
            }

            for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                NoClient* pClient = *it;
                pClient->PutClient(":" + pClient->GetNickMask() + " JOIN " + pChannel->GetName());
            }

            PutChan(ssNicks,
                    ":" + NICK_PREFIX + sNick + "!" + pUser->GetIdent() + "@" + sHost + " JOIN " + pChannel->GetName(),
                    false,
                    true,
                    pUser);

            if (!pChannel->GetTopic().empty()) {
                for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                    NoClient* pClient = *it;
                    pClient->PutClient(":" + GetIRCServer(pClient->GetNetwork()) + " 332 " + pClient->GetNickMask() +
                                       " " + pChannel->GetName() + " :" + pChannel->GetTopic());
                }
            }

            SendNickList(pUser, nullptr, ssNicks, pChannel->GetName());

            /* Tell the other clients we have op or voice, the current user's clients already know from NAMES list */

            if (pUser->IsAdmin()) {
                PutChan(ssNicks,
                        ":*" + GetModName() + "!znc@znc.in MODE " + pChannel->GetName() + " +o " + NICK_PREFIX + pUser->GetUserName(),
                        false,
                        false,
                        pUser);
            }

            PutChan(ssNicks,
                    ":*" + GetModName() + "!znc@znc.in MODE " + pChannel->GetName() + " +v " + NICK_PREFIX + pUser->GetUserName(),
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

        NoUser* pUser = GetUser();
        NoClient* pClient = GetClient();
        NoNetwork* pNetwork = GetNetwork();
        NoString sHost = pUser->GetBindHost();

        if (sHost.empty()) {
            sHost = "znc.in";
        }

        if (cPrefix == CHAN_PREFIX_1C) {
            if (FindChannel(sTarget) == nullptr) {
                pClient->PutClient(":" + GetIRCServer(pNetwork) + " 401 " + pClient->GetNick() + " " + sTarget +
                                   " :No such channel");
                return HALT;
            }

            PutChan(sTarget,
                    ":" + NICK_PREFIX + pUser->GetUserName() + "!" + pUser->GetIdent() + "@" + sHost + " " + sCmd +
                    " " + sTarget + " :" + sMessage,
                    true,
                    false);
        } else {
            NoString sNick = sTarget.leftChomp_n(1);
            NoUser* pTargetUser = NoApp::Get().FindUser(sNick);

            if (pTargetUser) {
                std::vector<NoClient*> vClients = pTargetUser->GetAllClients();

                if (vClients.empty()) {
                    pClient->PutClient(":" + GetIRCServer(pNetwork) + " 401 " + pClient->GetNick() + " " + sTarget +
                                       " :User is not attached: " + sNick + "");
                    return HALT;
                }

                for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
                    NoClient* pTarget = *it;

                    pTarget->PutClient(":" + NICK_PREFIX + pUser->GetUserName() + "!" + pUser->GetIdent() + "@" +
                                       sHost + " " + sCmd + " " + pTarget->GetNick() + " :" + sMessage);
                }
            } else {
                pClient->PutClient(":" + GetIRCServer(pNetwork) + " 401 " + pClient->GetNick() + " " + sTarget +
                                   " :No such znc user: " + sNick + "");
            }
        }

        return HALT;
    }

    ModRet OnUserMsg(NoString& sTarget, NoString& sMessage) override
    {
        return HandleMessage("PRIVMSG", sTarget, sMessage);
    }

    ModRet OnUserNotice(NoString& sTarget, NoString& sMessage) override
    {
        return HandleMessage("NOTICE", sTarget, sMessage);
    }

    ModRet OnUserAction(NoString& sTarget, NoString& sMessage) override
    {
        return HandleMessage("PRIVMSG", sTarget, "\001ACTION " + sMessage + "\001");
    }

    ModRet OnUserCTCP(NoString& sTarget, NoString& sMessage) override
    {
        return HandleMessage("PRIVMSG", sTarget, "\001" + sMessage + "\001");
    }

    ModRet OnUserCTCPReply(NoString& sTarget, NoString& sMessage) override
    {
        return HandleMessage("NOTICE", sTarget, "\001" + sMessage + "\001");
    }

    const NoString GetIRCServer(NoNetwork* pNetwork)
    {
        if (!pNetwork) {
            return "irc.znc.in";
        }

        const NoString& sServer = pNetwork->GetIRCServer();
        if (!sServer.empty()) return sServer;
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
        const std::map<NoString, NoUser*>& msUsers = NoApp::Get().GetUserMap();

        if (!pUser) pUser = GetUser();
        if (!pClient) pClient = GetClient();

        for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it) {
            if (ssNicks.find(it->first) != ssNicks.end()) {
                if (it->second == pUser) {
                    if (bIncludeCurUser) {
                        it->second->PutAllUser(sLine, nullptr, (bIncludeClient ? nullptr : pClient));
                    }
                } else {
                    it->second->PutAllUser(sLine);
                }
            }
        }
    }

    void PutUserIRCNick(NoUser* pUser, const NoString& sPre, const NoString& sPost)
    {
        const std::vector<NoClient*>& vClients = pUser->GetAllClients();
        std::vector<NoClient*>::const_iterator it;
        for (it = vClients.begin(); it != vClients.end(); ++it) {
            (*it)->PutClient(sPre + (*it)->GetNick() + sPost);
        }
    }

    void SendNickList(NoUser* pUser, NoNetwork* pNetwork, const std::set<NoString>& ssNicks, const NoString& sChan)
    {
        NoString sNickList;

        for (std::set<NoString>::const_iterator it = ssNicks.begin(); it != ssNicks.end(); ++it) {
            NoUser* pChanUser = NoApp::Get().FindUser(*it);

            if (pChanUser == pUser) {
                continue;
            }

            if (pChanUser && pChanUser->IsUserAttached()) {
                sNickList += (pChanUser->IsAdmin()) ? "@" : "+";
            }

            sNickList += NICK_PREFIX + (*it) + " ";

            if (sNickList.size() >= 500) {
                PutUserIRCNick(pUser, ":" + GetIRCServer(pNetwork) + " 353 ", " @ " + sChan + " :" + sNickList);
                sNickList.clear();
            }
        }

        if (sNickList.size()) {
            PutUserIRCNick(pUser, ":" + GetIRCServer(pNetwork) + " 353 ", " @ " + sChan + " :" + sNickList);
        }

        std::vector<NoClient*> vClients = pUser->GetAllClients();
        for (std::vector<NoClient*>::const_iterator it = vClients.begin(); it != vClients.end(); ++it) {
            NoClient* pClient = *it;
            pClient->PutClient(":" + GetIRCServer(pNetwork) + " 353 " + pClient->GetNick() + " @ " + sChan + " :" +
                               ((pUser->IsAdmin()) ? "@" : "+") + pClient->GetNick());
        }

        PutUserIRCNick(pUser, ":" + GetIRCServer(pNetwork) + " 366 ", " " + sChan + " :End of /NAMES list.");
    }

    NoPartylineChannel* FindChannel(const NoString& sChan)
    {
        NoString sChannel = sChan.toLower();

        for (std::set<NoPartylineChannel*>::iterator it = m_ssChannels.begin(); it != m_ssChannels.end(); ++it) {
            if ((*it)->GetName().toLower() == sChannel) return *it;
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

template <> void no_moduleInfo<NoPartylineMod>(NoModuleInfo& Info)
{
    Info.SetWikiPage("partyline");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("You may enter a list of channels the user joins, when entering the internal partyline.");
}

GLOBALMODULEDEFS(NoPartylineMod, "Internal channels and queries for users connected to znc")
