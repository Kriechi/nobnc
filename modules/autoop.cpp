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

#include <no/nonetwork.h>
#include <no/nochannel.h>

class NoAutoOpMod;

#define AUTOOP_CHALLENGE_LENGTH 32

class NoAutoOpTimer : public NoTimer
{
public:
    NoAutoOpTimer(NoAutoOpMod* pModule)
        : NoTimer((NoModule*)pModule, 20, 0, "AutoOpChecker", "Check channels for auto op candidates")
    {
        m_pParent = pModule;
    }

    virtual ~NoAutoOpTimer() {}

private:
protected:
    void RunJob() override;

    NoAutoOpMod* m_pParent;
};

class NoAutoOpUser
{
public:
    NoAutoOpUser() {}

    NoAutoOpUser(const NoString& sLine) { FromString(sLine); }

    NoAutoOpUser(const NoString& sUsername, const NoString& sUserKey, const NoString& sHostmasks, const NoString& sChannels)
        : m_sUsername(sUsername), m_sUserKey(sUserKey)
    {
        AddHostmasks(sHostmasks);
        AddChans(sChannels);
    }

    virtual ~NoAutoOpUser() {}

    const NoString& GetUsername() const { return m_sUsername; }
    const NoString& GetUserKey() const { return m_sUserKey; }

    bool ChannelMatches(const NoString& sChan) const
    {
        for (std::set<NoString>::const_iterator it = m_ssChans.begin(); it != m_ssChans.end(); ++it) {
            if (sChan.AsLower().WildCmp(*it, No::CaseInsensitive)) {
                return true;
            }
        }

        return false;
    }

    bool HostMatches(const NoString& sHostmask)
    {
        for (std::set<NoString>::const_iterator it = m_ssHostmasks.begin(); it != m_ssHostmasks.end(); ++it) {
            if (sHostmask.WildCmp(*it, No::CaseInsensitive)) {
                return true;
            }
        }
        return false;
    }

    NoString GetHostmasks() const { return NoString(",").Join(m_ssHostmasks.begin(), m_ssHostmasks.end()); }

    NoString GetChannels() const { return NoString(" ").Join(m_ssChans.begin(), m_ssChans.end()); }

    bool DelHostmasks(const NoString& sHostmasks)
    {
        NoStringVector vsHostmasks = sHostmasks.Split(",");

        for (uint a = 0; a < vsHostmasks.size(); a++) {
            m_ssHostmasks.erase(vsHostmasks[a]);
        }

        return m_ssHostmasks.empty();
    }

    void AddHostmasks(const NoString& sHostmasks)
    {
        NoStringVector vsHostmasks = sHostmasks.Split(",");

        for (uint a = 0; a < vsHostmasks.size(); a++) {
            m_ssHostmasks.insert(vsHostmasks[a]);
        }
    }

    void DelChans(const NoString& sChans)
    {
        NoStringVector vsChans = sChans.Split(" ");

        for (uint a = 0; a < vsChans.size(); a++) {
            m_ssChans.erase(vsChans[a].AsLower());
        }
    }

    void AddChans(const NoString& sChans)
    {
        NoStringVector vsChans = sChans.Split(" ");

        for (uint a = 0; a < vsChans.size(); a++) {
            m_ssChans.insert(vsChans[a].AsLower());
        }
    }

    NoString ToString() const { return m_sUsername + "\t" + GetHostmasks() + "\t" + m_sUserKey + "\t" + GetChannels(); }

    bool FromString(const NoString& sLine)
    {
        m_sUsername = sLine.Token(0, false, "\t");
        m_sUserKey = sLine.Token(2, false, "\t");

        NoStringVector vsHostMasks = sLine.Token(1, false, "\t").Split(",");
        m_ssHostmasks = NoStringSet(vsHostMasks.begin(), vsHostMasks.end());

        NoStringVector vsChans = sLine.Token(3, false, "\t").Split(" ");
        m_ssChans = NoStringSet(vsChans.begin(), vsChans.end());

        return !m_sUserKey.empty();
    }

private:
protected:
    NoString m_sUsername;
    NoString m_sUserKey;
    std::set<NoString> m_ssHostmasks;
    std::set<NoString> m_ssChans;
};

class NoAutoOpMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoAutoOpMod)
    {
        AddHelpCommand();
        AddCommand("ListUsers",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAutoOpMod::OnListUsersCommand),
                   "",
                   "List all users");
        AddCommand("AddChans",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAutoOpMod::OnAddChansCommand),
                   "<user> <channel> [channel] ...",
                   "Adds channels to a user");
        AddCommand("DelChans",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAutoOpMod::OnDelChansCommand),
                   "<user> <channel> [channel] ...",
                   "Removes channels from a user");
        AddCommand("AddMasks",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAutoOpMod::OnAddMasksCommand),
                   "<user> <mask>,[mask] ...",
                   "Adds masks to a user");
        AddCommand("DelMasks",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAutoOpMod::OnDelMasksCommand),
                   "<user> <mask>,[mask] ...",
                   "Removes masks from a user");
        AddCommand("AddUser",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAutoOpMod::OnAddUserCommand),
                   "<user> <hostmask>[,<hostmasks>...] <key> [channels]",
                   "Adds a user");
        AddCommand("DelUser",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAutoOpMod::OnDelUserCommand),
                   "<user>",
                   "Removes a user");
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        AddTimer(new NoAutoOpTimer(this));

        // Load the users
        for (NoStringMap::iterator it = BeginNV(); it != EndNV(); ++it) {
            const NoString& sLine = it->second;
            NoAutoOpUser* pUser = new NoAutoOpUser;

            if (!pUser->FromString(sLine) || FindUser(pUser->GetUsername().AsLower())) {
                delete pUser;
            } else {
                m_msUsers[pUser->GetUsername().AsLower()] = pUser;
            }
        }

        return true;
    }

    virtual ~NoAutoOpMod()
    {
        for (std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            delete it->second;
        }
        m_msUsers.clear();
    }

    void OnJoin(const NoNick& Nick, NoChannel& Channel) override
    {
        // If we have ops in this chan
        if (Channel.hasPerm(NoChannel::Op)) {
            CheckAutoOp(Nick, Channel);
        }
    }

    void OnQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans) override
    {
        NoStringMap::iterator it = m_msQueue.find(Nick.nick().AsLower());

        if (it != m_msQueue.end()) {
            m_msQueue.erase(it);
        }
    }

    void OnNick(const NoNick& OldNick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans) override
    {
        // Update the queue with nick changes
        NoStringMap::iterator it = m_msQueue.find(OldNick.nick().AsLower());

        if (it != m_msQueue.end()) {
            m_msQueue[sNewNick.AsLower()] = it->second;
            m_msQueue.erase(it);
        }
    }

    EModRet OnPrivNotice(NoNick& Nick, NoString& sMessage) override
    {
        if (!sMessage.Token(0).Equals("!ZNCAO")) {
            return CONTINUE;
        }

        NoString sCommand = sMessage.Token(1);

        if (sCommand.Equals("CHALLENGE")) {
            ChallengeRespond(Nick, sMessage.Token(2));
        } else if (sCommand.Equals("RESPONSE")) {
            VerifyResponse(Nick, sMessage.Token(2));
        }

        return HALTCORE;
    }

    void OnOp2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override
    {
        if (Nick.nick() == GetNetwork()->GetIRNoNick().nick()) {
            const std::map<NoString, NoNick>& msNicks = Channel.getNicks();

            for (std::map<NoString, NoNick>::const_iterator it = msNicks.begin(); it != msNicks.end(); ++it) {
                if (!it->second.hasPerm(NoChannel::Op)) {
                    CheckAutoOp(it->second, Channel);
                }
            }
        }
    }

    void OnModCommand(const NoString& sLine) override
    {
        NoString sCommand = sLine.Token(0).AsUpper();
        if (sCommand.Equals("TIMERS")) {
            // for testing purposes - hidden from help
            ListTimers();
        } else {
            HandleCommand(sLine);
        }
    }

    void OnAddUserCommand(const NoString& sLine)
    {
        NoString sUser = sLine.Token(1);
        NoString sHost = sLine.Token(2);
        NoString sKey = sLine.Token(3);

        if (sHost.empty()) {
            PutModule("Usage: AddUser <user> <hostmask>[,<hostmasks>...] <key> [channels]");
        } else {
            NoAutoOpUser* pUser = AddUser(sUser, sKey, sHost, sLine.Token(4, true));

            if (pUser) {
                SetNV(sUser, pUser->ToString());
            }
        }
    }

    void OnDelUserCommand(const NoString& sLine)
    {
        NoString sUser = sLine.Token(1);

        if (sUser.empty()) {
            PutModule("Usage: DelUser <user>");
        } else {
            DelUser(sUser);
            DelNV(sUser);
        }
    }

    void OnListUsersCommand(const NoString& sLine)
    {
        if (m_msUsers.empty()) {
            PutModule("There are no users defined");
            return;
        }

        NoTable Table;

        Table.AddColumn("User");
        Table.AddColumn("Hostmasks");
        Table.AddColumn("Key");
        Table.AddColumn("Channels");

        for (std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            NoStringVector vsHostmasks = it->second->GetHostmasks().Split(",");
            for (uint a = 0; a < vsHostmasks.size(); a++) {
                Table.AddRow();
                if (a == 0) {
                    Table.SetCell("User", it->second->GetUsername());
                    Table.SetCell("Key", it->second->GetUserKey());
                    Table.SetCell("Channels", it->second->GetChannels());
                } else if (a == vsHostmasks.size() - 1) {
                    Table.SetCell("User", "`-");
                } else {
                    Table.SetCell("User", "|-");
                }
                Table.SetCell("Hostmasks", vsHostmasks[a]);
            }
        }

        PutModule(Table);
    }

    void OnAddChansCommand(const NoString& sLine)
    {
        NoString sUser = sLine.Token(1);
        NoString sChans = sLine.Token(2, true);

        if (sChans.empty()) {
            PutModule("Usage: AddChans <user> <channel> [channel] ...");
            return;
        }

        NoAutoOpUser* pUser = FindUser(sUser);

        if (!pUser) {
            PutModule("No such user");
            return;
        }

        pUser->AddChans(sChans);
        PutModule("Channel(s) added to user [" + pUser->GetUsername() + "]");
        SetNV(pUser->GetUsername(), pUser->ToString());
    }

    void OnDelChansCommand(const NoString& sLine)
    {
        NoString sUser = sLine.Token(1);
        NoString sChans = sLine.Token(2, true);

        if (sChans.empty()) {
            PutModule("Usage: DelChans <user> <channel> [channel] ...");
            return;
        }

        NoAutoOpUser* pUser = FindUser(sUser);

        if (!pUser) {
            PutModule("No such user");
            return;
        }

        pUser->DelChans(sChans);
        PutModule("Channel(s) Removed from user [" + pUser->GetUsername() + "]");
        SetNV(pUser->GetUsername(), pUser->ToString());
    }

    void OnAddMasksCommand(const NoString& sLine)
    {
        NoString sUser = sLine.Token(1);
        NoString sHostmasks = sLine.Token(2, true);

        if (sHostmasks.empty()) {
            PutModule("Usage: AddMasks <user> <mask>,[mask] ...");
            return;
        }

        NoAutoOpUser* pUser = FindUser(sUser);

        if (!pUser) {
            PutModule("No such user");
            return;
        }

        pUser->AddHostmasks(sHostmasks);
        PutModule("Hostmasks(s) added to user [" + pUser->GetUsername() + "]");
        SetNV(pUser->GetUsername(), pUser->ToString());
    }

    void OnDelMasksCommand(const NoString& sLine)
    {
        NoString sUser = sLine.Token(1);
        NoString sHostmasks = sLine.Token(2, true);

        if (sHostmasks.empty()) {
            PutModule("Usage: DelMasks <user> <mask>,[mask] ...");
            return;
        }

        NoAutoOpUser* pUser = FindUser(sUser);

        if (!pUser) {
            PutModule("No such user");
            return;
        }

        if (pUser->DelHostmasks(sHostmasks)) {
            PutModule("Removed user [" + pUser->GetUsername() + "] with key [" + pUser->GetUserKey() +
                      "] and channels [" + pUser->GetChannels() + "]");
            DelUser(sUser);
            DelNV(sUser);
        } else {
            PutModule("Hostmasks(s) Removed from user [" + pUser->GetUsername() + "]");
            SetNV(pUser->GetUsername(), pUser->ToString());
        }
    }

    NoAutoOpUser* FindUser(const NoString& sUser)
    {
        std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.find(sUser.AsLower());

        return (it != m_msUsers.end()) ? it->second : nullptr;
    }

    NoAutoOpUser* FindUserByHost(const NoString& sHostmask, const NoString& sChannel = "")
    {
        for (std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            NoAutoOpUser* pUser = it->second;

            if (pUser->HostMatches(sHostmask) && (sChannel.empty() || pUser->ChannelMatches(sChannel))) {
                return pUser;
            }
        }

        return nullptr;
    }

    bool CheckAutoOp(const NoNick& Nick, NoChannel& Channel)
    {
        NoAutoOpUser* pUser = FindUserByHost(Nick.hostMask(), Channel.getName());

        if (!pUser) {
            return false;
        }

        if (pUser->GetUserKey().Equals("__NOKEY__")) {
            PutIRC("MODE " + Channel.getName() + " +o " + Nick.nick());
        } else {
            // then insert this nick into the queue, the timer does the rest
            NoString sNick = Nick.nick().AsLower();
            if (m_msQueue.find(sNick) == m_msQueue.end()) {
                m_msQueue[sNick] = "";
            }
        }

        return true;
    }

    void DelUser(const NoString& sUser)
    {
        std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.find(sUser.AsLower());

        if (it == m_msUsers.end()) {
            PutModule("That user does not exist");
            return;
        }

        delete it->second;
        m_msUsers.erase(it);
        PutModule("User [" + sUser + "] removed");
    }

    NoAutoOpUser* AddUser(const NoString& sUser, const NoString& sKey, const NoString& sHosts, const NoString& sChans)
    {
        if (m_msUsers.find(sUser) != m_msUsers.end()) {
            PutModule("That user already exists");
            return nullptr;
        }

        NoAutoOpUser* pUser = new NoAutoOpUser(sUser, sKey, sHosts, sChans);
        m_msUsers[sUser.AsLower()] = pUser;
        PutModule("User [" + sUser + "] added with hostmask(s) [" + sHosts + "]");
        return pUser;
    }

    bool ChallengeRespond(const NoNick& Nick, const NoString& sChallenge)
    {
        // Validate before responding - don't blindly trust everyone
        bool bValid = false;
        bool bMatchedHost = false;
        NoAutoOpUser* pUser = nullptr;

        for (std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            pUser = it->second;

            // First verify that the person who challenged us matches a user's host
            if (pUser->HostMatches(Nick.hostMask())) {
                const std::vector<NoChannel*>& Chans = GetNetwork()->GetChans();
                bMatchedHost = true;

                // Also verify that they are opped in at least one of the user's chans
                for (size_t a = 0; a < Chans.size(); a++) {
                    const NoChannel& Chan = *Chans[a];

                    const NoNick* pNick = Chan.findNick(Nick.nick());

                    if (pNick) {
                        if (pNick->hasPerm(NoChannel::Op) && pUser->ChannelMatches(Chan.getName())) {
                            bValid = true;
                            break;
                        }
                    }
                }

                if (bValid) {
                    break;
                }
            }
        }

        if (!bValid) {
            if (bMatchedHost) {
                PutModule("[" + Nick.hostMask() +
                          "] sent us a challenge but they are not opped in any defined channels.");
            } else {
                PutModule("[" + Nick.hostMask() + "] sent us a challenge but they do not match a defined user.");
            }

            return false;
        }

        if (sChallenge.length() != AUTOOP_CHALLENGE_LENGTH) {
            PutModule("WARNING! [" + Nick.hostMask() + "] sent an invalid challenge.");
            return false;
        }

        NoString sResponse = pUser->GetUserKey() + "::" + sChallenge;
        PutIRC("NOTICE " + Nick.nick() + " :!ZNCAO RESPONSE " + NoUtils::MD5(sResponse));
        return false;
    }

    bool VerifyResponse(const NoNick& Nick, const NoString& sResponse)
    {
        NoStringMap::iterator itQueue = m_msQueue.find(Nick.nick().AsLower());

        if (itQueue == m_msQueue.end()) {
            PutModule("[" + Nick.hostMask() + "] sent an unchallenged response.  This could be due to lag.");
            return false;
        }

        NoString sChallenge = itQueue->second;
        m_msQueue.erase(itQueue);

        for (std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            if (it->second->HostMatches(Nick.hostMask())) {
                if (sResponse == NoUtils::MD5(it->second->GetUserKey() + "::" + sChallenge)) {
                    OpUser(Nick, *it->second);
                    return true;
                } else {
                    PutModule("WARNING! [" + Nick.hostMask() +
                              "] sent a bad response.  Please verify that you have their correct password.");
                    return false;
                }
            }
        }

        PutModule("WARNING! [" + Nick.hostMask() + "] sent a response but did not match any defined users.");
        return false;
    }

    void ProcessQueue()
    {
        bool bRemoved = true;

        // First remove any stale challenges

        while (bRemoved) {
            bRemoved = false;

            for (NoStringMap::iterator it = m_msQueue.begin(); it != m_msQueue.end(); ++it) {
                if (!it->second.empty()) {
                    m_msQueue.erase(it);
                    bRemoved = true;
                    break;
                }
            }
        }

        // Now issue challenges for the new users in the queue
        for (NoStringMap::iterator it = m_msQueue.begin(); it != m_msQueue.end(); ++it) {
            it->second = NoUtils::RandomString(AUTOOP_CHALLENGE_LENGTH);
            PutIRC("NOTICE " + it->first + " :!ZNCAO CHALLENGE " + it->second);
        }
    }

    void OpUser(const NoNick& Nick, const NoAutoOpUser& User)
    {
        const std::vector<NoChannel*>& Chans = GetNetwork()->GetChans();

        for (size_t a = 0; a < Chans.size(); a++) {
            const NoChannel& Chan = *Chans[a];

            if (Chan.hasPerm(NoChannel::Op) && User.ChannelMatches(Chan.getName())) {
                const NoNick* pNick = Chan.findNick(Nick.nick());

                if (pNick && !pNick->hasPerm(NoChannel::Op)) {
                    PutIRC("MODE " + Chan.getName() + " +o " + Nick.nick());
                }
            }
        }
    }

private:
    std::map<NoString, NoAutoOpUser*> m_msUsers;
    NoStringMap m_msQueue;
};

void NoAutoOpTimer::RunJob() { m_pParent->ProcessQueue(); }

template <> void TModInfo<NoAutoOpMod>(NoModInfo& Info) { Info.SetWikiPage("autoop"); }

NETWORKMODULEDEFS(NoAutoOpMod, "Auto op the good people")
