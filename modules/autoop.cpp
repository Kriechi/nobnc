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
#include <no/nonetwork.h>
#include <no/nochannel.h>
#include <no/noregistry.h>
#include <no/nonick.h>

class NoAutoOpMod;

#define AUTOOP_CHALLENGE_LENGTH 32

class NoAutoOpTimer : public NoTimer
{
public:
    NoAutoOpTimer(NoModule* pModule) : NoTimer(pModule)
    {
        setName("AutoOpChecker");
        setDescription("Check channels for auto op candidates");
    }

protected:
    void run() override;
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

    const NoString& GetUsername() const { return m_sUsername; }
    const NoString& GetUserKey() const { return m_sUserKey; }

    bool ChannelMatches(const NoString& sChan) const
    {
        for (std::set<NoString>::const_iterator it = m_ssChans.begin(); it != m_ssChans.end(); ++it) {
            if (No::wildCmp(sChan, *it, No::CaseInsensitive)) {
                return true;
            }
        }

        return false;
    }

    bool HostMatches(const NoString& sHostmask)
    {
        for (std::set<NoString>::const_iterator it = m_ssHostmasks.begin(); it != m_ssHostmasks.end(); ++it) {
            if (No::wildCmp(sHostmask, *it, No::CaseInsensitive)) {
                return true;
            }
        }
        return false;
    }

    NoString GetHostmasks() const { return NoString(",").join(m_ssHostmasks.begin(), m_ssHostmasks.end()); }

    NoString GetChannels() const { return NoString(" ").join(m_ssChans.begin(), m_ssChans.end()); }

    bool DelHostmasks(const NoString& sHostmasks)
    {
        NoStringVector vsHostmasks = sHostmasks.split(",");

        for (uint a = 0; a < vsHostmasks.size(); a++) {
            m_ssHostmasks.erase(vsHostmasks[a]);
        }

        return m_ssHostmasks.empty();
    }

    void AddHostmasks(const NoString& sHostmasks)
    {
        NoStringVector vsHostmasks = sHostmasks.split(",");

        for (uint a = 0; a < vsHostmasks.size(); a++) {
            m_ssHostmasks.insert(vsHostmasks[a]);
        }
    }

    void DelChans(const NoString& sChans)
    {
        NoStringVector vsChans = sChans.split(" ");

        for (uint a = 0; a < vsChans.size(); a++) {
            m_ssChans.erase(vsChans[a].toLower());
        }
    }

    void AddChans(const NoString& sChans)
    {
        NoStringVector vsChans = sChans.split(" ");

        for (uint a = 0; a < vsChans.size(); a++) {
            m_ssChans.insert(vsChans[a].toLower());
        }
    }

    NoString ToString() const { return m_sUsername + "\t" + GetHostmasks() + "\t" + m_sUserKey + "\t" + GetChannels(); }

    bool FromString(const NoString& sLine)
    {
        m_sUsername = No::token(sLine, 0, "\t");
        m_sUserKey = No::token(sLine, 2, "\t");

        NoStringVector vsHostMasks = No::token(sLine, 1, "\t").split(",");
        m_ssHostmasks = NoStringSet(vsHostMasks.begin(), vsHostMasks.end());

        NoStringVector vsChans = No::token(sLine, 3, "\t").split(" ");
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
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoOpMod::OnListUsersCommand),
                   "",
                   "List all users");
        AddCommand("AddChans",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoOpMod::OnAddChansCommand),
                   "<user> <channel> [channel] ...",
                   "Adds channels to a user");
        AddCommand("DelChans",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoOpMod::OnDelChansCommand),
                   "<user> <channel> [channel] ...",
                   "Removes channels from a user");
        AddCommand("AddMasks",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoOpMod::OnAddMasksCommand),
                   "<user> <mask>,[mask] ...",
                   "Adds masks to a user");
        AddCommand("DelMasks",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoOpMod::OnDelMasksCommand),
                   "<user> <mask>,[mask] ...",
                   "Removes masks from a user");
        AddCommand("AddUser",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoOpMod::onAddUserCommand),
                   "<user> <hostmask>[,<hostmasks>...] <key> [channels]",
                   "Adds a user");
        AddCommand("DelUser",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoOpMod::OnDelUserCommand),
                   "<user>",
                   "Removes a user");
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        NoAutoOpTimer* timer = new NoAutoOpTimer(this);
        timer->start(20);

        // Load the users
        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            const NoString& sLine = registry.value(key);
            NoAutoOpUser* pUser = new NoAutoOpUser;

            if (!pUser->FromString(sLine) || FindUser(pUser->GetUsername().toLower())) {
                delete pUser;
            } else {
                m_msUsers[pUser->GetUsername().toLower()] = pUser;
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

    void onJoin(const NoNick& Nick, NoChannel& Channel) override
    {
        // If we have ops in this chan
        if (Channel.hasPerm(NoChannel::Op)) {
            CheckAutoOp(Nick, Channel);
        }
    }

    void onQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans) override
    {
        NoStringMap::iterator it = m_msQueue.find(Nick.nick().toLower());

        if (it != m_msQueue.end()) {
            m_msQueue.erase(it);
        }
    }

    void onNick(const NoNick& OldNick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans) override
    {
        // Update the queue with nick changes
        NoStringMap::iterator it = m_msQueue.find(OldNick.nick().toLower());

        if (it != m_msQueue.end()) {
            m_msQueue[sNewNick.toLower()] = it->second;
            m_msQueue.erase(it);
        }
    }

    ModRet onPrivNotice(NoNick& Nick, NoString& sMessage) override
    {
        if (!No::token(sMessage, 0).equals("!ZNCAO")) {
            return CONTINUE;
        }

        NoString sCommand = No::token(sMessage, 1);

        if (sCommand.equals("CHALLENGE")) {
            ChallengeRespond(Nick, No::token(sMessage, 2));
        } else if (sCommand.equals("RESPONSE")) {
            VerifyResponse(Nick, No::token(sMessage, 2));
        }

        return HALTCORE;
    }

    void onOp2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override
    {
        if (Nick.nick() == GetNetwork()->GetIRCNick().nick()) {
            const std::map<NoString, NoNick>& msNicks = Channel.getNicks();

            for (std::map<NoString, NoNick>::const_iterator it = msNicks.begin(); it != msNicks.end(); ++it) {
                if (!it->second.hasPerm(NoChannel::Op)) {
                    CheckAutoOp(it->second, Channel);
                }
            }
        }
    }

    void onModCommand(const NoString& sLine) override
    {
        NoString sCommand = No::token(sLine, 0).toUpper();
        if (sCommand.equals("TIMERS")) {
            // for testing purposes - hidden from help
            ListTimers();
        } else {
            HandleCommand(sLine);
        }
    }

    void onAddUserCommand(const NoString& sLine)
    {
        NoString sUser = No::token(sLine, 1);
        NoString sHost = No::token(sLine, 2);
        NoString sKey = No::token(sLine, 3);

        if (sHost.empty()) {
            PutModule("Usage: AddUser <user> <hostmask>[,<hostmasks>...] <key> [channels]");
        } else {
            NoAutoOpUser* pUser = AddUser(sUser, sKey, sHost, No::tokens(sLine, 4));

            if (pUser) {
                NoRegistry registry(this);
                registry.setValue(sUser, pUser->ToString());
            }
        }
    }

    void OnDelUserCommand(const NoString& sLine)
    {
        NoString sUser = No::token(sLine, 1);

        if (sUser.empty()) {
            PutModule("Usage: DelUser <user>");
        } else {
            DelUser(sUser);
            NoRegistry registry(this);
            registry.remove(sUser);
        }
    }

    void OnListUsersCommand(const NoString& sLine)
    {
        if (m_msUsers.empty()) {
            PutModule("There are no users defined");
            return;
        }

        NoTable Table;

        Table.addColumn("User");
        Table.addColumn("Hostmasks");
        Table.addColumn("Key");
        Table.addColumn("Channels");

        for (std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            NoStringVector vsHostmasks = it->second->GetHostmasks().split(",");
            for (uint a = 0; a < vsHostmasks.size(); a++) {
                Table.addRow();
                if (a == 0) {
                    Table.setValue("User", it->second->GetUsername());
                    Table.setValue("Key", it->second->GetUserKey());
                    Table.setValue("Channels", it->second->GetChannels());
                } else if (a == vsHostmasks.size() - 1) {
                    Table.setValue("User", "`-");
                } else {
                    Table.setValue("User", "|-");
                }
                Table.setValue("Hostmasks", vsHostmasks[a]);
            }
        }

        PutModule(Table);
    }

    void OnAddChansCommand(const NoString& sLine)
    {
        NoString sUser = No::token(sLine, 1);
        NoString sChans = No::tokens(sLine, 2);

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

        NoRegistry registry(this);
        registry.setValue(pUser->GetUsername(), pUser->ToString());
    }

    void OnDelChansCommand(const NoString& sLine)
    {
        NoString sUser = No::token(sLine, 1);
        NoString sChans = No::tokens(sLine, 2);

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

        NoRegistry registry(this);
        registry.setValue(pUser->GetUsername(), pUser->ToString());
    }

    void OnAddMasksCommand(const NoString& sLine)
    {
        NoString sUser = No::token(sLine, 1);
        NoString sHostmasks = No::tokens(sLine, 2);

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

        NoRegistry registry(this);
        registry.setValue(pUser->GetUsername(), pUser->ToString());
    }

    void OnDelMasksCommand(const NoString& sLine)
    {
        NoString sUser = No::token(sLine, 1);
        NoString sHostmasks = No::tokens(sLine, 2);

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
            NoRegistry registry(this);
            registry.remove(sUser);
        } else {
            PutModule("Hostmasks(s) Removed from user [" + pUser->GetUsername() + "]");
            NoRegistry registry(this);
            registry.setValue(pUser->GetUsername(), pUser->ToString());
        }
    }

    NoAutoOpUser* FindUser(const NoString& sUser)
    {
        std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.find(sUser.toLower());

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

        if (pUser->GetUserKey().equals("__NOKEY__")) {
            PutIRC("MODE " + Channel.getName() + " +o " + Nick.nick());
        } else {
            // then insert this nick into the queue, the timer does the rest
            NoString sNick = Nick.nick().toLower();
            if (m_msQueue.find(sNick) == m_msQueue.end()) {
                m_msQueue[sNick] = "";
            }
        }

        return true;
    }

    void DelUser(const NoString& sUser)
    {
        std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.find(sUser.toLower());

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
        m_msUsers[sUser.toLower()] = pUser;
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
        PutIRC("NOTICE " + Nick.nick() + " :!ZNCAO RESPONSE " + No::md5(sResponse));
        return false;
    }

    bool VerifyResponse(const NoNick& Nick, const NoString& sResponse)
    {
        NoStringMap::iterator itQueue = m_msQueue.find(Nick.nick().toLower());

        if (itQueue == m_msQueue.end()) {
            PutModule("[" + Nick.hostMask() + "] sent an unchallenged response.  This could be due to lag.");
            return false;
        }

        NoString sChallenge = itQueue->second;
        m_msQueue.erase(itQueue);

        for (std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            if (it->second->HostMatches(Nick.hostMask())) {
                if (sResponse == No::md5(it->second->GetUserKey() + "::" + sChallenge)) {
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
            it->second = No::randomString(AUTOOP_CHALLENGE_LENGTH);
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

void NoAutoOpTimer::run()
{
    static_cast<NoAutoOpMod*>(module())->ProcessQueue();
}

template <> void no_moduleInfo<NoAutoOpMod>(NoModuleInfo& Info) { Info.SetWikiPage("autoop"); }

NETWORKMODULEDEFS(NoAutoOpMod, "Auto op the good people")
