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
#include <nobnc/noregistry.h>
#include <nobnc/nonick.h>

class NoAutoOpMod;

#define AUTOOP_CHALLENGE_LENGTH 32

class NoAutoOpTimer : public NoTimer
{
public:
    NoAutoOpTimer(NoModule* module) : NoTimer(module)
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
    NoAutoOpUser()
    {
    }

    NoAutoOpUser(const NoString& line)
    {
        FromString(line);
    }

    NoAutoOpUser(const NoString& username, const NoString& sUserKey, const NoString& sHostmasks, const NoString& sChannels)
        : m_sUsername(username), m_sUserKey(sUserKey)
    {
        AddHostmasks(sHostmasks);
        addChannels(sChannels);
    }

    const NoString& GetUsername() const
    {
        return m_sUsername;
    }
    const NoString& GetUserKey() const
    {
        return m_sUserKey;
    }

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

    NoString GetHostmasks() const
    {
        return NoString(",").join(m_ssHostmasks.begin(), m_ssHostmasks.end());
    }

    NoString GetChannels() const
    {
        return NoString(" ").join(m_ssChans.begin(), m_ssChans.end());
    }

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

    void removeChannels(const NoString& sChans)
    {
        NoStringVector vsChans = sChans.split(" ");

        for (uint a = 0; a < vsChans.size(); a++) {
            m_ssChans.erase(vsChans[a].toLower());
        }
    }

    void addChannels(const NoString& sChans)
    {
        NoStringVector vsChans = sChans.split(" ");

        for (uint a = 0; a < vsChans.size(); a++) {
            m_ssChans.insert(vsChans[a].toLower());
        }
    }

    NoString ToString() const
    {
        return m_sUsername + "\t" + GetHostmasks() + "\t" + m_sUserKey + "\t" + GetChannels();
    }

    bool FromString(const NoString& line)
    {
        m_sUsername = No::token(line, 0, "\t");
        m_sUserKey = No::token(line, 2, "\t");

        NoStringVector vsHostMasks = No::token(line, 1, "\t").split(",");
        m_ssHostmasks = NoStringSet(vsHostMasks.begin(), vsHostMasks.end());

        NoStringVector vsChans = No::token(line, 3, "\t").split(" ");
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
        addHelpCommand();
        addCommand("ListUsers",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoOpMod::OnListUsersCommand),
                   "",
                   "List all users");
        addCommand("addChannels",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoOpMod::OnaddChannelsCommand),
                   "<user> <channel> [channel] ...",
                   "Adds channels to a user");
        addCommand("removeChannels",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoOpMod::OnremoveChannelsCommand),
                   "<user> <channel> [channel] ...",
                   "Removes channels from a user");
        addCommand("AddMasks",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoOpMod::OnAddMasksCommand),
                   "<user> <mask>,[mask] ...",
                   "Adds masks to a user");
        addCommand("DelMasks",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoOpMod::OnDelMasksCommand),
                   "<user> <mask>,[mask] ...",
                   "Removes masks from a user");
        addCommand("AddUser",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoOpMod::onAddUserCommand),
                   "<user> <hostmask>[,<hostmasks>...] <key> [channels]",
                   "Adds a user");
        addCommand("DelUser",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoOpMod::OnDelUserCommand),
                   "<user>",
                   "Removes a user");
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        NoAutoOpTimer* timer = new NoAutoOpTimer(this);
        timer->start(20);

        // Load the users
        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            const NoString& line = registry.value(key);
            NoAutoOpUser* user = new NoAutoOpUser;

            if (!user->FromString(line) || FindUser(user->GetUsername().toLower())) {
                delete user;
            } else {
                m_msUsers[user->GetUsername().toLower()] = user;
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

    void onJoin(const NoNick& nick, NoChannel* channel) override
    {
        // If we have ops in this chan
        if (channel->hasPerm(NoChannel::Op)) {
            CheckAutoOp(nick, channel);
        }
    }

    void onQuit(const NoNick& nick, const NoString& message, const std::vector<NoChannel*>& channels) override
    {
        NoStringMap::iterator it = m_msQueue.find(nick.nick().toLower());

        if (it != m_msQueue.end()) {
            m_msQueue.erase(it);
        }
    }

    void onNick(const NoNick& OldNick, const NoString& newNick, const std::vector<NoChannel*>& channels) override
    {
        // Update the queue with nick changes
        NoStringMap::iterator it = m_msQueue.find(OldNick.nick().toLower());

        if (it != m_msQueue.end()) {
            m_msQueue[newNick.toLower()] = it->second;
            m_msQueue.erase(it);
        }
    }

    ModRet onPrivNotice(NoNick& nick, NoString& message) override
    {
        if (!No::token(message, 0).equals("!ZNCAO")) {
            return CONTINUE;
        }

        NoString command = No::token(message, 1);

        if (command.equals("CHALLENGE")) {
            ChallengeRespond(nick, No::token(message, 2));
        } else if (command.equals("RESPONSE")) {
            VerifyResponse(nick, No::token(message, 2));
        }

        return HALTCORE;
    }

    void onOp2(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange) override
    {
        if (nick.nick() == network()->ircNick().nick()) {
            const std::map<NoString, NoNick>& msNicks = channel->nicks();

            for (std::map<NoString, NoNick>::const_iterator it = msNicks.begin(); it != msNicks.end(); ++it) {
                if (!it->second.hasPerm(NoChannel::Op)) {
                    CheckAutoOp(it->second, channel);
                }
            }
        }
    }

    void onModCommand(const NoString& line) override
    {
        NoString command = No::token(line, 0).toUpper();
        if (command.equals("TIMERS")) {
            // for testing purposes - hidden from help
            listTimers();
        } else {
            handleCommand(line);
        }
    }

    void onAddUserCommand(const NoString& line)
    {
        NoString sUser = No::token(line, 1);
        NoString host = No::token(line, 2);
        NoString key = No::token(line, 3);

        if (host.empty()) {
            putModule("Usage: AddUser <user> <hostmask>[,<hostmasks>...] <key> [channels]");
        } else {
            NoAutoOpUser* user = AddUser(sUser, key, host, No::tokens(line, 4));

            if (user) {
                NoRegistry registry(this);
                registry.setValue(sUser, user->ToString());
            }
        }
    }

    void OnDelUserCommand(const NoString& line)
    {
        NoString sUser = No::token(line, 1);

        if (sUser.empty()) {
            putModule("Usage: DelUser <user>");
        } else {
            DelUser(sUser);
            NoRegistry registry(this);
            registry.remove(sUser);
        }
    }

    void OnListUsersCommand(const NoString& line)
    {
        if (m_msUsers.empty()) {
            putModule("There are no users defined");
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

        putModule(Table);
    }

    void OnaddChannelsCommand(const NoString& line)
    {
        NoString sUser = No::token(line, 1);
        NoString sChans = No::tokens(line, 2);

        if (sChans.empty()) {
            putModule("Usage: addChannels <user> <channel> [channel] ...");
            return;
        }

        NoAutoOpUser* user = FindUser(sUser);

        if (!user) {
            putModule("No such user");
            return;
        }

        user->addChannels(sChans);
        putModule("channel(s) added to user [" + user->GetUsername() + "]");

        NoRegistry registry(this);
        registry.setValue(user->GetUsername(), user->ToString());
    }

    void OnremoveChannelsCommand(const NoString& line)
    {
        NoString sUser = No::token(line, 1);
        NoString sChans = No::tokens(line, 2);

        if (sChans.empty()) {
            putModule("Usage: removeChannels <user> <channel> [channel] ...");
            return;
        }

        NoAutoOpUser* user = FindUser(sUser);

        if (!user) {
            putModule("No such user");
            return;
        }

        user->removeChannels(sChans);
        putModule("channel(s) Removed from user [" + user->GetUsername() + "]");

        NoRegistry registry(this);
        registry.setValue(user->GetUsername(), user->ToString());
    }

    void OnAddMasksCommand(const NoString& line)
    {
        NoString sUser = No::token(line, 1);
        NoString sHostmasks = No::tokens(line, 2);

        if (sHostmasks.empty()) {
            putModule("Usage: AddMasks <user> <mask>,[mask] ...");
            return;
        }

        NoAutoOpUser* user = FindUser(sUser);

        if (!user) {
            putModule("No such user");
            return;
        }

        user->AddHostmasks(sHostmasks);
        putModule("Hostmasks(s) added to user [" + user->GetUsername() + "]");

        NoRegistry registry(this);
        registry.setValue(user->GetUsername(), user->ToString());
    }

    void OnDelMasksCommand(const NoString& line)
    {
        NoString sUser = No::token(line, 1);
        NoString sHostmasks = No::tokens(line, 2);

        if (sHostmasks.empty()) {
            putModule("Usage: DelMasks <user> <mask>,[mask] ...");
            return;
        }

        NoAutoOpUser* user = FindUser(sUser);

        if (!user) {
            putModule("No such user");
            return;
        }

        if (user->DelHostmasks(sHostmasks)) {
            putModule("Removed user [" + user->GetUsername() + "] with key [" + user->GetUserKey() +
                      "] and channels [" + user->GetChannels() + "]");
            DelUser(sUser);
            NoRegistry registry(this);
            registry.remove(sUser);
        } else {
            putModule("Hostmasks(s) Removed from user [" + user->GetUsername() + "]");
            NoRegistry registry(this);
            registry.setValue(user->GetUsername(), user->ToString());
        }
    }

    NoAutoOpUser* FindUser(const NoString& sUser)
    {
        std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.find(sUser.toLower());

        return (it != m_msUsers.end()) ? it->second : nullptr;
    }

    NoAutoOpUser* FindUserByHost(const NoString& sHostmask, const NoString& channel = "")
    {
        for (std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            NoAutoOpUser* user = it->second;

            if (user->HostMatches(sHostmask) && (channel.empty() || user->ChannelMatches(channel))) {
                return user;
            }
        }

        return nullptr;
    }

    bool CheckAutoOp(const NoNick& nick, NoChannel* channel)
    {
        NoAutoOpUser* user = FindUserByHost(nick.hostMask(), channel->name());

        if (!user) {
            return false;
        }

        if (user->GetUserKey().equals("__NOKEY__")) {
            putIrc("MODE " + channel->name() + " +o " + nick.nick());
        } else {
            // then insert this nick into the queue, the timer does the rest
            NoString lower = nick.nick().toLower();
            if (m_msQueue.find(lower) == m_msQueue.end()) {
                m_msQueue[lower] = "";
            }
        }

        return true;
    }

    void DelUser(const NoString& sUser)
    {
        std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.find(sUser.toLower());

        if (it == m_msUsers.end()) {
            putModule("That user does not exist");
            return;
        }

        delete it->second;
        m_msUsers.erase(it);
        putModule("User [" + sUser + "] removed");
    }

    NoAutoOpUser* AddUser(const NoString& sUser, const NoString& key, const NoString& sHosts, const NoString& sChans)
    {
        if (m_msUsers.find(sUser) != m_msUsers.end()) {
            putModule("That user already exists");
            return nullptr;
        }

        NoAutoOpUser* user = new NoAutoOpUser(sUser, key, sHosts, sChans);
        m_msUsers[sUser.toLower()] = user;
        putModule("User [" + sUser + "] added with hostmask(s) [" + sHosts + "]");
        return user;
    }

    bool ChallengeRespond(const NoNick& nick, const NoString& sChallenge)
    {
        // Validate before responding - don't blindly trust everyone
        bool bValid = false;
        bool bMatchedHost = false;
        NoAutoOpUser* user = nullptr;

        for (std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            user = it->second;

            // First verify that the person who challenged us matches a user's host
            if (user->HostMatches(nick.hostMask())) {
                const std::vector<NoChannel*>& Chans = network()->channels();
                bMatchedHost = true;

                // Also verify that they are opped in at least one of the user's chans
                for (size_t a = 0; a < Chans.size(); a++) {
                    const NoChannel* channel = Chans[a];

                    const NoNick* pNick = channel->findNick(nick.nick());

                    if (pNick) {
                        if (pNick->hasPerm(NoChannel::Op) && user->ChannelMatches(channel->name())) {
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
                putModule("[" + nick.hostMask() +
                          "] sent us a challenge but they are not opped in any defined channels.");
            } else {
                putModule("[" + nick.hostMask() + "] sent us a challenge but they do not match a defined user.");
            }

            return false;
        }

        if (sChallenge.length() != AUTOOP_CHALLENGE_LENGTH) {
            putModule("WARNING! [" + nick.hostMask() + "] sent an invalid challenge.");
            return false;
        }

        NoString response = user->GetUserKey() + "::" + sChallenge;
        putIrc("NOTICE " + nick.nick() + " :!ZNCAO RESPONSE " + No::md5(response));
        return false;
    }

    bool VerifyResponse(const NoNick& nick, const NoString& response)
    {
        NoStringMap::iterator itQueue = m_msQueue.find(nick.nick().toLower());

        if (itQueue == m_msQueue.end()) {
            putModule("[" + nick.hostMask() + "] sent an unchallenged response.  This could be due to lag.");
            return false;
        }

        NoString sChallenge = itQueue->second;
        m_msQueue.erase(itQueue);

        for (std::map<NoString, NoAutoOpUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            if (it->second->HostMatches(nick.hostMask())) {
                if (response == No::md5(it->second->GetUserKey() + "::" + sChallenge)) {
                    OpUser(nick, *it->second);
                    return true;
                } else {
                    putModule("WARNING! [" + nick.hostMask() +
                              "] sent a bad response.  Please verify that you have their correct password.");
                    return false;
                }
            }
        }

        putModule("WARNING! [" + nick.hostMask() + "] sent a response but did not match any defined users.");
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
            putIrc("NOTICE " + it->first + " :!ZNCAO CHALLENGE " + it->second);
        }
    }

    void OpUser(const NoNick& nick, const NoAutoOpUser& User)
    {
        const std::vector<NoChannel*>& Chans = network()->channels();

        for (size_t a = 0; a < Chans.size(); a++) {
            const NoChannel* channel = Chans[a];

            if (channel->hasPerm(NoChannel::Op) && User.ChannelMatches(channel->name())) {
                const NoNick* pNick = channel->findNick(nick.nick());

                if (pNick && !pNick->hasPerm(NoChannel::Op)) {
                    putIrc("MODE " + channel->name() + " +o " + nick.nick());
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

template <>
void no_moduleInfo<NoAutoOpMod>(NoModuleInfo& info)
{
    info.setWikiPage("autoop");
}

NETWORKMODULEDEFS(NoAutoOpMod, "Auto op the good people")
