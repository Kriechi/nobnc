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
#include <nobnc/nochannel.h>
#include <nobnc/noregistry.h>
#include <nobnc/nonick.h>

class NoAutoVoiceUser
{
public:
    NoAutoVoiceUser()
    {
    }

    NoAutoVoiceUser(const NoString& line)
    {
        FromString(line);
    }

    NoAutoVoiceUser(const NoString& username, const NoString& sHostmask, const NoString& sChannels)
        : m_sUsername(username), m_sHostmask(sHostmask)
    {
        addChannels(sChannels);
    }

    const NoString& GetUsername() const
    {
        return m_sUsername;
    }
    const NoString& GetHostmask() const
    {
        return m_sHostmask;
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
        return No::wildCmp(sHostmask, m_sHostmask, No::CaseInsensitive);
    }

    NoString GetChannels() const
    {
        NoString ret;

        for (std::set<NoString>::const_iterator it = m_ssChans.begin(); it != m_ssChans.end(); ++it) {
            if (!ret.empty()) {
                ret += " ";
            }

            ret += *it;
        }

        return ret;
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
        NoString sChans;

        for (std::set<NoString>::const_iterator it = m_ssChans.begin(); it != m_ssChans.end(); ++it) {
            if (!sChans.empty()) {
                sChans += " ";
            }

            sChans += *it;
        }

        return m_sUsername + "\t" + m_sHostmask + "\t" + sChans;
    }

    bool FromString(const NoString& line)
    {
        m_sUsername = No::token(line, 0, "\t");
        m_sHostmask = No::token(line, 1, "\t");

        NoStringVector vsChans = No::token(line, 2, "\t").split(" ");
        m_ssChans = NoStringSet(vsChans.begin(), vsChans.end());

        return !m_sHostmask.empty();
    }

private:
protected:
    NoString m_sUsername;
    NoString m_sHostmask;
    std::set<NoString> m_ssChans;
};

class NoAutoVoiceMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoAutoVoiceMod)
    {
        addHelpCommand();
        addCommand("ListUsers",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoVoiceMod::OnListUsersCommand),
                   "",
                   "List all users");
        addCommand("addChannels",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoVoiceMod::OnaddChannelsCommand),
                   "<user> <channel> [channel] ...",
                   "Adds channels to a user");
        addCommand("removeChannels",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoVoiceMod::OnremoveChannelsCommand),
                   "<user> <channel> [channel] ...",
                   "Removes channels from a user");
        addCommand("AddUser",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoVoiceMod::onAddUserCommand),
                   "<user> <hostmask> [channels]",
                   "Adds a user");
        addCommand("DelUser",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoVoiceMod::OnDelUserCommand),
                   "<user>",
                   "Removes a user");
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        // Load the chans from the command line
        uint a = 0;
        NoStringVector vsChans = args.split(" ", No::SkipEmptyParts);

        for (NoStringVector::const_iterator it = vsChans.begin(); it != vsChans.end(); ++it) {
            NoString name = "Args";
            name += NoString(a);
            AddUser(name, "*", *it);
        }

        // Load the saved users
        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            const NoString& line = registry.value(key);
            NoAutoVoiceUser* user = new NoAutoVoiceUser;

            if (!user->FromString(line) || FindUser(user->GetUsername().toLower())) {
                delete user;
            } else {
                m_msUsers[user->GetUsername().toLower()] = user;
            }
        }

        return true;
    }

    virtual ~NoAutoVoiceMod()
    {
        for (std::map<NoString, NoAutoVoiceUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            delete it->second;
        }

        m_msUsers.clear();
    }

    void onJoin(const NoNick& nick, NoChannel& channel) override
    {
        // If we have ops in this chan
        if (channel.hasPerm(NoChannel::Op) || channel.hasPerm(NoChannel::HalfOp)) {
            for (std::map<NoString, NoAutoVoiceUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
                // and the nick who joined is a valid user
                if (it->second->HostMatches(nick.hostMask()) && it->second->ChannelMatches(channel.name())) {
                    putIrc("MODE " + channel.name() + " +v " + nick.nick());
                    break;
                }
            }
        }
    }

    void onAddUserCommand(const NoString& line)
    {
        NoString sUser = No::token(line, 1);
        NoString host = No::token(line, 2);

        if (host.empty()) {
            putModule("Usage: AddUser <user> <hostmask> [channels]");
        } else {
            NoAutoVoiceUser* user = AddUser(sUser, host, No::tokens(line, 3));

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
        Table.addColumn("Hostmask");
        Table.addColumn("Channels");

        for (std::map<NoString, NoAutoVoiceUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            Table.addRow();
            Table.setValue("User", it->second->GetUsername());
            Table.setValue("Hostmask", it->second->GetHostmask());
            Table.setValue("Channels", it->second->GetChannels());
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

        NoAutoVoiceUser* user = FindUser(sUser);

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

        NoAutoVoiceUser* user = FindUser(sUser);

        if (!user) {
            putModule("No such user");
            return;
        }

        user->removeChannels(sChans);
        putModule("channel(s) Removed from user [" + user->GetUsername() + "]");

        NoRegistry registry(this);
        registry.setValue(user->GetUsername(), user->ToString());
    }

    NoAutoVoiceUser* FindUser(const NoString& sUser)
    {
        std::map<NoString, NoAutoVoiceUser*>::iterator it = m_msUsers.find(sUser.toLower());

        return (it != m_msUsers.end()) ? it->second : nullptr;
    }

    NoAutoVoiceUser* FindUserByHost(const NoString& sHostmask, const NoString& channel = "")
    {
        for (std::map<NoString, NoAutoVoiceUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            NoAutoVoiceUser* user = it->second;

            if (user->HostMatches(sHostmask) && (channel.empty() || user->ChannelMatches(channel))) {
                return user;
            }
        }

        return nullptr;
    }

    void DelUser(const NoString& sUser)
    {
        std::map<NoString, NoAutoVoiceUser*>::iterator it = m_msUsers.find(sUser.toLower());

        if (it == m_msUsers.end()) {
            putModule("That user does not exist");
            return;
        }

        delete it->second;
        m_msUsers.erase(it);
        putModule("User [" + sUser + "] removed");
    }

    NoAutoVoiceUser* AddUser(const NoString& sUser, const NoString& host, const NoString& sChans)
    {
        if (m_msUsers.find(sUser) != m_msUsers.end()) {
            putModule("That user already exists");
            return nullptr;
        }

        NoAutoVoiceUser* user = new NoAutoVoiceUser(sUser, host, sChans);
        m_msUsers[sUser.toLower()] = user;
        putModule("User [" + sUser + "] added with hostmask [" + host + "]");
        return user;
    }

private:
    std::map<NoString, NoAutoVoiceUser*> m_msUsers;
};

template <>
void no_moduleInfo<NoAutoVoiceMod>(NoModuleInfo& info)
{
    info.setWikiPage("autovoice");
    info.setHasArgs(true);
    info.setArgsHelpText("Each argument is either a channel you want autovoice for (which can include wildcards) or, "
                         "if it starts with !, it is an exception for autovoice.");
}

NETWORKMODULEDEFS(NoAutoVoiceMod, "Auto voice the good people")
