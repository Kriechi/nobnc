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

#include <no/nomodules.h>
#include <no/nochannel.h>

class NoAutoVoiceUser
{
public:
    NoAutoVoiceUser() {}

    NoAutoVoiceUser(const NoString& sLine) { FromString(sLine); }

    NoAutoVoiceUser(const NoString& sUsername, const NoString& sHostmask, const NoString& sChannels)
        : m_sUsername(sUsername), m_sHostmask(sHostmask)
    {
        AddChans(sChannels);
    }

    virtual ~NoAutoVoiceUser() {}

    const NoString& GetUsername() const { return m_sUsername; }
    const NoString& GetHostmask() const { return m_sHostmask; }

    bool ChannelMatches(const NoString& sChan) const
    {
        for (std::set<NoString>::const_iterator it = m_ssChans.begin(); it != m_ssChans.end(); ++it) {
            if (sChan.AsLower().WildCmp(*it, No::CaseInsensitive)) {
                return true;
            }
        }

        return false;
    }

    bool HostMatches(const NoString& sHostmask) { return sHostmask.WildCmp(m_sHostmask, No::CaseInsensitive); }

    NoString GetChannels() const
    {
        NoString sRet;

        for (std::set<NoString>::const_iterator it = m_ssChans.begin(); it != m_ssChans.end(); ++it) {
            if (!sRet.empty()) {
                sRet += " ";
            }

            sRet += *it;
        }

        return sRet;
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

    bool FromString(const NoString& sLine)
    {
        m_sUsername = sLine.Token(0, "\t");
        m_sHostmask = sLine.Token(1, "\t");

        NoStringVector vsChans = sLine.Token(2, "\t").Split(" ");
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
        AddHelpCommand();
        AddCommand("ListUsers",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAutoVoiceMod::OnListUsersCommand),
                   "",
                   "List all users");
        AddCommand("AddChans",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAutoVoiceMod::OnAddChansCommand),
                   "<user> <channel> [channel] ...",
                   "Adds channels to a user");
        AddCommand("DelChans",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAutoVoiceMod::OnDelChansCommand),
                   "<user> <channel> [channel] ...",
                   "Removes channels from a user");
        AddCommand("AddUser",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAutoVoiceMod::OnAddUserCommand),
                   "<user> <hostmask> [channels]",
                   "Adds a user");
        AddCommand("DelUser",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAutoVoiceMod::OnDelUserCommand),
                   "<user>",
                   "Removes a user");
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        // Load the chans from the command line
        uint a = 0;
        NoStringVector vsChans = sArgs.Split(" ", No::SkipEmptyParts);

        for (NoStringVector::const_iterator it = vsChans.begin(); it != vsChans.end(); ++it) {
            NoString sName = "Args";
            sName += NoString(a);
            AddUser(sName, "*", *it);
        }

        // Load the saved users
        for (NoStringMap::iterator it = BeginNV(); it != EndNV(); ++it) {
            const NoString& sLine = it->second;
            NoAutoVoiceUser* pUser = new NoAutoVoiceUser;

            if (!pUser->FromString(sLine) || FindUser(pUser->GetUsername().AsLower())) {
                delete pUser;
            } else {
                m_msUsers[pUser->GetUsername().AsLower()] = pUser;
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

    void OnJoin(const NoNick& Nick, NoChannel& Channel) override
    {
        // If we have ops in this chan
        if (Channel.hasPerm(NoChannel::Op) || Channel.hasPerm(NoChannel::HalfOp)) {
            for (std::map<NoString, NoAutoVoiceUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
                // and the nick who joined is a valid user
                if (it->second->HostMatches(Nick.hostMask()) && it->second->ChannelMatches(Channel.getName())) {
                    PutIRC("MODE " + Channel.getName() + " +v " + Nick.nick());
                    break;
                }
            }
        }
    }

    void OnAddUserCommand(const NoString& sLine)
    {
        NoString sUser = sLine.Token(1);
        NoString sHost = sLine.Token(2);

        if (sHost.empty()) {
            PutModule("Usage: AddUser <user> <hostmask> [channels]");
        } else {
            NoAutoVoiceUser* pUser = AddUser(sUser, sHost, sLine.Tokens(3));

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
        Table.AddColumn("Hostmask");
        Table.AddColumn("Channels");

        for (std::map<NoString, NoAutoVoiceUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            Table.AddRow();
            Table.SetCell("User", it->second->GetUsername());
            Table.SetCell("Hostmask", it->second->GetHostmask());
            Table.SetCell("Channels", it->second->GetChannels());
        }

        PutModule(Table);
    }

    void OnAddChansCommand(const NoString& sLine)
    {
        NoString sUser = sLine.Token(1);
        NoString sChans = sLine.Tokens(2);

        if (sChans.empty()) {
            PutModule("Usage: AddChans <user> <channel> [channel] ...");
            return;
        }

        NoAutoVoiceUser* pUser = FindUser(sUser);

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
        NoString sChans = sLine.Tokens(2);

        if (sChans.empty()) {
            PutModule("Usage: DelChans <user> <channel> [channel] ...");
            return;
        }

        NoAutoVoiceUser* pUser = FindUser(sUser);

        if (!pUser) {
            PutModule("No such user");
            return;
        }

        pUser->DelChans(sChans);
        PutModule("Channel(s) Removed from user [" + pUser->GetUsername() + "]");

        SetNV(pUser->GetUsername(), pUser->ToString());
    }

    NoAutoVoiceUser* FindUser(const NoString& sUser)
    {
        std::map<NoString, NoAutoVoiceUser*>::iterator it = m_msUsers.find(sUser.AsLower());

        return (it != m_msUsers.end()) ? it->second : nullptr;
    }

    NoAutoVoiceUser* FindUserByHost(const NoString& sHostmask, const NoString& sChannel = "")
    {
        for (std::map<NoString, NoAutoVoiceUser*>::iterator it = m_msUsers.begin(); it != m_msUsers.end(); ++it) {
            NoAutoVoiceUser* pUser = it->second;

            if (pUser->HostMatches(sHostmask) && (sChannel.empty() || pUser->ChannelMatches(sChannel))) {
                return pUser;
            }
        }

        return nullptr;
    }

    void DelUser(const NoString& sUser)
    {
        std::map<NoString, NoAutoVoiceUser*>::iterator it = m_msUsers.find(sUser.AsLower());

        if (it == m_msUsers.end()) {
            PutModule("That user does not exist");
            return;
        }

        delete it->second;
        m_msUsers.erase(it);
        PutModule("User [" + sUser + "] removed");
    }

    NoAutoVoiceUser* AddUser(const NoString& sUser, const NoString& sHost, const NoString& sChans)
    {
        if (m_msUsers.find(sUser) != m_msUsers.end()) {
            PutModule("That user already exists");
            return nullptr;
        }

        NoAutoVoiceUser* pUser = new NoAutoVoiceUser(sUser, sHost, sChans);
        m_msUsers[sUser.AsLower()] = pUser;
        PutModule("User [" + sUser + "] added with hostmask [" + sHost + "]");
        return pUser;
    }

private:
    std::map<NoString, NoAutoVoiceUser*> m_msUsers;
};

template <> void TModInfo<NoAutoVoiceMod>(NoModInfo& Info)
{
    Info.SetWikiPage("autovoice");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("Each argument is either a channel you want autovoice for (which can include wildcards) or, "
                         "if it starts with !, it is an exception for autovoice.");
}

NETWORKMODULEDEFS(NoAutoVoiceMod, "Auto voice the good people")
