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
#include <nobnc/noutils.h>
#include <nobnc/notable.h>

class NoAttachMatch
{
public:
    NoAttachMatch(NoModule* module, const NoString& sChannels, const NoString& search, const NoString& sHostmasks, bool bNegated)
    {
        m_pModule = module;
        m_sChannelWildcard = sChannels;
        m_sSearchWildcard = search;
        m_sHostmaskWildcard = sHostmasks;
        m_bNegated = bNegated;

        if (m_sChannelWildcard.empty())
            m_sChannelWildcard = "*";
        if (m_sSearchWildcard.empty())
            m_sSearchWildcard = "*";
        if (m_sHostmaskWildcard.empty())
            m_sHostmaskWildcard = "*!*@*";
    }

    bool IsMatch(const NoString& sChan, const NoString& host, const NoString& message) const
    {
        if (!No::wildCmp(host, m_sHostmaskWildcard, No::CaseInsensitive))
            return false;
        if (!No::wildCmp(sChan, m_sChannelWildcard, No::CaseInsensitive))
            return false;
        if (!No::wildCmp(message, m_pModule->expandString(m_sSearchWildcard), No::CaseInsensitive))
            return false;
        return true;
    }

    bool IsNegated() const
    {
        return m_bNegated;
    }

    const NoString& GetHostMask() const
    {
        return m_sHostmaskWildcard;
    }

    const NoString& GetSearch() const
    {
        return m_sSearchWildcard;
    }

    const NoString& channels() const
    {
        return m_sChannelWildcard;
    }

    NoString ToString()
    {
        NoString res;
        if (m_bNegated)
            res += "!";
        res += m_sChannelWildcard;
        res += " ";
        res += m_sSearchWildcard;
        res += " ";
        res += m_sHostmaskWildcard;
        return res;
    }

private:
    bool m_bNegated;
    NoModule* m_pModule;
    NoString m_sChannelWildcard;
    NoString m_sSearchWildcard;
    NoString m_sHostmaskWildcard;
};

class NoChannelAttach : public NoModule
{
public:
    typedef std::vector<NoAttachMatch> VAttachMatch;
    typedef VAttachMatch::iterator VAttachIter;

private:
    void HandleAdd(const NoString& line)
    {
        NoString msg = No::tokens(line, 1);
        bool bHelp = false;
        bool bNegated = msg.trimPrefix("!");
        NoString sChan = No::token(msg, 0);
        NoString search = No::token(msg, 1);
        NoString host = No::token(msg, 2);

        if (sChan.empty()) {
            bHelp = true;
        } else if (Add(bNegated, sChan, search, host)) {
            putModule("Added to list");
        } else {
            putModule(No::tokens(line, 1) + " is already added");
            bHelp = true;
        }
        if (bHelp) {
            putModule("Usage: Add [!]<#chan> <search> <host>");
            putModule("Wildcards are allowed");
        }
    }

    void HandleDel(const NoString& line)
    {
        NoString msg = No::tokens(line, 1);
        bool bNegated = msg.trimPrefix("!");
        NoString sChan = No::token(msg, 0);
        NoString search = No::token(msg, 1);
        NoString host = No::token(msg, 2);

        if (Del(bNegated, sChan, search, host)) {
            putModule("Removed " + sChan + " from list");
        } else {
            putModule("Usage: Del [!]<#chan> <search> <host>");
        }
    }

    void HandleList(const NoString& line)
    {
        NoTable Table;
        Table.addColumn("Channel");
        Table.addColumn("Match");

        VAttachIter it = m_vMatches.begin();
        for (; it != m_vMatches.end(); ++it) {
            Table.addRow();
            Table.setValue("Channel", it->channels());
            Table.setValue("Match", (it->IsNegated() ? "!" : "") + it->GetSearch() + " (" + it->GetHostMask() + ")");
        }

        if (Table.size()) {
            putModule(Table);
        } else {
            putModule("You have no entries.");
        }
    }

public:
    MODCONSTRUCTOR(NoChannelAttach)
    {
        addHelpCommand();
        addCommand("Add",
                   static_cast<NoModule::CommandFunction>(&NoChannelAttach::HandleAdd),
                   "[!]<#chan> <search> <host>",
                   "Add an entry, use !#chan to negate and * for wildcards");
        addCommand("Del",
                   static_cast<NoModule::CommandFunction>(&NoChannelAttach::HandleDel),
                   "[!]<#chan> <search> <host>",
                   "Remove an entry, needs to be an exact match");
        addCommand("List",
                   static_cast<NoModule::CommandFunction>(&NoChannelAttach::HandleList),
                   "",
                   "List all entries");
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        NoStringVector vsChans = args.split(" ", No::SkipEmptyParts);

        for (NoStringVector::const_iterator it = vsChans.begin(); it != vsChans.end(); ++it) {
            NoString sAdd = *it;
            bool bNegated = sAdd.trimPrefix("!");
            NoString sChan = No::token(sAdd, 0);
            NoString search = No::token(sAdd, 1);
            NoString host = No::tokens(sAdd, 2);

            if (!Add(bNegated, sChan, search, host)) {
                putModule("Unable to add [" + *it + "]");
            }
        }

        // Load our saved settings, ignore errors
        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            NoString str = key;
            bool bNegated = str.trimPrefix("!");
            NoString sChan = No::token(str, 0);
            NoString search = No::token(str, 1);
            NoString host = No::tokens(str, 2);

            Add(bNegated, sChan, search, host);
        }

        return true;
    }

    void TryAttach(const NoNick& nick, NoChannel* channel, NoString& Message)
    {
        const NoString& sChan = channel->name();
        const NoString& host = nick.hostMask();
        const NoString& message = Message;
        VAttachIter it;

        if (!channel->isDetached())
            return;

        // Any negated match?
        for (it = m_vMatches.begin(); it != m_vMatches.end(); ++it) {
            if (it->IsNegated() && it->IsMatch(sChan, host, message))
                return;
        }

        // Now check for a positive match
        for (it = m_vMatches.begin(); it != m_vMatches.end(); ++it) {
            if (!it->IsNegated() && it->IsMatch(sChan, host, message)) {
                channel->attachUser();
                return;
            }
        }
    }

    Return onChannelNotice(NoNick& nick, NoChannel* channel, NoString& message) override
    {
        TryAttach(nick, channel, message);
        return Continue;
    }

    Return onChannelMessage(NoNick& nick, NoChannel* channel, NoString& message) override
    {
        TryAttach(nick, channel, message);
        return Continue;
    }

    Return onChannelAction(NoNick& nick, NoChannel* channel, NoString& message) override
    {
        TryAttach(nick, channel, message);
        return Continue;
    }

    VAttachIter FindEntry(const NoString& sChan, const NoString& search, const NoString& host)
    {
        VAttachIter it = m_vMatches.begin();
        for (; it != m_vMatches.end(); ++it) {
            if (host.empty() || it->GetHostMask() != host)
                continue;
            if (search.empty() || it->GetSearch() != search)
                continue;
            if (sChan.empty() || it->channels() != sChan)
                continue;
            return it;
        }
        return m_vMatches.end();
    }

    bool Add(bool bNegated, const NoString& sChan, const NoString& search, const NoString& host)
    {
        NoAttachMatch attach(this, sChan, search, host, bNegated);

        // Check for duplicates
        VAttachIter it = m_vMatches.begin();
        for (; it != m_vMatches.end(); ++it) {
            if (it->GetHostMask() == attach.GetHostMask() && it->channels() == attach.channels() &&
                it->GetSearch() == attach.GetSearch())
                return false;
        }

        m_vMatches.push_back(attach);

        // Also save it for next module load
        NoRegistry registry(this);
        registry.setValue(attach.ToString(), "");

        return true;
    }

    bool Del(bool bNegated, const NoString& sChan, const NoString& search, const NoString& host)
    {
        VAttachIter it = FindEntry(sChan, search, host);
        if (it == m_vMatches.end() || it->IsNegated() != bNegated)
            return false;

        NoRegistry registry(this);
        registry.remove(it->ToString());
        m_vMatches.erase(it);

        return true;
    }

private:
    VAttachMatch m_vMatches;
};

template <>
void no_moduleInfo<NoChannelAttach>(NoModuleInfo& info)
{
    info.addType(No::UserModule);
    info.setWikiPage("autoattach");
    info.setHasArgs(true);
    info.setArgsHelpText("List of channel masks and channel masks with ! before them.");
}

NETWORKMODULEDEFS(NoChannelAttach, "Reattaches you to channels on activity.")
