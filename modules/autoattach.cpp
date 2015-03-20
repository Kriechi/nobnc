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
#include <no/nochannel.h>

class NoAttachMatch
{
public:
    NoAttachMatch(NoModule* pModule, const NoString& sChannels, const NoString& sSearch, const NoString& sHostmasks, bool bNegated)
    {
        m_pModule = pModule;
        m_sChannelWildcard = sChannels;
        m_sSearchWildcard = sSearch;
        m_sHostmaskWildcard = sHostmasks;
        m_bNegated = bNegated;

        if (m_sChannelWildcard.empty()) m_sChannelWildcard = "*";
        if (m_sSearchWildcard.empty()) m_sSearchWildcard = "*";
        if (m_sHostmaskWildcard.empty()) m_sHostmaskWildcard = "*!*@*";
    }

    bool IsMatch(const NoString& sChan, const NoString& sHost, const NoString& sMessage) const
    {
        if (!sHost.wildCmp(m_sHostmaskWildcard, No::CaseInsensitive)) return false;
        if (!sChan.wildCmp(m_sChannelWildcard, No::CaseInsensitive)) return false;
        if (!sMessage.wildCmp(m_pModule->ExpandString(m_sSearchWildcard), No::CaseInsensitive)) return false;
        return true;
    }

    bool IsNegated() const { return m_bNegated; }

    const NoString& GetHostMask() const { return m_sHostmaskWildcard; }

    const NoString& GetSearch() const { return m_sSearchWildcard; }

    const NoString& GetChans() const { return m_sChannelWildcard; }

    NoString ToString()
    {
        NoString sRes;
        if (m_bNegated) sRes += "!";
        sRes += m_sChannelWildcard;
        sRes += " ";
        sRes += m_sSearchWildcard;
        sRes += " ";
        sRes += m_sHostmaskWildcard;
        return sRes;
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
    void HandleAdd(const NoString& sLine)
    {
        NoString sMsg = sLine.tokens(1);
        bool bHelp = false;
        bool bNegated = sMsg.trimPrefix("!");
        NoString sChan = sMsg.token(0);
        NoString sSearch = sMsg.token(1);
        NoString sHost = sMsg.token(2);

        if (sChan.empty()) {
            bHelp = true;
        } else if (Add(bNegated, sChan, sSearch, sHost)) {
            PutModule("Added to list");
        } else {
            PutModule(sLine.tokens(1) + " is already added");
            bHelp = true;
        }
        if (bHelp) {
            PutModule("Usage: Add [!]<#chan> <search> <host>");
            PutModule("Wildcards are allowed");
        }
    }

    void HandleDel(const NoString& sLine)
    {
        NoString sMsg = sLine.tokens(1);
        bool bNegated = sMsg.trimPrefix("!");
        NoString sChan = sMsg.token(0);
        NoString sSearch = sMsg.token(1);
        NoString sHost = sMsg.token(2);

        if (Del(bNegated, sChan, sSearch, sHost)) {
            PutModule("Removed " + sChan + " from list");
        } else {
            PutModule("Usage: Del [!]<#chan> <search> <host>");
        }
    }

    void HandleList(const NoString& sLine)
    {
        NoTable Table;
        Table.AddColumn("Neg");
        Table.AddColumn("Chan");
        Table.AddColumn("Search");
        Table.AddColumn("Host");

        VAttachIter it = m_vMatches.begin();
        for (; it != m_vMatches.end(); ++it) {
            Table.AddRow();
            Table.SetCell("Neg", it->IsNegated() ? "!" : "");
            Table.SetCell("Chan", it->GetChans());
            Table.SetCell("Search", it->GetSearch());
            Table.SetCell("Host", it->GetHostMask());
        }

        if (Table.size()) {
            PutModule(Table);
        } else {
            PutModule("You have no entries.");
        }
    }

public:
    MODCONSTRUCTOR(NoChannelAttach)
    {
        AddHelpCommand();
        AddCommand("Add",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoChannelAttach::HandleAdd),
                   "[!]<#chan> <search> <host>",
                   "Add an entry, use !#chan to negate and * for wildcards");
        AddCommand("Del", static_cast<NoModuleCommand::ModCmdFunc>(&NoChannelAttach::HandleDel), "[!]<#chan> <search> <host>", "Remove an entry, needs to be an exact match");
        AddCommand("List", static_cast<NoModuleCommand::ModCmdFunc>(&NoChannelAttach::HandleList), "", "List all entries");
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        NoStringVector vsChans = sArgs.split(" ", No::SkipEmptyParts);

        for (NoStringVector::const_iterator it = vsChans.begin(); it != vsChans.end(); ++it) {
            NoString sAdd = *it;
            bool bNegated = sAdd.trimPrefix("!");
            NoString sChan = sAdd.token(0);
            NoString sSearch = sAdd.token(1);
            NoString sHost = sAdd.tokens(2);

            if (!Add(bNegated, sChan, sSearch, sHost)) {
                PutModule("Unable to add [" + *it + "]");
            }
        }

        // Load our saved settings, ignore errors
        NoStringMap::iterator it;
        for (it = BeginNV(); it != EndNV(); ++it) {
            NoString sAdd = it->first;
            bool bNegated = sAdd.trimPrefix("!");
            NoString sChan = sAdd.token(0);
            NoString sSearch = sAdd.token(1);
            NoString sHost = sAdd.tokens(2);

            Add(bNegated, sChan, sSearch, sHost);
        }

        return true;
    }

    void TryAttach(const NoNick& Nick, NoChannel& Channel, NoString& Message)
    {
        const NoString& sChan = Channel.getName();
        const NoString& sHost = Nick.hostMask();
        const NoString& sMessage = Message;
        VAttachIter it;

        if (!Channel.isDetached()) return;

        // Any negated match?
        for (it = m_vMatches.begin(); it != m_vMatches.end(); ++it) {
            if (it->IsNegated() && it->IsMatch(sChan, sHost, sMessage)) return;
        }

        // Now check for a positive match
        for (it = m_vMatches.begin(); it != m_vMatches.end(); ++it) {
            if (!it->IsNegated() && it->IsMatch(sChan, sHost, sMessage)) {
                Channel.attachUser();
                return;
            }
        }
    }

    ModRet OnChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        TryAttach(Nick, Channel, sMessage);
        return CONTINUE;
    }

    ModRet OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        TryAttach(Nick, Channel, sMessage);
        return CONTINUE;
    }

    ModRet OnChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        TryAttach(Nick, Channel, sMessage);
        return CONTINUE;
    }

    VAttachIter FindEntry(const NoString& sChan, const NoString& sSearch, const NoString& sHost)
    {
        VAttachIter it = m_vMatches.begin();
        for (; it != m_vMatches.end(); ++it) {
            if (sHost.empty() || it->GetHostMask() != sHost) continue;
            if (sSearch.empty() || it->GetSearch() != sSearch) continue;
            if (sChan.empty() || it->GetChans() != sChan) continue;
            return it;
        }
        return m_vMatches.end();
    }

    bool Add(bool bNegated, const NoString& sChan, const NoString& sSearch, const NoString& sHost)
    {
        NoAttachMatch attach(this, sChan, sSearch, sHost, bNegated);

        // Check for duplicates
        VAttachIter it = m_vMatches.begin();
        for (; it != m_vMatches.end(); ++it) {
            if (it->GetHostMask() == attach.GetHostMask() && it->GetChans() == attach.GetChans() &&
                it->GetSearch() == attach.GetSearch())
                return false;
        }

        m_vMatches.push_back(attach);

        // Also save it for next module load
        SetNV(attach.ToString(), "");

        return true;
    }

    bool Del(bool bNegated, const NoString& sChan, const NoString& sSearch, const NoString& sHost)
    {
        VAttachIter it = FindEntry(sChan, sSearch, sHost);
        if (it == m_vMatches.end() || it->IsNegated() != bNegated) return false;

        DelNV(it->ToString());
        m_vMatches.erase(it);

        return true;
    }

private:
    VAttachMatch m_vMatches;
};

template <> void no_moduleInfo<NoChannelAttach>(NoModuleInfo& Info)
{
    Info.AddType(No::UserModule);
    Info.SetWikiPage("autoattach");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("List of channel masks and channel masks with ! before them.");
}

NETWORKMODULEDEFS(NoChannelAttach, "Reattaches you to channels on activity.")
