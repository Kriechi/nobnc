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

#include <no/nochannel.h>
#include <no/nonetwork.h>

using std::vector;

class NoAutoCycleMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoAutoCycleMod)
    {
        AddHelpCommand();
        AddCommand("Add",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAutoCycleMod::OnAddCommand),
                   "[!]<#chan>",
                   "Add an entry, use !#chan to negate and * for wildcards");
        AddCommand("Del",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAutoCycleMod::OnDelCommand),
                   "[!]<#chan>",
                   "Remove an entry, needs to be an exact match");
        AddCommand("List", static_cast<NoModCommand::ModCmdFunc>(&NoAutoCycleMod::OnListCommand), "", "List all entries");
        m_recentlyCycled.SetTTL(15 * 1000);
    }

    virtual ~NoAutoCycleMod() {}

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        NoStringVector vsChans;
        sArgs.Split(" ", vsChans, false);

        for (NoStringVector::const_iterator it = vsChans.begin(); it != vsChans.end(); ++it) {
            if (!Add(*it)) {
                PutModule("Unable to add [" + *it + "]");
            }
        }

        // Load our saved settings, ignore errors
        NoStringMap::iterator it;
        for (it = BeginNV(); it != EndNV(); ++it) {
            Add(it->first);
        }

        // Default is auto cycle for all channels
        if (m_vsChans.empty()) Add("*");

        return true;
    }

    void OnAddCommand(const NoString& sLine)
    {
        NoString sChan = sLine.Token(1);

        if (AlreadyAdded(sChan)) {
            PutModule(sChan + " is already added");
        } else if (Add(sChan)) {
            PutModule("Added " + sChan + " to list");
        } else {
            PutModule("Usage: Add [!]<#chan>");
        }
    }

    void OnDelCommand(const NoString& sLine)
    {
        NoString sChan = sLine.Token(1);

        if (Del(sChan))
            PutModule("Removed " + sChan + " from list");
        else
            PutModule("Usage: Del [!]<#chan>");
    }

    void OnListCommand(const NoString& sLine)
    {
        NoTable Table;
        Table.AddColumn("Chan");

        for (unsigned int a = 0; a < m_vsChans.size(); a++) {
            Table.AddRow();
            Table.SetCell("Chan", m_vsChans[a]);
        }

        for (unsigned int b = 0; b < m_vsNegChans.size(); b++) {
            Table.AddRow();
            Table.SetCell("Chan", "!" + m_vsNegChans[b]);
        }

        if (Table.size()) {
            PutModule(Table);
        } else {
            PutModule("You have no entries.");
        }
    }

    void OnPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage) override { AutoCycle(Channel); }

    void OnQuit(const NoNick& Nick, const NoString& sMessage, const vector<NoChannel*>& vChans) override
    {
        for (unsigned int i = 0; i < vChans.size(); i++) AutoCycle(*vChans[i]);
    }

    void OnKick(const NoNick& Nick, const NoString& sOpNick, NoChannel& Channel, const NoString& sMessage) override
    {
        AutoCycle(Channel);
    }

protected:
    void AutoCycle(NoChannel& Channel)
    {
        if (!IsAutoCycle(Channel.GetName())) return;

        // Did we recently annoy opers via cycling of an empty channel?
        if (m_recentlyCycled.HasItem(Channel.GetName())) return;

        // Is there only one person left in the channel?
        if (Channel.GetNickCount() != 1) return;

        // Is that person us and we don't have op?
        const NoNick& pNick = Channel.GetNicks().begin()->second;
        if (!pNick.HasPerm(NoChannel::Op) && pNick.NickEquals(GetNetwork()->GetCurNick())) {
            Channel.Cycle();
            m_recentlyCycled.AddItem(Channel.GetName());
        }
    }

    bool AlreadyAdded(const NoString& sInput)
    {
        vector<NoString>::iterator it;

        if (sInput.Left(1) == "!") {
            NoString sChan = sInput.substr(1);
            for (it = m_vsNegChans.begin(); it != m_vsNegChans.end(); ++it) {
                if (*it == sChan) return true;
            }
        } else {
            for (it = m_vsChans.begin(); it != m_vsChans.end(); ++it) {
                if (*it == sInput) return true;
            }
        }
        return false;
    }

    bool Add(const NoString& sChan)
    {
        if (sChan.empty() || sChan == "!") {
            return false;
        }

        if (sChan.Left(1) == "!") {
            m_vsNegChans.push_back(sChan.substr(1));
        } else {
            m_vsChans.push_back(sChan);
        }

        // Also save it for next module load
        SetNV(sChan, "");

        return true;
    }

    bool Del(const NoString& sChan)
    {
        vector<NoString>::iterator it, end;

        if (sChan.empty() || sChan == "!") return false;

        if (sChan.Left(1) == "!") {
            NoString sTmp = sChan.substr(1);
            it = m_vsNegChans.begin();
            end = m_vsNegChans.end();

            for (; it != end; ++it)
                if (*it == sTmp) break;

            if (it == end) return false;

            m_vsNegChans.erase(it);
        } else {
            it = m_vsChans.begin();
            end = m_vsChans.end();

            for (; it != end; ++it)
                if (*it == sChan) break;

            if (it == end) return false;

            m_vsChans.erase(it);
        }

        DelNV(sChan);

        return true;
    }

    bool IsAutoCycle(const NoString& sChan)
    {
        for (unsigned int a = 0; a < m_vsNegChans.size(); a++) {
            if (sChan.WildCmp(m_vsNegChans[a], NoString::CaseInsensitive)) {
                return false;
            }
        }

        for (unsigned int b = 0; b < m_vsChans.size(); b++) {
            if (sChan.WildCmp(m_vsChans[b], NoString::CaseInsensitive)) {
                return true;
            }
        }

        return false;
    }

private:
    vector<NoString> m_vsChans;
    vector<NoString> m_vsNegChans;
    TCacheMap<NoString> m_recentlyCycled;
};

template <> void TModInfo<NoAutoCycleMod>(NoModInfo& Info)
{
    Info.SetWikiPage("autocycle");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("List of channel masks and channel masks with ! before them.");
}

NETWORKMODULEDEFS(NoAutoCycleMod, "Rejoins channels to gain Op if you're the only user left")
