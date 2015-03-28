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
#include <no/nochannel.h>
#include <no/nonetwork.h>
#include <no/nocachemap.h>
#include <no/noregistry.h>
#include <no/nonick.h>

class NoAutoCycleMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoAutoCycleMod)
    {
        AddHelpCommand();
        AddCommand("Add",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoCycleMod::OnAddCommand),
                   "[!]<#chan>",
                   "Add an entry, use !#chan to negate and * for wildcards");
        AddCommand("Del",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoCycleMod::OnDelCommand),
                   "[!]<#chan>",
                   "Remove an entry, needs to be an exact match");
        AddCommand("List", static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoCycleMod::OnListCommand), "", "List all entries");
        m_recentlyCycled.setExpiration(15 * 1000);
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        NoStringVector vsChans = sArgs.split(" ", No::SkipEmptyParts);

        for (NoStringVector::const_iterator it = vsChans.begin(); it != vsChans.end(); ++it) {
            if (!Add(*it)) {
                PutModule("Unable to add [" + *it + "]");
            }
        }

        // Load our saved settings, ignore errors
        NoRegistry registry(this);
        for (const NoString& key : registry.keys())
            Add(key);

        // Default is auto cycle for all channels
        if (m_vsChans.empty()) Add("*");

        return true;
    }

    void OnAddCommand(const NoString& sLine)
    {
        NoString sChan = No::token(sLine, 1);

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
        NoString sChan = No::token(sLine, 1);

        if (Del(sChan))
            PutModule("Removed " + sChan + " from list");
        else
            PutModule("Usage: Del [!]<#chan>");
    }

    void OnListCommand(const NoString& sLine)
    {
        NoTable Table;
        Table.addColumn("Chan");

        for (uint a = 0; a < m_vsChans.size(); a++) {
            Table.addRow();
            Table.setValue("Chan", m_vsChans[a]);
        }

        for (uint b = 0; b < m_vsNegChans.size(); b++) {
            Table.addRow();
            Table.setValue("Chan", "!" + m_vsNegChans[b]);
        }

        if (Table.size()) {
            PutModule(Table);
        } else {
            PutModule("You have no entries.");
        }
    }

    void onPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage) override { AutoCycle(Channel); }

    void onQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans) override
    {
        for (uint i = 0; i < vChans.size(); i++) AutoCycle(*vChans[i]);
    }

    void onKick(const NoNick& Nick, const NoString& sOpNick, NoChannel& Channel, const NoString& sMessage) override
    {
        AutoCycle(Channel);
    }

protected:
    void AutoCycle(NoChannel& Channel)
    {
        if (!IsAutoCycle(Channel.name())) return;

        // Did we recently annoy opers via cycling of an empty channel?
        if (m_recentlyCycled.contains(Channel.name())) return;

        // Is there only one person left in the channel?
        if (Channel.nickCount() != 1) return;

        // Is that person us and we don't have op?
        const NoNick& pNick = Channel.nicks().begin()->second;
        if (!pNick.hasPerm(NoChannel::Op) && pNick.equals(GetNetwork()->currentNick())) {
            Channel.cycle();
            m_recentlyCycled.insert(Channel.name());
        }
    }

    bool AlreadyAdded(const NoString& sInput)
    {
        std::vector<NoString>::iterator it;

        if (sInput.left(1) == "!") {
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

        if (sChan.left(1) == "!") {
            m_vsNegChans.push_back(sChan.substr(1));
        } else {
            m_vsChans.push_back(sChan);
        }

        // Also save it for next module load
        NoRegistry registry(this);
        registry.setValue(sChan, "");

        return true;
    }

    bool Del(const NoString& sChan)
    {
        std::vector<NoString>::iterator it, end;

        if (sChan.empty() || sChan == "!") return false;

        if (sChan.left(1) == "!") {
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

        NoRegistry registry(this);
        registry.remove(sChan);

        return true;
    }

    bool IsAutoCycle(const NoString& sChan)
    {
        for (uint a = 0; a < m_vsNegChans.size(); a++) {
            if (No::wildCmp(sChan, m_vsNegChans[a], No::CaseInsensitive)) {
                return false;
            }
        }

        for (uint b = 0; b < m_vsChans.size(); b++) {
            if (No::wildCmp(sChan, m_vsChans[b], No::CaseInsensitive)) {
                return true;
            }
        }

        return false;
    }

private:
    std::vector<NoString> m_vsChans;
    std::vector<NoString> m_vsNegChans;
    NoCacheMap<NoString> m_recentlyCycled;
};

template <> void no_moduleInfo<NoAutoCycleMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("autocycle");
    Info.setHasArgs(true);
    Info.setArgsHelpText("List of channel masks and channel masks with ! before them.");
}

NETWORKMODULEDEFS(NoAutoCycleMod, "Rejoins channels to gain Op if you're the only user left")
