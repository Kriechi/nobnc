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
#include <nobnc/nonetwork.h>
#include <nobnc/nocachemap.h>
#include <nobnc/noregistry.h>
#include <nobnc/nonick.h>
#include <nobnc/nohostmask.h>
#include <nobnc/notable.h>

class NoAutoCycleMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoAutoCycleMod)
    {
        addHelpCommand();
        addCommand("Add",
                   static_cast<NoModule::CommandFunction>(&NoAutoCycleMod::OnaddCommand),
                   "[!]<#chan>",
                   "Add an entry, use !#chan to negate and * for wildcards");
        addCommand("Del",
                   static_cast<NoModule::CommandFunction>(&NoAutoCycleMod::OnDelCommand),
                   "[!]<#chan>",
                   "Remove an entry, needs to be an exact match");
        addCommand("List",
                   static_cast<NoModule::CommandFunction>(&NoAutoCycleMod::OnListCommand),
                   "",
                   "List all entries");
        m_recentlyCycled.setExpiration(15 * 1000);
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        NoStringVector vsChans = args.split(" ", No::SkipEmptyParts);

        for (NoStringVector::const_iterator it = vsChans.begin(); it != vsChans.end(); ++it) {
            if (!Add(*it)) {
                putModule("Unable to add [" + *it + "]");
            }
        }

        // Load our saved settings, ignore errors
        NoRegistry registry(this);
        for (const NoString& key : registry.keys())
            Add(key);

        // Default is auto cycle for all channels
        if (m_vsChans.empty())
            Add("*");

        return true;
    }

    void OnaddCommand(const NoString& line)
    {
        NoString sChan = No::token(line, 1);

        if (AlreadyAdded(sChan)) {
            putModule(sChan + " is already added");
        } else if (Add(sChan)) {
            putModule("Added " + sChan + " to list");
        } else {
            putModule("Usage: Add [!]<#chan>");
        }
    }

    void OnDelCommand(const NoString& line)
    {
        NoString sChan = No::token(line, 1);

        if (Del(sChan))
            putModule("Removed " + sChan + " from list");
        else
            putModule("Usage: Del [!]<#chan>");
    }

    void OnListCommand(const NoString& line)
    {
        NoTable Table;
        Table.addColumn("Channel");

        for (uint a = 0; a < m_vsChans.size(); a++) {
            Table.addRow();
            Table.setValue("Channel", m_vsChans[a]);
        }

        for (uint b = 0; b < m_vsNegChans.size(); b++) {
            Table.addRow();
            Table.setValue("Channel", "!" + m_vsNegChans[b]);
        }

        if (Table.size()) {
            putModule(Table);
        } else {
            putModule("You have no entries.");
        }
    }

    void onPart(const NoNick& nick, NoChannel* channel, const NoString& message) override
    {
        AutoCycle(channel);
    }

    void onQuit(const NoHostMask& nick, const NoString& message) override
    {
        std::vector<NoChannel*> channels = network()->findNick(nick.nick());
        for (NoChannel* channel : channels)
            AutoCycle(channel);
    }

    void onKick(const NoNick& nick, const NoString& opNick, NoChannel* channel, const NoString& message) override
    {
        AutoCycle(channel);
    }

protected:
    void AutoCycle(NoChannel* channel)
    {
        if (!IsAutoCycle(channel->name()))
            return;

        // Did we recently annoy opers via cycling of an empty channel?
        if (m_recentlyCycled.contains(channel->name()))
            return;

        // Is there only one person left in the channel?
        if (channel->nickCount() != 1)
            return;

        // Is that person us and we don't have op?
        const NoNick& pNick = channel->nicks().begin()->second;
        if (!pNick.hasPerm(NoChannel::Op) && pNick.equals(network()->currentNick())) {
            channel->cycle();
            m_recentlyCycled.insert(channel->name());
        }
    }

    bool AlreadyAdded(const NoString& sInput)
    {
        std::vector<NoString>::iterator it;

        if (sInput.left(1) == "!") {
            NoString sChan = sInput.substr(1);
            for (it = m_vsNegChans.begin(); it != m_vsNegChans.end(); ++it) {
                if (*it == sChan)
                    return true;
            }
        } else {
            for (it = m_vsChans.begin(); it != m_vsChans.end(); ++it) {
                if (*it == sInput)
                    return true;
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

        if (sChan.empty() || sChan == "!")
            return false;

        if (sChan.left(1) == "!") {
            NoString sTmp = sChan.substr(1);
            it = m_vsNegChans.begin();
            end = m_vsNegChans.end();

            for (; it != end; ++it)
                if (*it == sTmp)
                    break;

            if (it == end)
                return false;

            m_vsNegChans.erase(it);
        } else {
            it = m_vsChans.begin();
            end = m_vsChans.end();

            for (; it != end; ++it)
                if (*it == sChan)
                    break;

            if (it == end)
                return false;

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

template <>
void no_moduleInfo<NoAutoCycleMod>(NoModuleInfo& info)
{
    info.setWikiPage("autocycle");
    info.setHasArgs(true);
    info.setArgsHelpText("List of channel masks and channel masks with ! before them.");
}

NETWORKMODULEDEFS(NoAutoCycleMod, "Rejoins channels to gain Op if you're the only user left")
