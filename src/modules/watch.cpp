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
#include <nobnc/noescape.h>
#include <nobnc/noregistry.h>
#include <nobnc/nonick.h>
#include <nobnc/nobuffer.h>
#include <nobnc/nohostmask.h>

#include <list>

class NoWatchSource
{
public:
    NoWatchSource(const NoString& sSource, bool bNegated)
    {
        m_sSource = sSource;
        m_bNegated = bNegated;
    }

    // Getters
    const NoString& GetSource() const
    {
        return m_sSource;
    }
    bool IsNegated() const
    {
        return m_bNegated;
    }
    // !Getters

    // Setters
    // !Setters
private:
protected:
    bool m_bNegated;
    NoString m_sSource;
};

class NoWatchEntry
{
public:
    NoWatchEntry(const NoString& hostMask, const NoString& target, const NoString& sPattern)
    {
        m_bDisabled = false;
        m_bDetachedClientOnly = false;
        m_bDetachedChannelOnly = false;
        m_sPattern = (sPattern.size()) ? sPattern : "*";

        NoNick nick(hostMask);

        m_sHostMask = (nick.nick().size()) ? nick.nick() : "*";
        m_sHostMask += "!";
        m_sHostMask += (nick.ident().size()) ? nick.ident() : "*";
        m_sHostMask += "@";
        m_sHostMask += (nick.host().size()) ? nick.host() : "*";

        if (target.size()) {
            m_sTarget = target;
        } else {
            m_sTarget = "$";
            m_sTarget += nick.nick();
        }
    }

    bool IsMatch(const NoString& hostMask, const NoString& text, const NoString& sSource, const NoNetwork* network)
    {
        if (IsDisabled()) {
            return false;
        }

        bool bGoodSource = true;

        if (!sSource.empty() && !m_vsSources.empty()) {
            bGoodSource = false;

            for (uint a = 0; a < m_vsSources.size(); a++) {
                const NoWatchSource& WatchSource = m_vsSources[a];

                if (No::wildCmp(sSource, WatchSource.GetSource(), No::CaseInsensitive)) {
                    if (WatchSource.IsNegated()) {
                        return false;
                    } else {
                        bGoodSource = true;
                    }
                }
            }
        }

        if (!bGoodSource)
            return false;
        if (!No::wildCmp(hostMask, m_sHostMask, No::CaseInsensitive))
            return false;
        return (No::wildCmp(text, network->expandString(m_sPattern), No::CaseInsensitive));
    }

    bool operator==(const NoWatchEntry& WatchEntry)
    {
        return (GetHostMask().equals(WatchEntry.GetHostMask()) && GetTarget().equals(WatchEntry.GetTarget()) &&
                GetPattern().equals(WatchEntry.GetPattern()));
    }

    // Getters
    const NoString& GetHostMask() const
    {
        return m_sHostMask;
    }
    const NoString& GetTarget() const
    {
        return m_sTarget;
    }
    const NoString& GetPattern() const
    {
        return m_sPattern;
    }
    bool IsDisabled() const
    {
        return m_bDisabled;
    }
    bool IsDetachedClientOnly() const
    {
        return m_bDetachedClientOnly;
    }
    bool IsDetachedChannelOnly() const
    {
        return m_bDetachedChannelOnly;
    }
    const std::vector<NoWatchSource>& GetSources() const
    {
        return m_vsSources;
    }
    NoString GetSourcesStr() const
    {
        NoString ret;

        for (uint a = 0; a < m_vsSources.size(); a++) {
            const NoWatchSource& WatchSource = m_vsSources[a];

            if (a) {
                ret += " ";
            }

            if (WatchSource.IsNegated()) {
                ret += "!";
            }

            ret += WatchSource.GetSource();
        }

        return ret;
    }
    // !Getters

    // Setters
    void SetHostMask(const NoString& s)
    {
        m_sHostMask = s;
    }
    void SetTarget(const NoString& s)
    {
        m_sTarget = s;
    }
    void SetPattern(const NoString& s)
    {
        m_sPattern = s;
    }
    void SetDisabled(bool b = true)
    {
        m_bDisabled = b;
    }
    void SetDetachedClientOnly(bool b = true)
    {
        m_bDetachedClientOnly = b;
    }
    void SetDetachedChannelOnly(bool b = true)
    {
        m_bDetachedChannelOnly = b;
    }
    void SetSources(const NoString& sSources)
    {
        NoStringVector vsSources = sSources.split(" ", No::SkipEmptyParts);
        NoStringVector::iterator it;

        m_vsSources.clear();

        for (it = vsSources.begin(); it != vsSources.end(); ++it) {
            if (it->at(0) == '!' && it->size() > 1) {
                m_vsSources.push_back(NoWatchSource(it->substr(1), true));
            } else {
                m_vsSources.push_back(NoWatchSource(*it, false));
            }
        }
    }
    // !Setters
private:
protected:
    NoString m_sHostMask;
    NoString m_sTarget;
    NoString m_sPattern;
    bool m_bDisabled;
    bool m_bDetachedClientOnly;
    bool m_bDetachedChannelOnly;
    std::vector<NoWatchSource> m_vsSources;
};

class NoWatcherMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoWatcherMod)
    {
        m_Buffer.setLimit(500);
        Load();
    }

    void onRawMode2(const NoNick* opNick, NoChannel* channel, const NoString& modes, const NoString& args) override
    {
        if (opNick)
            Process(opNick->hostMask(), "* " + opNick->nick() + " sets mode: " + modes + " " + args + " on " + channel->name(), channel->name());
    }

    void onClientLogin() override
    {
        NoStringMap msParams;
        msParams["target"] = network()->currentNick();

        size_t uSize = m_Buffer.size();
        for (uint uIdx = 0; uIdx < uSize; uIdx++) {
            putUser(m_Buffer.message(uIdx, client(), msParams));
        }
        m_Buffer.clear();
    }

    void onKick(const NoNick& opNick, const NoString& sKickedNick, NoChannel* channel, const NoString& message) override
    {
        Process(opNick.hostMask(),
                "* " + opNick.nick() + " kicked " + sKickedNick + " from " + channel->name() + " because [" + message + "]",
                channel->name());
    }

    void onQuit(const NoHostMask& nick, const NoString& message) override
    {
        Process(nick.toString(),
                "* Quits: " + nick.nick() + " (" + nick.ident() + "@" + nick.host() + ") "
                                                                                      "(" +
                message + ")",
                "");
    }

    void onJoin(const NoNick& nick, NoChannel* channel) override
    {
        Process(nick.hostMask(), "* " + nick.nick() + " (" + nick.ident() + "@" + nick.host() + ") joins " + channel->name(), channel->name());
    }

    void onPart(const NoNick& nick, NoChannel* channel, const NoString& message) override
    {
        Process(nick.hostMask(),
                "* " + nick.nick() + " (" + nick.ident() + "@" + nick.host() + ") parts " + channel->name() + "(" + message + ")",
                channel->name());
    }

    void onNick(const NoHostMask& OldNick, const NoString& newNick) override
    {
        Process(OldNick.toString(), "* " + OldNick.nick() + " is now known as " + newNick, "");
    }

    ModRet onCtcpReply(NoHostMask& nick, NoString& message) override
    {
        Process(nick.toString(), "* CTCP: " + nick.nick() + " reply [" + message + "]", "priv");
        return CONTINUE;
    }

    ModRet onPrivCtcp(NoHostMask& nick, NoString& message) override
    {
        Process(nick.toString(), "* CTCP: " + nick.nick() + " [" + message + "]", "priv");
        return CONTINUE;
    }

    ModRet onChanCtcp(NoNick& nick, NoChannel* channel, NoString& message) override
    {
        Process(nick.hostMask(),
                "* CTCP: " + nick.nick() + " [" + message + "] to "
                                                             "[" +
                channel->name() + "]",
                channel->name());
        return CONTINUE;
    }

    ModRet onPrivNotice(NoHostMask& nick, NoString& message) override
    {
        Process(nick.toString(), "-" + nick.nick() + "- " + message, "priv");
        return CONTINUE;
    }

    ModRet onChanNotice(NoNick& nick, NoChannel* channel, NoString& message) override
    {
        Process(nick.hostMask(), "-" + nick.nick() + ":" + channel->name() + "- " + message, channel->name());
        return CONTINUE;
    }

    ModRet onPrivMsg(NoHostMask& nick, NoString& message) override
    {
        Process(nick.toString(), "<" + nick.nick() + "> " + message, "priv");
        return CONTINUE;
    }

    ModRet onChanMsg(NoNick& nick, NoChannel* channel, NoString& message) override
    {
        Process(nick.hostMask(), "<" + nick.nick() + ":" + channel->name() + "> " + message, channel->name());
        return CONTINUE;
    }

    void onModCommand(const NoString& command) override
    {
        NoString sCmdName = No::token(command, 0);
        if (sCmdName.equals("ADD") || sCmdName.equals("WATCH")) {
            Watch(No::token(command, 1), No::token(command, 2), No::tokens(command, 3));
        } else if (sCmdName.equals("HELP")) {
            Help();
        } else if (sCmdName.equals("LIST")) {
            List();
        } else if (sCmdName.equals("DUMP")) {
            Dump();
        } else if (sCmdName.equals("ENABLE")) {
            NoString sTok = No::token(command, 1);

            if (sTok == "*") {
                SetDisabled(~0, false);
            } else {
                SetDisabled(sTok.toUInt(), false);
            }
        } else if (sCmdName.equals("DISABLE")) {
            NoString sTok = No::token(command, 1);

            if (sTok == "*") {
                SetDisabled(~0, true);
            } else {
                SetDisabled(sTok.toUInt(), true);
            }
        } else if (sCmdName.equals("SETDETACHEDCLIENTONLY")) {
            NoString sTok = No::token(command, 1);
            bool bDetachedClientOnly = No::token(command, 2).toBool();

            if (sTok == "*") {
                SetDetachedClientOnly(~0, bDetachedClientOnly);
            } else {
                SetDetachedClientOnly(sTok.toUInt(), bDetachedClientOnly);
            }
        } else if (sCmdName.equals("SETDETACHEDCHANNELONLY")) {
            NoString sTok = No::token(command, 1);
            bool bDetachedchannelOnly = No::token(command, 2).toBool();

            if (sTok == "*") {
                SetDetachedChannelOnly(~0, bDetachedchannelOnly);
            } else {
                SetDetachedChannelOnly(sTok.toUInt(), bDetachedchannelOnly);
            }
        } else if (sCmdName.equals("SETSOURCES")) {
            SetSources(No::token(command, 1).toUInt(), No::tokens(command, 2));
        } else if (sCmdName.equals("CLEAR")) {
            m_lsWatchers.clear();
            putModule("All entries cleared.");
            Save();
        } else if (sCmdName.equals("BUFFER")) {
            NoString sCount = No::token(command, 1);

            if (sCount.size()) {
                m_Buffer.setLimit(sCount.toUInt());
            }

            putModule("Buffer count is set to [" + NoString(m_Buffer.limit()) + "]");
        } else if (sCmdName.equals("DEL")) {
            Remove(No::token(command, 1).toUInt());
        } else {
            putModule("Unknown command: [" + sCmdName + "]");
        }
    }

private:
    void Process(const NoString& hostMask, const NoString& message, const NoString& sSource)
    {
        std::set<NoString> sHandledTargets;
        NoNetwork* network = NoModule::network();
        NoChannel* pChannel = network->findChannel(sSource);

        for (std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin(); it != m_lsWatchers.end(); ++it) {
            NoWatchEntry& WatchEntry = *it;

            if (network->isUserAttached() && WatchEntry.IsDetachedClientOnly()) {
                continue;
            }

            if (pChannel && !pChannel->isDetached() && WatchEntry.IsDetachedChannelOnly()) {
                continue;
            }

            if (WatchEntry.IsMatch(hostMask, message, sSource, network) && sHandledTargets.count(WatchEntry.GetTarget()) < 1) {
                if (network->isUserAttached()) {
                    network->putUser(":" + WatchEntry.GetTarget() + "!watch@znc.in PRIVMSG " +
                                      network->currentNick() + " :" + message);
                } else {
                    m_Buffer.addMessage(":" + _NAMEDFMT(WatchEntry.GetTarget()) +
                                        "!watch@znc.in PRIVMSG {target} :{text}",
                                        message);
                }
                sHandledTargets.insert(WatchEntry.GetTarget());
            }
        }
    }

    void SetDisabled(uint uIdx, bool bDisabled)
    {
        if (uIdx == (uint)~0) {
            for (std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin(); it != m_lsWatchers.end(); ++it) {
                (*it).SetDisabled(bDisabled);
            }

            putModule(((bDisabled) ? "Disabled all entries." : "Enabled all entries."));
            Save();
            return;
        }

        uIdx--; // "convert" index to zero based
        if (uIdx >= m_lsWatchers.size()) {
            putModule("Invalid Id");
            return;
        }

        std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin();
        for (uint a = 0; a < uIdx; a++)
            ++it;

        (*it).SetDisabled(bDisabled);
        putModule("Id " + NoString(uIdx + 1) + ((bDisabled) ? " Disabled" : " Enabled"));
        Save();
    }

    void SetDetachedClientOnly(uint uIdx, bool bDetachedClientOnly)
    {
        if (uIdx == (uint)~0) {
            for (std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin(); it != m_lsWatchers.end(); ++it) {
                (*it).SetDetachedClientOnly(bDetachedClientOnly);
            }

            putModule(NoString("Set DetachedClientOnly for all entries to: ") + ((bDetachedClientOnly) ? "Yes" : "No"));
            Save();
            return;
        }

        uIdx--; // "convert" index to zero based
        if (uIdx >= m_lsWatchers.size()) {
            putModule("Invalid Id");
            return;
        }

        std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin();
        for (uint a = 0; a < uIdx; a++)
            ++it;

        (*it).SetDetachedClientOnly(bDetachedClientOnly);
        putModule("Id " + NoString(uIdx + 1) + " set to: " + ((bDetachedClientOnly) ? "Yes" : "No"));
        Save();
    }

    void SetDetachedChannelOnly(uint uIdx, bool bDetachedChannelOnly)
    {
        if (uIdx == (uint)~0) {
            for (std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin(); it != m_lsWatchers.end(); ++it) {
                (*it).SetDetachedChannelOnly(bDetachedChannelOnly);
            }

            putModule(NoString("Set DetachedChannelOnly for all entries to: ") +
                      ((bDetachedChannelOnly) ? "Yes" : "No"));
            Save();
            return;
        }

        uIdx--; // "convert" index to zero based
        if (uIdx >= m_lsWatchers.size()) {
            putModule("Invalid Id");
            return;
        }

        std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin();
        for (uint a = 0; a < uIdx; a++)
            ++it;

        (*it).SetDetachedChannelOnly(bDetachedChannelOnly);
        putModule("Id " + NoString(uIdx + 1) + " set to: " + ((bDetachedChannelOnly) ? "Yes" : "No"));
        Save();
    }

    void List()
    {
        NoTable Table;
        Table.addColumn("Id");
        Table.addColumn("HostMask");
        Table.addColumn("Target");
        Table.addColumn("Pattern");
        Table.addColumn("Sources");
        Table.addColumn("Off");
        Table.addColumn("DetachedClientOnly");
        Table.addColumn("DetachedChannelOnly");

        uint uIdx = 1;

        for (std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin(); it != m_lsWatchers.end(); ++it, uIdx++) {
            NoWatchEntry& WatchEntry = *it;

            Table.addRow();
            Table.setValue("Id", NoString(uIdx));
            Table.setValue("HostMask", WatchEntry.GetHostMask());
            Table.setValue("Target", WatchEntry.GetTarget());
            Table.setValue("Pattern", WatchEntry.GetPattern());
            Table.setValue("Sources", WatchEntry.GetSourcesStr());
            Table.setValue("Off", (WatchEntry.IsDisabled()) ? "Off" : "");
            Table.setValue("DetachedClientOnly", (WatchEntry.IsDetachedClientOnly()) ? "Yes" : "No");
            Table.setValue("DetachedChannelOnly", (WatchEntry.IsDetachedChannelOnly()) ? "Yes" : "No");
        }

        if (Table.size()) {
            putModule(Table);
        } else {
            putModule("You have no entries.");
        }
    }

    void Dump()
    {
        if (m_lsWatchers.empty()) {
            putModule("You have no entries.");
            return;
        }

        putModule("---------------");
        putModule("/msg " + moduleNick() + " CLEAR");

        uint uIdx = 1;

        for (std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin(); it != m_lsWatchers.end(); ++it, uIdx++) {
            NoWatchEntry& WatchEntry = *it;

            putModule("/msg " + moduleNick() + " ADD " + WatchEntry.GetHostMask() + " " + WatchEntry.GetTarget() + " " +
                      WatchEntry.GetPattern());

            if (WatchEntry.GetSourcesStr().size()) {
                putModule("/msg " + moduleNick() + " SETSOURCES " + NoString(uIdx) + " " + WatchEntry.GetSourcesStr());
            }

            if (WatchEntry.IsDisabled()) {
                putModule("/msg " + moduleNick() + " DISABLE " + NoString(uIdx));
            }

            if (WatchEntry.IsDetachedClientOnly()) {
                putModule("/msg " + moduleNick() + " SETDETACHEDCLIENTONLY " + NoString(uIdx) + " TRUE");
            }

            if (WatchEntry.IsDetachedChannelOnly()) {
                putModule("/msg " + moduleNick() + " SETDETACHEDCHANNELONLY " + NoString(uIdx) + " TRUE");
            }
        }

        putModule("---------------");
    }

    void SetSources(uint uIdx, const NoString& sSources)
    {
        uIdx--; // "convert" index to zero based
        if (uIdx >= m_lsWatchers.size()) {
            putModule("Invalid Id");
            return;
        }

        std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin();
        for (uint a = 0; a < uIdx; a++)
            ++it;

        (*it).SetSources(sSources);
        putModule("Sources set for Id " + NoString(uIdx + 1) + ".");
        Save();
    }

    void Remove(uint uIdx)
    {
        uIdx--; // "convert" index to zero based
        if (uIdx >= m_lsWatchers.size()) {
            putModule("Invalid Id");
            return;
        }

        std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin();
        for (uint a = 0; a < uIdx; a++)
            ++it;

        m_lsWatchers.erase(it);
        putModule("Id " + NoString(uIdx + 1) + " Removed.");
        Save();
    }

    void Help()
    {
        NoTable Table;

        Table.addColumn("Command");
        Table.addColumn("Description");

        Table.addRow();
        Table.setValue("Command", "Add <HostMask> [Target] [Pattern]");
        Table.setValue("Description", "Used to add an entry to watch for.");

        Table.addRow();
        Table.setValue("Command", "List");
        Table.setValue("Description", "List all entries being watched.");

        Table.addRow();
        Table.setValue("Command", "Dump");
        Table.setValue("Description", "Dump a list of all current entries to be used later.");

        Table.addRow();
        Table.setValue("Command", "Del <Id>");
        Table.setValue("Description", "Deletes Id from the list of watched entries.");

        Table.addRow();
        Table.setValue("Command", "Clear");
        Table.setValue("Description", "Delete all entries.");

        Table.addRow();
        Table.setValue("Command", "Enable <Id | *>");
        Table.setValue("Description", "Enable a disabled entry.");

        Table.addRow();
        Table.setValue("Command", "Disable <Id | *>");
        Table.setValue("Description", "Disable (but don't delete) an entry.");

        Table.addRow();
        Table.setValue("Command", "SetDetachedClientOnly <Id | *> <True | False>");
        Table.setValue("Description", "Enable or disable detached client only for an entry.");

        Table.addRow();
        Table.setValue("Command", "SetDetachedChannelOnly <Id | *> <True | False>");
        Table.setValue("Description", "Enable or disable detached channel only for an entry.");

        Table.addRow();
        Table.setValue("Command", "Buffer [Count]");
        Table.setValue("Description", "Show/Set the amount of buffered lines while detached.");

        Table.addRow();
        Table.setValue("Command", "SetSources <Id> [#chan priv #foo* !#bar]");
        Table.setValue("Description", "Set the source channels that you care about.");

        Table.addRow();
        Table.setValue("Command", "Help");
        Table.setValue("Description", "This help.");

        putModule(Table);
    }

    void Watch(const NoString& hostMask, const NoString& target, const NoString& sPattern, bool bNotice = false)
    {
        NoString message;

        if (hostMask.size()) {
            NoWatchEntry WatchEntry(hostMask, target, sPattern);

            bool bExists = false;
            for (std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin(); it != m_lsWatchers.end(); ++it) {
                if (*it == WatchEntry) {
                    message = "Entry for [" + WatchEntry.GetHostMask() + "] already exists.";
                    bExists = true;
                    break;
                }
            }

            if (!bExists) {
                message = "Adding entry: [" + WatchEntry.GetHostMask() + "] watching for "
                                                                          "[" +
                           WatchEntry.GetPattern() + "] -> [" + WatchEntry.GetTarget() + "]";
                m_lsWatchers.push_back(WatchEntry);
            }
        } else {
            message = "Watch: Not enough arguments.  Try Help";
        }

        if (bNotice) {
            putModuleNotice(message);
        } else {
            putModule(message);
        }
        Save();
    }

    void Save()
    {
        NoRegistry registry(this);
        registry.clear();
        for (std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin(); it != m_lsWatchers.end(); ++it) {
            NoWatchEntry& WatchEntry = *it;
            NoString sSave;

            sSave = WatchEntry.GetHostMask() + "\n";
            sSave += WatchEntry.GetTarget() + "\n";
            sSave += WatchEntry.GetPattern() + "\n";
            sSave += (WatchEntry.IsDisabled() ? "disabled\n" : "enabled\n");
            sSave += NoString(WatchEntry.IsDetachedClientOnly()) + "\n";
            sSave += NoString(WatchEntry.IsDetachedChannelOnly()) + "\n";
            sSave += WatchEntry.GetSourcesStr();
            // Without this, loading fails if GetSourcesStr()
            // returns an empty string
            sSave += " ";

            registry.setValue(sSave, "");
        }
    }

    void Load()
    {
        // Just to make sure we dont mess up badly
        m_lsWatchers.clear();

        bool bWarn = false;

        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            NoStringVector vList = key.split("\n");

            // Backwards compatibility with the old save format
            if (vList.size() != 5 && vList.size() != 7) {
                bWarn = true;
                continue;
            }

            NoWatchEntry WatchEntry(vList[0], vList[1], vList[2]);
            if (vList[3].equals("disabled"))
                WatchEntry.SetDisabled(true);
            else
                WatchEntry.SetDisabled(false);

            // Backwards compatibility with the old save format
            if (vList.size() == 5) {
                WatchEntry.SetSources(vList[4]);
            } else {
                WatchEntry.SetDetachedClientOnly(vList[4].toBool());
                WatchEntry.SetDetachedChannelOnly(vList[5].toBool());
                WatchEntry.SetSources(vList[6]);
            }
            m_lsWatchers.push_back(WatchEntry);
        }

        if (bWarn)
            putModule("WARNING: malformed entry found while loading");
    }

    std::list<NoWatchEntry> m_lsWatchers;
    NoBuffer m_Buffer;
};

template <>
void no_moduleInfo<NoWatcherMod>(NoModuleInfo& info)
{
    info.setWikiPage("watch");
}

NETWORKMODULEDEFS(NoWatcherMod, "Copy activity from a specific user into a separate window")
