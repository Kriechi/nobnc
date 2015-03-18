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

class NoWatchSource
{
public:
    NoWatchSource(const NoString& sSource, bool bNegated)
    {
        m_sSource = sSource;
        m_bNegated = bNegated;
    }
    virtual ~NoWatchSource() {}

    // Getters
    const NoString& GetSource() const { return m_sSource; }
    bool IsNegated() const { return m_bNegated; }
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
    NoWatchEntry(const NoString& sHostMask, const NoString& sTarget, const NoString& sPattern)
    {
        m_bDisabled = false;
        m_bDetachedClientOnly = false;
        m_bDetachedChannelOnly = false;
        m_sPattern = (sPattern.size()) ? sPattern : "*";

        NoNick Nick(sHostMask);

        m_sHostMask = (Nick.nick().size()) ? Nick.nick() : "*";
        m_sHostMask += "!";
        m_sHostMask += (Nick.ident().size()) ? Nick.ident() : "*";
        m_sHostMask += "@";
        m_sHostMask += (Nick.host().size()) ? Nick.host() : "*";

        if (sTarget.size()) {
            m_sTarget = sTarget;
        } else {
            m_sTarget = "$";
            m_sTarget += Nick.nick();
        }
    }
    virtual ~NoWatchEntry() {}

    bool IsMatch(const NoNick& Nick, const NoString& sText, const NoString& sSource, const NoNetwork* pNetwork)
    {
        if (IsDisabled()) {
            return false;
        }

        bool bGoodSource = true;

        if (!sSource.empty() && !m_vsSources.empty()) {
            bGoodSource = false;

            for (uint a = 0; a < m_vsSources.size(); a++) {
                const NoWatchSource& WatchSource = m_vsSources[a];

                if (sSource.WildCmp(WatchSource.GetSource(), NoString::CaseInsensitive)) {
                    if (WatchSource.IsNegated()) {
                        return false;
                    } else {
                        bGoodSource = true;
                    }
                }
            }
        }

        if (!bGoodSource) return false;
        if (!Nick.hostMask().WildCmp(m_sHostMask, NoString::CaseInsensitive)) return false;
        return (sText.WildCmp(pNetwork->ExpandString(m_sPattern), NoString::CaseInsensitive));
    }

    bool operator==(const NoWatchEntry& WatchEntry)
    {
        return (GetHostMask().Equals(WatchEntry.GetHostMask()) && GetTarget().Equals(WatchEntry.GetTarget()) &&
                GetPattern().Equals(WatchEntry.GetPattern()));
    }

    // Getters
    const NoString& GetHostMask() const { return m_sHostMask; }
    const NoString& GetTarget() const { return m_sTarget; }
    const NoString& GetPattern() const { return m_sPattern; }
    bool IsDisabled() const { return m_bDisabled; }
    bool IsDetachedClientOnly() const { return m_bDetachedClientOnly; }
    bool IsDetachedChannelOnly() const { return m_bDetachedChannelOnly; }
    const std::vector<NoWatchSource>& GetSources() const { return m_vsSources; }
    NoString GetSourcesStr() const
    {
        NoString sRet;

        for (uint a = 0; a < m_vsSources.size(); a++) {
            const NoWatchSource& WatchSource = m_vsSources[a];

            if (a) {
                sRet += " ";
            }

            if (WatchSource.IsNegated()) {
                sRet += "!";
            }

            sRet += WatchSource.GetSource();
        }

        return sRet;
    }
    // !Getters

    // Setters
    void SetHostMask(const NoString& s) { m_sHostMask = s; }
    void SetTarget(const NoString& s) { m_sTarget = s; }
    void SetPattern(const NoString& s) { m_sPattern = s; }
    void SetDisabled(bool b = true) { m_bDisabled = b; }
    void SetDetachedClientOnly(bool b = true) { m_bDetachedClientOnly = b; }
    void SetDetachedChannelOnly(bool b = true) { m_bDetachedChannelOnly = b; }
    void SetSources(const NoString& sSources)
    {
        NoStringVector vsSources;
        NoStringVector::iterator it;
        sSources.Split(" ", vsSources, false);

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

    virtual ~NoWatcherMod() {}

    void OnRawMode(const NoNick& OpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs) override
    {
        Process(OpNick, "* " + OpNick.nick() + " sets mode: " + sModes + " " + sArgs + " on " + Channel.getName(), Channel.getName());
    }

    void OnClientLogin() override
    {
        NoStringMap msParams;
        msParams["target"] = GetNetwork()->GetCurNick();

        size_t uSize = m_Buffer.size();
        for (uint uIdx = 0; uIdx < uSize; uIdx++) {
            PutUser(m_Buffer.getMessage(uIdx, *GetClient(), msParams));
        }
        m_Buffer.clear();
    }

    void OnKick(const NoNick& OpNick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage) override
    {
        Process(OpNick,
                "* " + OpNick.nick() + " kicked " + sKickedNick + " from " + Channel.getName() + " because [" + sMessage + "]",
                Channel.getName());
    }

    void OnQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans) override
    {
        Process(Nick,
                "* Quits: " + Nick.nick() + " (" + Nick.ident() + "@" + Nick.host() + ") "
                                                                                               "(" +
                sMessage + ")",
                "");
    }

    void OnJoin(const NoNick& Nick, NoChannel& Channel) override
    {
        Process(Nick,
                "* " + Nick.nick() + " (" + Nick.ident() + "@" + Nick.host() + ") joins " + Channel.getName(),
                Channel.getName());
    }

    void OnPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage) override
    {
        Process(Nick,
                "* " + Nick.nick() + " (" + Nick.ident() + "@" + Nick.host() + ") parts " + Channel.getName() +
                "(" + sMessage + ")",
                Channel.getName());
    }

    void OnNick(const NoNick& OldNick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans) override
    {
        Process(OldNick, "* " + OldNick.nick() + " is now known as " + sNewNick, "");
    }

    EModRet OnCTCPReply(NoNick& Nick, NoString& sMessage) override
    {
        Process(Nick, "* CTCP: " + Nick.nick() + " reply [" + sMessage + "]", "priv");
        return CONTINUE;
    }

    EModRet OnPrivCTCP(NoNick& Nick, NoString& sMessage) override
    {
        Process(Nick, "* CTCP: " + Nick.nick() + " [" + sMessage + "]", "priv");
        return CONTINUE;
    }

    EModRet OnChanCTCP(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        Process(Nick,
                "* CTCP: " + Nick.nick() + " [" + sMessage + "] to "
                                                                "[" +
                Channel.getName() + "]",
                Channel.getName());
        return CONTINUE;
    }

    EModRet OnPrivNotice(NoNick& Nick, NoString& sMessage) override
    {
        Process(Nick, "-" + Nick.nick() + "- " + sMessage, "priv");
        return CONTINUE;
    }

    EModRet OnChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        Process(Nick, "-" + Nick.nick() + ":" + Channel.getName() + "- " + sMessage, Channel.getName());
        return CONTINUE;
    }

    EModRet OnPrivMsg(NoNick& Nick, NoString& sMessage) override
    {
        Process(Nick, "<" + Nick.nick() + "> " + sMessage, "priv");
        return CONTINUE;
    }

    EModRet OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        Process(Nick, "<" + Nick.nick() + ":" + Channel.getName() + "> " + sMessage, Channel.getName());
        return CONTINUE;
    }

    void OnModCommand(const NoString& sCommand) override
    {
        NoString sCmdName = sCommand.Token(0);
        if (sCmdName.Equals("ADD") || sCmdName.Equals("WATCH")) {
            Watch(sCommand.Token(1), sCommand.Token(2), sCommand.Token(3, true));
        } else if (sCmdName.Equals("HELP")) {
            Help();
        } else if (sCmdName.Equals("LIST")) {
            List();
        } else if (sCmdName.Equals("DUMP")) {
            Dump();
        } else if (sCmdName.Equals("ENABLE")) {
            NoString sTok = sCommand.Token(1);

            if (sTok == "*") {
                SetDisabled(~0, false);
            } else {
                SetDisabled(sTok.ToUInt(), false);
            }
        } else if (sCmdName.Equals("DISABLE")) {
            NoString sTok = sCommand.Token(1);

            if (sTok == "*") {
                SetDisabled(~0, true);
            } else {
                SetDisabled(sTok.ToUInt(), true);
            }
        } else if (sCmdName.Equals("SETDETACHEDCLIENTONLY")) {
            NoString sTok = sCommand.Token(1);
            bool bDetachedClientOnly = sCommand.Token(2).ToBool();

            if (sTok == "*") {
                SetDetachedClientOnly(~0, bDetachedClientOnly);
            } else {
                SetDetachedClientOnly(sTok.ToUInt(), bDetachedClientOnly);
            }
        } else if (sCmdName.Equals("SETDETACHEDCHANNELONLY")) {
            NoString sTok = sCommand.Token(1);
            bool bDetachedchannelOnly = sCommand.Token(2).ToBool();

            if (sTok == "*") {
                SetDetachedChannelOnly(~0, bDetachedchannelOnly);
            } else {
                SetDetachedChannelOnly(sTok.ToUInt(), bDetachedchannelOnly);
            }
        } else if (sCmdName.Equals("SETSOURCES")) {
            SetSources(sCommand.Token(1).ToUInt(), sCommand.Token(2, true));
        } else if (sCmdName.Equals("CLEAR")) {
            m_lsWatchers.clear();
            PutModule("All entries cleared.");
            Save();
        } else if (sCmdName.Equals("BUFFER")) {
            NoString sCount = sCommand.Token(1);

            if (sCount.size()) {
                m_Buffer.setLimit(sCount.ToUInt());
            }

            PutModule("Buffer count is set to [" + NoString(m_Buffer.getLimit()) + "]");
        } else if (sCmdName.Equals("DEL")) {
            Remove(sCommand.Token(1).ToUInt());
        } else {
            PutModule("Unknown command: [" + sCmdName + "]");
        }
    }

private:
    void Process(const NoNick& Nick, const NoString& sMessage, const NoString& sSource)
    {
        std::set<NoString> sHandledTargets;
        NoNetwork* pNetwork = GetNetwork();
        NoChannel* pChannel = pNetwork->FindChan(sSource);

        for (std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin(); it != m_lsWatchers.end(); ++it) {
            NoWatchEntry& WatchEntry = *it;

            if (pNetwork->IsUserAttached() && WatchEntry.IsDetachedClientOnly()) {
                continue;
            }

            if (pChannel && !pChannel->isDetached() && WatchEntry.IsDetachedChannelOnly()) {
                continue;
            }

            if (WatchEntry.IsMatch(Nick, sMessage, sSource, pNetwork) && sHandledTargets.count(WatchEntry.GetTarget()) < 1) {
                if (pNetwork->IsUserAttached()) {
                    pNetwork->PutUser(":" + WatchEntry.GetTarget() + "!watch@znc.in PRIVMSG " + pNetwork->GetCurNick() + " :" + sMessage);
                } else {
                    m_Buffer.addMessage(":" + _NAMEDFMT(WatchEntry.GetTarget()) + "!watch@znc.in PRIVMSG {target} :{text}", sMessage);
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

            PutModule(((bDisabled) ? "Disabled all entries." : "Enabled all entries."));
            Save();
            return;
        }

        uIdx--; // "convert" index to zero based
        if (uIdx >= m_lsWatchers.size()) {
            PutModule("Invalid Id");
            return;
        }

        std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin();
        for (uint a = 0; a < uIdx; a++) ++it;

        (*it).SetDisabled(bDisabled);
        PutModule("Id " + NoString(uIdx + 1) + ((bDisabled) ? " Disabled" : " Enabled"));
        Save();
    }

    void SetDetachedClientOnly(uint uIdx, bool bDetachedClientOnly)
    {
        if (uIdx == (uint)~0) {
            for (std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin(); it != m_lsWatchers.end(); ++it) {
                (*it).SetDetachedClientOnly(bDetachedClientOnly);
            }

            PutModule(NoString("Set DetachedClientOnly for all entries to: ") + ((bDetachedClientOnly) ? "Yes" : "No"));
            Save();
            return;
        }

        uIdx--; // "convert" index to zero based
        if (uIdx >= m_lsWatchers.size()) {
            PutModule("Invalid Id");
            return;
        }

        std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin();
        for (uint a = 0; a < uIdx; a++) ++it;

        (*it).SetDetachedClientOnly(bDetachedClientOnly);
        PutModule("Id " + NoString(uIdx + 1) + " set to: " + ((bDetachedClientOnly) ? "Yes" : "No"));
        Save();
    }

    void SetDetachedChannelOnly(uint uIdx, bool bDetachedChannelOnly)
    {
        if (uIdx == (uint)~0) {
            for (std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin(); it != m_lsWatchers.end(); ++it) {
                (*it).SetDetachedChannelOnly(bDetachedChannelOnly);
            }

            PutModule(NoString("Set DetachedChannelOnly for all entries to: ") +
                      ((bDetachedChannelOnly) ? "Yes" : "No"));
            Save();
            return;
        }

        uIdx--; // "convert" index to zero based
        if (uIdx >= m_lsWatchers.size()) {
            PutModule("Invalid Id");
            return;
        }

        std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin();
        for (uint a = 0; a < uIdx; a++) ++it;

        (*it).SetDetachedChannelOnly(bDetachedChannelOnly);
        PutModule("Id " + NoString(uIdx + 1) + " set to: " + ((bDetachedChannelOnly) ? "Yes" : "No"));
        Save();
    }

    void List()
    {
        NoTable Table;
        Table.AddColumn("Id");
        Table.AddColumn("HostMask");
        Table.AddColumn("Target");
        Table.AddColumn("Pattern");
        Table.AddColumn("Sources");
        Table.AddColumn("Off");
        Table.AddColumn("DetachedClientOnly");
        Table.AddColumn("DetachedChannelOnly");

        uint uIdx = 1;

        for (std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin(); it != m_lsWatchers.end(); ++it, uIdx++) {
            NoWatchEntry& WatchEntry = *it;

            Table.AddRow();
            Table.SetCell("Id", NoString(uIdx));
            Table.SetCell("HostMask", WatchEntry.GetHostMask());
            Table.SetCell("Target", WatchEntry.GetTarget());
            Table.SetCell("Pattern", WatchEntry.GetPattern());
            Table.SetCell("Sources", WatchEntry.GetSourcesStr());
            Table.SetCell("Off", (WatchEntry.IsDisabled()) ? "Off" : "");
            Table.SetCell("DetachedClientOnly", (WatchEntry.IsDetachedClientOnly()) ? "Yes" : "No");
            Table.SetCell("DetachedChannelOnly", (WatchEntry.IsDetachedChannelOnly()) ? "Yes" : "No");
        }

        if (Table.size()) {
            PutModule(Table);
        } else {
            PutModule("You have no entries.");
        }
    }

    void Dump()
    {
        if (m_lsWatchers.empty()) {
            PutModule("You have no entries.");
            return;
        }

        PutModule("---------------");
        PutModule("/msg " + GetModNick() + " CLEAR");

        uint uIdx = 1;

        for (std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin(); it != m_lsWatchers.end(); ++it, uIdx++) {
            NoWatchEntry& WatchEntry = *it;

            PutModule("/msg " + GetModNick() + " ADD " + WatchEntry.GetHostMask() + " " + WatchEntry.GetTarget() + " " +
                      WatchEntry.GetPattern());

            if (WatchEntry.GetSourcesStr().size()) {
                PutModule("/msg " + GetModNick() + " SETSOURCES " + NoString(uIdx) + " " + WatchEntry.GetSourcesStr());
            }

            if (WatchEntry.IsDisabled()) {
                PutModule("/msg " + GetModNick() + " DISABLE " + NoString(uIdx));
            }

            if (WatchEntry.IsDetachedClientOnly()) {
                PutModule("/msg " + GetModNick() + " SETDETACHEDCLIENTONLY " + NoString(uIdx) + " TRUE");
            }

            if (WatchEntry.IsDetachedChannelOnly()) {
                PutModule("/msg " + GetModNick() + " SETDETACHEDCHANNELONLY " + NoString(uIdx) + " TRUE");
            }
        }

        PutModule("---------------");
    }

    void SetSources(uint uIdx, const NoString& sSources)
    {
        uIdx--; // "convert" index to zero based
        if (uIdx >= m_lsWatchers.size()) {
            PutModule("Invalid Id");
            return;
        }

        std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin();
        for (uint a = 0; a < uIdx; a++) ++it;

        (*it).SetSources(sSources);
        PutModule("Sources set for Id " + NoString(uIdx + 1) + ".");
        Save();
    }

    void Remove(uint uIdx)
    {
        uIdx--; // "convert" index to zero based
        if (uIdx >= m_lsWatchers.size()) {
            PutModule("Invalid Id");
            return;
        }

        std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin();
        for (uint a = 0; a < uIdx; a++) ++it;

        m_lsWatchers.erase(it);
        PutModule("Id " + NoString(uIdx + 1) + " Removed.");
        Save();
    }

    void Help()
    {
        NoTable Table;

        Table.AddColumn("Command");
        Table.AddColumn("Description");

        Table.AddRow();
        Table.SetCell("Command", "Add <HostMask> [Target] [Pattern]");
        Table.SetCell("Description", "Used to add an entry to watch for.");

        Table.AddRow();
        Table.SetCell("Command", "List");
        Table.SetCell("Description", "List all entries being watched.");

        Table.AddRow();
        Table.SetCell("Command", "Dump");
        Table.SetCell("Description", "Dump a list of all current entries to be used later.");

        Table.AddRow();
        Table.SetCell("Command", "Del <Id>");
        Table.SetCell("Description", "Deletes Id from the list of watched entries.");

        Table.AddRow();
        Table.SetCell("Command", "Clear");
        Table.SetCell("Description", "Delete all entries.");

        Table.AddRow();
        Table.SetCell("Command", "Enable <Id | *>");
        Table.SetCell("Description", "Enable a disabled entry.");

        Table.AddRow();
        Table.SetCell("Command", "Disable <Id | *>");
        Table.SetCell("Description", "Disable (but don't delete) an entry.");

        Table.AddRow();
        Table.SetCell("Command", "SetDetachedClientOnly <Id | *> <True | False>");
        Table.SetCell("Description", "Enable or disable detached client only for an entry.");

        Table.AddRow();
        Table.SetCell("Command", "SetDetachedChannelOnly <Id | *> <True | False>");
        Table.SetCell("Description", "Enable or disable detached channel only for an entry.");

        Table.AddRow();
        Table.SetCell("Command", "Buffer [Count]");
        Table.SetCell("Description", "Show/Set the amount of buffered lines while detached.");

        Table.AddRow();
        Table.SetCell("Command", "SetSources <Id> [#chan priv #foo* !#bar]");
        Table.SetCell("Description", "Set the source channels that you care about.");

        Table.AddRow();
        Table.SetCell("Command", "Help");
        Table.SetCell("Description", "This help.");

        PutModule(Table);
    }

    void Watch(const NoString& sHostMask, const NoString& sTarget, const NoString& sPattern, bool bNotice = false)
    {
        NoString sMessage;

        if (sHostMask.size()) {
            NoWatchEntry WatchEntry(sHostMask, sTarget, sPattern);

            bool bExists = false;
            for (std::list<NoWatchEntry>::iterator it = m_lsWatchers.begin(); it != m_lsWatchers.end(); ++it) {
                if (*it == WatchEntry) {
                    sMessage = "Entry for [" + WatchEntry.GetHostMask() + "] already exists.";
                    bExists = true;
                    break;
                }
            }

            if (!bExists) {
                sMessage = "Adding entry: [" + WatchEntry.GetHostMask() + "] watching for "
                                                                          "[" +
                           WatchEntry.GetPattern() + "] -> [" + WatchEntry.GetTarget() + "]";
                m_lsWatchers.push_back(WatchEntry);
            }
        } else {
            sMessage = "Watch: Not enough arguments.  Try Help";
        }

        if (bNotice) {
            PutModNotice(sMessage);
        } else {
            PutModule(sMessage);
        }
        Save();
    }

    void Save()
    {
        ClearNV(false);
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

            SetNV(sSave, "", false);
        }

        SaveRegistry();
    }

    void Load()
    {
        // Just to make sure we dont mess up badly
        m_lsWatchers.clear();

        bool bWarn = false;

        for (NoStringMap::iterator it = BeginNV(); it != EndNV(); ++it) {
            NoStringVector vList;
            it->first.Split("\n", vList);

            // Backwards compatibility with the old save format
            if (vList.size() != 5 && vList.size() != 7) {
                bWarn = true;
                continue;
            }

            NoWatchEntry WatchEntry(vList[0], vList[1], vList[2]);
            if (vList[3].Equals("disabled"))
                WatchEntry.SetDisabled(true);
            else
                WatchEntry.SetDisabled(false);

            // Backwards compatibility with the old save format
            if (vList.size() == 5) {
                WatchEntry.SetSources(vList[4]);
            } else {
                WatchEntry.SetDetachedClientOnly(vList[4].ToBool());
                WatchEntry.SetDetachedChannelOnly(vList[5].ToBool());
                WatchEntry.SetSources(vList[6]);
            }
            m_lsWatchers.push_back(WatchEntry);
        }

        if (bWarn) PutModule("WARNING: malformed entry found while loading");
    }

    std::list<NoWatchEntry> m_lsWatchers;
    NoBuffer m_Buffer;
};

template <> void TModInfo<NoWatcherMod>(NoModInfo& Info) { Info.SetWikiPage("watch"); }

NETWORKMODULEDEFS(NoWatcherMod, "Copy activity from a specific user into a separate window")
