/*
 * Copyright (C) 2015 NoBNC
 * Copyright (C) 2004-2015 ZNC, see the NOTICE file for details.
 * Copyright (C) 2006-2007, CNU <bshalm@broadpark.no> (http://cnu.dieplz.net/znc)
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
#include <no/nodir.h>
#include <no/nofile.h>
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/nochannel.h>
#include <no/noserverinfo.h>
#include <no/nodebug.h>
#include <no/noregistry.h>
#include <no/nonick.h>

#include <algorithm>

class NoLogRule
{
public:
    NoLogRule(const NoString& sRule, bool bEnabled = true) : m_sRule(sRule), m_bEnabled(bEnabled) {}

    const NoString& GetRule() const { return m_sRule; }
    bool IsEnabled() const { return m_bEnabled; }
    void SetEnabled(bool bEnabled) { m_bEnabled = bEnabled; }

    bool Compare(const NoString& sTarget) const { return No::wildCmp(sTarget, m_sRule, No::CaseInsensitive); }

    bool operator==(const NoLogRule& sOther) const { return m_sRule == sOther.GetRule(); }

    NoString ToString() const { return (m_bEnabled ? "" : "!") + m_sRule; }

private:
    NoString m_sRule;
    bool m_bEnabled;
};

class NoLogMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoLogMod)
    {
        m_bSanitize = false;
        AddHelpCommand();
        AddCommand("SetRules",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoLogMod::SetRulesCmd),
                   "<rules>",
                   "Set logging rules, use !#chan or !query to negate and * for wildcards");
        AddCommand("ClearRules",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoLogMod::ClearRulesCmd),
                   "",
                   "Clear all logging rules");
        AddCommand("ListRules",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoLogMod::ListRulesCmd),
                   "",
                   "List all logging rules");
    }

    void SetRulesCmd(const NoString& sLine);
    void ClearRulesCmd(const NoString& sLine);
    void ListRulesCmd(const NoString& sLine = "");
    void SetRules(const NoStringVector& vsRules);
    NoStringVector SplitRules(const NoString& sRules) const;
    NoString JoinRules(const NoString& sSeparator) const;
    bool TestRules(const NoString& sTarget) const;

    void PutLog(const NoString& sLine, const NoString& sWindow = "status");
    void PutLog(const NoString& sLine, const NoChannel& Channel);
    void PutLog(const NoString& sLine, const NoNick& Nick);
    NoString GetServer();

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override;
    void onIrcConnected() override;
    void onIrcDisconnected() override;
    ModRet onBroadcast(NoString& sMessage) override;

    void onRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs) override;
    void onKick(const NoNick& OpNick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage) override;
    void onQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans) override;
    void onJoin(const NoNick& Nick, NoChannel& Channel) override;
    void onPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage) override;
    void onNick(const NoNick& OldNick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans) override;
    ModRet onTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic) override;

    /* notices */
    ModRet onUserNotice(NoString& sTarget, NoString& sMessage) override;
    ModRet onPrivNotice(NoNick& Nick, NoString& sMessage) override;
    ModRet onChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override;

    /* actions */
    ModRet onUserAction(NoString& sTarget, NoString& sMessage) override;
    ModRet onPrivAction(NoNick& Nick, NoString& sMessage) override;
    ModRet onChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override;

    /* msgs */
    ModRet onUserMsg(NoString& sTarget, NoString& sMessage) override;
    ModRet onPrivMsg(NoNick& Nick, NoString& sMessage) override;
    ModRet onChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override;

private:
    NoString m_sLogPath;
    bool m_bSanitize;
    std::vector<NoLogRule> m_vRules;
};

void NoLogMod::SetRulesCmd(const NoString& sLine)
{
    NoStringVector vsRules = SplitRules(No::tokens(sLine, 1));

    if (vsRules.empty()) {
        PutModule("Usage: SetRules <rules>");
        PutModule("Wildcards are allowed");
    } else {
        SetRules(vsRules);
        NoRegistry registry(this);
        registry.setValue("rules", JoinRules(","));
        ListRulesCmd();
    }
}

void NoLogMod::ClearRulesCmd(const NoString& sLine)
{
    size_t uCount = m_vRules.size();

    if (uCount == 0) {
        PutModule("No logging rules. Everything is logged.");
    } else {
        NoString sRules = JoinRules(" ");
        SetRules(NoStringVector());
        NoRegistry registry(this);
        registry.remove("rules");
        PutModule(NoString(uCount) + " rule(s) removed: " + sRules);
    }
}

void NoLogMod::ListRulesCmd(const NoString& sLine)
{
    NoTable Table;
    Table.addColumn("Rule");
    Table.addColumn("Logging enabled");

    for (const NoLogRule& Rule : m_vRules) {
        Table.addRow();
        Table.setValue("Rule", Rule.GetRule());
        Table.setValue("Logging enabled", NoString(Rule.IsEnabled()));
    }

    if (Table.isEmpty()) {
        PutModule("No logging rules. Everything is logged.");
    } else {
        PutModule(Table);
    }
}

void NoLogMod::SetRules(const NoStringVector& vsRules)
{
    m_vRules.clear();

    for (NoString sRule : vsRules) {
        bool bEnabled = !sRule.trimPrefix("!");
        m_vRules.push_back(NoLogRule(sRule, bEnabled));
    }
}

NoStringVector NoLogMod::SplitRules(const NoString& sRules) const
{
    NoString sCopy = sRules;
    sCopy.replace(",", " ");

    NoStringVector vsRules = sCopy.split(" ", No::SkipEmptyParts);

    return vsRules;
}

NoString NoLogMod::JoinRules(const NoString& sSeparator) const
{
    NoStringVector vsRules;
    for (const NoLogRule& Rule : m_vRules) {
        vsRules.push_back(Rule.ToString());
    }

    return sSeparator.join(vsRules.begin(), vsRules.end());
}

bool NoLogMod::TestRules(const NoString& sTarget) const
{
    for (const NoLogRule& Rule : m_vRules) {
        if (Rule.Compare(sTarget)) {
            return Rule.IsEnabled();
        }
    }

    return true;
}

void NoLogMod::PutLog(const NoString& sLine, const NoString& sWindow /*= "Status"*/)
{
    if (!TestRules(sWindow)) {
        return;
    }

    NoString sPath;
    time_t curtime;

    time(&curtime);
    // Generate file name
    sPath = No::formatTime(curtime, m_sLogPath, GetUser()->timezone());
    if (sPath.empty()) {
        NO_DEBUG("Could not format log path [" << sPath << "]");
        return;
    }

    // TODO: Properly handle IRC case mapping
    // $WINDOW has to be handled last, since it can contain %
    sPath.replace("$USER", NoString((GetUser() ? GetUser()->userName() : "UNKNOWN")).toLower());
    sPath.replace("$NETWORK", NoString((GetNetwork() ? GetNetwork()->name() : "znc")).toLower());
    sPath.replace("$WINDOW", NoString(sWindow.replace_n("/", "-").replace_n("\\", "-")).toLower());

    // Check if it's allowed to write in this specific path
    sPath = NoDir::CheckPathPrefix(GetSavePath(), sPath);
    if (sPath.empty()) {
        NO_DEBUG("Invalid log path [" << m_sLogPath << "].");
        return;
    }

    NoFile LogFile(sPath);
    NoString sLogDir = LogFile.GetDir();
    struct stat ModDirInfo;
    NoFile::GetInfo(GetSavePath(), ModDirInfo);
    if (!NoFile::Exists(sLogDir)) NoDir::MakeDir(sLogDir, ModDirInfo.st_mode);
    if (LogFile.Open(O_WRONLY | O_APPEND | O_CREAT)) {
        LogFile.Write(No::formatTime(curtime, "[%H:%M:%S] ", GetUser()->timezone()) +
                      (m_bSanitize ? No::stripControls(sLine) : sLine) + "\n");
    } else
        NO_DEBUG("Could not open log file [" << sPath << "]: " << strerror(errno));
}

void NoLogMod::PutLog(const NoString& sLine, const NoChannel& Channel) { PutLog(sLine, Channel.name()); }

void NoLogMod::PutLog(const NoString& sLine, const NoNick& Nick) { PutLog(sLine, Nick.nick()); }

NoString NoLogMod::GetServer()
{
    NoServerInfo* pServer = GetNetwork()->currentServer();
    NoString sSSL;

    if (!pServer) return "(no server)";

    if (pServer->isSsl()) sSSL = "+";
    return pServer->host() + " " + sSSL + NoString(pServer->port());
}

bool NoLogMod::OnLoad(const NoString& sArgs, NoString& sMessage)
{
    size_t uIndex = 0;
    if (No::token(sArgs, 0).equals("-sanitize")) {
        m_bSanitize = true;
        ++uIndex;
    }

    // Use load parameter as save path
    m_sLogPath = No::token(sArgs, uIndex);

    // Add default filename to path if it's a folder
    if (GetType() == No::UserModule) {
        if (m_sLogPath.right(1) == "/" || !m_sLogPath.contains("$WINDOW") || !m_sLogPath.contains("$NETWORK")) {
            if (!m_sLogPath.empty()) {
                m_sLogPath += "/";
            }
            m_sLogPath += "$NETWORK/$WINDOW/%Y-%m-%d.log";
        }
    } else if (GetType() == No::NetworkModule) {
        if (m_sLogPath.right(1) == "/" || !m_sLogPath.contains("$WINDOW")) {
            if (!m_sLogPath.empty()) {
                m_sLogPath += "/";
            }
            m_sLogPath += "$WINDOW/%Y-%m-%d.log";
        }
    } else {
        if (m_sLogPath.right(1) == "/" || !m_sLogPath.contains("$USER") ||
            !m_sLogPath.contains("$WINDOW") || !m_sLogPath.contains("$NETWORK")) {
            if (!m_sLogPath.empty()) {
                m_sLogPath += "/";
            }
            m_sLogPath += "$USER/$NETWORK/$WINDOW/%Y-%m-%d.log";
        }
    }

    NoRegistry registry(this);
    NoString sRules = registry.value("rules");
    NoStringVector vsRules = SplitRules(sRules);
    SetRules(vsRules);

    // Check if it's allowed to write in this path in general
    m_sLogPath = NoDir::CheckPathPrefix(GetSavePath(), m_sLogPath);
    if (m_sLogPath.empty()) {
        sMessage = "Invalid log path [" + m_sLogPath + "].";
        return false;
    } else {
        sMessage = "Logging to [" + m_sLogPath + "].";
        return true;
    }
}


void NoLogMod::onIrcConnected() { PutLog("Connected to IRC (" + GetServer() + ")"); }

void NoLogMod::onIrcDisconnected() { PutLog("Disconnected from IRC (" + GetServer() + ")"); }

NoModule::ModRet NoLogMod::onBroadcast(NoString& sMessage)
{
    PutLog("Broadcast: " + sMessage);
    return CONTINUE;
}

void NoLogMod::onRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs)
{
    const NoString sNick = pOpNick ? pOpNick->nick() : "Server";
    PutLog("*** " + sNick + " sets mode: " + sModes + " " + sArgs, Channel);
}

void NoLogMod::onKick(const NoNick& OpNick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage)
{
    PutLog("*** " + sKickedNick + " was kicked by " + OpNick.nick() + " (" + sMessage + ")", Channel);
}

void NoLogMod::onQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans)
{
    for (std::vector<NoChannel*>::const_iterator pChan = vChans.begin(); pChan != vChans.end(); ++pChan)
        PutLog("*** Quits: " + Nick.nick() + " (" + Nick.ident() + "@" + Nick.host() + ") (" + sMessage + ")", **pChan);
}

void NoLogMod::onJoin(const NoNick& Nick, NoChannel& Channel)
{
    PutLog("*** Joins: " + Nick.nick() + " (" + Nick.ident() + "@" + Nick.host() + ")", Channel);
}

void NoLogMod::onPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage)
{
    PutLog("*** Parts: " + Nick.nick() + " (" + Nick.ident() + "@" + Nick.host() + ") (" + sMessage + ")", Channel);
}

void NoLogMod::onNick(const NoNick& OldNick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans)
{
    for (std::vector<NoChannel*>::const_iterator pChan = vChans.begin(); pChan != vChans.end(); ++pChan)
        PutLog("*** " + OldNick.nick() + " is now known as " + sNewNick, **pChan);
}

NoModule::ModRet NoLogMod::onTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic)
{
    PutLog("*** " + Nick.nick() + " changes topic to '" + sTopic + "'", Channel);
    return CONTINUE;
}

/* notices */
NoModule::ModRet NoLogMod::onUserNotice(NoString& sTarget, NoString& sMessage)
{
    NoNetwork* pNetwork = GetNetwork();
    if (pNetwork) {
        PutLog("-" + pNetwork->currentNick() + "- " + sMessage, sTarget);
    }

    return CONTINUE;
}

NoModule::ModRet NoLogMod::onPrivNotice(NoNick& Nick, NoString& sMessage)
{
    PutLog("-" + Nick.nick() + "- " + sMessage, Nick);
    return CONTINUE;
}

NoModule::ModRet NoLogMod::onChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    PutLog("-" + Nick.nick() + "- " + sMessage, Channel);
    return CONTINUE;
}

/* actions */
NoModule::ModRet NoLogMod::onUserAction(NoString& sTarget, NoString& sMessage)
{
    NoNetwork* pNetwork = GetNetwork();
    if (pNetwork) {
        PutLog("* " + pNetwork->currentNick() + " " + sMessage, sTarget);
    }

    return CONTINUE;
}

NoModule::ModRet NoLogMod::onPrivAction(NoNick& Nick, NoString& sMessage)
{
    PutLog("* " + Nick.nick() + " " + sMessage, Nick);
    return CONTINUE;
}

NoModule::ModRet NoLogMod::onChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    PutLog("* " + Nick.nick() + " " + sMessage, Channel);
    return CONTINUE;
}

/* msgs */
NoModule::ModRet NoLogMod::onUserMsg(NoString& sTarget, NoString& sMessage)
{
    NoNetwork* pNetwork = GetNetwork();
    if (pNetwork) {
        PutLog("<" + pNetwork->currentNick() + "> " + sMessage, sTarget);
    }

    return CONTINUE;
}

NoModule::ModRet NoLogMod::onPrivMsg(NoNick& Nick, NoString& sMessage)
{
    PutLog("<" + Nick.nick() + "> " + sMessage, Nick);
    return CONTINUE;
}

NoModule::ModRet NoLogMod::onChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    PutLog("<" + Nick.nick() + "> " + sMessage, Channel);
    return CONTINUE;
}

template <> void no_moduleInfo<NoLogMod>(NoModuleInfo& Info)
{
    Info.AddType(No::NetworkModule);
    Info.AddType(No::GlobalModule);
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("[-sanitize] Optional path where to store logs.");
    Info.SetWikiPage("log");
}

USERMODULEDEFS(NoLogMod, "Write IRC logs.")
