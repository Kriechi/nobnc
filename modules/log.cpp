/*
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

#include <no/nodir.h>
#include <no/nofile.h>
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/nochannel.h>
#include <no/noserver.h>
#include <algorithm>

class NoLogRule
{
public:
    NoLogRule(const NoString& sRule, bool bEnabled = true) : m_sRule(sRule), m_bEnabled(bEnabled) {}

    const NoString& GetRule() const { return m_sRule; }
    bool IsEnabled() const { return m_bEnabled; }
    void SetEnabled(bool bEnabled) { m_bEnabled = bEnabled; }

    bool Compare(const NoString& sTarget) const { return sTarget.WildCmp(m_sRule, NoString::CaseInsensitive); }

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
                   static_cast<NoModCommand::ModCmdFunc>(&NoLogMod::SetRulesCmd),
                   "<rules>",
                   "Set logging rules, use !#chan or !query to negate and * for wildcards");
        AddCommand("ClearRules",
                   static_cast<NoModCommand::ModCmdFunc>(&NoLogMod::ClearRulesCmd),
                   "",
                   "Clear all logging rules");
        AddCommand("ListRules",
                   static_cast<NoModCommand::ModCmdFunc>(&NoLogMod::ListRulesCmd),
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
    void OnIRCConnected() override;
    void OnIRCDisconnected() override;
    EModRet OnBroadcast(NoString& sMessage) override;

    void OnRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs) override;
    void OnKick(const NoNick& OpNick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage) override;
    void OnQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans) override;
    void OnJoin(const NoNick& Nick, NoChannel& Channel) override;
    void OnPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage) override;
    void OnNick(const NoNick& OldNick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans) override;
    EModRet OnTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic) override;

    /* notices */
    EModRet OnUserNotice(NoString& sTarget, NoString& sMessage) override;
    EModRet OnPrivNotice(NoNick& Nick, NoString& sMessage) override;
    EModRet OnChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override;

    /* actions */
    EModRet OnUserAction(NoString& sTarget, NoString& sMessage) override;
    EModRet OnPrivAction(NoNick& Nick, NoString& sMessage) override;
    EModRet OnChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override;

    /* msgs */
    EModRet OnUserMsg(NoString& sTarget, NoString& sMessage) override;
    EModRet OnPrivMsg(NoNick& Nick, NoString& sMessage) override;
    EModRet OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override;

private:
    NoString m_sLogPath;
    bool m_bSanitize;
    std::vector<NoLogRule> m_vRules;
};

void NoLogMod::SetRulesCmd(const NoString& sLine)
{
    NoStringVector vsRules = SplitRules(sLine.Token(1, true));

    if (vsRules.empty()) {
        PutModule("Usage: SetRules <rules>");
        PutModule("Wildcards are allowed");
    } else {
        SetRules(vsRules);
        SetNV("rules", JoinRules(","));
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
        DelNV("rules");
        PutModule(NoString(uCount) + " rule(s) removed: " + sRules);
    }
}

void NoLogMod::ListRulesCmd(const NoString& sLine)
{
    NoTable Table;
    Table.AddColumn("Rule");
    Table.AddColumn("Logging enabled");

    for (const NoLogRule& Rule : m_vRules) {
        Table.AddRow();
        Table.SetCell("Rule", Rule.GetRule());
        Table.SetCell("Logging enabled", NoString(Rule.IsEnabled()));
    }

    if (Table.empty()) {
        PutModule("No logging rules. Everything is logged.");
    } else {
        PutModule(Table);
    }
}

void NoLogMod::SetRules(const NoStringVector& vsRules)
{
    m_vRules.clear();

    for (NoString sRule : vsRules) {
        bool bEnabled = !sRule.TrimPrefix("!");
        m_vRules.push_back(NoLogRule(sRule, bEnabled));
    }
}

NoStringVector NoLogMod::SplitRules(const NoString& sRules) const
{
    NoString sCopy = sRules;
    sCopy.Replace(",", " ");

    NoStringVector vsRules;
    sCopy.Split(" ", vsRules, false, "", "", true, true);

    return vsRules;
}

NoString NoLogMod::JoinRules(const NoString& sSeparator) const
{
    NoStringVector vsRules;
    for (const NoLogRule& Rule : m_vRules) {
        vsRules.push_back(Rule.ToString());
    }

    return sSeparator.Join(vsRules.begin(), vsRules.end());
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
    sPath = NoUtils::FormatTime(curtime, m_sLogPath, GetUser()->GetTimezone());
    if (sPath.empty()) {
        DEBUG("Could not format log path [" << sPath << "]");
        return;
    }

    // TODO: Properly handle IRC case mapping
    // $WINDOW has to be handled last, since it can contain %
    sPath.Replace("$USER", NoString((GetUser() ? GetUser()->GetUserName() : "UNKNOWN")).AsLower());
    sPath.Replace("$NETWORK", NoString((GetNetwork() ? GetNetwork()->GetName() : "znc")).AsLower());
    sPath.Replace("$WINDOW", NoString(sWindow.Replace_n("/", "-").Replace_n("\\", "-")).AsLower());

    // Check if it's allowed to write in this specific path
    sPath = NoDir::CheckPathPrefix(GetSavePath(), sPath);
    if (sPath.empty()) {
        DEBUG("Invalid log path [" << m_sLogPath << "].");
        return;
    }

    NoFile LogFile(sPath);
    NoString sLogDir = LogFile.GetDir();
    struct stat ModDirInfo;
    NoFile::GetInfo(GetSavePath(), ModDirInfo);
    if (!NoFile::Exists(sLogDir)) NoDir::MakeDir(sLogDir, ModDirInfo.st_mode);
    if (LogFile.Open(O_WRONLY | O_APPEND | O_CREAT)) {
        LogFile.Write(NoUtils::FormatTime(curtime, "[%H:%M:%S] ", GetUser()->GetTimezone()) +
                      (m_bSanitize ? sLine.StripControls_n() : sLine) + "\n");
    } else
        DEBUG("Could not open log file [" << sPath << "]: " << strerror(errno));
}

void NoLogMod::PutLog(const NoString& sLine, const NoChannel& Channel) { PutLog(sLine, Channel.getName()); }

void NoLogMod::PutLog(const NoString& sLine, const NoNick& Nick) { PutLog(sLine, Nick.nick()); }

NoString NoLogMod::GetServer()
{
    NoServer* pServer = GetNetwork()->GetCurrentServer();
    NoString sSSL;

    if (!pServer) return "(no server)";

    if (pServer->IsSSL()) sSSL = "+";
    return pServer->GetName() + " " + sSSL + NoString(pServer->GetPort());
}

bool NoLogMod::OnLoad(const NoString& sArgs, NoString& sMessage)
{
    size_t uIndex = 0;
    if (sArgs.Token(0).Equals("-sanitize")) {
        m_bSanitize = true;
        ++uIndex;
    }

    // Use load parameter as save path
    m_sLogPath = sArgs.Token(uIndex);

    // Add default filename to path if it's a folder
    if (GetType() == NoModInfo::UserModule) {
        if (m_sLogPath.Right(1) == "/" || m_sLogPath.find("$WINDOW") == NoString::npos || m_sLogPath.find("$NETWORK") == NoString::npos) {
            if (!m_sLogPath.empty()) {
                m_sLogPath += "/";
            }
            m_sLogPath += "$NETWORK/$WINDOW/%Y-%m-%d.log";
        }
    } else if (GetType() == NoModInfo::NetworkModule) {
        if (m_sLogPath.Right(1) == "/" || m_sLogPath.find("$WINDOW") == NoString::npos) {
            if (!m_sLogPath.empty()) {
                m_sLogPath += "/";
            }
            m_sLogPath += "$WINDOW/%Y-%m-%d.log";
        }
    } else {
        if (m_sLogPath.Right(1) == "/" || m_sLogPath.find("$USER") == NoString::npos ||
            m_sLogPath.find("$WINDOW") == NoString::npos || m_sLogPath.find("$NETWORK") == NoString::npos) {
            if (!m_sLogPath.empty()) {
                m_sLogPath += "/";
            }
            m_sLogPath += "$USER/$NETWORK/$WINDOW/%Y-%m-%d.log";
        }
    }

    NoString sRules = GetNV("rules");
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


void NoLogMod::OnIRCConnected() { PutLog("Connected to IRC (" + GetServer() + ")"); }

void NoLogMod::OnIRCDisconnected() { PutLog("Disconnected from IRC (" + GetServer() + ")"); }

NoModule::EModRet NoLogMod::OnBroadcast(NoString& sMessage)
{
    PutLog("Broadcast: " + sMessage);
    return CONTINUE;
}

void NoLogMod::OnRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs)
{
    const NoString sNick = pOpNick ? pOpNick->nick() : "Server";
    PutLog("*** " + sNick + " sets mode: " + sModes + " " + sArgs, Channel);
}

void NoLogMod::OnKick(const NoNick& OpNick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage)
{
    PutLog("*** " + sKickedNick + " was kicked by " + OpNick.nick() + " (" + sMessage + ")", Channel);
}

void NoLogMod::OnQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans)
{
    for (std::vector<NoChannel*>::const_iterator pChan = vChans.begin(); pChan != vChans.end(); ++pChan)
        PutLog("*** Quits: " + Nick.nick() + " (" + Nick.ident() + "@" + Nick.host() + ") (" + sMessage + ")", **pChan);
}

void NoLogMod::OnJoin(const NoNick& Nick, NoChannel& Channel)
{
    PutLog("*** Joins: " + Nick.nick() + " (" + Nick.ident() + "@" + Nick.host() + ")", Channel);
}

void NoLogMod::OnPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage)
{
    PutLog("*** Parts: " + Nick.nick() + " (" + Nick.ident() + "@" + Nick.host() + ") (" + sMessage + ")", Channel);
}

void NoLogMod::OnNick(const NoNick& OldNick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans)
{
    for (std::vector<NoChannel*>::const_iterator pChan = vChans.begin(); pChan != vChans.end(); ++pChan)
        PutLog("*** " + OldNick.nick() + " is now known as " + sNewNick, **pChan);
}

NoModule::EModRet NoLogMod::OnTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic)
{
    PutLog("*** " + Nick.nick() + " changes topic to '" + sTopic + "'", Channel);
    return CONTINUE;
}

/* notices */
NoModule::EModRet NoLogMod::OnUserNotice(NoString& sTarget, NoString& sMessage)
{
    NoNetwork* pNetwork = GetNetwork();
    if (pNetwork) {
        PutLog("-" + pNetwork->GetCurNick() + "- " + sMessage, sTarget);
    }

    return CONTINUE;
}

NoModule::EModRet NoLogMod::OnPrivNotice(NoNick& Nick, NoString& sMessage)
{
    PutLog("-" + Nick.nick() + "- " + sMessage, Nick);
    return CONTINUE;
}

NoModule::EModRet NoLogMod::OnChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    PutLog("-" + Nick.nick() + "- " + sMessage, Channel);
    return CONTINUE;
}

/* actions */
NoModule::EModRet NoLogMod::OnUserAction(NoString& sTarget, NoString& sMessage)
{
    NoNetwork* pNetwork = GetNetwork();
    if (pNetwork) {
        PutLog("* " + pNetwork->GetCurNick() + " " + sMessage, sTarget);
    }

    return CONTINUE;
}

NoModule::EModRet NoLogMod::OnPrivAction(NoNick& Nick, NoString& sMessage)
{
    PutLog("* " + Nick.nick() + " " + sMessage, Nick);
    return CONTINUE;
}

NoModule::EModRet NoLogMod::OnChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    PutLog("* " + Nick.nick() + " " + sMessage, Channel);
    return CONTINUE;
}

/* msgs */
NoModule::EModRet NoLogMod::OnUserMsg(NoString& sTarget, NoString& sMessage)
{
    NoNetwork* pNetwork = GetNetwork();
    if (pNetwork) {
        PutLog("<" + pNetwork->GetCurNick() + "> " + sMessage, sTarget);
    }

    return CONTINUE;
}

NoModule::EModRet NoLogMod::OnPrivMsg(NoNick& Nick, NoString& sMessage)
{
    PutLog("<" + Nick.nick() + "> " + sMessage, Nick);
    return CONTINUE;
}

NoModule::EModRet NoLogMod::OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    PutLog("<" + Nick.nick() + "> " + sMessage, Channel);
    return CONTINUE;
}

template <> void TModInfo<NoLogMod>(NoModInfo& Info)
{
    Info.AddType(NoModInfo::NetworkModule);
    Info.AddType(NoModInfo::GlobalModule);
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("[-sanitize] Optional path where to store logs.");
    Info.SetWikiPage("log");
}

USERMODULEDEFS(NoLogMod, "Write IRC logs.")
