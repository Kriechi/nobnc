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

#include "nomodule.h"
#include "nodir.h"
#include "notemplate.h"
#include "nouser.h"
#include "nonetwork.h"
#include "nowebmodules.h"
#include "noapp.h"
#include <dlfcn.h>

using std::map;
using std::set;
using std::vector;

NoModule::NoModule(ModHandle pDLL, NoUser* pUser, NoNetwork* pNetwork, const NoString& sModName, const NoString& sDataDir, NoModInfo::EModuleType eType)
    : m_eType(eType), m_sDescription(""), m_sTimers(), m_sSockets(),
#ifdef HAVE_PTHREAD
      m_sJobs(),
#endif
      m_pDLL(pDLL), m_pManager(&(NoApp::Get().GetManager())), m_pUser(pUser), m_pNetwork(pNetwork), m_pClient(nullptr),
      m_sModName(sModName), m_sDataDir(sDataDir), m_sSavePath(""), m_sArgs(""), m_sModPath(""), m_mssRegistry(),
      m_vSubPages(), m_mCommands()
{
    if (m_pNetwork) {
        m_sSavePath = m_pNetwork->GetNetworkPath() + "/moddata/" + m_sModName;
    } else if (m_pUser) {
        m_sSavePath = m_pUser->GetUserPath() + "/moddata/" + m_sModName;
    } else {
        m_sSavePath = NoApp::Get().GetZNCPath() + "/moddata/" + m_sModName;
    }
    LoadRegistry();
}

NoModule::~NoModule()
{
    while (!m_sTimers.empty()) {
        RemTimer(*m_sTimers.begin());
    }

    while (!m_sSockets.empty()) {
        RemSocket(*m_sSockets.begin());
    }

    SaveRegistry();

#ifdef HAVE_PTHREAD
    CancelJobs(m_sJobs);
#endif
}

void NoModule::SetUser(NoUser* pUser) { m_pUser = pUser; }
void NoModule::SetNetwork(NoNetwork* pNetwork) { m_pNetwork = pNetwork; }
void NoModule::SetClient(NoClient* pClient) { m_pClient = pClient; }

NoString NoModule::ExpandString(const NoString& sStr) const
{
    NoString sRet;
    return ExpandString(sStr, sRet);
}

NoString& NoModule::ExpandString(const NoString& sStr, NoString& sRet) const
{
    sRet = sStr;

    if (m_pNetwork) {
        return m_pNetwork->ExpandString(sRet, sRet);
    }

    if (m_pUser) {
        return m_pUser->ExpandString(sRet, sRet);
    }

    return sRet;
}

const NoString& NoModule::GetSavePath() const
{
    if (!NoFile::Exists(m_sSavePath)) {
        NoDir::MakeDir(m_sSavePath);
    }
    return m_sSavePath;
}

NoString NoModule::GetWebPath()
{
    switch (m_eType) {
    case NoModInfo::GlobalModule:
        return "/mods/global/" + GetModName() + "/";
    case NoModInfo::UserModule:
        return "/mods/user/" + GetModName() + "/";
    case NoModInfo::NetworkModule:
        return "/mods/network/" + m_pNetwork->GetName() + "/" + GetModName() + "/";
    default:
        return "/";
    }
}

NoString NoModule::GetWebFilesPath()
{
    switch (m_eType) {
    case NoModInfo::GlobalModule:
        return "/modfiles/global/" + GetModName() + "/";
    case NoModInfo::UserModule:
        return "/modfiles/user/" + GetModName() + "/";
    case NoModInfo::NetworkModule:
        return "/modfiles/network/" + m_pNetwork->GetName() + "/" + GetModName() + "/";
    default:
        return "/";
    }
}

bool NoModule::LoadRegistry()
{
    // NoString sPrefix = (m_pUser) ? m_pUser->GetUserName() : ".global";
    return (m_mssRegistry.ReadFromDisk(GetSavePath() + "/.registry") == NoStringMap::MCS_SUCCESS);
}

bool NoModule::SaveRegistry() const
{
    // NoString sPrefix = (m_pUser) ? m_pUser->GetUserName() : ".global";
    return (m_mssRegistry.WriteToDisk(GetSavePath() + "/.registry", 0600) == NoStringMap::MCS_SUCCESS);
}

bool NoModule::MoveRegistry(const NoString& sPath)
{
    if (m_sSavePath != sPath) {
        NoFile fOldNVFile = NoFile(m_sSavePath + "/.registry");
        if (!fOldNVFile.Exists()) {
            return false;
        }
        if (!NoFile::Exists(sPath) && !NoDir::MakeDir(sPath)) {
            return false;
        }
        fOldNVFile.Copy(sPath + "/.registry");
        m_sSavePath = sPath;
        return true;
    }
    return false;
}

bool NoModule::SetNV(const NoString& sName, const NoString& sValue, bool bWriteToDisk)
{
    m_mssRegistry[sName] = sValue;
    if (bWriteToDisk) {
        return SaveRegistry();
    }

    return true;
}

NoString NoModule::GetNV(const NoString& sName) const
{
    NoStringMap::const_iterator it = m_mssRegistry.find(sName);

    if (it != m_mssRegistry.end()) {
        return it->second;
    }

    return "";
}

bool NoModule::DelNV(const NoString& sName, bool bWriteToDisk)
{
    NoStringMap::iterator it = m_mssRegistry.find(sName);

    if (it != m_mssRegistry.end()) {
        m_mssRegistry.erase(it);
    } else {
        return false;
    }

    if (bWriteToDisk) {
        return SaveRegistry();
    }

    return true;
}

bool NoModule::ClearNV(bool bWriteToDisk)
{
    m_mssRegistry.clear();

    if (bWriteToDisk) {
        return SaveRegistry();
    }
    return true;
}

bool NoModule::AddTimer(NoTimer* pTimer)
{
    if ((!pTimer) || (!pTimer->GetName().empty() && FindTimer(pTimer->GetName()))) {
        delete pTimer;
        return false;
    }

    if (!m_sTimers.insert(pTimer).second)
        // Was already added
        return true;

    m_pManager->AddCron(pTimer);
    return true;
}

bool NoModule::AddTimer(FPTimer_t pFBCallback, const NoString& sLabel, u_int uInterval, u_int uCycles, const NoString& sDescription)
{
    NoFPTimer* pTimer = new NoFPTimer(this, uInterval, uCycles, sLabel, sDescription);
    pTimer->SetFPCallback(pFBCallback);

    return AddTimer(pTimer);
}

bool NoModule::RemTimer(NoTimer* pTimer)
{
    if (m_sTimers.erase(pTimer) == 0) return false;
    m_pManager->DelCronByAddr(pTimer);
    return true;
}

bool NoModule::RemTimer(const NoString& sLabel)
{
    NoTimer* pTimer = FindTimer(sLabel);
    if (!pTimer) return false;
    return RemTimer(pTimer);
}

bool NoModule::UnlinkTimer(NoTimer* pTimer) { return m_sTimers.erase(pTimer); }

NoTimer* NoModule::FindTimer(const NoString& sLabel)
{
    if (sLabel.empty()) {
        return nullptr;
    }

    for (NoTimer* pTimer : m_sTimers) {
        if (pTimer->GetName().Equals(sLabel)) {
            return pTimer;
        }
    }

    return nullptr;
}

void NoModule::ListTimers()
{
    if (m_sTimers.empty()) {
        PutModule("You have no timers running.");
        return;
    }

    NoTable Table;
    Table.AddColumn("Name");
    Table.AddColumn("Secs");
    Table.AddColumn("Cycles");
    Table.AddColumn("Description");

    for (const NoTimer* pTimer : m_sTimers) {
        unsigned int uCycles = pTimer->GetCyclesLeft();
        timeval Interval = pTimer->GetInterval();

        Table.AddRow();
        Table.SetCell("Name", pTimer->GetName());
        Table.SetCell("Secs",
                      NoString(Interval.tv_sec) + "seconds" +
                      (Interval.tv_usec ? " " + NoString(Interval.tv_usec) + " microseconds" : ""));
        Table.SetCell("Cycles", ((uCycles) ? NoString(uCycles) : "INF"));
        Table.SetCell("Description", pTimer->GetDescription());
    }

    PutModule(Table);
}

bool NoModule::AddSocket(NoSocket* pSocket)
{
    if (!pSocket) {
        return false;
    }

    m_sSockets.insert(pSocket);
    return true;
}

bool NoModule::RemSocket(NoSocket* pSocket)
{
    if (m_sSockets.erase(pSocket)) {
        m_pManager->DelSockByAddr(pSocket);
        return true;
    }

    return false;
}

bool NoModule::RemSocket(const NoString& sSockName)
{
    for (NoSocket* pSocket : m_sSockets) {
        if (pSocket->GetSockName().Equals(sSockName)) {
            m_sSockets.erase(pSocket);
            m_pManager->DelSockByAddr(pSocket);
            return true;
        }
    }

    return false;
}

bool NoModule::UnlinkSocket(NoSocket* pSocket) { return m_sSockets.erase(pSocket); }

NoSocket* NoModule::FindSocket(const NoString& sSockName)
{
    for (NoSocket* pSocket : m_sSockets) {
        if (pSocket->GetSockName().Equals(sSockName)) {
            return pSocket;
        }
    }

    return nullptr;
}

void NoModule::ListSockets()
{
    if (m_sSockets.empty()) {
        PutModule("You have no open sockets.");
        return;
    }

    NoTable Table;
    Table.AddColumn("Name");
    Table.AddColumn("State");
    Table.AddColumn("LocalPort");
    Table.AddColumn("SSL");
    Table.AddColumn("RemoteIP");
    Table.AddColumn("RemotePort");

    for (const NoSocket* pSocket : m_sSockets) {
        Table.AddRow();
        Table.SetCell("Name", pSocket->GetSockName());

        if (pSocket->GetType() == NoSocket::LISTENER) {
            Table.SetCell("State", "Listening");
        } else {
            Table.SetCell("State", (pSocket->IsConnected() ? "Connected" : ""));
        }

        Table.SetCell("LocalPort", NoString(pSocket->GetLocalPort()));
        Table.SetCell("SSL", (pSocket->GetSSL() ? "yes" : "no"));
        Table.SetCell("RemoteIP", pSocket->GetRemoteIP());
        Table.SetCell("RemotePort", (pSocket->GetRemotePort()) ? NoString(pSocket->GetRemotePort()) : NoString(""));
    }

    PutModule(Table);
}

#ifdef HAVE_PTHREAD
NoModuleJob::~NoModuleJob() { m_pModule->UnlinkJob(this); }

void NoModule::AddJob(NoModuleJob* pJob)
{
    NoThreadPool::Get().addJob(pJob);
    m_sJobs.insert(pJob);
}

void NoModule::CancelJob(NoModuleJob* pJob)
{
    if (pJob == nullptr) return;
    // Destructor calls UnlinkJob and removes the job from m_sJobs
    NoThreadPool::Get().cancelJob(pJob);
}

bool NoModule::CancelJob(const NoString& sJobName)
{
    for (NoModuleJob* pJob : m_sJobs) {
        if (pJob->GetName().Equals(sJobName)) {
            CancelJob(pJob);
            return true;
        }
    }
    return false;
}

void NoModule::CancelJobs(const std::set<NoModuleJob*>& sJobs)
{
    set<NoJob*> sPlainJobs(sJobs.begin(), sJobs.end());

    // Destructor calls UnlinkJob and removes the jobs from m_sJobs
    NoThreadPool::Get().cancelJobs(sPlainJobs);
}

bool NoModule::UnlinkJob(NoModuleJob* pJob) { return 0 != m_sJobs.erase(pJob); }
#endif

bool NoModule::AddCommand(const NoModCommand& Command)
{
    if (Command.GetFunction() == nullptr) return false;
    if (Command.GetCommand().find(' ') != NoString::npos) return false;
    if (FindCommand(Command.GetCommand()) != nullptr) return false;

    m_mCommands[Command.GetCommand()] = Command;
    return true;
}

bool NoModule::AddCommand(const NoString& sCmd, NoModCommand::ModCmdFunc func, const NoString& sArgs, const NoString& sDesc)
{
    NoModCommand cmd(sCmd, this, func, sArgs, sDesc);
    return AddCommand(cmd);
}

bool NoModule::AddCommand(const NoString& sCmd, const NoString& sArgs, const NoString& sDesc, std::function<void(const NoString& sLine)> func)
{
    NoModCommand cmd(sCmd, std::move(func), sArgs, sDesc);
    return AddCommand(std::move(cmd));
}

void NoModule::AddHelpCommand() { AddCommand("Help", &NoModule::HandleHelpCommand, "search", "Generate this output"); }

bool NoModule::RemCommand(const NoString& sCmd) { return m_mCommands.erase(sCmd) > 0; }

const NoModCommand* NoModule::FindCommand(const NoString& sCmd) const
{
    for (const auto& it : m_mCommands) {
        if (!it.first.Equals(sCmd)) continue;
        return &it.second;
    }
    return nullptr;
}

bool NoModule::HandleCommand(const NoString& sLine)
{
    const NoString& sCmd = sLine.Token(0);
    const NoModCommand* pCmd = FindCommand(sCmd);

    if (pCmd) {
        pCmd->Call(sLine);
        return true;
    }

    OnUnknownModCommand(sLine);

    return false;
}

void NoModule::HandleHelpCommand(const NoString& sLine)
{
    NoString sFilter = sLine.Token(1).AsLower();
    NoTable Table;

    NoModCommand::InitHelp(Table);
    for (const auto& it : m_mCommands) {
        NoString sCmd = it.second.GetCommand().AsLower();
        if (sFilter.empty() || (sCmd.StartsWith(sFilter, NoString::CaseSensitive)) || sCmd.WildCmp(sFilter)) {
            it.second.AddHelp(Table);
        }
    }
    if (Table.empty()) {
        PutModule("No matches for '" + sFilter + "'");
    } else {
        PutModule(Table);
    }
}

NoString NoModule::GetModNick() const { return ((m_pUser) ? m_pUser->GetStatusPrefix() : "*") + m_sModName; }

// Webmods
bool NoModule::OnWebPreRequest(NoWebSock& WebSock, const NoString& sPageName) { return false; }
bool NoModule::OnWebRequest(NoWebSock& WebSock, const NoString& sPageName, NoTemplate& Tmpl) { return false; }
bool NoModule::OnEmbeddedWebRequest(NoWebSock& WebSock, const NoString& sPageName, NoTemplate& Tmpl) { return false; }
// !Webmods

bool NoModule::OnLoad(const NoString& sArgs, NoString& sMessage)
{
    sMessage = "";
    return true;
}
bool NoModule::OnBoot() { return true; }
void NoModule::OnPreRehash() {}
void NoModule::OnPostRehash() {}
void NoModule::OnIRCDisconnected() {}
void NoModule::OnIRCConnected() {}
NoModule::EModRet NoModule::OnIRCConnecting(NoIrcSock* IRCSock) { return CONTINUE; }
void NoModule::OnIRCConnectionError(NoIrcSock* IRCSock) {}
NoModule::EModRet NoModule::OnIRCRegistration(NoString& sPass, NoString& sNick, NoString& sIdent, NoString& sRealName)
{
    return CONTINUE;
}
NoModule::EModRet NoModule::OnBroadcast(NoString& sMessage) { return CONTINUE; }

void NoModule::OnChanPermission2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, unsigned char uMode, bool bAdded, bool bNoChange)
{
    if (pOpNick) OnChanPermission(*pOpNick, Nick, Channel, uMode, bAdded, bNoChange);
}
void NoModule::OnOp2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    if (pOpNick) OnOp(*pOpNick, Nick, Channel, bNoChange);
}
void NoModule::OnDeop2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    if (pOpNick) OnDeop(*pOpNick, Nick, Channel, bNoChange);
}
void NoModule::OnVoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    if (pOpNick) OnVoice(*pOpNick, Nick, Channel, bNoChange);
}
void NoModule::OnDevoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    if (pOpNick) OnDevoice(*pOpNick, Nick, Channel, bNoChange);
}
void NoModule::OnRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs)
{
    if (pOpNick) OnRawMode(*pOpNick, Channel, sModes, sArgs);
}
void NoModule::OnMode2(const NoNick* pOpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange)
{
    if (pOpNick) OnMode(*pOpNick, Channel, uMode, sArg, bAdded, bNoChange);
}

void NoModule::OnChanPermission(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, unsigned char uMode, bool bAdded, bool bNoChange)
{
}
void NoModule::OnOp(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) {}
void NoModule::OnDeop(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) {}
void NoModule::OnVoice(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) {}
void NoModule::OnDevoice(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) {}
void NoModule::OnRawMode(const NoNick& pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs) {}
void NoModule::OnMode(const NoNick& pOpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange)
{
}

NoModule::EModRet NoModule::OnRaw(NoString& sLine) { return CONTINUE; }

NoModule::EModRet NoModule::OnStatusCommand(NoString& sCommand) { return CONTINUE; }
void NoModule::OnModNotice(const NoString& sMessage) {}
void NoModule::OnModCTCP(const NoString& sMessage) {}

void NoModule::OnModCommand(const NoString& sCommand) { HandleCommand(sCommand); }
void NoModule::OnUnknownModCommand(const NoString& sLine)
{
    if (m_mCommands.empty())
        // This function is only called if OnModCommand wasn't
        // overriden, so no false warnings for modules which don't use
        // NoModCommand for command handling.
        PutModule("This module doesn't implement any commands.");
    else
        PutModule("Unknown command!");
}

void NoModule::OnQuit(const NoNick& Nick, const NoString& sMessage, const vector<NoChannel*>& vChans) {}
void NoModule::OnNick(const NoNick& Nick, const NoString& sNewNick, const vector<NoChannel*>& vChans) {}
void NoModule::OnKick(const NoNick& Nick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage) {}
NoModule::EModRet NoModule::OnJoining(NoChannel& Channel) { return CONTINUE; }
void NoModule::OnJoin(const NoNick& Nick, NoChannel& Channel) {}
void NoModule::OnPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage) {}
NoModule::EModRet NoModule::OnInvite(const NoNick& Nick, const NoString& sChan) { return CONTINUE; }

NoModule::EModRet NoModule::OnChanBufferStarting(NoChannel& Chan, NoClient& Client) { return CONTINUE; }
NoModule::EModRet NoModule::OnChanBufferEnding(NoChannel& Chan, NoClient& Client) { return CONTINUE; }
NoModule::EModRet NoModule::OnChanBufferPlayLine(NoChannel& Chan, NoClient& Client, NoString& sLine) { return CONTINUE; }
NoModule::EModRet NoModule::OnPrivBufferPlayLine(NoClient& Client, NoString& sLine) { return CONTINUE; }

NoModule::EModRet NoModule::OnChanBufferPlayLine2(NoChannel& Chan, NoClient& Client, NoString& sLine, const timeval& tv)
{
    return OnChanBufferPlayLine(Chan, Client, sLine);
}
NoModule::EModRet NoModule::OnPrivBufferPlayLine2(NoClient& Client, NoString& sLine, const timeval& tv)
{
    return OnPrivBufferPlayLine(Client, sLine);
}

void NoModule::OnClientLogin() {}
void NoModule::OnClientDisconnect() {}
NoModule::EModRet NoModule::OnUserRaw(NoString& sLine) { return CONTINUE; }
NoModule::EModRet NoModule::OnUserCTCPReply(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnUserCTCP(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnUserAction(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnUserMsg(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnUserNotice(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnUserJoin(NoString& sChannel, NoString& sKey) { return CONTINUE; }
NoModule::EModRet NoModule::OnUserPart(NoString& sChannel, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnUserTopic(NoString& sChannel, NoString& sTopic) { return CONTINUE; }
NoModule::EModRet NoModule::OnUserTopicRequest(NoString& sChannel) { return CONTINUE; }
NoModule::EModRet NoModule::OnUserQuit(NoString& sMessage) { return CONTINUE; }

NoModule::EModRet NoModule::OnCTCPReply(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnPrivCTCP(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnChanCTCP(NoNick& Nick, NoChannel& Channel, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnPrivAction(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnPrivMsg(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnPrivNotice(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage) { return CONTINUE; }
NoModule::EModRet NoModule::OnTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic) { return CONTINUE; }
NoModule::EModRet NoModule::OnTimerAutoJoin(NoChannel& Channel) { return CONTINUE; }
NoModule::EModRet NoModule::OnAddNetwork(NoNetwork& Network, NoString& sErrorRet) { return CONTINUE; }
NoModule::EModRet NoModule::OnDeleteNetwork(NoNetwork& Network) { return CONTINUE; }

NoModule::EModRet NoModule::OnSendToClient(NoString& sLine, NoClient& Client) { return CONTINUE; }
NoModule::EModRet NoModule::OnSendToIRC(NoString& sLine) { return CONTINUE; }

bool NoModule::OnServerCapAvailable(const NoString& sCap) { return false; }
void NoModule::OnServerCapResult(const NoString& sCap, bool bSuccess) {}

bool NoModule::PutIRC(const NoString& sLine) { return (m_pNetwork) ? m_pNetwork->PutIRC(sLine) : false; }
bool NoModule::PutUser(const NoString& sLine) { return (m_pNetwork) ? m_pNetwork->PutUser(sLine, m_pClient) : false; }
bool NoModule::PutStatus(const NoString& sLine) { return (m_pNetwork) ? m_pNetwork->PutStatus(sLine, m_pClient) : false; }
unsigned int NoModule::PutModule(const NoTable& table)
{
    if (!m_pUser) return 0;

    unsigned int idx = 0;
    NoString sLine;
    while (table.GetLine(idx++, sLine)) PutModule(sLine);
    return idx - 1;
}
bool NoModule::PutModule(const NoString& sLine)
{
    if (m_pClient) {
        m_pClient->PutModule(GetModName(), sLine);
        return true;
    }

    if (m_pNetwork) {
        return m_pNetwork->PutModule(GetModName(), sLine);
    }

    if (m_pUser) {
        return m_pUser->PutModule(GetModName(), sLine);
    }

    return false;
}
bool NoModule::PutModNotice(const NoString& sLine)
{
    if (!m_pUser) return false;

    if (m_pClient) {
        m_pClient->PutModNotice(GetModName(), sLine);
        return true;
    }

    return m_pUser->PutModNotice(GetModName(), sLine);
}

///////////////////
// Global Module //
///////////////////
NoModule::EModRet NoModule::OnAddUser(NoUser& User, NoString& sErrorRet) { return CONTINUE; }
NoModule::EModRet NoModule::OnDeleteUser(NoUser& User) { return CONTINUE; }
void NoModule::OnClientConnect(NoBaseSocket* pClient, const NoString& sHost, unsigned short uPort) {}
NoModule::EModRet NoModule::OnLoginAttempt(std::shared_ptr<NoAuthBase> Auth) { return CONTINUE; }
void NoModule::OnFailedLogin(const NoString& sUsername, const NoString& sRemoteIP) {}
NoModule::EModRet NoModule::OnUnknownUserRaw(NoClient* pClient, NoString& sLine) { return CONTINUE; }
void NoModule::OnClientCapLs(NoClient* pClient, NoStringSet& ssCaps) {}
bool NoModule::IsClientCapSupported(NoClient* pClient, const NoString& sCap, bool bState) { return false; }
void NoModule::OnClientCapRequest(NoClient* pClient, const NoString& sCap, bool bState) {}
NoModule::EModRet
NoModule::OnModuleLoading(const NoString& sModName, const NoString& sArgs, NoModInfo::EModuleType eType, bool& bSuccess, NoString& sRetMsg)
{
    return CONTINUE;
}
NoModule::EModRet NoModule::OnModuleUnloading(NoModule* pModule, bool& bSuccess, NoString& sRetMsg) { return CONTINUE; }
NoModule::EModRet NoModule::OnGetModInfo(NoModInfo& ModInfo, const NoString& sModule, bool& bSuccess, NoString& sRetMsg)
{
    return CONTINUE;
}
void NoModule::OnGetAvailableMods(set<NoModInfo>& ssMods, NoModInfo::EModuleType eType) {}

NoModCommand::NoModCommand() : m_sCmd(), m_pFunc(nullptr), m_sArgs(), m_sDesc() {}

NoModCommand::NoModCommand(const NoString& sCmd, NoModule* pMod, ModCmdFunc func, const NoString& sArgs, const NoString& sDesc)
    : m_sCmd(sCmd), m_pFunc([pMod, func](const NoString& sLine) { (pMod->*func)(sLine); }), m_sArgs(sArgs), m_sDesc(sDesc)
{
}

NoModCommand::NoModCommand(const NoString& sCmd, CmdFunc func, const NoString& sArgs, const NoString& sDesc)
    : m_sCmd(sCmd), m_pFunc(std::move(func)), m_sArgs(sArgs), m_sDesc(sDesc)
{
}

NoModCommand::NoModCommand(const NoModCommand& other)
    : m_sCmd(other.m_sCmd), m_pFunc(other.m_pFunc), m_sArgs(other.m_sArgs), m_sDesc(other.m_sDesc)
{
}

NoModCommand& NoModCommand::operator=(const NoModCommand& other)
{
    m_sCmd = other.m_sCmd;
    m_pFunc = other.m_pFunc;
    m_sArgs = other.m_sArgs;
    m_sDesc = other.m_sDesc;
    return *this;
}

void NoModCommand::InitHelp(NoTable& Table)
{
    Table.AddColumn("Command");
    Table.AddColumn("Arguments");
    Table.AddColumn("Description");
}

void NoModCommand::AddHelp(NoTable& Table) const
{
    Table.AddRow();
    Table.SetCell("Command", GetCommand());
    Table.SetCell("Arguments", GetArgs());
    Table.SetCell("Description", GetDescription());
}