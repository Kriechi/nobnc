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
#include "noznc.h"
#include <dlfcn.h>

using std::map;
using std::set;
using std::vector;

CModule::CModule(ModHandle pDLL, CUser* pUser, CNetwork* pNetwork, const CString& sModName, const CString& sDataDir, CModInfo::EModuleType eType)
    : m_eType(eType), m_sDescription(""), m_sTimers(), m_sSockets(),
#ifdef HAVE_PTHREAD
      m_sJobs(),
#endif
      m_pDLL(pDLL), m_pManager(&(CZNC::Get().GetManager())), m_pUser(pUser), m_pNetwork(pNetwork), m_pClient(nullptr),
      m_sModName(sModName), m_sDataDir(sDataDir), m_sSavePath(""), m_sArgs(""), m_sModPath(""), m_mssRegistry(),
      m_vSubPages(), m_mCommands()
{
    if (m_pNetwork) {
        m_sSavePath = m_pNetwork->GetNetworkPath() + "/moddata/" + m_sModName;
    } else if (m_pUser) {
        m_sSavePath = m_pUser->GetUserPath() + "/moddata/" + m_sModName;
    } else {
        m_sSavePath = CZNC::Get().GetZNCPath() + "/moddata/" + m_sModName;
    }
    LoadRegistry();
}

CModule::~CModule()
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

void CModule::SetUser(CUser* pUser) { m_pUser = pUser; }
void CModule::SetNetwork(CNetwork* pNetwork) { m_pNetwork = pNetwork; }
void CModule::SetClient(CClient* pClient) { m_pClient = pClient; }

CString CModule::ExpandString(const CString& sStr) const
{
    CString sRet;
    return ExpandString(sStr, sRet);
}

CString& CModule::ExpandString(const CString& sStr, CString& sRet) const
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

const CString& CModule::GetSavePath() const
{
    if (!CFile::Exists(m_sSavePath)) {
        CDir::MakeDir(m_sSavePath);
    }
    return m_sSavePath;
}

CString CModule::GetWebPath()
{
    switch (m_eType) {
    case CModInfo::GlobalModule:
        return "/mods/global/" + GetModName() + "/";
    case CModInfo::UserModule:
        return "/mods/user/" + GetModName() + "/";
    case CModInfo::NetworkModule:
        return "/mods/network/" + m_pNetwork->GetName() + "/" + GetModName() + "/";
    default:
        return "/";
    }
}

CString CModule::GetWebFilesPath()
{
    switch (m_eType) {
    case CModInfo::GlobalModule:
        return "/modfiles/global/" + GetModName() + "/";
    case CModInfo::UserModule:
        return "/modfiles/user/" + GetModName() + "/";
    case CModInfo::NetworkModule:
        return "/modfiles/network/" + m_pNetwork->GetName() + "/" + GetModName() + "/";
    default:
        return "/";
    }
}

bool CModule::LoadRegistry()
{
    // CString sPrefix = (m_pUser) ? m_pUser->GetUserName() : ".global";
    return (m_mssRegistry.ReadFromDisk(GetSavePath() + "/.registry") == MCString::MCS_SUCCESS);
}

bool CModule::SaveRegistry() const
{
    // CString sPrefix = (m_pUser) ? m_pUser->GetUserName() : ".global";
    return (m_mssRegistry.WriteToDisk(GetSavePath() + "/.registry", 0600) == MCString::MCS_SUCCESS);
}

bool CModule::MoveRegistry(const CString& sPath)
{
    if (m_sSavePath != sPath) {
        CFile fOldNVFile = CFile(m_sSavePath + "/.registry");
        if (!fOldNVFile.Exists()) {
            return false;
        }
        if (!CFile::Exists(sPath) && !CDir::MakeDir(sPath)) {
            return false;
        }
        fOldNVFile.Copy(sPath + "/.registry");
        m_sSavePath = sPath;
        return true;
    }
    return false;
}

bool CModule::SetNV(const CString& sName, const CString& sValue, bool bWriteToDisk)
{
    m_mssRegistry[sName] = sValue;
    if (bWriteToDisk) {
        return SaveRegistry();
    }

    return true;
}

CString CModule::GetNV(const CString& sName) const
{
    MCString::const_iterator it = m_mssRegistry.find(sName);

    if (it != m_mssRegistry.end()) {
        return it->second;
    }

    return "";
}

bool CModule::DelNV(const CString& sName, bool bWriteToDisk)
{
    MCString::iterator it = m_mssRegistry.find(sName);

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

bool CModule::ClearNV(bool bWriteToDisk)
{
    m_mssRegistry.clear();

    if (bWriteToDisk) {
        return SaveRegistry();
    }
    return true;
}

bool CModule::AddTimer(CTimer* pTimer)
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

bool CModule::AddTimer(FPTimer_t pFBCallback, const CString& sLabel, u_int uInterval, u_int uCycles, const CString& sDescription)
{
    CFPTimer* pTimer = new CFPTimer(this, uInterval, uCycles, sLabel, sDescription);
    pTimer->SetFPCallback(pFBCallback);

    return AddTimer(pTimer);
}

bool CModule::RemTimer(CTimer* pTimer)
{
    if (m_sTimers.erase(pTimer) == 0) return false;
    m_pManager->DelCronByAddr(pTimer);
    return true;
}

bool CModule::RemTimer(const CString& sLabel)
{
    CTimer* pTimer = FindTimer(sLabel);
    if (!pTimer) return false;
    return RemTimer(pTimer);
}

bool CModule::UnlinkTimer(CTimer* pTimer) { return m_sTimers.erase(pTimer); }

CTimer* CModule::FindTimer(const CString& sLabel)
{
    if (sLabel.empty()) {
        return nullptr;
    }

    for (CTimer* pTimer : m_sTimers) {
        if (pTimer->GetName().Equals(sLabel)) {
            return pTimer;
        }
    }

    return nullptr;
}

void CModule::ListTimers()
{
    if (m_sTimers.empty()) {
        PutModule("You have no timers running.");
        return;
    }

    CTable Table;
    Table.AddColumn("Name");
    Table.AddColumn("Secs");
    Table.AddColumn("Cycles");
    Table.AddColumn("Description");

    for (const CTimer* pTimer : m_sTimers) {
        unsigned int uCycles = pTimer->GetCyclesLeft();
        timeval Interval = pTimer->GetInterval();

        Table.AddRow();
        Table.SetCell("Name", pTimer->GetName());
        Table.SetCell("Secs",
                      CString(Interval.tv_sec) + "seconds" +
                      (Interval.tv_usec ? " " + CString(Interval.tv_usec) + " microseconds" : ""));
        Table.SetCell("Cycles", ((uCycles) ? CString(uCycles) : "INF"));
        Table.SetCell("Description", pTimer->GetDescription());
    }

    PutModule(Table);
}

bool CModule::AddSocket(CSocket* pSocket)
{
    if (!pSocket) {
        return false;
    }

    m_sSockets.insert(pSocket);
    return true;
}

bool CModule::RemSocket(CSocket* pSocket)
{
    if (m_sSockets.erase(pSocket)) {
        m_pManager->DelSockByAddr(pSocket);
        return true;
    }

    return false;
}

bool CModule::RemSocket(const CString& sSockName)
{
    for (CSocket* pSocket : m_sSockets) {
        if (pSocket->GetSockName().Equals(sSockName)) {
            m_sSockets.erase(pSocket);
            m_pManager->DelSockByAddr(pSocket);
            return true;
        }
    }

    return false;
}

bool CModule::UnlinkSocket(CSocket* pSocket) { return m_sSockets.erase(pSocket); }

CSocket* CModule::FindSocket(const CString& sSockName)
{
    for (CSocket* pSocket : m_sSockets) {
        if (pSocket->GetSockName().Equals(sSockName)) {
            return pSocket;
        }
    }

    return nullptr;
}

void CModule::ListSockets()
{
    if (m_sSockets.empty()) {
        PutModule("You have no open sockets.");
        return;
    }

    CTable Table;
    Table.AddColumn("Name");
    Table.AddColumn("State");
    Table.AddColumn("LocalPort");
    Table.AddColumn("SSL");
    Table.AddColumn("RemoteIP");
    Table.AddColumn("RemotePort");

    for (const CSocket* pSocket : m_sSockets) {
        Table.AddRow();
        Table.SetCell("Name", pSocket->GetSockName());

        if (pSocket->GetType() == CSocket::LISTENER) {
            Table.SetCell("State", "Listening");
        } else {
            Table.SetCell("State", (pSocket->IsConnected() ? "Connected" : ""));
        }

        Table.SetCell("LocalPort", CString(pSocket->GetLocalPort()));
        Table.SetCell("SSL", (pSocket->GetSSL() ? "yes" : "no"));
        Table.SetCell("RemoteIP", pSocket->GetRemoteIP());
        Table.SetCell("RemotePort", (pSocket->GetRemotePort()) ? CString(pSocket->GetRemotePort()) : CString(""));
    }

    PutModule(Table);
}

#ifdef HAVE_PTHREAD
CModuleJob::~CModuleJob() { m_pModule->UnlinkJob(this); }

void CModule::AddJob(CModuleJob* pJob)
{
    CThreadPool::Get().addJob(pJob);
    m_sJobs.insert(pJob);
}

void CModule::CancelJob(CModuleJob* pJob)
{
    if (pJob == nullptr) return;
    // Destructor calls UnlinkJob and removes the job from m_sJobs
    CThreadPool::Get().cancelJob(pJob);
}

bool CModule::CancelJob(const CString& sJobName)
{
    for (CModuleJob* pJob : m_sJobs) {
        if (pJob->GetName().Equals(sJobName)) {
            CancelJob(pJob);
            return true;
        }
    }
    return false;
}

void CModule::CancelJobs(const std::set<CModuleJob*>& sJobs)
{
    set<CJob*> sPlainJobs(sJobs.begin(), sJobs.end());

    // Destructor calls UnlinkJob and removes the jobs from m_sJobs
    CThreadPool::Get().cancelJobs(sPlainJobs);
}

bool CModule::UnlinkJob(CModuleJob* pJob) { return 0 != m_sJobs.erase(pJob); }
#endif

bool CModule::AddCommand(const CModCommand& Command)
{
    if (Command.GetFunction() == nullptr) return false;
    if (Command.GetCommand().find(' ') != CString::npos) return false;
    if (FindCommand(Command.GetCommand()) != nullptr) return false;

    m_mCommands[Command.GetCommand()] = Command;
    return true;
}

bool CModule::AddCommand(const CString& sCmd, CModCommand::ModCmdFunc func, const CString& sArgs, const CString& sDesc)
{
    CModCommand cmd(sCmd, this, func, sArgs, sDesc);
    return AddCommand(cmd);
}

bool CModule::AddCommand(const CString& sCmd, const CString& sArgs, const CString& sDesc, std::function<void(const CString& sLine)> func)
{
    CModCommand cmd(sCmd, std::move(func), sArgs, sDesc);
    return AddCommand(std::move(cmd));
}

void CModule::AddHelpCommand() { AddCommand("Help", &CModule::HandleHelpCommand, "search", "Generate this output"); }

bool CModule::RemCommand(const CString& sCmd) { return m_mCommands.erase(sCmd) > 0; }

const CModCommand* CModule::FindCommand(const CString& sCmd) const
{
    for (const auto& it : m_mCommands) {
        if (!it.first.Equals(sCmd)) continue;
        return &it.second;
    }
    return nullptr;
}

bool CModule::HandleCommand(const CString& sLine)
{
    const CString& sCmd = sLine.Token(0);
    const CModCommand* pCmd = FindCommand(sCmd);

    if (pCmd) {
        pCmd->Call(sLine);
        return true;
    }

    OnUnknownModCommand(sLine);

    return false;
}

void CModule::HandleHelpCommand(const CString& sLine)
{
    CString sFilter = sLine.Token(1).AsLower();
    CTable Table;

    CModCommand::InitHelp(Table);
    for (const auto& it : m_mCommands) {
        CString sCmd = it.second.GetCommand().AsLower();
        if (sFilter.empty() || (sCmd.StartsWith(sFilter, CString::CaseSensitive)) || sCmd.WildCmp(sFilter)) {
            it.second.AddHelp(Table);
        }
    }
    if (Table.empty()) {
        PutModule("No matches for '" + sFilter + "'");
    } else {
        PutModule(Table);
    }
}

CString CModule::GetModNick() const { return ((m_pUser) ? m_pUser->GetStatusPrefix() : "*") + m_sModName; }

// Webmods
bool CModule::OnWebPreRequest(CWebSock& WebSock, const CString& sPageName) { return false; }
bool CModule::OnWebRequest(CWebSock& WebSock, const CString& sPageName, CTemplate& Tmpl) { return false; }
bool CModule::OnEmbeddedWebRequest(CWebSock& WebSock, const CString& sPageName, CTemplate& Tmpl) { return false; }
// !Webmods

bool CModule::OnLoad(const CString& sArgs, CString& sMessage)
{
    sMessage = "";
    return true;
}
bool CModule::OnBoot() { return true; }
void CModule::OnPreRehash() {}
void CModule::OnPostRehash() {}
void CModule::OnIRCDisconnected() {}
void CModule::OnIRCConnected() {}
CModule::EModRet CModule::OnIRCConnecting(CIRCSock* IRCSock) { return CONTINUE; }
void CModule::OnIRCConnectionError(CIRCSock* IRCSock) {}
CModule::EModRet CModule::OnIRCRegistration(CString& sPass, CString& sNick, CString& sIdent, CString& sRealName)
{
    return CONTINUE;
}
CModule::EModRet CModule::OnBroadcast(CString& sMessage) { return CONTINUE; }

void CModule::OnChanPermission2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, unsigned char uMode, bool bAdded, bool bNoChange)
{
    if (pOpNick) OnChanPermission(*pOpNick, Nick, Channel, uMode, bAdded, bNoChange);
}
void CModule::OnOp2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange)
{
    if (pOpNick) OnOp(*pOpNick, Nick, Channel, bNoChange);
}
void CModule::OnDeop2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange)
{
    if (pOpNick) OnDeop(*pOpNick, Nick, Channel, bNoChange);
}
void CModule::OnVoice2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange)
{
    if (pOpNick) OnVoice(*pOpNick, Nick, Channel, bNoChange);
}
void CModule::OnDevoice2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange)
{
    if (pOpNick) OnDevoice(*pOpNick, Nick, Channel, bNoChange);
}
void CModule::OnRawMode2(const CNick* pOpNick, CChannel& Channel, const CString& sModes, const CString& sArgs)
{
    if (pOpNick) OnRawMode(*pOpNick, Channel, sModes, sArgs);
}
void CModule::OnMode2(const CNick* pOpNick, CChannel& Channel, char uMode, const CString& sArg, bool bAdded, bool bNoChange)
{
    if (pOpNick) OnMode(*pOpNick, Channel, uMode, sArg, bAdded, bNoChange);
}

void CModule::OnChanPermission(const CNick& pOpNick, const CNick& Nick, CChannel& Channel, unsigned char uMode, bool bAdded, bool bNoChange)
{
}
void CModule::OnOp(const CNick& pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange) {}
void CModule::OnDeop(const CNick& pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange) {}
void CModule::OnVoice(const CNick& pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange) {}
void CModule::OnDevoice(const CNick& pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange) {}
void CModule::OnRawMode(const CNick& pOpNick, CChannel& Channel, const CString& sModes, const CString& sArgs) {}
void CModule::OnMode(const CNick& pOpNick, CChannel& Channel, char uMode, const CString& sArg, bool bAdded, bool bNoChange)
{
}

CModule::EModRet CModule::OnRaw(CString& sLine) { return CONTINUE; }

CModule::EModRet CModule::OnStatusCommand(CString& sCommand) { return CONTINUE; }
void CModule::OnModNotice(const CString& sMessage) {}
void CModule::OnModCTCP(const CString& sMessage) {}

void CModule::OnModCommand(const CString& sCommand) { HandleCommand(sCommand); }
void CModule::OnUnknownModCommand(const CString& sLine)
{
    if (m_mCommands.empty())
        // This function is only called if OnModCommand wasn't
        // overriden, so no false warnings for modules which don't use
        // CModCommand for command handling.
        PutModule("This module doesn't implement any commands.");
    else
        PutModule("Unknown command!");
}

void CModule::OnQuit(const CNick& Nick, const CString& sMessage, const vector<CChannel*>& vChans) {}
void CModule::OnNick(const CNick& Nick, const CString& sNewNick, const vector<CChannel*>& vChans) {}
void CModule::OnKick(const CNick& Nick, const CString& sKickedNick, CChannel& Channel, const CString& sMessage) {}
CModule::EModRet CModule::OnJoining(CChannel& Channel) { return CONTINUE; }
void CModule::OnJoin(const CNick& Nick, CChannel& Channel) {}
void CModule::OnPart(const CNick& Nick, CChannel& Channel, const CString& sMessage) {}
CModule::EModRet CModule::OnInvite(const CNick& Nick, const CString& sChan) { return CONTINUE; }

CModule::EModRet CModule::OnChanBufferStarting(CChannel& Chan, CClient& Client) { return CONTINUE; }
CModule::EModRet CModule::OnChanBufferEnding(CChannel& Chan, CClient& Client) { return CONTINUE; }
CModule::EModRet CModule::OnChanBufferPlayLine(CChannel& Chan, CClient& Client, CString& sLine) { return CONTINUE; }
CModule::EModRet CModule::OnPrivBufferPlayLine(CClient& Client, CString& sLine) { return CONTINUE; }

CModule::EModRet CModule::OnChanBufferPlayLine2(CChannel& Chan, CClient& Client, CString& sLine, const timeval& tv)
{
    return OnChanBufferPlayLine(Chan, Client, sLine);
}
CModule::EModRet CModule::OnPrivBufferPlayLine2(CClient& Client, CString& sLine, const timeval& tv)
{
    return OnPrivBufferPlayLine(Client, sLine);
}

void CModule::OnClientLogin() {}
void CModule::OnClientDisconnect() {}
CModule::EModRet CModule::OnUserRaw(CString& sLine) { return CONTINUE; }
CModule::EModRet CModule::OnUserCTCPReply(CString& sTarget, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnUserCTCP(CString& sTarget, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnUserAction(CString& sTarget, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnUserMsg(CString& sTarget, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnUserNotice(CString& sTarget, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnUserJoin(CString& sChannel, CString& sKey) { return CONTINUE; }
CModule::EModRet CModule::OnUserPart(CString& sChannel, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnUserTopic(CString& sChannel, CString& sTopic) { return CONTINUE; }
CModule::EModRet CModule::OnUserTopicRequest(CString& sChannel) { return CONTINUE; }
CModule::EModRet CModule::OnUserQuit(CString& sMessage) { return CONTINUE; }

CModule::EModRet CModule::OnCTCPReply(CNick& Nick, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnPrivCTCP(CNick& Nick, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnChanCTCP(CNick& Nick, CChannel& Channel, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnPrivAction(CNick& Nick, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnChanAction(CNick& Nick, CChannel& Channel, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnPrivMsg(CNick& Nick, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnChanMsg(CNick& Nick, CChannel& Channel, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnPrivNotice(CNick& Nick, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnChanNotice(CNick& Nick, CChannel& Channel, CString& sMessage) { return CONTINUE; }
CModule::EModRet CModule::OnTopic(CNick& Nick, CChannel& Channel, CString& sTopic) { return CONTINUE; }
CModule::EModRet CModule::OnTimerAutoJoin(CChannel& Channel) { return CONTINUE; }
CModule::EModRet CModule::OnAddNetwork(CNetwork& Network, CString& sErrorRet) { return CONTINUE; }
CModule::EModRet CModule::OnDeleteNetwork(CNetwork& Network) { return CONTINUE; }

CModule::EModRet CModule::OnSendToClient(CString& sLine, CClient& Client) { return CONTINUE; }
CModule::EModRet CModule::OnSendToIRC(CString& sLine) { return CONTINUE; }

bool CModule::OnServerCapAvailable(const CString& sCap) { return false; }
void CModule::OnServerCapResult(const CString& sCap, bool bSuccess) {}

bool CModule::PutIRC(const CString& sLine) { return (m_pNetwork) ? m_pNetwork->PutIRC(sLine) : false; }
bool CModule::PutUser(const CString& sLine) { return (m_pNetwork) ? m_pNetwork->PutUser(sLine, m_pClient) : false; }
bool CModule::PutStatus(const CString& sLine) { return (m_pNetwork) ? m_pNetwork->PutStatus(sLine, m_pClient) : false; }
unsigned int CModule::PutModule(const CTable& table)
{
    if (!m_pUser) return 0;

    unsigned int idx = 0;
    CString sLine;
    while (table.GetLine(idx++, sLine)) PutModule(sLine);
    return idx - 1;
}
bool CModule::PutModule(const CString& sLine)
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
bool CModule::PutModNotice(const CString& sLine)
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
CModule::EModRet CModule::OnAddUser(CUser& User, CString& sErrorRet) { return CONTINUE; }
CModule::EModRet CModule::OnDeleteUser(CUser& User) { return CONTINUE; }
void CModule::OnClientConnect(CZNCSock* pClient, const CString& sHost, unsigned short uPort) {}
CModule::EModRet CModule::OnLoginAttempt(std::shared_ptr<CAuthBase> Auth) { return CONTINUE; }
void CModule::OnFailedLogin(const CString& sUsername, const CString& sRemoteIP) {}
CModule::EModRet CModule::OnUnknownUserRaw(CClient* pClient, CString& sLine) { return CONTINUE; }
void CModule::OnClientCapLs(CClient* pClient, SCString& ssCaps) {}
bool CModule::IsClientCapSupported(CClient* pClient, const CString& sCap, bool bState) { return false; }
void CModule::OnClientCapRequest(CClient* pClient, const CString& sCap, bool bState) {}
CModule::EModRet
CModule::OnModuleLoading(const CString& sModName, const CString& sArgs, CModInfo::EModuleType eType, bool& bSuccess, CString& sRetMsg)
{
    return CONTINUE;
}
CModule::EModRet CModule::OnModuleUnloading(CModule* pModule, bool& bSuccess, CString& sRetMsg) { return CONTINUE; }
CModule::EModRet CModule::OnGetModInfo(CModInfo& ModInfo, const CString& sModule, bool& bSuccess, CString& sRetMsg)
{
    return CONTINUE;
}
void CModule::OnGetAvailableMods(set<CModInfo>& ssMods, CModInfo::EModuleType eType) {}

CModCommand::CModCommand() : m_sCmd(), m_pFunc(nullptr), m_sArgs(), m_sDesc() {}

CModCommand::CModCommand(const CString& sCmd, CModule* pMod, ModCmdFunc func, const CString& sArgs, const CString& sDesc)
    : m_sCmd(sCmd), m_pFunc([pMod, func](const CString& sLine) { (pMod->*func)(sLine); }), m_sArgs(sArgs), m_sDesc(sDesc)
{
}

CModCommand::CModCommand(const CString& sCmd, CmdFunc func, const CString& sArgs, const CString& sDesc)
    : m_sCmd(sCmd), m_pFunc(std::move(func)), m_sArgs(sArgs), m_sDesc(sDesc)
{
}

CModCommand::CModCommand(const CModCommand& other)
    : m_sCmd(other.m_sCmd), m_pFunc(other.m_pFunc), m_sArgs(other.m_sArgs), m_sDesc(other.m_sDesc)
{
}

CModCommand& CModCommand::operator=(const CModCommand& other)
{
    m_sCmd = other.m_sCmd;
    m_pFunc = other.m_pFunc;
    m_sArgs = other.m_sArgs;
    m_sDesc = other.m_sDesc;
    return *this;
}

void CModCommand::InitHelp(CTable& Table)
{
    Table.AddColumn("Command");
    Table.AddColumn("Arguments");
    Table.AddColumn("Description");
}

void CModCommand::AddHelp(CTable& Table) const
{
    Table.AddRow();
    Table.SetCell("Command", GetCommand());
    Table.SetCell("Arguments", GetArgs());
    Table.SetCell("Description", GetDescription());
}
