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
#include "noclient.h"
#include "noapp.h"
#include "nomodulejob.h"
#include "nothreadpool.h"
#include "nomodulesocket.h"
#include <dlfcn.h>

NoModule::NoModule(NoModuleHandle pDLL, NoUser* pUser, NoNetwork* pNetwork, const NoString& sModName, const NoString& sDataDir, No::ModuleType eType)
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

void NoModule::Unload() { throw UNLOAD; }

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

void NoModule::SetType(No::ModuleType eType) { m_eType = eType; }

void NoModule::SetDescription(const NoString& s) { m_sDescription = s; }

void NoModule::SetModPath(const NoString& s) { m_sModPath = s; }

void NoModule::SetArgs(const NoString& s) { m_sArgs = s; }

No::ModuleType NoModule::GetType() const { return m_eType; }

const NoString& NoModule::GetDescription() const { return m_sDescription; }

const NoString& NoModule::GetArgs() const { return m_sArgs; }

const NoString& NoModule::GetModPath() const { return m_sModPath; }

NoUser* NoModule::GetUser() const { return m_pUser; }

NoNetwork* NoModule::GetNetwork() const { return m_pNetwork; }

NoClient* NoModule::GetClient() const { return m_pClient; }

NoSocketManager* NoModule::GetManager() const { return m_pManager; }

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
    case No::GlobalModule:
        return "/mods/global/" + GetModName() + "/";
    case No::UserModule:
        return "/mods/user/" + GetModName() + "/";
    case No::NetworkModule:
        return "/mods/network/" + m_pNetwork->GetName() + "/" + GetModName() + "/";
    default:
        return "/";
    }
}

NoString NoModule::GetWebFilesPath()
{
    switch (m_eType) {
    case No::GlobalModule:
        return "/modfiles/global/" + GetModName() + "/";
    case No::UserModule:
        return "/modfiles/user/" + GetModName() + "/";
    case No::NetworkModule:
        return "/modfiles/network/" + m_pNetwork->GetName() + "/" + GetModName() + "/";
    default:
        return "/";
    }
}

bool NoModule::LoadRegistry()
{
    // NoString sPrefix = (m_pUser) ? m_pUser->GetUserName() : ".global";
    return NoUtils::ReadFromDisk(m_mssRegistry, GetSavePath() + "/.registry") == NoUtils::MCS_SUCCESS;
}

bool NoModule::SaveRegistry() const
{
    // NoString sPrefix = (m_pUser) ? m_pUser->GetUserName() : ".global";
    return NoUtils::WriteToDisk(m_mssRegistry, GetSavePath() + "/.registry", 0600) == NoUtils::MCS_SUCCESS;
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

NoStringMap::iterator NoModule::FindNV(const NoString& sName) { return m_mssRegistry.find(sName); }

NoStringMap::iterator NoModule::EndNV() { return m_mssRegistry.end(); }

NoStringMap::iterator NoModule::BeginNV() { return m_mssRegistry.begin(); }

void NoModule::DelNV(NoStringMap::iterator it) { m_mssRegistry.erase(it); }

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

    m_pManager->AddCron(pTimer->GetHandle());
    return true;
}

bool NoModule::AddTimer(NoTimer::Callback pFBCallback, const NoString& sLabel, u_int uInterval, u_int uCycles, const NoString& sDescription)
{
    NoTimer* pTimer = new NoTimer(this, uInterval, uCycles, sLabel, sDescription);
    pTimer->setCallback(pFBCallback);

    return AddTimer(pTimer);
}

bool NoModule::RemTimer(NoTimer* pTimer)
{
    if (m_sTimers.erase(pTimer) == 0) return false;
    m_pManager->DelCronByAddr(pTimer->GetHandle());
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
        if (pTimer->GetName().equals(sLabel)) {
            return pTimer;
        }
    }

    return nullptr;
}

std::set<NoTimer*>::const_iterator NoModule::BeginTimers() const { return m_sTimers.begin(); }

std::set<NoTimer*>::const_iterator NoModule::EndTimers() const { return m_sTimers.end(); }

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
        uint uCycles = pTimer->GetCyclesLeft();
        timeval Interval = pTimer->GetInterval();

        Table.AddRow();
        Table.SetCell("Name", pTimer->GetName());
        Table.SetCell("Secs",
                      NoString(Interval.tv_sec) + "seconds" +
                      (Interval.tv_usec ? " " + NoString(Interval.tv_usec) + " microseconds" : ""));
        Table.SetCell("Cycles", ((uCycles) ? NoString(uCycles) : "INF"));
        Table.SetCell("Description", pTimer->description());
    }

    PutModule(Table);
}

bool NoModule::AddSocket(NoModuleSocket* pSocket)
{
    if (!pSocket) {
        return false;
    }

    m_sSockets.insert(pSocket);
    return true;
}

bool NoModule::RemSocket(NoModuleSocket* pSocket)
{
    if (m_sSockets.erase(pSocket)) {
        m_pManager->DelSockByAddr(pSocket);
        return true;
    }

    return false;
}

bool NoModule::RemSocket(const NoString& sSockName)
{
    for (NoModuleSocket* pSocket : m_sSockets) {
        if (pSocket->GetSockName().equals(sSockName)) {
            m_sSockets.erase(pSocket);
            m_pManager->DelSockByAddr(pSocket);
            return true;
        }
    }

    return false;
}

bool NoModule::UnlinkSocket(NoModuleSocket* pSocket) { return m_sSockets.erase(pSocket); }

NoModuleSocket* NoModule::FindSocket(const NoString& sSockName)
{
    for (NoModuleSocket* pSocket : m_sSockets) {
        if (pSocket->GetSockName().equals(sSockName)) {
            return pSocket;
        }
    }

    return nullptr;
}

std::set<NoModuleSocket*>::const_iterator NoModule::BeginSockets() const { return m_sSockets.begin(); }

std::set<NoModuleSocket*>::const_iterator NoModule::EndSockets() const { return m_sSockets.end(); }

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

    for (const NoModuleSocket* pSocket : m_sSockets) {
        Table.AddRow();
        Table.SetCell("Name", pSocket->GetSockName());

        if (pSocket->IsListener()) {
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
        if (pJob->GetName().equals(sJobName)) {
            CancelJob(pJob);
            return true;
        }
    }
    return false;
}

void NoModule::CancelJobs(const std::set<NoModuleJob*>& sJobs)
{
    std::set<NoJob*> sPlainJobs(sJobs.begin(), sJobs.end());

    // Destructor calls UnlinkJob and removes the jobs from m_sJobs
    NoThreadPool::Get().cancelJobs(sPlainJobs);
}

bool NoModule::UnlinkJob(NoModuleJob* pJob) { return 0 != m_sJobs.erase(pJob); }
#endif

bool NoModule::AddCommand(const NoModuleCommand& Command)
{
    if (Command.GetFunction() == nullptr) return false;
    if (Command.GetCommand().find(' ') != NoString::npos) return false;
    if (FindCommand(Command.GetCommand()) != nullptr) return false;

    m_mCommands[Command.GetCommand()] = Command;
    return true;
}

bool NoModule::AddCommand(const NoString& sCmd, NoModuleCommand::ModCmdFunc func, const NoString& sArgs, const NoString& sDesc)
{
    NoModuleCommand cmd(sCmd, this, func, sArgs, sDesc);
    return AddCommand(cmd);
}

bool NoModule::AddCommand(const NoString& sCmd, const NoString& sArgs, const NoString& sDesc, std::function<void(const NoString& sLine)> func)
{
    NoModuleCommand cmd(sCmd, std::move(func), sArgs, sDesc);
    return AddCommand(std::move(cmd));
}

void NoModule::AddHelpCommand() { AddCommand("Help", &NoModule::HandleHelpCommand, "search", "Generate this output"); }

bool NoModule::RemCommand(const NoString& sCmd) { return m_mCommands.erase(sCmd) > 0; }

const NoModuleCommand* NoModule::FindCommand(const NoString& sCmd) const
{
    for (const auto& it : m_mCommands) {
        if (!it.first.equals(sCmd)) continue;
        return &it.second;
    }
    return nullptr;
}

bool NoModule::HandleCommand(const NoString& sLine)
{
    const NoString& sCmd = sLine.token(0);
    const NoModuleCommand* pCmd = FindCommand(sCmd);

    if (pCmd) {
        pCmd->Call(sLine);
        return true;
    }

    OnUnknownModCommand(sLine);

    return false;
}

void NoModule::HandleHelpCommand(const NoString& sLine)
{
    NoString sFilter = sLine.token(1).toLower();
    NoTable Table;

    NoModuleCommand::InitHelp(Table);
    for (const auto& it : m_mCommands) {
        NoString sCmd = it.second.GetCommand().toLower();
        if (sFilter.empty() || (sCmd.startsWith(sFilter, No::CaseSensitive)) || sCmd.wildCmp(sFilter)) {
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

const NoString& NoModule::GetModDataDir() const { return m_sDataDir; }

// Webmods
bool NoModule::OnWebPreRequest(NoWebSocket& WebSock, const NoString& sPageName) { return false; }
bool NoModule::OnWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) { return false; }

void NoModule::AddSubPage(TWebSubPage spSubPage) { m_vSubPages.push_back(spSubPage); }

void NoModule::ClearSubPages() { m_vSubPages.clear(); }

VWebSubPages& NoModule::GetSubPages() { return m_vSubPages; }
bool NoModule::OnEmbeddedWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) { return false; }
// !Webmods

bool NoModule::OnLoad(const NoString& sArgs, NoString& sMessage)
{
    sMessage = "";
    return true;
}
bool NoModule::OnBoot() { return true; }

bool NoModule::WebRequiresLogin() { return true; }

bool NoModule::WebRequiresAdmin() { return false; }

NoString NoModule::GetWebMenuTitle() { return ""; }
void NoModule::OnPreRehash() {}
void NoModule::OnPostRehash() {}
void NoModule::OnIRCDisconnected() {}
void NoModule::OnIRCConnected() {}
NoModule::ModRet NoModule::OnIRCConnecting(NoIrcConnection* IRCSock) { return CONTINUE; }
void NoModule::OnIRCConnectionError(NoIrcConnection* IRCSock) {}
NoModule::ModRet NoModule::OnIRCRegistration(NoString& sPass, NoString& sNick, NoString& sIdent, NoString& sRealName)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::OnBroadcast(NoString& sMessage) { return CONTINUE; }

void NoModule::OnChanPermission2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange)
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

void NoModule::OnChanPermission(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange)
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

NoModule::ModRet NoModule::OnRaw(NoString& sLine) { return CONTINUE; }

NoModule::ModRet NoModule::OnStatusCommand(NoString& sCommand) { return CONTINUE; }
void NoModule::OnModNotice(const NoString& sMessage) {}
void NoModule::OnModCTCP(const NoString& sMessage) {}

void NoModule::OnModCommand(const NoString& sCommand) { HandleCommand(sCommand); }
void NoModule::OnUnknownModCommand(const NoString& sLine)
{
    if (m_mCommands.empty())
        // This function is only called if OnModCommand wasn't
        // overriden, so no false warnings for modules which don't use
        // NoModuleCommand for command handling.
        PutModule("This module doesn't implement any commands.");
    else
        PutModule("Unknown command!");
}

void NoModule::OnQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans) {}
void NoModule::OnNick(const NoNick& Nick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans) {}
void NoModule::OnKick(const NoNick& Nick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage) {}
NoModule::ModRet NoModule::OnJoining(NoChannel& Channel) { return CONTINUE; }
void NoModule::OnJoin(const NoNick& Nick, NoChannel& Channel) {}
void NoModule::OnPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage) {}
NoModule::ModRet NoModule::OnInvite(const NoNick& Nick, const NoString& sChan) { return CONTINUE; }

NoModule::ModRet NoModule::OnChanBufferStarting(NoChannel& Chan, NoClient& Client) { return CONTINUE; }
NoModule::ModRet NoModule::OnChanBufferEnding(NoChannel& Chan, NoClient& Client) { return CONTINUE; }
NoModule::ModRet NoModule::OnChanBufferPlayLine(NoChannel& Chan, NoClient& Client, NoString& sLine) { return CONTINUE; }
NoModule::ModRet NoModule::OnPrivBufferPlayLine(NoClient& Client, NoString& sLine) { return CONTINUE; }

NoModule::ModRet NoModule::OnChanBufferPlayLine2(NoChannel& Chan, NoClient& Client, NoString& sLine, const timeval& tv)
{
    return OnChanBufferPlayLine(Chan, Client, sLine);
}
NoModule::ModRet NoModule::OnPrivBufferPlayLine2(NoClient& Client, NoString& sLine, const timeval& tv)
{
    return OnPrivBufferPlayLine(Client, sLine);
}

void NoModule::OnClientLogin() {}
void NoModule::OnClientDisconnect() {}
NoModule::ModRet NoModule::OnUserRaw(NoString& sLine) { return CONTINUE; }
NoModule::ModRet NoModule::OnUserCTCPReply(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnUserCTCP(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnUserAction(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnUserMsg(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnUserNotice(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnUserJoin(NoString& sChannel, NoString& sKey) { return CONTINUE; }
NoModule::ModRet NoModule::OnUserPart(NoString& sChannel, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnUserTopic(NoString& sChannel, NoString& sTopic) { return CONTINUE; }
NoModule::ModRet NoModule::OnUserTopicRequest(NoString& sChannel) { return CONTINUE; }
NoModule::ModRet NoModule::OnUserQuit(NoString& sMessage) { return CONTINUE; }

NoModule::ModRet NoModule::OnCTCPReply(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnPrivCTCP(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnChanCTCP(NoNick& Nick, NoChannel& Channel, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnPrivAction(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnPrivMsg(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnPrivNotice(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::OnTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic) { return CONTINUE; }
NoModule::ModRet NoModule::OnTimerAutoJoin(NoChannel& Channel) { return CONTINUE; }
NoModule::ModRet NoModule::OnAddNetwork(NoNetwork& Network, NoString& sErrorRet) { return CONTINUE; }
NoModule::ModRet NoModule::OnDeleteNetwork(NoNetwork& Network) { return CONTINUE; }

NoModule::ModRet NoModule::OnSendToClient(NoString& sLine, NoClient& Client) { return CONTINUE; }
NoModule::ModRet NoModule::OnSendToIRC(NoString& sLine) { return CONTINUE; }

NoModuleHandle NoModule::GetDLL() { return m_pDLL; }

double NoModule::GetCoreVersion() { return NO_VERSION; }

bool NoModule::OnServerCapAvailable(const NoString& sCap) { return false; }
void NoModule::OnServerCapResult(const NoString& sCap, bool bSuccess) {}

bool NoModule::PutIRC(const NoString& sLine) { return (m_pNetwork) ? m_pNetwork->PutIRC(sLine) : false; }
bool NoModule::PutUser(const NoString& sLine) { return (m_pNetwork) ? m_pNetwork->PutUser(sLine, m_pClient) : false; }
bool NoModule::PutStatus(const NoString& sLine) { return (m_pNetwork) ? m_pNetwork->PutStatus(sLine, m_pClient) : false; }
uint NoModule::PutModule(const NoTable& table)
{
    if (!m_pUser) return 0;

    uint idx = 0;
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

const NoString& NoModule::GetModName() const { return m_sModName; }

///////////////////
// Global Module //
///////////////////
NoModule::ModRet NoModule::OnAddUser(NoUser& User, NoString& sErrorRet) { return CONTINUE; }
NoModule::ModRet NoModule::OnDeleteUser(NoUser& User) { return CONTINUE; }
void NoModule::OnClientConnect(NoSocket* pClient, const NoString& sHost, ushort uPort) {}
NoModule::ModRet NoModule::OnLoginAttempt(std::shared_ptr<NoAuthenticator> Auth) { return CONTINUE; }
void NoModule::OnFailedLogin(const NoString& sUsername, const NoString& sRemoteIP) {}
NoModule::ModRet NoModule::OnUnknownUserRaw(NoClient* pClient, NoString& sLine) { return CONTINUE; }
void NoModule::OnClientCapLs(NoClient* pClient, NoStringSet& ssCaps) {}
bool NoModule::IsClientCapSupported(NoClient* pClient, const NoString& sCap, bool bState) { return false; }
void NoModule::OnClientCapRequest(NoClient* pClient, const NoString& sCap, bool bState) {}
NoModule::ModRet
NoModule::OnModuleLoading(const NoString& sModName, const NoString& sArgs, No::ModuleType eType, bool& bSuccess, NoString& sRetMsg)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::OnModuleUnloading(NoModule* pModule, bool& bSuccess, NoString& sRetMsg) { return CONTINUE; }
NoModule::ModRet NoModule::OnGetModInfo(NoModuleInfo& ModInfo, const NoString& sModule, bool& bSuccess, NoString& sRetMsg)
{
    return CONTINUE;
}
void NoModule::OnGetAvailableMods(std::set<NoModuleInfo>& ssMods, No::ModuleType eType) {}
