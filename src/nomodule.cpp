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

#include "nomodule.h"
#include "nomodule_p.h"
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
    : d(new NoModulePrivate(pDLL, pUser, pNetwork, sModName, sDataDir, eType))
{
    if (pNetwork) {
        d->savePath = pNetwork->GetNetworkPath() + "/moddata/" + sModName;
    } else if (pUser) {
        d->savePath = pUser->GetUserPath() + "/moddata/" + sModName;
    } else {
        d->savePath = NoApp::Get().GetZNCPath() + "/moddata/" + sModName;
    }
}

NoModule::~NoModule()
{
    for (NoTimer* timer : d->timers)
        delete timer;
    d->timers.clear();

    for (NoModuleSocket* socket : d->sockets)
        delete socket;
    d->sockets.clear();

#ifdef HAVE_PTHREAD
    CancelJobs(d->jobs);
#endif
}

void NoModule::SetUser(NoUser* pUser) { d->user = pUser; }
void NoModule::SetNetwork(NoNetwork* pNetwork) { d->network = pNetwork; }
void NoModule::SetClient(NoClient* pClient) { d->client = pClient; }

void NoModule::Unload() { throw UNLOAD; }

NoString NoModule::ExpandString(const NoString& sStr) const
{
    NoString sRet;
    return ExpandString(sStr, sRet);
}

NoString& NoModule::ExpandString(const NoString& sStr, NoString& sRet) const
{
    sRet = sStr;

    if (d->network) {
        return d->network->ExpandString(sRet, sRet);
    }

    if (d->user) {
        return d->user->ExpandString(sRet, sRet);
    }

    return sRet;
}

void NoModule::SetType(No::ModuleType eType) { d->type = eType; }

void NoModule::SetDescription(const NoString& s) { d->description = s; }

void NoModule::SetModPath(const NoString& s) { d->path = s; }

void NoModule::SetArgs(const NoString& s) { d->args = s; }

No::ModuleType NoModule::GetType() const { return d->type; }

const NoString& NoModule::GetDescription() const { return d->description; }

const NoString& NoModule::GetArgs() const { return d->args; }

const NoString& NoModule::GetModPath() const { return d->path; }

NoUser* NoModule::GetUser() const { return d->user; }

NoNetwork* NoModule::GetNetwork() const { return d->network; }

NoClient* NoModule::GetClient() const { return d->client; }

NoSocketManager* NoModule::GetManager() const { return d->manager; }

const NoString& NoModule::GetSavePath() const
{
    if (!NoFile::Exists(d->savePath)) {
        NoDir::MakeDir(d->savePath);
    }
    return d->savePath;
}

NoString NoModule::GetWebPath()
{
    switch (d->type) {
    case No::GlobalModule:
        return "/mods/global/" + GetModName() + "/";
    case No::UserModule:
        return "/mods/user/" + GetModName() + "/";
    case No::NetworkModule:
        return "/mods/network/" + d->network->GetName() + "/" + GetModName() + "/";
    default:
        return "/";
    }
}

NoString NoModule::GetWebFilesPath()
{
    switch (d->type) {
    case No::GlobalModule:
        return "/modfiles/global/" + GetModName() + "/";
    case No::UserModule:
        return "/modfiles/user/" + GetModName() + "/";
    case No::NetworkModule:
        return "/modfiles/network/" + d->network->GetName() + "/" + GetModName() + "/";
    default:
        return "/";
    }
}

NoTimer* NoModule::FindTimer(const NoString& sLabel) const
{
    if (sLabel.empty()) {
        return nullptr;
    }

    for (NoTimer* pTimer : d->timers) {
        if (pTimer->name().equals(sLabel)) {
            return pTimer;
        }
    }

    return nullptr;
}

void NoModule::ListTimers()
{
    if (d->timers.empty()) {
        PutModule("You have no timers running.");
        return;
    }

    NoTable Table;
    Table.AddColumn("Name");
    Table.AddColumn("Secs");
    Table.AddColumn("Cycles");
    Table.AddColumn("Description");

    for (const NoTimer* pTimer : d->timers) {
        Table.AddRow();
        Table.SetCell("Name", pTimer->name());
        Table.SetCell("Interval", NoString(pTimer->interval()) + " seconds");
        Table.SetCell("Description", pTimer->description());
    }

    PutModule(Table);
}

NoModuleSocket* NoModule::FindSocket(const NoString& sName) const
{
    for (NoModuleSocket* pSocket : d->sockets) {
        if (pSocket->GetSockName().equals(sName)) {
            return pSocket;
        }
    }

    return nullptr;
}

void NoModule::ListSockets()
{
    if (d->sockets.empty()) {
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

    for (const NoModuleSocket* pSocket : d->sockets) {
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
    d->jobs.insert(pJob);
}

void NoModule::CancelJob(NoModuleJob* pJob)
{
    if (pJob == nullptr) return;
    // Destructor calls UnlinkJob and removes the job from d->jobs
    NoThreadPool::Get().cancelJob(pJob);
}

bool NoModule::CancelJob(const NoString& sJobName)
{
    for (NoModuleJob* pJob : d->jobs) {
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

    // Destructor calls UnlinkJob and removes the jobs from d->jobs
    NoThreadPool::Get().cancelJobs(sPlainJobs);
}

bool NoModule::UnlinkJob(NoModuleJob* pJob) { return 0 != d->jobs.erase(pJob); }
#endif

bool NoModule::AddCommand(const NoModuleCommand& Command)
{
    if (Command.GetFunction() == nullptr) return false;
    if (Command.GetCommand().contains(" ")) return false;
    if (FindCommand(Command.GetCommand()) != nullptr) return false;

    d->commands[Command.GetCommand()] = Command;
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

bool NoModule::RemCommand(const NoString& sCmd) { return d->commands.erase(sCmd) > 0; }

const NoModuleCommand* NoModule::FindCommand(const NoString& sCmd) const
{
    for (const auto& it : d->commands) {
        if (!it.first.equals(sCmd)) continue;
        return &it.second;
    }
    return nullptr;
}

bool NoModule::HandleCommand(const NoString& sLine)
{
    const NoString& sCmd = No::token(sLine, 0);
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
    NoString sFilter = No::token(sLine, 1).toLower();
    NoTable Table;

    NoModuleCommand::InitHelp(Table);
    for (const auto& it : d->commands) {
        NoString sCmd = it.second.GetCommand().toLower();
        if (sFilter.empty() || (sCmd.startsWith(sFilter, No::CaseSensitive)) || No::wildCmp(sCmd, sFilter)) {
            it.second.AddHelp(Table);
        }
    }
    if (Table.empty()) {
        PutModule("No matches for '" + sFilter + "'");
    } else {
        PutModule(Table);
    }
}

NoString NoModule::GetModNick() const { return (d->user ? d->user->GetStatusPrefix() : "*") + d->name; }

const NoString& NoModule::GetModDataDir() const { return d->dataDir; }

// Webmods
bool NoModule::OnWebPreRequest(NoWebSocket& WebSock, const NoString& sPageName) { return false; }
bool NoModule::OnWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) { return false; }

void NoModule::AddSubPage(std::shared_ptr<NoWebPage> spSubPage) { d->subPages.push_back(spSubPage); }

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
NoModule::ModRet NoModule::OnIRCConnecting(NoIrcSocket* IRCSock) { return CONTINUE; }
void NoModule::OnIRCConnectionError(NoIrcSocket* IRCSock) {}
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
    if (d->commands.empty())
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

NoModuleHandle NoModule::GetDLL() { return d->handle; }

double NoModule::GetCoreVersion() { return NO_VERSION; }

bool NoModule::OnServerCapAvailable(const NoString& sCap) { return false; }
void NoModule::OnServerCapResult(const NoString& sCap, bool bSuccess) {}

bool NoModule::PutIRC(const NoString& sLine) { return (d->network) ? d->network->PutIRC(sLine) : false; }
bool NoModule::PutUser(const NoString& sLine) { return (d->network) ? d->network->PutUser(sLine, d->client) : false; }
bool NoModule::PutStatus(const NoString& sLine) { return (d->network) ? d->network->PutStatus(sLine, d->client) : false; }
uint NoModule::PutModule(const NoTable& table)
{
    if (!d->user) return 0;

    uint idx = 0;
    NoString sLine;
    while (table.GetLine(idx++, sLine)) PutModule(sLine);
    return idx - 1;
}
bool NoModule::PutModule(const NoString& sLine)
{
    if (d->client) {
        d->client->PutModule(GetModName(), sLine);
        return true;
    }

    if (d->network) {
        return d->network->PutModule(GetModName(), sLine);
    }

    if (d->user) {
        return d->user->PutModule(GetModName(), sLine);
    }

    return false;
}
bool NoModule::PutModNotice(const NoString& sLine)
{
    if (!d->user) return false;

    if (d->client) {
        d->client->PutModNotice(GetModName(), sLine);
        return true;
    }

    return d->user->PutModNotice(GetModName(), sLine);
}

const NoString& NoModule::GetModName() const { return d->name; }

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
