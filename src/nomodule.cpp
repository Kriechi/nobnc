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
#include "nothread.h"
#include "nomodulesocket.h"
#include <dlfcn.h>

NoModule::NoModule(NoModuleHandle pDLL, NoUser* pUser, NoNetwork* pNetwork, const NoString& sModName, const NoString& sDataDir, No::ModuleType eType)
    : d(new NoModulePrivate(pDLL, pUser, pNetwork, sModName, sDataDir, eType))
{
    if (pNetwork) {
        d->savePath = pNetwork->networkPath() + "/moddata/" + sModName;
    } else if (pUser) {
        d->savePath = pUser->userPath() + "/moddata/" + sModName;
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
        return d->network->expandString(sRet, sRet);
    }

    if (d->user) {
        return d->user->expandString(sRet, sRet);
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
        return "/mods/network/" + d->network->name() + "/" + GetModName() + "/";
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
        return "/modfiles/network/" + d->network->name() + "/" + GetModName() + "/";
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
    Table.addColumn("Name");
    Table.addColumn("Secs");
    Table.addColumn("Cycles");
    Table.addColumn("Description");

    for (const NoTimer* pTimer : d->timers) {
        Table.addRow();
        Table.setValue("Name", pTimer->name());
        Table.setValue("Interval", NoString(pTimer->interval()) + " seconds");
        Table.setValue("Description", pTimer->description());
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
    Table.addColumn("Name");
    Table.addColumn("State");
    Table.addColumn("LocalPort");
    Table.addColumn("SSL");
    Table.addColumn("RemoteIP");
    Table.addColumn("RemotePort");

    for (const NoModuleSocket* pSocket : d->sockets) {
        Table.addRow();
        Table.setValue("Name", pSocket->GetSockName());

        if (pSocket->IsListener()) {
            Table.setValue("State", "Listening");
        } else {
            Table.setValue("State", (pSocket->IsConnected() ? "Connected" : ""));
        }

        Table.setValue("LocalPort", NoString(pSocket->GetLocalPort()));
        Table.setValue("SSL", (pSocket->GetSSL() ? "yes" : "no"));
        Table.setValue("RemoteIP", pSocket->GetRemoteIP());
        Table.setValue("RemotePort", (pSocket->GetRemotePort()) ? NoString(pSocket->GetRemotePort()) : NoString(""));
    }

    PutModule(Table);
}

#ifdef HAVE_PTHREAD
void NoModule::AddJob(NoModuleJob* pJob)
{
    NoThread::run(pJob);
    d->jobs.insert(pJob);
}

void NoModule::CancelJob(NoModuleJob* pJob)
{
    if (pJob == nullptr) return;
    // Destructor calls UnlinkJob and removes the job from d->jobs
    NoThread::cancel(pJob);
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
    for (NoModuleJob* job : sJobs) {
        // Destructor calls UnlinkJob and removes the jobs from d->jobs
        NoThread::cancel(job);
    }
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
    if (Table.isEmpty()) {
        PutModule("No matches for '" + sFilter + "'");
    } else {
        PutModule(Table);
    }
}

NoString NoModule::GetModNick() const { return (d->user ? d->user->statusPrefix() : "*") + d->name; }

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
bool NoModule::onBoot() { return true; }

bool NoModule::WebRequiresLogin() { return true; }

bool NoModule::WebRequiresAdmin() { return false; }

NoString NoModule::GetWebMenuTitle() { return ""; }
void NoModule::onPreRehash() {}
void NoModule::onPostRehash() {}
void NoModule::onIrcDisconnected() {}
void NoModule::onIrcConnected() {}
NoModule::ModRet NoModule::onIrcConnecting(NoIrcSocket* IRCSock) { return CONTINUE; }
void NoModule::onIrcConnectionError(NoIrcSocket* IRCSock) {}
NoModule::ModRet NoModule::onIrcRegistration(NoString& sPass, NoString& sNick, NoString& sIdent, NoString& sRealName)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onBroadcast(NoString& sMessage) { return CONTINUE; }

void NoModule::onChanPermission2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange)
{
    if (pOpNick) onChanPermission(*pOpNick, Nick, Channel, uMode, bAdded, bNoChange);
}
void NoModule::onOp2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    if (pOpNick) onOp(*pOpNick, Nick, Channel, bNoChange);
}
void NoModule::onDeop2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    if (pOpNick) onDeop(*pOpNick, Nick, Channel, bNoChange);
}
void NoModule::onVoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    if (pOpNick) onVoice(*pOpNick, Nick, Channel, bNoChange);
}
void NoModule::onDevoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    if (pOpNick) onDevoice(*pOpNick, Nick, Channel, bNoChange);
}
void NoModule::onRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs)
{
    if (pOpNick) onRawMode(*pOpNick, Channel, sModes, sArgs);
}
void NoModule::onMode2(const NoNick* pOpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange)
{
    if (pOpNick) onMode(*pOpNick, Channel, uMode, sArg, bAdded, bNoChange);
}

void NoModule::onChanPermission(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange)
{
}
void NoModule::onOp(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) {}
void NoModule::onDeop(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) {}
void NoModule::onVoice(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) {}
void NoModule::onDevoice(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) {}
void NoModule::onRawMode(const NoNick& pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs) {}
void NoModule::onMode(const NoNick& pOpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange)
{
}

NoModule::ModRet NoModule::onRaw(NoString& sLine) { return CONTINUE; }

NoModule::ModRet NoModule::onStatusCommand(NoString& sCommand) { return CONTINUE; }
void NoModule::onModNotice(const NoString& sMessage) {}
void NoModule::onModCTCP(const NoString& sMessage) {}

void NoModule::onModCommand(const NoString& sCommand) { HandleCommand(sCommand); }
void NoModule::OnUnknownModCommand(const NoString& sLine)
{
    if (d->commands.empty())
        // This function is only called if onModCommand wasn't
        // overriden, so no false warnings for modules which don't use
        // NoModuleCommand for command handling.
        PutModule("This module doesn't implement any commands.");
    else
        PutModule("Unknown command!");
}

void NoModule::onQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans) {}
void NoModule::onNick(const NoNick& Nick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans) {}
void NoModule::onKick(const NoNick& Nick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage) {}
NoModule::ModRet NoModule::onJoining(NoChannel& Channel) { return CONTINUE; }
void NoModule::onJoin(const NoNick& Nick, NoChannel& Channel) {}
void NoModule::onPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage) {}
NoModule::ModRet NoModule::onInvite(const NoNick& Nick, const NoString& sChan) { return CONTINUE; }

NoModule::ModRet NoModule::onChanBufferStarting(NoChannel& Chan, NoClient& Client) { return CONTINUE; }
NoModule::ModRet NoModule::onChanBufferEnding(NoChannel& Chan, NoClient& Client) { return CONTINUE; }
NoModule::ModRet NoModule::onChanBufferPlayLine(NoChannel& Chan, NoClient& Client, NoString& sLine) { return CONTINUE; }
NoModule::ModRet NoModule::onPrivBufferPlayLine(NoClient& Client, NoString& sLine) { return CONTINUE; }

NoModule::ModRet NoModule::onChanBufferPlayLine2(NoChannel& Chan, NoClient& Client, NoString& sLine, const timeval& tv)
{
    return onChanBufferPlayLine(Chan, Client, sLine);
}
NoModule::ModRet NoModule::onPrivBufferPlayLine2(NoClient& Client, NoString& sLine, const timeval& tv)
{
    return onPrivBufferPlayLine(Client, sLine);
}

void NoModule::onClientLogin() {}
void NoModule::onClientDisconnect() {}
NoModule::ModRet NoModule::onUserRaw(NoString& sLine) { return CONTINUE; }
NoModule::ModRet NoModule::onUserCtcpReply(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onUserCtcp(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onUserAction(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onUserMsg(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onUserNotice(NoString& sTarget, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onUserJoin(NoString& sChannel, NoString& sKey) { return CONTINUE; }
NoModule::ModRet NoModule::onUserPart(NoString& sChannel, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onUserTopic(NoString& sChannel, NoString& sTopic) { return CONTINUE; }
NoModule::ModRet NoModule::onUserTopicRequest(NoString& sChannel) { return CONTINUE; }
NoModule::ModRet NoModule::onUserQuit(NoString& sMessage) { return CONTINUE; }

NoModule::ModRet NoModule::onCtcpReply(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onPrivCtcp(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onChanCtcp(NoNick& Nick, NoChannel& Channel, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onPrivAction(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onPrivMsg(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onPrivNotice(NoNick& Nick, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage) { return CONTINUE; }
NoModule::ModRet NoModule::onTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic) { return CONTINUE; }
NoModule::ModRet NoModule::onTimerAutoJoin(NoChannel& Channel) { return CONTINUE; }
NoModule::ModRet NoModule::onAddNetwork(NoNetwork& Network, NoString& sErrorRet) { return CONTINUE; }
NoModule::ModRet NoModule::onDeleteNetwork(NoNetwork& Network) { return CONTINUE; }

NoModule::ModRet NoModule::onSendToClient(NoString& sLine, NoClient& Client) { return CONTINUE; }
NoModule::ModRet NoModule::onSendToIrc(NoString& sLine) { return CONTINUE; }

NoModuleHandle NoModule::GetDLL() { return d->handle; }

double NoModule::GetCoreVersion() { return NO_VERSION; }

bool NoModule::onServerCapAvailable(const NoString& sCap) { return false; }
void NoModule::onServerCapResult(const NoString& sCap, bool bSuccess) {}

bool NoModule::PutIRC(const NoString& sLine) { return (d->network) ? d->network->putIrc(sLine) : false; }
bool NoModule::PutUser(const NoString& sLine) { return (d->network) ? d->network->putUser(sLine, d->client) : false; }
bool NoModule::PutStatus(const NoString& sLine) { return (d->network) ? d->network->putStatus(sLine, d->client) : false; }
uint NoModule::PutModule(const NoTable& table)
{
    if (!d->user) return 0;

    NoStringVector lines = table.toString();
    for (const NoString& line : lines)
        PutModule(line);
    return lines.size() - 1;
}
bool NoModule::PutModule(const NoString& sLine)
{
    if (d->client) {
        d->client->PutModule(GetModName(), sLine);
        return true;
    }

    if (d->network) {
        return d->network->putModule(GetModName(), sLine);
    }

    if (d->user) {
        return d->user->putModule(GetModName(), sLine);
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

    return d->user->putModuleNotice(GetModName(), sLine);
}

const NoString& NoModule::GetModName() const { return d->name; }

///////////////////
// Global Module //
///////////////////
NoModule::ModRet NoModule::onAddUser(NoUser& User, NoString& sErrorRet) { return CONTINUE; }
NoModule::ModRet NoModule::onDeleteUser(NoUser& User) { return CONTINUE; }
void NoModule::onClientConnect(NoSocket* pClient, const NoString& sHost, ushort uPort) {}
NoModule::ModRet NoModule::onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth) { return CONTINUE; }
void NoModule::onFailedLogin(const NoString& sUsername, const NoString& sRemoteIP) {}
NoModule::ModRet NoModule::onUnknownUserRaw(NoClient* pClient, NoString& sLine) { return CONTINUE; }
void NoModule::onClientCapLs(NoClient* pClient, NoStringSet& ssCaps) {}
bool NoModule::isClientCapSupported(NoClient* pClient, const NoString& sCap, bool bState) { return false; }
void NoModule::onClientCapRequest(NoClient* pClient, const NoString& sCap, bool bState) {}
NoModule::ModRet
NoModule::onModuleLoading(const NoString& sModName, const NoString& sArgs, No::ModuleType eType, bool& bSuccess, NoString& sRetMsg)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onModuleUnloading(NoModule* pModule, bool& bSuccess, NoString& sRetMsg) { return CONTINUE; }
NoModule::ModRet NoModule::onGetModuleInfo(NoModuleInfo& ModInfo, const NoString& sModule, bool& bSuccess, NoString& sRetMsg)
{
    return CONTINUE;
}
void NoModule::onGetAvailableModules(std::set<NoModuleInfo>& ssMods, No::ModuleType eType) {}
