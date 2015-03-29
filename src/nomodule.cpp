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
#include "nofile.h"
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
    cancelJobs(d->jobs);
#endif
}

void NoModule::setUser(NoUser* pUser) { d->user = pUser; }
void NoModule::setNetwork(NoNetwork* pNetwork) { d->network = pNetwork; }
void NoModule::setClient(NoClient* pClient) { d->client = pClient; }

void NoModule::unload() { throw UNLOAD; }

NoString NoModule::expandString(const NoString& sStr) const
{
    NoString sRet;
    return expandString(sStr, sRet);
}

NoString& NoModule::expandString(const NoString& sStr, NoString& sRet) const
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

void NoModule::setType(No::ModuleType eType) { d->type = eType; }

void NoModule::setDescription(const NoString& s) { d->description = s; }

void NoModule::setModulePath(const NoString& s) { d->path = s; }

void NoModule::setArgs(const NoString& s) { d->args = s; }

No::ModuleType NoModule::type() const { return d->type; }

NoString NoModule::description() const { return d->description; }

NoString NoModule::args() const { return d->args; }

NoString NoModule::modulePath() const { return d->path; }

NoUser* NoModule::user() const { return d->user; }

NoNetwork* NoModule::network() const { return d->network; }

NoClient* NoModule::client() const { return d->client; }

NoSocketManager* NoModule::manager() const { return d->manager; }

NoString NoModule::savePath() const
{
    if (!NoFile::Exists(d->savePath)) {
        NoDir::mkpath(d->savePath);
    }
    return d->savePath;
}

NoString NoModule::webPath()
{
    switch (d->type) {
    case No::GlobalModule:
        return "/mods/global/" + moduleName() + "/";
    case No::UserModule:
        return "/mods/user/" + moduleName() + "/";
    case No::NetworkModule:
        return "/mods/network/" + d->network->name() + "/" + moduleName() + "/";
    default:
        return "/";
    }
}

NoString NoModule::webFilesPath()
{
    switch (d->type) {
    case No::GlobalModule:
        return "/modfiles/global/" + moduleName() + "/";
    case No::UserModule:
        return "/modfiles/user/" + moduleName() + "/";
    case No::NetworkModule:
        return "/modfiles/network/" + d->network->name() + "/" + moduleName() + "/";
    default:
        return "/";
    }
}

NoTimer* NoModule::findTimer(const NoString& sLabel) const
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

void NoModule::listTimers()
{
    if (d->timers.empty()) {
        putModule("You have no timers running.");
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

    putModule(Table);
}

NoModuleSocket* NoModule::findSocket(const NoString& sName) const
{
    for (NoModuleSocket* pSocket : d->sockets) {
        if (pSocket->GetSockName().equals(sName)) {
            return pSocket;
        }
    }

    return nullptr;
}

void NoModule::listSockets()
{
    if (d->sockets.empty()) {
        putModule("You have no open sockets.");
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

    putModule(Table);
}

#ifdef HAVE_PTHREAD
void NoModule::addJob(NoModuleJob* pJob)
{
    NoThread::run(pJob);
    d->jobs.insert(pJob);
}

void NoModule::cancelJob(NoModuleJob* pJob)
{
    if (pJob == nullptr) return;
    // Destructor calls UnlinkJob and removes the job from d->jobs
    NoThread::cancel(pJob);
}

bool NoModule::cancelJob(const NoString& sJobName)
{
    for (NoModuleJob* pJob : d->jobs) {
        if (pJob->name().equals(sJobName)) {
            cancelJob(pJob);
            return true;
        }
    }
    return false;
}

void NoModule::cancelJobs(const std::set<NoModuleJob*>& sJobs)
{
    for (NoModuleJob* job : sJobs) {
        // Destructor calls UnlinkJob and removes the jobs from d->jobs
        NoThread::cancel(job);
    }
}

bool NoModule::unlinkJob(NoModuleJob* pJob) { return 0 != d->jobs.erase(pJob); }
#endif

bool NoModule::addCommand(const NoModuleCommand& Command)
{
    if (Command.function() == nullptr) return false;
    if (Command.command().contains(" ")) return false;
    if (findCommand(Command.command()) != nullptr) return false;

    d->commands[Command.command()] = Command;
    return true;
}

bool NoModule::addCommand(const NoString& sCmd, NoModuleCommand::ModCmdFunc func, const NoString& sArgs, const NoString& sDesc)
{
    NoModuleCommand cmd(sCmd, this, func, sArgs, sDesc);
    return addCommand(cmd);
}

bool NoModule::addCommand(const NoString& sCmd, const NoString& sArgs, const NoString& sDesc, std::function<void(const NoString& sLine)> func)
{
    NoModuleCommand cmd(sCmd, std::move(func), sArgs, sDesc);
    return addCommand(std::move(cmd));
}

void NoModule::addHelpCommand() { addCommand("Help", &NoModule::handleHelpCommand, "search", "Generate this output"); }

bool NoModule::removeCommand(const NoString& sCmd) { return d->commands.erase(sCmd) > 0; }

const NoModuleCommand* NoModule::findCommand(const NoString& sCmd) const
{
    for (const auto& it : d->commands) {
        if (!it.first.equals(sCmd)) continue;
        return &it.second;
    }
    return nullptr;
}

bool NoModule::handleCommand(const NoString& sLine)
{
    const NoString& sCmd = No::token(sLine, 0);
    const NoModuleCommand* pCmd = findCommand(sCmd);

    if (pCmd) {
        pCmd->call(sLine);
        return true;
    }

    onUnknownModCommand(sLine);

    return false;
}

void NoModule::handleHelpCommand(const NoString& sLine)
{
    NoString sFilter = No::token(sLine, 1).toLower();
    NoTable Table;

    NoModuleCommand::initHelp(Table);
    for (const auto& it : d->commands) {
        NoString sCmd = it.second.command().toLower();
        if (sFilter.empty() || (sCmd.startsWith(sFilter, No::CaseSensitive)) || No::wildCmp(sCmd, sFilter)) {
            it.second.addHelp(Table);
        }
    }
    if (Table.isEmpty()) {
        putModule("No matches for '" + sFilter + "'");
    } else {
        putModule(Table);
    }
}

NoString NoModule::moduleNick() const { return (d->user ? d->user->statusPrefix() : "*") + d->name; }

NoString NoModule::moduleDataDir() const { return d->dataDir; }

// Webmods
bool NoModule::onWebPreRequest(NoWebSocket& WebSock, const NoString& sPageName) { return false; }
bool NoModule::onWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) { return false; }

void NoModule::addSubPage(std::shared_ptr<NoWebPage> spSubPage) { d->subPages.push_back(spSubPage); }

bool NoModule::onEmbeddedWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) { return false; }
// !Webmods

bool NoModule::onLoad(const NoString& sArgs, NoString& sMessage)
{
    sMessage = "";
    return true;
}
bool NoModule::onBoot() { return true; }

bool NoModule::webRequiresLogin() { return true; }

bool NoModule::webRequiresAdmin() { return false; }

NoString NoModule::webMenuTitle() { return ""; }
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

void NoModule::onModCommand(const NoString& sCommand) { handleCommand(sCommand); }
void NoModule::onUnknownModCommand(const NoString& sLine)
{
    if (d->commands.empty())
        // This function is only called if onModCommand wasn't
        // overriden, so no false warnings for modules which don't use
        // NoModuleCommand for command handling.
        putModule("This module doesn't implement any commands.");
    else
        putModule("Unknown command!");
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

bool NoModule::putIrc(const NoString& sLine) { return (d->network) ? d->network->putIrc(sLine) : false; }
bool NoModule::putUser(const NoString& sLine) { return (d->network) ? d->network->putUser(sLine, d->client) : false; }
bool NoModule::putStatus(const NoString& sLine) { return (d->network) ? d->network->putStatus(sLine, d->client) : false; }
uint NoModule::putModule(const NoTable& table)
{
    if (!d->user) return 0;

    NoStringVector lines = table.toString();
    for (const NoString& line : lines)
        putModule(line);
    return lines.size() - 1;
}
bool NoModule::putModule(const NoString& sLine)
{
    if (d->client) {
        d->client->putModule(moduleName(), sLine);
        return true;
    }

    if (d->network) {
        return d->network->putModule(moduleName(), sLine);
    }

    if (d->user) {
        return d->user->putModule(moduleName(), sLine);
    }

    return false;
}
bool NoModule::putModuleNotice(const NoString& sLine)
{
    if (!d->user) return false;

    if (d->client) {
        d->client->putModuleNotice(moduleName(), sLine);
        return true;
    }

    return d->user->putModuleNotice(moduleName(), sLine);
}

NoString NoModule::moduleName() const { return d->name; }

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
