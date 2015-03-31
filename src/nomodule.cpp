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

NoModule::NoModule(NoModuleHandle pDLL, NoUser* user, NoNetwork* network, const NoString& sModName, const NoString& sDataDir, No::ModuleType eType)
    : d(new NoModulePrivate(pDLL, user, network, sModName, sDataDir, eType))
{
    if (network) {
        d->savePath = network->networkPath() + "/moddata/" + sModName;
    } else if (user) {
        d->savePath = user->userPath() + "/moddata/" + sModName;
    } else {
        d->savePath = noApp->appPath() + "/moddata/" + sModName;
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

void NoModule::setUser(NoUser* user)
{
    d->user = user;
}
void NoModule::setNetwork(NoNetwork* network)
{
    d->network = network;
}
void NoModule::setClient(NoClient* client)
{
    d->client = client;
}

void NoModule::unload()
{
    throw UNLOAD;
}

NoString NoModule::expandString(const NoString& str) const
{
    NoString ret;
    return expandString(str, ret);
}

NoString& NoModule::expandString(const NoString& str, NoString& ret) const
{
    ret = str;

    if (d->network) {
        return d->network->expandString(ret, ret);
    }

    if (d->user) {
        return d->user->expandString(ret, ret);
    }

    return ret;
}

void NoModule::setType(No::ModuleType eType)
{
    d->type = eType;
}

void NoModule::setDescription(const NoString& s)
{
    d->description = s;
}

void NoModule::setModulePath(const NoString& s)
{
    d->path = s;
}

void NoModule::setArgs(const NoString& s)
{
    d->args = s;
}

No::ModuleType NoModule::type() const
{
    return d->type;
}

NoString NoModule::description() const
{
    return d->description;
}

NoString NoModule::args() const
{
    return d->args;
}

NoString NoModule::modulePath() const
{
    return d->path;
}

NoUser* NoModule::user() const
{
    return d->user;
}

NoNetwork* NoModule::network() const
{
    return d->network;
}

NoClient* NoModule::client() const
{
    return d->client;
}

NoSocketManager* NoModule::manager() const
{
    return d->manager;
}

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

NoModuleSocket* NoModule::findSocket(const NoString& name) const
{
    for (NoModuleSocket* pSocket : d->sockets) {
        if (pSocket->name().equals(name)) {
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
        Table.setValue("Name", pSocket->name());

        if (pSocket->isListener()) {
            Table.setValue("State", "Listening");
        } else {
            Table.setValue("State", (pSocket->isConnected() ? "Connected" : ""));
        }

        Table.setValue("LocalPort", NoString(pSocket->localPort()));
        Table.setValue("SSL", (pSocket->isSsl() ? "yes" : "no"));
        Table.setValue("RemoteIP", pSocket->remoteAddress());
        Table.setValue("RemotePort", (pSocket->remotePort()) ? NoString(pSocket->remotePort()) : NoString(""));
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
    if (pJob == nullptr)
        return;
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

bool NoModule::unlinkJob(NoModuleJob* pJob)
{
    return 0 != d->jobs.erase(pJob);
}
#endif

bool NoModule::addCommand(const NoModuleCommand& Command)
{
    if (Command.function() == nullptr)
        return false;
    if (Command.command().contains(" "))
        return false;
    if (findCommand(Command.command()) != nullptr)
        return false;

    d->commands[Command.command()] = Command;
    return true;
}

bool NoModule::addCommand(const NoString& cmd, NoModuleCommand::ModCmdFunc func, const NoString& args, const NoString& desc)
{
    return addCommand(NoModuleCommand(cmd, this, func, args, desc));
}

bool NoModule::addCommand(const NoString& cmd, const NoString& args, const NoString& desc, std::function<void(const NoString& line)> func)
{
    return addCommand(std::move(NoModuleCommand(cmd, std::move(func), args, desc)));
}

void NoModule::addHelpCommand()
{
    addCommand("Help", &NoModule::handleHelpCommand, "search", "Generate this output");
}

bool NoModule::removeCommand(const NoString& cmd)
{
    return d->commands.erase(cmd) > 0;
}

const NoModuleCommand* NoModule::findCommand(const NoString& cmd) const
{
    for (const auto& it : d->commands) {
        if (!it.first.equals(cmd))
            continue;
        return &it.second;
    }
    return nullptr;
}

bool NoModule::handleCommand(const NoString& line)
{
    const NoString& cmd = No::token(line, 0);
    const NoModuleCommand* pCmd = findCommand(cmd);

    if (pCmd) {
        pCmd->call(line);
        return true;
    }

    onUnknownModCommand(line);

    return false;
}

void NoModule::handleHelpCommand(const NoString& line)
{
    NoString filter = No::token(line, 1).toLower();
    NoTable Table;

    NoModuleCommand::initHelp(Table);
    for (const auto& it : d->commands) {
        NoString cmd = it.second.command().toLower();
        if (filter.empty() || (cmd.startsWith(filter, No::CaseSensitive)) || No::wildCmp(cmd, filter)) {
            it.second.addHelp(Table);
        }
    }
    if (Table.isEmpty()) {
        putModule("No matches for '" + filter + "'");
    } else {
        putModule(Table);
    }
}

NoString NoModule::moduleNick() const
{
    return (d->user ? d->user->statusPrefix() : "*") + d->name;
}

NoString NoModule::moduleDataDir() const
{
    return d->dataDir;
}

// Webmods
bool NoModule::onWebPreRequest(NoWebSocket& WebSock, const NoString& sPageName)
{
    return false;
}
bool NoModule::onWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl)
{
    return false;
}

void NoModule::addSubPage(std::shared_ptr<NoWebPage> spSubPage)
{
    d->subPages.push_back(spSubPage);
}

bool NoModule::onEmbeddedWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl)
{
    return false;
}
// !Webmods

bool NoModule::onLoad(const NoString& args, NoString& sMessage)
{
    sMessage = "";
    return true;
}
bool NoModule::onBoot()
{
    return true;
}

bool NoModule::webRequiresLogin()
{
    return true;
}

bool NoModule::webRequiresAdmin()
{
    return false;
}

NoString NoModule::webMenuTitle()
{
    return "";
}
void NoModule::onPreRehash()
{
}
void NoModule::onPostRehash()
{
}
void NoModule::onIrcDisconnected()
{
}
void NoModule::onIrcConnected()
{
}
NoModule::ModRet NoModule::onIrcConnecting(NoIrcSocket* IRCSock)
{
    return CONTINUE;
}
void NoModule::onIrcConnectionError(NoIrcSocket* IRCSock)
{
}
NoModule::ModRet NoModule::onIrcRegistration(NoString& pass, NoString& nick, NoString& ident, NoString& sRealName)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onBroadcast(NoString& sMessage)
{
    return CONTINUE;
}

void NoModule::onChanPermission2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange)
{
    if (pOpNick)
        onChanPermission(*pOpNick, Nick, Channel, uMode, bAdded, bNoChange);
}
void NoModule::onOp2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    if (pOpNick)
        onOp(*pOpNick, Nick, Channel, bNoChange);
}
void NoModule::onDeop2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    if (pOpNick)
        onDeop(*pOpNick, Nick, Channel, bNoChange);
}
void NoModule::onVoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    if (pOpNick)
        onVoice(*pOpNick, Nick, Channel, bNoChange);
}
void NoModule::onDevoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    if (pOpNick)
        onDevoice(*pOpNick, Nick, Channel, bNoChange);
}
void NoModule::onRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& args)
{
    if (pOpNick)
        onRawMode(*pOpNick, Channel, sModes, args);
}
void NoModule::onMode2(const NoNick* pOpNick, NoChannel& Channel, char uMode, const NoString& arg, bool bAdded, bool bNoChange)
{
    if (pOpNick)
        onMode(*pOpNick, Channel, uMode, arg, bAdded, bNoChange);
}

void NoModule::onChanPermission(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange)
{
}
void NoModule::onOp(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
}
void NoModule::onDeop(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
}
void NoModule::onVoice(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
}
void NoModule::onDevoice(const NoNick& pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
}
void NoModule::onRawMode(const NoNick& pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& args)
{
}
void NoModule::onMode(const NoNick& pOpNick, NoChannel& Channel, char uMode, const NoString& arg, bool bAdded, bool bNoChange)
{
}

NoModule::ModRet NoModule::onRaw(NoString& line)
{
    return CONTINUE;
}

NoModule::ModRet NoModule::onStatusCommand(NoString& command)
{
    return CONTINUE;
}
void NoModule::onModNotice(const NoString& sMessage)
{
}
void NoModule::onModCTCP(const NoString& sMessage)
{
}

void NoModule::onModCommand(const NoString& command)
{
    handleCommand(command);
}
void NoModule::onUnknownModCommand(const NoString& line)
{
    if (d->commands.empty())
        // This function is only called if onModCommand wasn't
        // overriden, so no false warnings for modules which don't use
        // NoModuleCommand for command handling.
        putModule("This module doesn't implement any commands.");
    else
        putModule("Unknown command!");
}

void NoModule::onQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& channels)
{
}
void NoModule::onNick(const NoNick& Nick, const NoString& sNewNick, const std::vector<NoChannel*>& channels)
{
}
void NoModule::onKick(const NoNick& Nick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage)
{
}
NoModule::ModRet NoModule::onJoining(NoChannel& Channel)
{
    return CONTINUE;
}
void NoModule::onJoin(const NoNick& Nick, NoChannel& Channel)
{
}
void NoModule::onPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage)
{
}
NoModule::ModRet NoModule::onInvite(const NoNick& Nick, const NoString& sChan)
{
    return CONTINUE;
}

NoModule::ModRet NoModule::onChanBufferStarting(NoChannel& Chan, NoClient& Client)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onChanBufferEnding(NoChannel& Chan, NoClient& Client)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onChanBufferPlayLine(NoChannel& Chan, NoClient& Client, NoString& line)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onPrivBufferPlayLine(NoClient& Client, NoString& line)
{
    return CONTINUE;
}

NoModule::ModRet NoModule::onChanBufferPlayLine2(NoChannel& Chan, NoClient& Client, NoString& line, const timeval& tv)
{
    return onChanBufferPlayLine(Chan, Client, line);
}
NoModule::ModRet NoModule::onPrivBufferPlayLine2(NoClient& Client, NoString& line, const timeval& tv)
{
    return onPrivBufferPlayLine(Client, line);
}

void NoModule::onClientLogin()
{
}
void NoModule::onClientDisconnect()
{
}
NoModule::ModRet NoModule::onUserRaw(NoString& line)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserCtcpReply(NoString& sTarget, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserCtcp(NoString& sTarget, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserAction(NoString& sTarget, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserMsg(NoString& sTarget, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserNotice(NoString& sTarget, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserJoin(NoString& sChannel, NoString& sKey)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserPart(NoString& sChannel, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserTopic(NoString& sChannel, NoString& sTopic)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserTopicRequest(NoString& sChannel)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserQuit(NoString& sMessage)
{
    return CONTINUE;
}

NoModule::ModRet NoModule::onCtcpReply(NoNick& Nick, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onPrivCtcp(NoNick& Nick, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onChanCtcp(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onPrivAction(NoNick& Nick, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onPrivMsg(NoNick& Nick, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onPrivNotice(NoNick& Nick, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onTimerAutoJoin(NoChannel& Channel)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onAddNetwork(NoNetwork& Network, NoString& sErrorRet)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onDeleteNetwork(NoNetwork& Network)
{
    return CONTINUE;
}

NoModule::ModRet NoModule::onSendToClient(NoString& line, NoClient& Client)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onSendToIrc(NoString& line)
{
    return CONTINUE;
}

NoModuleHandle NoModule::GetDLL()
{
    return d->handle;
}

double NoModule::GetCoreVersion()
{
    return NO_VERSION;
}

bool NoModule::onServerCapAvailable(const NoString& cap)
{
    return false;
}
void NoModule::onServerCapResult(const NoString& cap, bool bSuccess)
{
}

bool NoModule::putIrc(const NoString& line)
{
    return (d->network) ? d->network->putIrc(line) : false;
}
bool NoModule::putUser(const NoString& line)
{
    return (d->network) ? d->network->putUser(line, d->client) : false;
}
bool NoModule::putStatus(const NoString& line)
{
    return (d->network) ? d->network->putStatus(line, d->client) : false;
}
uint NoModule::putModule(const NoTable& table)
{
    if (!d->user)
        return 0;

    NoStringVector lines = table.toString();
    for (const NoString& line : lines)
        putModule(line);
    return lines.size() - 1;
}
bool NoModule::putModule(const NoString& line)
{
    if (d->client) {
        d->client->putModule(moduleName(), line);
        return true;
    }

    if (d->network) {
        return d->network->putModule(moduleName(), line);
    }

    if (d->user) {
        return d->user->putModule(moduleName(), line);
    }

    return false;
}
bool NoModule::putModuleNotice(const NoString& line)
{
    if (!d->user)
        return false;

    if (d->client) {
        d->client->putModuleNotice(moduleName(), line);
        return true;
    }

    return d->user->putModuleNotice(moduleName(), line);
}

NoString NoModule::moduleName() const
{
    return d->name;
}

///////////////////
// Global Module //
///////////////////
NoModule::ModRet NoModule::onAddUser(NoUser& User, NoString& sErrorRet)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onDeleteUser(NoUser& User)
{
    return CONTINUE;
}
void NoModule::onClientConnect(NoSocket* client, const NoString& host, ushort port)
{
}
NoModule::ModRet NoModule::onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth)
{
    return CONTINUE;
}
void NoModule::onFailedLogin(const NoString& sUsername, const NoString& sRemoteIP)
{
}
NoModule::ModRet NoModule::onUnknownUserRaw(NoClient* client, NoString& line)
{
    return CONTINUE;
}
void NoModule::onClientCapLs(NoClient* client, NoStringSet& ssCaps)
{
}
bool NoModule::isClientCapSupported(NoClient* client, const NoString& cap, bool bState)
{
    return false;
}
void NoModule::onClientCapRequest(NoClient* client, const NoString& cap, bool bState)
{
}
NoModule::ModRet
NoModule::onModuleLoading(const NoString& sModName, const NoString& args, No::ModuleType eType, bool& bSuccess, NoString& sRetMsg)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onModuleUnloading(NoModule* pModule, bool& bSuccess, NoString& sRetMsg)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onGetModuleInfo(NoModuleInfo& ModInfo, const NoString& module, bool& bSuccess, NoString& sRetMsg)
{
    return CONTINUE;
}
void NoModule::onGetAvailableModules(std::set<NoModuleInfo>& ssMods, No::ModuleType eType)
{
}
