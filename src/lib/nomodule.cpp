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
#include "notimer.h"
#include "notable.h"
#include "noexception.h"
#include <dlfcn.h>

NoModule::NoModule(NoModuleHandle pDLL, NoUser* user, NoNetwork* network, const NoString& name, const NoString& dataDir, No::ModuleType type)
    : d(new NoModulePrivate(pDLL, user, network, name, dataDir, type))
{
    if (network) {
        d->savePath = network->networkPath() + "/moddata/" + name;
    } else if (user) {
        d->savePath = user->userPath() + "/moddata/" + name;
    } else {
        d->savePath = noApp->appPath() + "/moddata/" + name;
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

void NoModule::unload()
{
    throw NoException(NoException::Unload);
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

No::ModuleType NoModule::type() const
{
    return d->type;
}

NoString NoModule::description() const
{
    return d->description;
}

NoString NoModule::modulePath() const
{
    return d->path;
}

NoString NoModule::args() const
{
    return d->args;
}

void NoModule::setArgs(const NoString& s)
{
    d->args = s;
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

NoTimer* NoModule::findTimer(const NoString& label) const
{
    if (label.empty()) {
        return nullptr;
    }

    for (NoTimer* timer : d->timers) {
        if (timer->name().equals(label)) {
            return timer;
        }
    }

    return nullptr;
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

bool NoModule::addCommand(const NoModuleCommand& command)
{
    if (command.function() == nullptr)
        return false;
    if (command.command().contains(" "))
        return false;
    if (findCommand(command.command()) != nullptr)
        return false;

    d->commands[command.command()] = command;
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
bool NoModule::onWebPreRequest(NoWebSocket* socket, const NoString& page)
{
    return false;
}
bool NoModule::onWebRequest(NoWebSocket* socket, const NoString& page, NoTemplate& tmpl)
{
    return false;
}

void NoModule::addSubPage(std::shared_ptr<NoWebPage> page)
{
    d->subPages.push_back(page);
}

bool NoModule::onEmbeddedWebRequest(NoWebSocket* socket, const NoString& page, NoTemplate& tmpl)
{
    return false;
}
// !Webmods

bool NoModule::onLoad(const NoString& args, NoString& message)
{
    message = "";
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
NoModule::ModRet NoModule::onIrcRegistration(NoString& pass, NoString& nick, NoString& ident, NoString& realName)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onBroadcast(NoString& message)
{
    return CONTINUE;
}

void NoModule::onChannelPermission(const NoNick* opNick, const NoNick& nick, NoChannel* channel, uchar mode, bool added, bool noChange)
{
}
void NoModule::onOp(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange)
{
}
void NoModule::onDeop(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange)
{
}
void NoModule::onVoice(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange)
{
}
void NoModule::onDevoice(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange)
{
}
void NoModule::onRawMode(const NoNick* opNick, NoChannel* channel, const NoString& modes, const NoString& args)
{
}
void NoModule::onMode(const NoNick* opNick, NoChannel* channel, char mode, const NoString& arg, bool added, bool noChange)
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
void NoModule::onModNotice(const NoString& message)
{
}
void NoModule::onModCTCP(const NoString& message)
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

void NoModule::onQuit(const NoHostMask& nick, const NoString& message)
{
}
void NoModule::onNick(const NoHostMask& nick, const NoString& newNick)
{
}
void NoModule::onKick(const NoNick& nick, const NoString& sKickedNick, NoChannel* channel, const NoString& message)
{
}
NoModule::ModRet NoModule::onJoining(NoChannel* channel)
{
    return CONTINUE;
}
void NoModule::onJoin(const NoNick& nick, NoChannel* channel)
{
}
void NoModule::onPart(const NoNick& nick, NoChannel* channel, const NoString& message)
{
}
NoModule::ModRet NoModule::onInvite(const NoHostMask& nick, const NoString& sChan)
{
    return CONTINUE;
}

NoModule::ModRet NoModule::onChannelBufferStarting(NoChannel* channel, NoClient* client)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onChannelBufferEnding(NoChannel* channel, NoClient* client)
{
    return CONTINUE;
}

NoModule::ModRet NoModule::onChannelBufferPlayLine(NoChannel* channel, NoClient* client, NoString& line, const timeval& tv)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onPrivateBufferPlayLine(NoClient* client, NoString& line, const timeval& tv)
{
    return CONTINUE;
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
NoModule::ModRet NoModule::onUserCtcpReply(NoString& target, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserCtcp(NoString& target, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserAction(NoString& target, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserMessage(NoString& target, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserNotice(NoString& target, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserJoin(NoString& channel, NoString& key)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserPart(NoString& channel, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserTopic(NoString& channel, NoString& topic)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserTopicRequest(NoString& channel)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onUserQuit(NoString& message)
{
    return CONTINUE;
}

NoModule::ModRet NoModule::onCtcpReply(NoHostMask& nick, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onPrivateCtcp(NoHostMask& nick, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onChannelCtcp(NoNick& nick, NoChannel* channel, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onPrivateAction(NoHostMask& nick, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onChannelAction(NoNick& nick, NoChannel* channel, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onPrivateMessage(NoHostMask& nick, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onChannelMessage(NoNick& nick, NoChannel* channel, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onPrivateNotice(NoHostMask& nick, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onChannelNotice(NoNick& nick, NoChannel* channel, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onTopic(NoNick& nick, NoChannel* channel, NoString& topic)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onTimerAutoJoin(NoChannel* channel)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onAddNetwork(NoNetwork* network, NoString& error)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onDeleteNetwork(NoNetwork* network)
{
    return CONTINUE;
}

NoModule::ModRet NoModule::onSendToClient(NoString& line, NoClient* client)
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
void NoModule::onServerCapResult(const NoString& cap, bool success)
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
NoModule::ModRet NoModule::onAddUser(NoUser* user, NoString& error)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onDeleteUser(NoUser* user)
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
void NoModule::onFailedLogin(const NoString& username, const NoString& sRemoteIP)
{
}
NoModule::ModRet NoModule::onUnknownUserRaw(NoClient* client, NoString& line)
{
    return CONTINUE;
}
void NoModule::onClientCapLs(NoClient* client, NoStringSet& caps)
{
}
bool NoModule::isClientCapSupported(NoClient* client, const NoString& cap, bool state)
{
    return false;
}
void NoModule::onClientCapRequest(NoClient* client, const NoString& cap, bool state)
{
}
NoModule::ModRet
NoModule::onModuleLoading(const NoString& name, const NoString& args, No::ModuleType type, bool& success, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onModuleUnloading(NoModule* module, bool& success, NoString& message)
{
    return CONTINUE;
}
NoModule::ModRet NoModule::onGetModuleInfo(NoModuleInfo& info, const NoString& name, bool& success, NoString& message)
{
    return CONTINUE;
}
void NoModule::onGetAvailableModules(std::set<NoModuleInfo>& modules, No::ModuleType type)
{
}
