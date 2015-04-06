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
#include "nouser.h"
#include "nonetwork.h"
#include "noclient.h"
#include "noapp.h"
#include "nosocket.h"
#include "notimer.h"
#include "notable.h"
#include "noexception_p.h"
#include <dlfcn.h>

double NoModulePrivate::buildVersion()
{
    return NO_VERSION;
}

static void initCommandHelp(NoTable& table)
{
    table.addColumn("Command");
    table.addColumn("Description");
}

static void addCommandHelp(NoTable& table, const NoModuleCommand& cmd)
{
    table.addRow();
    table.setValue("Command", cmd.command + " " + cmd.args);
    table.setValue("Description", cmd.description);
}

static void moduleCall(NoModuleCommand* cmd, NoModule* module, const NoString& line)
{
    (module->*(cmd->function))(line);
}

NoModule::NoModule(NoModuleHandle handle, NoUser* user, NoNetwork* network, const NoString& name, const NoString& dataDir, No::ModuleType type)
    : d(new NoModulePrivate(handle, user, network, name, dataDir, type))
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

    for (NoSocket* socket : d->sockets)
        delete socket;
    d->sockets.clear();
}

NoString NoModule::expandString(const NoString& str) const
{
    if (d->network)
        return d->network->expandString(str);
    if (d->user)
        return d->user->expandString(str);
    return str;
}

No::ModuleType NoModule::type() const
{
    return d->type;
}

NoString NoModule::description() const
{
    return d->description;
}

NoString NoModule::filePath() const
{
    return d->filePath;
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

NoString NoModule::savePath() const
{
    if (!NoFile::Exists(d->savePath)) {
        NoDir::mkpath(d->savePath);
    }
    return d->savePath;
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

NoSocket* NoModule::findSocket(const NoString& name) const
{
    for (NoSocket* pSocket : d->sockets) {
        if (pSocket->name().equals(name)) {
            return pSocket;
        }
    }

    return nullptr;
}

void NoModule::addCommand(const NoString& cmd, CommandFunction func, const NoString& args, const NoString& desc)
{
    if (!func || cmd.contains(" ") || d->findCommand(cmd))
        return;

    NoModuleCommand command;
    command.command = cmd;
    command.args = args;
    command.description = desc;
    command.function = func;

    d->commands[cmd] = command;
}

void NoModule::addHelpCommand()
{
    addCommand("Help", &NoModule::onHelpCommand, "search", "Generate this output");
}

void NoModule::removeCommand(const NoString& command)
{
    d->commands.erase(command);
}

void NoModule::onHelpCommand(const NoString& line)
{
    NoString filter = No::token(line, 1).toLower();
    NoTable Table;

    initCommandHelp(Table);
    for (const auto& it : d->commands) {
        NoString cmd = it.second.command.toLower();
        if (filter.empty() || (cmd.startsWith(filter, No::CaseSensitive)) || No::wildCmp(cmd, filter)) {
            addCommandHelp(Table, it.second);
        }
    }
    if (Table.isEmpty()) {
        putModule("No matches for '" + filter + "'");
    } else {
        putModule(Table);
    }
}

NoString NoModule::prefix() const
{
    return (d->user ? d->user->statusPrefix() : "*") + d->name;
}

NoString NoModule::dataPath() const
{
    return d->dataPath;
}

bool NoModule::onLoad(const NoString& args, NoString& message)
{
    message = "";
    return true;
}
bool NoModule::onBoot()
{
    return true;
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
NoModule::Return NoModule::onIrcConnecting(NoIrcSocket* socket)
{
    return Continue;
}
void NoModule::onIrcConnectionError(NoIrcSocket* socket)
{
}
NoModule::Return NoModule::onIrcRegistration(NoString& pass, NoString& nick, NoString& ident, NoString& realName)
{
    return Continue;
}
NoModule::Return NoModule::onBroadcast(NoString& message)
{
    return Continue;
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

NoModule::Return NoModule::onRaw(NoString& line)
{
    return Continue;
}

NoModule::Return NoModule::onStatusCommand(NoString& command)
{
    return Continue;
}
void NoModule::onModuleNotice(const NoString& message)
{
}
void NoModule::onModuleCtcp(const NoString& message)
{
}

void NoModule::onModuleCommand(const NoString& line)
{
    NoModuleCommand* cmd = d->findCommand(No::token(line, 0));
    if (cmd)
        moduleCall(cmd, this, line);
    else
        onUnknownModuleCommand(line);
}
void NoModule::onUnknownModuleCommand(const NoString& line)
{
    if (d->commands.empty())
        // This function is only called if onModuleCommand wasn't
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
NoModule::Return NoModule::onJoining(NoChannel* channel)
{
    return Continue;
}
void NoModule::onJoin(const NoNick& nick, NoChannel* channel)
{
}
void NoModule::onPart(const NoNick& nick, NoChannel* channel, const NoString& message)
{
}
NoModule::Return NoModule::onInvite(const NoHostMask& nick, const NoString& sChan)
{
    return Continue;
}

NoModule::Return NoModule::onChannelBufferStarting(NoChannel* channel, NoClient* client)
{
    return Continue;
}
NoModule::Return NoModule::onChannelBufferEnding(NoChannel* channel, NoClient* client)
{
    return Continue;
}

NoModule::Return NoModule::onChannelBufferPlayLine(NoChannel* channel, NoClient* client, NoString& line, const timeval& tv)
{
    return Continue;
}
NoModule::Return NoModule::onPrivateBufferPlayLine(NoClient* client, NoString& line, const timeval& tv)
{
    return Continue;
}

void NoModule::onClientLogin()
{
}
void NoModule::onClientDisconnect()
{
}
NoModule::Return NoModule::onUserRaw(NoString& line)
{
    return Continue;
}
NoModule::Return NoModule::onUserCtcpReply(NoString& target, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onUserCtcp(NoString& target, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onUserAction(NoString& target, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onUserMessage(NoString& target, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onUserNotice(NoString& target, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onUserJoin(NoString& channel, NoString& key)
{
    return Continue;
}
NoModule::Return NoModule::onUserPart(NoString& channel, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onUserTopic(NoString& channel, NoString& topic)
{
    return Continue;
}
NoModule::Return NoModule::onUserTopicRequest(NoString& channel)
{
    return Continue;
}
NoModule::Return NoModule::onUserQuit(NoString& message)
{
    return Continue;
}

NoModule::Return NoModule::onCtcpReply(NoHostMask& nick, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onPrivateCtcp(NoHostMask& nick, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onChannelCtcp(NoNick& nick, NoChannel* channel, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onPrivateAction(NoHostMask& nick, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onChannelAction(NoNick& nick, NoChannel* channel, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onPrivateMessage(NoHostMask& nick, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onChannelMessage(NoNick& nick, NoChannel* channel, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onPrivateNotice(NoHostMask& nick, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onChannelNotice(NoNick& nick, NoChannel* channel, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onTopic(NoNick& nick, NoChannel* channel, NoString& topic)
{
    return Continue;
}
NoModule::Return NoModule::onTimerAutoJoin(NoChannel* channel)
{
    return Continue;
}
NoModule::Return NoModule::onAddNetwork(NoNetwork* network, NoString& error)
{
    return Continue;
}
NoModule::Return NoModule::onDeleteNetwork(NoNetwork* network)
{
    return Continue;
}

NoModule::Return NoModule::onSendToClient(NoString& line, NoClient* client)
{
    return Continue;
}
NoModule::Return NoModule::onSendToIrc(NoString& line)
{
    return Continue;
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
bool NoModule::putModule(const NoTable& table)
{
    if (!d->user)
        return false;

    NoStringVector lines = table.toString();
    for (const NoString& line : lines) {
        if (!putModule(line))
            return false;
    }
    return true;
}
bool NoModule::putModule(const NoString& line)
{
    if (d->client) {
        d->client->putModule(name(), line);
        return true;
    }

    if (d->network) {
        return d->network->putModule(name(), line);
    }

    if (d->user) {
        return d->user->putModule(name(), line);
    }

    return false;
}
bool NoModule::putModuleNotice(const NoString& line)
{
    if (!d->user)
        return false;

    if (d->client) {
        d->client->putModuleNotice(name(), line);
        return true;
    }

    return d->user->putModuleNotice(name(), line);
}

NoString NoModule::name() const
{
    return d->name;
}

///////////////////
// Global Module //
///////////////////
NoModule::Return NoModule::onAddUser(NoUser* user, NoString& error)
{
    return Continue;
}
NoModule::Return NoModule::onDeleteUser(NoUser* user)
{
    return Continue;
}
void NoModule::onClientConnect(NoSocket* client, const NoString& host, ushort port)
{
}
NoModule::Return NoModule::onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth)
{
    return Continue;
}
void NoModule::onFailedLogin(const NoString& username, const NoString& sRemoteIP)
{
}
NoModule::Return NoModule::onUnknownUserRaw(NoClient* client, NoString& line)
{
    return Continue;
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
NoModule::Return
NoModule::onModuleLoading(const NoString& name, const NoString& args, No::ModuleType type, bool& success, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onModuleUnloading(NoModule* module, bool& success, NoString& message)
{
    return Continue;
}
NoModule::Return NoModule::onGetModuleInfo(NoModuleInfo& info, const NoString& name, bool& success, NoString& message)
{
    return Continue;
}
void NoModule::onGetAvailableModules(std::set<NoModuleInfo>& modules, No::ModuleType type)
{
}
