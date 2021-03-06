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

#ifndef NOMODULELOADER_H
#define NOMODULELOADER_H

#include <nobnc/noglobal.h>
#include <nobnc/nomodule.h>
#include <memory>

class NoNick;
class NoClient;
class NoChannel;
class NoNetwork;
class NoIrcSocket;
class NoAuthenticator;
class NoModuleLoaderPrivate;

class NO_EXPORT NoModuleLoader
{
public:
    NoModuleLoader();
    ~NoModuleLoader();

    bool isEmpty() const;
    std::vector<NoModule*> modules() const;

    NoUser* user() const;
    void setUser(NoUser* user);

    NoNetwork* network() const;
    void setNetwork(NoNetwork* network);

    NoClient* client() const;
    void setClient(NoClient* client);

    NoModule* findModule(const NoString& name) const;
    bool loadModule(const NoString& name, const NoString& args, No::ModuleType type, NoUser* user, NoNetwork* network, NoString& message);
    bool unloadModule(const NoString& name);
    bool unloadModule(const NoString& name, NoString& message);
    bool reloadModule(const NoString& name, const NoString& args, NoUser* user, NoNetwork* network, NoString& message);
    void unloadAllModules();

    static bool moduleInfo(NoModuleInfo& info, const NoString& name, NoString& message);
    static bool modulePath(NoModuleInfo& info, const NoString& name, const NoString& path, NoString& message);

    static std::set<NoModuleInfo> availableModules(No::ModuleType type);
    static std::set<NoModuleInfo> defaultModules(No::ModuleType type);

    bool onBoot();
    bool onPreRehash();
    bool onPostRehash();
    bool onIrcDisconnected();
    bool onIrcConnected();
    bool onIrcConnecting(NoIrcSocket* socket);
    bool onIrcConnectionError(NoIrcSocket* socket);
    bool onIrcRegistration(NoString& pass, NoString& nick, NoString& ident, NoString& realName);
    bool onBroadcast(NoString& message);

    bool onChannelPermission(const NoNick* opNick, const NoNick& nick, NoChannel* channel, uchar mode, bool added, bool noChange);
    bool onOp(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange);
    bool onDeop(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange);
    bool onVoice(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange);
    bool onDevoice(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange);
    bool onRawMode(const NoNick* opNick, NoChannel* channel, const NoString& modes, const NoString& args);
    bool onMode(const NoNick* opNick, NoChannel* channel, char mode, const NoString& arg, bool added, bool noChange);

    bool onRaw(NoString& line);

    bool onStatusCommand(NoString& command);
    bool onModuleCommand(const NoString& command);
    bool onModuleNotice(const NoString& message);
    bool onModuleCtcp(const NoString& message);

    bool onQuit(const NoHostMask& nick, const NoString& message);
    bool onNick(const NoHostMask& nick, const NoString& newNick);
    bool onKick(const NoNick& nick, const NoString& opNick, NoChannel* channel, const NoString& message);
    bool onJoining(NoChannel* channel);
    bool onJoin(const NoNick& nick, NoChannel* channel);
    bool onPart(const NoNick& nick, NoChannel* channel, const NoString& message);
    bool onInvite(const NoHostMask& nick, const NoString& sChan);

    bool onChannelBufferStarting(NoChannel* channel, NoClient* client);
    bool onChannelBufferEnding(NoChannel* channel, NoClient* client);
    bool onChannelBufferPlayLine(NoChannel* channel, NoClient* client, NoString& line, const timeval& tv);
    bool onPrivateBufferPlayLine(NoClient* client, NoString& line, const timeval& tv);

    bool onClientLogin();
    bool onClientDisconnect();
    bool onUserRaw(NoString& line);
    bool onUserCtcpReply(NoString& target, NoString& message);
    bool onUserCtcp(NoString& target, NoString& message);
    bool onUserAction(NoString& target, NoString& message);
    bool onUserMessage(NoString& target, NoString& message);
    bool onUserNotice(NoString& target, NoString& message);
    bool onUserJoin(NoString& channel, NoString& key);
    bool onUserPart(NoString& channel, NoString& message);
    bool onUserTopic(NoString& channel, NoString& topic);
    bool onUserTopicRequest(NoString& channel);
    bool onUserQuit(NoString& message);

    bool onCtcpReply(NoHostMask& nick, NoString& message);
    bool onPrivateCtcp(NoHostMask& nick, NoString& message);
    bool onChannelCtcp(NoNick& nick, NoChannel* channel, NoString& message);
    bool onPrivateAction(NoHostMask& nick, NoString& message);
    bool onChannelAction(NoNick& nick, NoChannel* channel, NoString& message);
    bool onPrivateMessage(NoHostMask& nick, NoString& message);
    bool onChannelMessage(NoNick& nick, NoChannel* channel, NoString& message);
    bool onPrivateNotice(NoHostMask& nick, NoString& message);
    bool onChannelNotice(NoNick& nick, NoChannel* channel, NoString& message);
    bool onTopic(NoNick& nick, NoChannel* channel, NoString& topic);
    bool onTimerAutoJoin(NoChannel* channel);

    bool onAddNetwork(NoNetwork* network, NoString& error);
    bool onDeleteNetwork(NoNetwork* network);

    bool onSendToClient(NoString& line, NoClient* client);
    bool onSendToIrc(NoString& line);

    bool onServerCapAvailable(const NoString& cap);
    bool onServerCapResult(const NoString& cap, bool success);

    bool onAddUser(NoUser* user, NoString& error);
    bool onDeleteUser(NoUser* user);
    bool onClientConnect(NoSocket* socket, const NoString& host, ushort port);
    bool onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth);
    bool onFailedLogin(const NoString& username, const NoString& sRemoteIP);
    bool onUnknownUserRaw(NoClient* client, NoString& line);
    bool onClientCapLs(NoClient* client, NoStringSet& caps);
    bool isClientCapSupported(NoClient* client, const NoString& cap, bool state);
    bool onClientCapRequest(NoClient* client, const NoString& cap, bool state);
    bool onModuleLoading(const NoString& name, const NoString& args, No::ModuleType type, bool& success, NoString& message);
    bool onModuleUnloading(NoModule* module, bool& success, NoString& message);
    bool onGetModuleInfo(NoModuleInfo& info, const NoString& name, bool& success, NoString& message);
    bool onGetAvailableModules(std::set<NoModuleInfo>& modules, No::ModuleType type);

private:
    NoModuleLoader(const NoModuleLoader&) = delete;
    NoModuleLoader& operator=(const NoModuleLoader&) = delete;

    std::unique_ptr<NoModuleLoaderPrivate> d;
};

#endif // NOMODULELOADER_H
