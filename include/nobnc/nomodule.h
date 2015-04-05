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

#ifndef NOMODULE_H
#define NOMODULE_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
#include <nobnc/nomoduleinfo.h>
#include <nobnc/nomodulecommand.h>

#include <sys/time.h>
#include <memory>

class NoUser;
class NoNick;
class NoTimer;
class NoSocket;
class NoClient;
class NoChannel;
class NoNetwork;
class NoWebPage;
class NoHostMask;
class NoTemplate;
class NoWebSocket;
class NoIrcSocket;
class NoModuleSocket;
class NoAuthenticator;
class NoModulePrivate;

#ifdef REQUIRESSL
#ifndef HAVE_LIBSSL
#error -
#error -
#error This module only works when ZNC is compiled with OpenSSL support
#error -
#error -
#endif
#endif

#define MODCOMMONDEFS(CLASS, DESCRIPTION, TYPE)                          \
    extern "C" {                                                         \
    NO_DECL_EXPORT bool no_moduleInfo(double version, NoModuleInfo& info) \
    {                                                                    \
        if (version != NO_VERSION)                                       \
            return false;                                                \
        info.setDescription(DESCRIPTION);                                \
        info.setDefaultType(TYPE);                                       \
        info.addType(TYPE);                                              \
        info.setLoader(no_loadModule<CLASS>);                            \
        no_moduleInfo<CLASS>(info);                                      \
        return true;                                                     \
    }                                                                    \
    }

#define USERMODULEDEFS(CLASS, DESCRIPTION) MODCOMMONDEFS(CLASS, DESCRIPTION, No::UserModule)
#define GLOBALMODULEDEFS(CLASS, DESCRIPTION) MODCOMMONDEFS(CLASS, DESCRIPTION, No::GlobalModule)
#define NETWORKMODULEDEFS(CLASS, DESCRIPTION) MODCOMMONDEFS(CLASS, DESCRIPTION, No::NetworkModule)

#define MODCONSTRUCTOR(CLASS)                                                                                                                \
    CLASS(NoModuleHandle handle, NoUser* user, NoNetwork* network, const NoString& name, const NoString& path, No::ModuleType type) \
        : NoModule(handle, user, network, name, path, type)

class NO_EXPORT NoModule
{
public:
    NoModule(NoModuleHandle handle, NoUser* user, NoNetwork* network, const NoString& name, const NoString& dataDir, No::ModuleType type);
    virtual ~NoModule();

    No::ModuleType type() const;

    NoUser* user() const;
    NoNetwork* network() const;
    NoClient* client() const;

    NoString name() const;
    NoString prefix() const;
    NoString description() const;

    NoString args() const;
    void setArgs(const NoString& args);

    NoString path() const;
    NoString dataPath() const;
    NoString savePath() const;

    NoString expandString(const NoString& str) const;
    NoString& expandString(const NoString& str, NoString& ret) const;

    enum ModRet {
        CONTINUE = 1,
        HALT = 2,
        HALTMODS = 3,
        HALTCORE = 4
    };

    void unload();

    virtual bool onLoad(const NoString& args, NoString& message);
    virtual bool onBoot();

    virtual bool webRequiresLogin();
    virtual bool webRequiresAdmin();
    virtual NoString webMenuTitle();
    virtual NoString webPath();
    virtual NoString webFilesPath();
    virtual bool onWebPreRequest(NoWebSocket* socket, const NoString& page);
    virtual bool onWebRequest(NoWebSocket* socket, const NoString& page, NoTemplate& tmpl);
    virtual void addSubPage(std::shared_ptr<NoWebPage> page);
    virtual bool onEmbeddedWebRequest(NoWebSocket* socket, const NoString& page, NoTemplate& tmpl);

    virtual void onPreRehash();
    virtual void onPostRehash();

    virtual void onIrcDisconnected();
    virtual void onIrcConnected();
    virtual ModRet onIrcConnecting(NoIrcSocket* socket);
    virtual void onIrcConnectionError(NoIrcSocket* socket);
    virtual ModRet onIrcRegistration(NoString& pass, NoString& nick, NoString& ident, NoString& realName);

    virtual ModRet onBroadcast(NoString& message);

    virtual void onChannelPermission(const NoNick* opNick, const NoNick& nick, NoChannel* channel, uchar mode, bool added, bool noChange);
    virtual void onOp(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange);
    virtual void onDeop(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange);
    virtual void onVoice(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange);
    virtual void onDevoice(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange);
    virtual void onMode(const NoNick* opNick, NoChannel* channel, char mode, const NoString& arg, bool added, bool noChange);
    virtual void onRawMode(const NoNick* opNick, NoChannel* channel, const NoString& modes, const NoString& args);

    virtual ModRet onRaw(NoString& line);

    virtual ModRet onStatusCommand(NoString& command);
    virtual void onModuleCommand(const NoString& command);
    virtual void onUnknownModuleCommand(const NoString& command);
    virtual void onModuleNotice(const NoString& message);
    virtual void onModuleCtcp(const NoString& message);

    virtual void onQuit(const NoHostMask& nick, const NoString& message);
    virtual void onNick(const NoHostMask& nick, const NoString& newNick);
    virtual void onKick(const NoNick& opNick, const NoString& sKickedNick, NoChannel* channel, const NoString& message);
    virtual ModRet onJoining(NoChannel* channel);
    virtual void onJoin(const NoNick& nick, NoChannel* channel);
    virtual void onPart(const NoNick& nick, NoChannel* channel, const NoString& message);
    virtual ModRet onInvite(const NoHostMask& nick, const NoString& sChan);

    virtual ModRet onChannelBufferStarting(NoChannel* channel, NoClient* client);
    virtual ModRet onChannelBufferEnding(NoChannel* channel, NoClient* client);
    virtual ModRet onChannelBufferPlayLine(NoChannel* channel, NoClient* client, NoString& line, const timeval& tv);
    virtual ModRet onPrivateBufferPlayLine(NoClient* client, NoString& line, const timeval& tv);

    virtual void onClientLogin();
    virtual void onClientDisconnect();

    virtual ModRet onUserRaw(NoString& line);
    virtual ModRet onUserCtcpReply(NoString& target, NoString& message);
    virtual ModRet onUserCtcp(NoString& target, NoString& message);
    virtual ModRet onUserAction(NoString& target, NoString& message);
    virtual ModRet onUserMessage(NoString& target, NoString& message);
    virtual ModRet onUserNotice(NoString& target, NoString& message);
    virtual ModRet onUserJoin(NoString& channel, NoString& key);
    virtual ModRet onUserPart(NoString& channel, NoString& message);
    virtual ModRet onUserTopic(NoString& channel, NoString& topic);
    virtual ModRet onUserTopicRequest(NoString& channel);
    virtual ModRet onUserQuit(NoString& message);

    virtual ModRet onCtcpReply(NoHostMask& nick, NoString& message);
    virtual ModRet onPrivateCtcp(NoHostMask& nick, NoString& message);
    virtual ModRet onChannelCtcp(NoNick& nick, NoChannel* channel, NoString& message);
    virtual ModRet onPrivateAction(NoHostMask& nick, NoString& message);
    virtual ModRet onChannelAction(NoNick& nick, NoChannel* channel, NoString& message);
    virtual ModRet onPrivateMessage(NoHostMask& nick, NoString& message);
    virtual ModRet onChannelMessage(NoNick& nick, NoChannel* channel, NoString& message);
    virtual ModRet onPrivateNotice(NoHostMask& nick, NoString& message);
    virtual ModRet onChannelNotice(NoNick& nick, NoChannel* channel, NoString& message);
    virtual ModRet onTopic(NoNick& nick, NoChannel* channel, NoString& topic);

    virtual bool onServerCapAvailable(const NoString& cap);
    virtual void onServerCapResult(const NoString& cap, bool success);

    virtual ModRet onTimerAutoJoin(NoChannel* channel);

    virtual ModRet onAddNetwork(NoNetwork* network, NoString& error);
    virtual ModRet onDeleteNetwork(NoNetwork* network);

    virtual ModRet onSendToClient(NoString& line, NoClient* client);
    virtual ModRet onSendToIrc(NoString& line);

    virtual bool putIrc(const NoString& line);
    virtual bool putUser(const NoString& line);
    virtual bool putStatus(const NoString& line);
    virtual bool putModule(const NoString& line);
    virtual uint putModule(const NoTable& table);
    virtual bool putModuleNotice(const NoString& line);

    NoTimer* findTimer(const NoString& label) const;
    NoModuleSocket* findSocket(const NoString& name) const;

    void addHelpCommand();
    bool addCommand(const NoModuleCommand& command);
    bool addCommand(const NoString& cmd, NoModuleCommand::ModCmdFunc func, const NoString& args = "", const NoString& desc = "");
    bool addCommand(const NoString& cmd, const NoString& args, const NoString& desc, std::function<void(const NoString& line)> func);
    bool removeCommand(const NoString& cmd);
    const NoModuleCommand* findCommand(const NoString& cmd) const;
    bool handleCommand(const NoString& line);
    void handleHelpCommand(const NoString& line = "");

    virtual ModRet onAddUser(NoUser* user, NoString& error);
    virtual ModRet onDeleteUser(NoUser* user);

    virtual void onClientConnect(NoSocket* socket, const NoString& host, ushort port);
    virtual ModRet onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth);
    virtual void onFailedLogin(const NoString& username, const NoString& sRemoteIP);

    virtual ModRet onUnknownUserRaw(NoClient* client, NoString& line);

    virtual void onClientCapLs(NoClient* client, NoStringSet& caps);
    virtual bool isClientCapSupported(NoClient* client, const NoString& cap, bool state);
    virtual void onClientCapRequest(NoClient* client, const NoString& cap, bool state);

    virtual ModRet onModuleLoading(const NoString& name, const NoString& args, No::ModuleType type, bool& success, NoString& message);
    virtual ModRet onModuleUnloading(NoModule* module, bool& success, NoString& message);
    virtual ModRet onGetModuleInfo(NoModuleInfo& info, const NoString& name, bool& success, NoString& message);
    virtual void onGetAvailableModules(std::set<NoModuleInfo>& modules, No::ModuleType type);

private:
    NoModule(const NoModule&) = delete;
    NoModule& operator=(const NoModule&) = delete;
    std::unique_ptr<NoModulePrivate> d;
    friend class NoModulePrivate;
};

#endif // NOMODULE_H
