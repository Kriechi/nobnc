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

#include "nomoduleloader.h"
#include "nomodule_p.h"
#include "nofile.h"
#include "nodir.h"
#include "noapp.h"
#include <dlfcn.h>
#include <queue>

bool ZNC_NO_NEED_TO_DO_ANYTHING_ON_MODULE_CALL_EXITER;

#ifndef RTLD_LOCAL
#define RTLD_LOCAL 0
#warning "your crap box doesnt define RTLD_LOCAL !?"
#endif

#define MODUNLOADCHK(func)                          \
    for (NoModule * mod : d->modules) {            \
        try {                                       \
            NoClient* oldClient = mod->client();  \
            NoModulePrivate::get(mod)->client = d->client;             \
            NoUser* oldUser = nullptr;             \
            if (d->user) {                          \
                oldUser = mod->user();            \
                NoModulePrivate::get(mod)->user = d->user;             \
            }                                       \
            NoNetwork* oldNetwork = nullptr;          \
            if (d->network) {                       \
                oldNetwork = mod->network();         \
                NoModulePrivate::get(mod)->network = d->network;       \
            }                                       \
            mod->func;                             \
            if (d->user)                            \
                NoModulePrivate::get(mod)->user = oldUser;            \
            if (d->network)                         \
                NoModulePrivate::get(mod)->network = oldNetwork;         \
            NoModulePrivate::get(mod)->client = oldClient;            \
        } catch (const NoModule::ModException& e) { \
            if (e == NoModule::UNLOAD) {            \
                unloadModule(mod->moduleName());   \
            }                                       \
        }                                           \
    }


#define MODHALTCHK(func)                             \
    bool bHaltCore = false;                          \
    for (NoModule * mod : d->modules) {             \
        try {                                        \
            NoModule::ModRet e = NoModule::CONTINUE; \
            NoClient* oldClient = mod->client();   \
            NoModulePrivate::get(mod)->client = d->client;              \
            NoUser* oldUser = nullptr;              \
            if (d->user) {                           \
                oldUser = mod->user();             \
                NoModulePrivate::get(mod)->user = d->user;              \
            }                                        \
            NoNetwork* oldNetwork = nullptr;           \
            if (d->network) {                        \
                oldNetwork = mod->network();          \
                NoModulePrivate::get(mod)->network = d->network;        \
            }                                        \
            e = mod->func;                          \
            if (d->user)                             \
                NoModulePrivate::get(mod)->user = oldUser;             \
            if (d->network)                          \
                NoModulePrivate::get(mod)->network = oldNetwork;          \
            NoModulePrivate::get(mod)->client = oldClient;             \
            if (e == NoModule::HALTMODS) {           \
                break;                               \
            } else if (e == NoModule::HALTCORE) {    \
                bHaltCore = true;                    \
            } else if (e == NoModule::HALT) {        \
                bHaltCore = true;                    \
                break;                               \
            }                                        \
        } catch (const NoModule::ModException& e) {  \
            if (e == NoModule::UNLOAD) {             \
                unloadModule(mod->moduleName());    \
            }                                        \
        }                                            \
    }                                                \
    return bHaltCore;

// This returns the path to the .so and to the data dir
// which is where static data (webadmin skins) are saved
static bool findModulePath(const NoString& name, NoString& path, NoString& sDataPath);
// Return a list of <module dir, data dir> pairs for directories in
// which modules can be found.
typedef std::queue<std::pair<NoString, NoString>> NoModDirList;
static NoModDirList moduleDirs();

static NoModuleHandle
OpenModule(const NoString& name, const NoString& path, bool& bVersionMismatch, NoModuleInfo& info, NoString& message);

class NoModuleLoaderPrivate
{
public:
    NoUser* user = nullptr;
    NoNetwork* network = nullptr;
    NoClient* client = nullptr;
    std::vector<NoModule*> modules;
};

NoModuleLoader::NoModuleLoader() : d(new NoModuleLoaderPrivate)
{
}

NoModuleLoader::~NoModuleLoader()
{
    unloadAllModules();
}

bool NoModuleLoader::isEmpty() const
{
    return d->modules.empty();
}

std::vector<NoModule*> NoModuleLoader::modules() const
{
    return d->modules;
}

void NoModuleLoader::setUser(NoUser* user)
{
    d->user = user;
}

void NoModuleLoader::setNetwork(NoNetwork* network)
{
    d->network = network;
}

void NoModuleLoader::setClient(NoClient* client)
{
    d->client = client;
}

NoUser* NoModuleLoader::user() const
{
    return d->user;
}

NoNetwork* NoModuleLoader::network() const
{
    return d->network;
}

NoClient* NoModuleLoader::client() const
{
    return d->client;
}

void NoModuleLoader::unloadAllModules()
{
    while (!d->modules.empty()) {
        NoString message;
        NoString name = d->modules.back()->moduleName();
        unloadModule(name, message);
    }
}

bool NoModuleLoader::onBoot()
{
    for (NoModule* mod : d->modules) {
        try {
            if (!mod->onBoot()) {
                return true;
            }
        } catch (const NoModule::ModException& e) {
            if (e == NoModule::UNLOAD) {
                unloadModule(mod->moduleName());
            }
        }
    }

    return false;
}

bool NoModuleLoader::onPreRehash()
{
    MODUNLOADCHK(onPreRehash());
    return false;
}
bool NoModuleLoader::onPostRehash()
{
    MODUNLOADCHK(onPostRehash());
    return false;
}
bool NoModuleLoader::onIrcConnected()
{
    MODUNLOADCHK(onIrcConnected());
    return false;
}
bool NoModuleLoader::onIrcConnecting(NoIrcSocket* socket)
{
    MODHALTCHK(onIrcConnecting(socket));
}
bool NoModuleLoader::onIrcConnectionError(NoIrcSocket* socket)
{
    MODUNLOADCHK(onIrcConnectionError(socket));
    return false;
}
bool NoModuleLoader::onIrcRegistration(NoString& pass, NoString& nick, NoString& ident, NoString& realName)
{
    MODHALTCHK(onIrcRegistration(pass, nick, ident, realName));
}
bool NoModuleLoader::onBroadcast(NoString& message)
{
    MODHALTCHK(onBroadcast(message));
}
bool NoModuleLoader::onIrcDisconnected()
{
    MODUNLOADCHK(onIrcDisconnected());
    return false;
}

bool NoModuleLoader::onChanPermission(const NoNick* opNick, const NoNick& nick, NoChannel* channel, uchar mode, bool added, bool noChange)
{
    MODUNLOADCHK(onChanPermission(opNick, nick, channel, mode, added, noChange));
    return false;
}
bool NoModuleLoader::onOp(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange)
{
    MODUNLOADCHK(onOp(opNick, nick, channel, noChange));
    return false;
}
bool NoModuleLoader::onDeop(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange)
{
    MODUNLOADCHK(onDeop(opNick, nick, channel, noChange));
    return false;
}
bool NoModuleLoader::onVoice(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange)
{
    MODUNLOADCHK(onVoice(opNick, nick, channel, noChange));
    return false;
}
bool NoModuleLoader::onDevoice(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange)
{
    MODUNLOADCHK(onDevoice(opNick, nick, channel, noChange));
    return false;
}
bool NoModuleLoader::onRawMode(const NoNick* opNick, NoChannel* channel, const NoString& modes, const NoString& args)
{
    MODUNLOADCHK(onRawMode(opNick, channel, modes, args));
    return false;
}
bool NoModuleLoader::onMode(const NoNick* opNick, NoChannel* channel, char mode, const NoString& arg, bool added, bool noChange)
{
    MODUNLOADCHK(onMode(opNick, channel, mode, arg, added, noChange));
    return false;
}
bool NoModuleLoader::onRaw(NoString& line)
{
    MODHALTCHK(onRaw(line));
}

bool NoModuleLoader::onClientLogin()
{
    MODUNLOADCHK(onClientLogin());
    return false;
}
bool NoModuleLoader::onClientDisconnect()
{
    MODUNLOADCHK(onClientDisconnect());
    return false;
}
bool NoModuleLoader::onUserRaw(NoString& line)
{
    MODHALTCHK(onUserRaw(line));
}
bool NoModuleLoader::onUserCtcpReply(NoString& target, NoString& message)
{
    MODHALTCHK(onUserCtcpReply(target, message));
}
bool NoModuleLoader::onUserCtcp(NoString& target, NoString& message)
{
    MODHALTCHK(onUserCtcp(target, message));
}
bool NoModuleLoader::onUserAction(NoString& target, NoString& message)
{
    MODHALTCHK(onUserAction(target, message));
}
bool NoModuleLoader::onUserMsg(NoString& target, NoString& message)
{
    MODHALTCHK(onUserMsg(target, message));
}
bool NoModuleLoader::onUserNotice(NoString& target, NoString& message)
{
    MODHALTCHK(onUserNotice(target, message));
}
bool NoModuleLoader::onUserJoin(NoString& channel, NoString& key)
{
    MODHALTCHK(onUserJoin(channel, key));
}
bool NoModuleLoader::onUserPart(NoString& channel, NoString& message)
{
    MODHALTCHK(onUserPart(channel, message));
}
bool NoModuleLoader::onUserTopic(NoString& channel, NoString& topic)
{
    MODHALTCHK(onUserTopic(channel, topic));
}
bool NoModuleLoader::onUserTopicRequest(NoString& channel)
{
    MODHALTCHK(onUserTopicRequest(channel));
}
bool NoModuleLoader::onUserQuit(NoString& message)
{
    MODHALTCHK(onUserQuit(message));
}

bool NoModuleLoader::onQuit(const NoHostMask& nick, const NoString& message)
{
    MODUNLOADCHK(onQuit(nick, message));
    return false;
}
bool NoModuleLoader::onNick(const NoHostMask& nick, const NoString& newNick)
{
    MODUNLOADCHK(onNick(nick, newNick));
    return false;
}
bool NoModuleLoader::onKick(const NoNick& nick, const NoString& sKickedNick, NoChannel* channel, const NoString& message)
{
    MODUNLOADCHK(onKick(nick, sKickedNick, channel, message));
    return false;
}
bool NoModuleLoader::onJoining(NoChannel* channel)
{
    MODHALTCHK(onJoining(channel));
}
bool NoModuleLoader::onJoin(const NoNick& nick, NoChannel* channel)
{
    MODUNLOADCHK(onJoin(nick, channel));
    return false;
}
bool NoModuleLoader::onPart(const NoNick& nick, NoChannel* channel, const NoString& message)
{
    MODUNLOADCHK(onPart(nick, channel, message));
    return false;
}
bool NoModuleLoader::onInvite(const NoHostMask& nick, const NoString& sChan)
{
    MODHALTCHK(onInvite(nick, sChan));
}
bool NoModuleLoader::onChanBufferStarting(NoChannel* channel, NoClient* client)
{
    MODHALTCHK(onChanBufferStarting(channel, client));
}
bool NoModuleLoader::onChanBufferEnding(NoChannel* channel, NoClient* client)
{
    MODHALTCHK(onChanBufferEnding(channel, client));
}
bool NoModuleLoader::onChanBufferPlayLine(NoChannel* channel, NoClient* client, NoString& line, const timeval& tv)
{
    MODHALTCHK(onChanBufferPlayLine(channel, client, line, tv));
}
bool NoModuleLoader::onPrivBufferPlayLine(NoClient* client, NoString& line, const timeval& tv)
{
    MODHALTCHK(onPrivBufferPlayLine(client, line, tv));
}
bool NoModuleLoader::onCtcpReply(NoHostMask& nick, NoString& message)
{
    MODHALTCHK(onCtcpReply(nick, message));
}
bool NoModuleLoader::onPrivCtcp(NoHostMask& nick, NoString& message)
{
    MODHALTCHK(onPrivCtcp(nick, message));
}
bool NoModuleLoader::onChanCtcp(NoNick& nick, NoChannel* channel, NoString& message)
{
    MODHALTCHK(onChanCtcp(nick, channel, message));
}
bool NoModuleLoader::onPrivAction(NoHostMask& nick, NoString& message)
{
    MODHALTCHK(onPrivAction(nick, message));
}
bool NoModuleLoader::onChanAction(NoNick& nick, NoChannel* channel, NoString& message)
{
    MODHALTCHK(onChanAction(nick, channel, message));
}
bool NoModuleLoader::onPrivMsg(NoHostMask& nick, NoString& message)
{
    MODHALTCHK(onPrivMsg(nick, message));
}
bool NoModuleLoader::onChanMsg(NoNick& nick, NoChannel* channel, NoString& message)
{
    MODHALTCHK(onChanMsg(nick, channel, message));
}
bool NoModuleLoader::onPrivNotice(NoHostMask& nick, NoString& message)
{
    MODHALTCHK(onPrivNotice(nick, message));
}
bool NoModuleLoader::onChanNotice(NoNick& nick, NoChannel* channel, NoString& message)
{
    MODHALTCHK(onChanNotice(nick, channel, message));
}
bool NoModuleLoader::onTopic(NoNick& nick, NoChannel* channel, NoString& topic)
{
    MODHALTCHK(onTopic(nick, channel, topic));
}
bool NoModuleLoader::onTimerAutoJoin(NoChannel* channel)
{
    MODHALTCHK(onTimerAutoJoin(channel));
}
bool NoModuleLoader::onAddNetwork(NoNetwork* network, NoString& error)
{
    MODHALTCHK(onAddNetwork(network, error));
}
bool NoModuleLoader::onDeleteNetwork(NoNetwork* network)
{
    MODHALTCHK(onDeleteNetwork(network));
}
bool NoModuleLoader::onSendToClient(NoString& line, NoClient* client)
{
    MODHALTCHK(onSendToClient(line, client));
}
bool NoModuleLoader::onSendToIrc(NoString& line)
{
    MODHALTCHK(onSendToIrc(line));
}
bool NoModuleLoader::onStatusCommand(NoString& command)
{
    MODHALTCHK(onStatusCommand(command));
}
bool NoModuleLoader::onModCommand(const NoString& command)
{
    MODUNLOADCHK(onModCommand(command));
    return false;
}
bool NoModuleLoader::onModNotice(const NoString& message)
{
    MODUNLOADCHK(onModNotice(message));
    return false;
}
bool NoModuleLoader::onModCTCP(const NoString& message)
{
    MODUNLOADCHK(onModCTCP(message));
    return false;
}

// Why MODHALTCHK works only with functions returning ModRet ? :(
bool NoModuleLoader::onServerCapAvailable(const NoString& cap)
{
    bool bResult = false;
    for (NoModule* mod : d->modules) {
        try {
            NoClient* oldClient = mod->client();
            NoModulePrivate::get(mod)->client = d->client;
            if (d->user) {
                NoUser* oldUser = mod->user();
                NoModulePrivate::get(mod)->user = d->user;
                bResult |= mod->onServerCapAvailable(cap);
                NoModulePrivate::get(mod)->user = oldUser;
            } else {
                // WTF? Is that possible?
                bResult |= mod->onServerCapAvailable(cap);
            }
            NoModulePrivate::get(mod)->client = oldClient;
        } catch (const NoModule::ModException& e) {
            if (NoModule::UNLOAD == e) {
                unloadModule(mod->moduleName());
            }
        }
    }
    return bResult;
}

bool NoModuleLoader::onServerCapResult(const NoString& cap, bool success)
{
    MODUNLOADCHK(onServerCapResult(cap, success));
    return false;
}

////////////////////
// Global Modules //
////////////////////
bool NoModuleLoader::onAddUser(NoUser* user, NoString& error)
{
    MODHALTCHK(onAddUser(user, error));
}

bool NoModuleLoader::onDeleteUser(NoUser* user)
{
    MODHALTCHK(onDeleteUser(user));
}

bool NoModuleLoader::onClientConnect(NoSocket* client, const NoString& host, ushort port)
{
    MODUNLOADCHK(onClientConnect(client, host, port));
    return false;
}

bool NoModuleLoader::onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth)
{
    MODHALTCHK(onLoginAttempt(Auth));
}

bool NoModuleLoader::onFailedLogin(const NoString& username, const NoString& sRemoteIP)
{
    MODUNLOADCHK(onFailedLogin(username, sRemoteIP));
    return false;
}

bool NoModuleLoader::onUnknownUserRaw(NoClient* client, NoString& line)
{
    MODHALTCHK(onUnknownUserRaw(client, line));
}

bool NoModuleLoader::onClientCapLs(NoClient* client, NoStringSet& caps)
{
    MODUNLOADCHK(onClientCapLs(client, caps));
    return false;
}

// Maybe create new macro for this?
bool NoModuleLoader::isClientCapSupported(NoClient* client, const NoString& cap, bool state)
{
    bool bResult = false;
    for (NoModule* mod : d->modules) {
        try {
            NoClient* oldClient = mod->client();
            NoModulePrivate::get(mod)->client = d->client;
            if (d->user) {
                NoUser* oldUser = mod->user();
                NoModulePrivate::get(mod)->user = d->user;
                bResult |= mod->isClientCapSupported(client, cap, state);
                NoModulePrivate::get(mod)->user = oldUser;
            } else {
                // WTF? Is that possible?
                bResult |= mod->isClientCapSupported(client, cap, state);
            }
            NoModulePrivate::get(mod)->client = oldClient;
        } catch (const NoModule::ModException& e) {
            if (NoModule::UNLOAD == e) {
                unloadModule(mod->moduleName());
            }
        }
    }
    return bResult;
}

bool NoModuleLoader::onClientCapRequest(NoClient* client, const NoString& cap, bool state)
{
    MODUNLOADCHK(onClientCapRequest(client, cap, state));
    return false;
}

bool NoModuleLoader::onModuleLoading(const NoString& name, const NoString& args, No::ModuleType type, bool& success, NoString& message)
{
    MODHALTCHK(onModuleLoading(name, args, type, success, message));
}

bool NoModuleLoader::onModuleUnloading(NoModule* module, bool& success, NoString& message)
{
    MODHALTCHK(onModuleUnloading(module, success, message));
}

bool NoModuleLoader::onGetModuleInfo(NoModuleInfo& info, const NoString& name, bool& success, NoString& message)
{
    MODHALTCHK(onGetModuleInfo(info, name, success, message));
}

bool NoModuleLoader::onGetAvailableModules(std::set<NoModuleInfo>& modules, No::ModuleType type)
{
    MODUNLOADCHK(onGetAvailableModules(modules, type));
    return false;
}


NoModule* NoModuleLoader::findModule(const NoString& name) const
{
    for (NoModule* mod : d->modules) {
        if (name.equals(mod->moduleName())) {
            return mod;
        }
    }

    return nullptr;
}

bool NoModuleLoader::loadModule(const NoString& name, const NoString& args, No::ModuleType type, NoUser* user, NoNetwork* network, NoString& message)
{
    message = "";

    if (findModule(name) != nullptr) {
        message = "Module [" + name + "] already loaded.";
        return false;
    }

    bool success;
    bool bHandled = false;
    _GLOBALMODULECALL(onModuleLoading(name, args, type, success, message), user, network, nullptr, &bHandled);
    if (bHandled)
        return success;

    NoString path, sDataPath;
    bool bVersionMismatch;
    NoModuleInfo info;

    if (!findModulePath(name, path, sDataPath)) {
        message = "Unable to find module [" + name + "]";
        return false;
    }

    NoModuleHandle p = OpenModule(name, path, bVersionMismatch, info, message);

    if (!p)
        return false;

    if (bVersionMismatch) {
        dlclose(p);
        message = "Version mismatch, recompile this module.";
        return false;
    }

    if (!info.supportsType(type)) {
        dlclose(p);
        message = "Module [" + name + "] does not support module type [" + NoModuleInfo::moduleTypeToString(type) + "].";
        return false;
    }

    if (!user && type == No::UserModule) {
        dlclose(p);
        message = "Module [" + name + "] requires a user.";
        return false;
    }

    if (!network && type == No::NetworkModule) {
        dlclose(p);
        message = "Module [" + name + "] requires a network.";
        return false;
    }

    NoModule* module = info.loader()(p, user, network, name, sDataPath, type);
    NoModulePrivate::get(module)->description = info.description();
    NoModulePrivate::get(module)->args = args;
    NoModulePrivate::get(module)->path = NoDir::current().filePath(path);
    d->modules.push_back(module);

    bool bLoaded;
    try {
        bLoaded = module->onLoad(args, message);
    } catch (const NoModule::ModException&) {
        bLoaded = false;
        message = "Caught an exception";
    }

    if (!bLoaded) {
        unloadModule(name, path);
        if (!message.empty())
            message = "Module [" + name + "] aborted: " + message;
        else
            message = "Module [" + name + "] aborted.";
        return false;
    }

    if (!message.empty()) {
        message += " ";
    }
    message += "[" + path + "]";
    return true;
}

bool NoModuleLoader::unloadModule(const NoString& name)
{
    NoString s;
    return unloadModule(name, s);
}

bool NoModuleLoader::unloadModule(const NoString& name, NoString& message)
{
    NoString sMod = name; // Make a copy incase the reference passed in is from NoModule::moduleName()
    NoModule* module = findModule(sMod);
    message = "";

    if (!module) {
        message = "Module [" + sMod + "] not loaded.";
        return false;
    }

    bool success;
    bool bHandled = false;
    _GLOBALMODULECALL(onModuleUnloading(module, success, message), module->user(), module->network(), nullptr, &bHandled);
    if (bHandled)
        return success;

    NoModuleHandle p = module->GetDLL();

    if (p) {
        delete module;

        for (auto it = d->modules.begin(); it != d->modules.end(); ++it) {
            if (*it == module) {
                d->modules.erase(it);
                break;
            }
        }

        dlclose(p);
        message = "Module [" + sMod + "] unloaded";

        return true;
    }

    message = "Unable to unload module [" + sMod + "]";
    return false;
}

bool NoModuleLoader::reloadModule(const NoString& name, const NoString& args, NoUser* user, NoNetwork* network, NoString& message)
{
    NoString sMod = name; // Make a copy incase the reference passed in is from NoModule::moduleName()
    NoModule* module = findModule(sMod);

    if (!module) {
        message = "Module [" + sMod + "] not loaded";
        return false;
    }

    No::ModuleType type = module->type();
    module = nullptr;

    message = "";
    if (!unloadModule(sMod, message)) {
        return false;
    }

    if (!loadModule(sMod, args, type, user, network, message)) {
        return false;
    }

    message = "Reloaded module [" + sMod + "]";
    return true;
}

bool NoModuleLoader::moduleInfo(NoModuleInfo& info, const NoString& name, NoString& message)
{
    NoString path, sTmp;

    bool success;
    bool bHandled = false;
    GLOBALMODULECALL(onGetModuleInfo(info, name, success, message), &bHandled);
    if (bHandled)
        return success;

    if (!findModulePath(name, path, sTmp)) {
        message = "Unable to find module [" + name + "]";
        return false;
    }

    return modulePath(info, name, path, message);
}

bool NoModuleLoader::modulePath(NoModuleInfo& info, const NoString& name, const NoString& path, NoString& message)
{
    bool bVersionMismatch;

    NoModuleHandle p = OpenModule(name, path, bVersionMismatch, info, message);

    if (!p)
        return false;

    info.setName(name);
    info.setPath(path);

    if (bVersionMismatch) {
        info.setDescription("--- Version mismatch, recompile this module. ---");
    }

    dlclose(p);

    return true;
}

std::set<NoModuleInfo> NoModuleLoader::availableModules(No::ModuleType type)
{
    std::set<NoModuleInfo> modules;

    NoModDirList dirs = moduleDirs();

    while (!dirs.empty()) {
        NoDir Dir(dirs.front().first);
        dirs.pop();

        for (NoFile* file : Dir.files("*.so")) {
            NoString name = file->GetShortName();
            NoString path = file->GetLongName();
            NoModuleInfo info;
            name.rightChomp(3);

            NoString sIgnoreRetMsg;
            if (modulePath(info, name, path, sIgnoreRetMsg)) {
                if (info.supportsType(type)) {
                    modules.insert(info);
                }
            }
        }
    }

    GLOBALMODULECALL(onGetAvailableModules(modules, type), NOTHING);

    return modules;
}

std::set<NoModuleInfo> NoModuleLoader::defaultModules(No::ModuleType type)
{
    std::set<NoModuleInfo> modules = availableModules(type);

    const std::map<NoString, No::ModuleType> ns = { { "chansaver", No::UserModule },
                                                    { "controlpanel", No::UserModule },
                                                    { "simple_away", No::NetworkModule },
                                                    { "webadmin", No::GlobalModule } };

    auto it = modules.begin();
    while (it != modules.end()) {
        auto it2 = ns.find(it->name());
        if (it2 != ns.end() && it2->second == type) {
            ++it;
        } else {
            it = modules.erase(it);
        }
    }
    return modules;
}

bool findModulePath(const NoString& name, NoString& path, NoString& sDataPath)
{
    NoString sMod = name;
    NoString sDir = sMod;
    if (!name.contains("."))
        sMod += ".so";

    NoModDirList dirs = moduleDirs();

    while (!dirs.empty()) {
        path = dirs.front().first + sMod;
        sDataPath = dirs.front().second;
        dirs.pop();

        if (NoFile::Exists(path)) {
            sDataPath += sDir;
            return true;
        }
    }

    return false;
}

NoModDirList moduleDirs()
{
    NoModDirList ret;
    NoString sDir;

    // ~/.znc/modules
    sDir = noApp->modulePath() + "/";
    ret.push(std::make_pair(sDir, sDir));

    // <moduledir> and <datadir> (<prefix>/lib/znc)
    ret.push(std::make_pair(_MODDIR_ + NoString("/"), _DATADIR_ + NoString("/modules/")));

    return ret;
}

NoModuleHandle OpenModule(const NoString& name, const NoString& path, bool& bVersionMismatch, NoModuleInfo& info, NoString& message)
{
    // Some sane defaults in case anything errors out below
    bVersionMismatch = false;
    message.clear();

    for (uint a = 0; a < name.length(); a++) {
        if (((name[a] < '0') || (name[a] > '9')) && ((name[a] < 'a') || (name[a] > 'z')) &&
            ((name[a] < 'A') || (name[a] > 'Z')) && (name[a] != '_')) {
            message = "Module names can only contain letters, numbers and underscores, [" + name + "] is invalid.";
            return nullptr;
        }
    }

    // The second argument to dlopen() has a long history. It seems clear
    // that (despite what the man page says) we must include either of
    // RTLD_NOW and RTLD_LAZY and either of RTLD_GLOBAL and RTLD_LOCAL.
    //
    // RTLD_NOW vs. RTLD_LAZY: We use RTLD_NOW to avoid ZNC dying due to
    // failed symbol lookups later on. Doesn't really seem to have much of a
    // performance impact.
    //
    // RTLD_GLOBAL vs. RTLD_LOCAL: If perl is loaded with RTLD_LOCAL and later on
    // loads own modules (which it apparently does with RTLD_LAZY), we will die in a
    // name lookup since one of perl's symbols isn't found. That's worse
    // than any theoretical issue with RTLD_GLOBAL.
    NoModuleHandle p = dlopen((path).c_str(), RTLD_NOW | RTLD_GLOBAL);

    if (!p) {
        // dlerror() returns pointer to static buffer, which may be overwritten very soon with another dl call
        // also it may just return null.
        const char* cDlError = dlerror();
        NoString sDlError = cDlError ? cDlError : "Unknown error";
        message = "Unable to open module [" + name + "] [" + sDlError + "]";
        return nullptr;
    }

    typedef bool (*InfoFP)(double, NoModuleInfo&);
    InfoFP no_moduleInfo = (InfoFP)dlsym(p, "no_moduleInfo");

    if (!no_moduleInfo) {
        dlclose(p);
        message = "Could not find no_moduleInfo() in module [" + name + "]";
        return nullptr;
    }

    if (no_moduleInfo(NoModule::GetCoreVersion(), info)) {
        message = "";
        bVersionMismatch = false;
    } else {
        bVersionMismatch = true;
        message = "Version mismatch, recompile this module.";
    }

    return p;
}
