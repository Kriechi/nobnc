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
#include "nofile.h"
#include "nodir.h"
#include "noapp.h"
#include <dlfcn.h>

bool ZNC_NO_NEED_TO_DO_ANYTHING_ON_MODULE_CALL_EXITER;

#ifndef RTLD_LOCAL
#define RTLD_LOCAL 0
#warning "your crap box doesnt define RTLD_LOCAL !?"
#endif

#define MODUNLOADCHK(func)                          \
    for (NoModule * mod : d->modules) {            \
        try {                                       \
            NoClient* pOldClient = mod->client();  \
            mod->setClient(d->client);             \
            NoUser* pOldUser = nullptr;             \
            if (d->user) {                          \
                pOldUser = mod->user();            \
                mod->setUser(d->user);             \
            }                                       \
            NoNetwork* network = nullptr;          \
            if (d->network) {                       \
                network = mod->network();         \
                mod->setNetwork(d->network);       \
            }                                       \
            mod->func;                             \
            if (d->user)                            \
                mod->setUser(pOldUser);            \
            if (d->network)                         \
                mod->setNetwork(network);         \
            mod->setClient(pOldClient);            \
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
            NoClient* pOldClient = mod->client();   \
            mod->setClient(d->client);              \
            NoUser* pOldUser = nullptr;              \
            if (d->user) {                           \
                pOldUser = mod->user();             \
                mod->setUser(d->user);              \
            }                                        \
            NoNetwork* network = nullptr;           \
            if (d->network) {                        \
                network = mod->network();          \
                mod->setNetwork(d->network);        \
            }                                        \
            e = mod->func;                          \
            if (d->user)                             \
                mod->setUser(pOldUser);             \
            if (d->network)                          \
                mod->setNetwork(network);          \
            mod->setClient(pOldClient);             \
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
static bool findModulePath(const NoString& module, NoString& sModPath, NoString& sDataPath);
// Return a list of <module dir, data dir> pairs for directories in
// which modules can be found.
typedef std::queue<std::pair<NoString, NoString>> NoModDirList;
static NoModDirList moduleDirs();

static NoModuleHandle
OpenModule(const NoString& module, const NoString& sModPath, bool& bVersionMismatch, NoModuleInfo& Info, NoString& sRetMsg);

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
        NoString sRetMsg;
        NoString sModName = d->modules.back()->moduleName();
        unloadModule(sModName, sRetMsg);
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
bool NoModuleLoader::onIrcConnecting(NoIrcSocket* pIRCSock)
{
    MODHALTCHK(onIrcConnecting(pIRCSock));
}
bool NoModuleLoader::onIrcConnectionError(NoIrcSocket* pIRCSock)
{
    MODUNLOADCHK(onIrcConnectionError(pIRCSock));
    return false;
}
bool NoModuleLoader::onIrcRegistration(NoString& pass, NoString& nick, NoString& ident, NoString& sRealName)
{
    MODHALTCHK(onIrcRegistration(pass, nick, ident, sRealName));
}
bool NoModuleLoader::onBroadcast(NoString& sMessage)
{
    MODHALTCHK(onBroadcast(sMessage));
}
bool NoModuleLoader::onIrcDisconnected()
{
    MODUNLOADCHK(onIrcDisconnected());
    return false;
}

bool NoModuleLoader::onChanPermission2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange)
{
    MODUNLOADCHK(onChanPermission2(pOpNick, Nick, Channel, uMode, bAdded, bNoChange));
    return false;
}
bool NoModuleLoader::onChanPermission(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange)
{
    MODUNLOADCHK(onChanPermission(OpNick, Nick, Channel, uMode, bAdded, bNoChange));
    return false;
}
bool NoModuleLoader::onOp2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(onOp2(pOpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModuleLoader::onOp(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(onOp(OpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModuleLoader::onDeop2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(onDeop2(pOpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModuleLoader::onDeop(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(onDeop(OpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModuleLoader::onVoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(onVoice2(pOpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModuleLoader::onVoice(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(onVoice(OpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModuleLoader::onDevoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(onDevoice2(pOpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModuleLoader::onDevoice(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(onDevoice(OpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModuleLoader::onRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& args)
{
    MODUNLOADCHK(onRawMode2(pOpNick, Channel, sModes, args));
    return false;
}
bool NoModuleLoader::onRawMode(const NoNick& OpNick, NoChannel& Channel, const NoString& sModes, const NoString& args)
{
    MODUNLOADCHK(onRawMode(OpNick, Channel, sModes, args));
    return false;
}
bool NoModuleLoader::onMode2(const NoNick* pOpNick, NoChannel& Channel, char uMode, const NoString& arg, bool bAdded, bool bNoChange)
{
    MODUNLOADCHK(onMode2(pOpNick, Channel, uMode, arg, bAdded, bNoChange));
    return false;
}
bool NoModuleLoader::onMode(const NoNick& OpNick, NoChannel& Channel, char uMode, const NoString& arg, bool bAdded, bool bNoChange)
{
    MODUNLOADCHK(onMode(OpNick, Channel, uMode, arg, bAdded, bNoChange));
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
bool NoModuleLoader::onUserCtcpReply(NoString& sTarget, NoString& sMessage)
{
    MODHALTCHK(onUserCtcpReply(sTarget, sMessage));
}
bool NoModuleLoader::onUserCtcp(NoString& sTarget, NoString& sMessage)
{
    MODHALTCHK(onUserCtcp(sTarget, sMessage));
}
bool NoModuleLoader::onUserAction(NoString& sTarget, NoString& sMessage)
{
    MODHALTCHK(onUserAction(sTarget, sMessage));
}
bool NoModuleLoader::onUserMsg(NoString& sTarget, NoString& sMessage)
{
    MODHALTCHK(onUserMsg(sTarget, sMessage));
}
bool NoModuleLoader::onUserNotice(NoString& sTarget, NoString& sMessage)
{
    MODHALTCHK(onUserNotice(sTarget, sMessage));
}
bool NoModuleLoader::onUserJoin(NoString& sChannel, NoString& sKey)
{
    MODHALTCHK(onUserJoin(sChannel, sKey));
}
bool NoModuleLoader::onUserPart(NoString& sChannel, NoString& sMessage)
{
    MODHALTCHK(onUserPart(sChannel, sMessage));
}
bool NoModuleLoader::onUserTopic(NoString& sChannel, NoString& sTopic)
{
    MODHALTCHK(onUserTopic(sChannel, sTopic));
}
bool NoModuleLoader::onUserTopicRequest(NoString& sChannel)
{
    MODHALTCHK(onUserTopicRequest(sChannel));
}
bool NoModuleLoader::onUserQuit(NoString& sMessage)
{
    MODHALTCHK(onUserQuit(sMessage));
}

bool NoModuleLoader::onQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& channels)
{
    MODUNLOADCHK(onQuit(Nick, sMessage, channels));
    return false;
}
bool NoModuleLoader::onNick(const NoNick& Nick, const NoString& sNewNick, const std::vector<NoChannel*>& channels)
{
    MODUNLOADCHK(onNick(Nick, sNewNick, channels));
    return false;
}
bool NoModuleLoader::onKick(const NoNick& Nick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage)
{
    MODUNLOADCHK(onKick(Nick, sKickedNick, Channel, sMessage));
    return false;
}
bool NoModuleLoader::onJoining(NoChannel& Channel)
{
    MODHALTCHK(onJoining(Channel));
}
bool NoModuleLoader::onJoin(const NoNick& Nick, NoChannel& Channel)
{
    MODUNLOADCHK(onJoin(Nick, Channel));
    return false;
}
bool NoModuleLoader::onPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage)
{
    MODUNLOADCHK(onPart(Nick, Channel, sMessage));
    return false;
}
bool NoModuleLoader::onInvite(const NoNick& Nick, const NoString& sChan)
{
    MODHALTCHK(onInvite(Nick, sChan));
}
bool NoModuleLoader::onChanBufferStarting(NoChannel& Chan, NoClient& Client)
{
    MODHALTCHK(onChanBufferStarting(Chan, Client));
}
bool NoModuleLoader::onChanBufferEnding(NoChannel& Chan, NoClient& Client)
{
    MODHALTCHK(onChanBufferEnding(Chan, Client));
}
bool NoModuleLoader::onChanBufferPlayLine2(NoChannel& Chan, NoClient& Client, NoString& line, const timeval& tv)
{
    MODHALTCHK(onChanBufferPlayLine2(Chan, Client, line, tv));
}
bool NoModuleLoader::onChanBufferPlayLine(NoChannel& Chan, NoClient& Client, NoString& line)
{
    MODHALTCHK(onChanBufferPlayLine(Chan, Client, line));
}
bool NoModuleLoader::onPrivBufferPlayLine2(NoClient& Client, NoString& line, const timeval& tv)
{
    MODHALTCHK(onPrivBufferPlayLine2(Client, line, tv));
}
bool NoModuleLoader::onPrivBufferPlayLine(NoClient& Client, NoString& line)
{
    MODHALTCHK(onPrivBufferPlayLine(Client, line));
}
bool NoModuleLoader::onCtcpReply(NoNick& Nick, NoString& sMessage)
{
    MODHALTCHK(onCtcpReply(Nick, sMessage));
}
bool NoModuleLoader::onPrivCtcp(NoNick& Nick, NoString& sMessage)
{
    MODHALTCHK(onPrivCtcp(Nick, sMessage));
}
bool NoModuleLoader::onChanCtcp(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    MODHALTCHK(onChanCtcp(Nick, Channel, sMessage));
}
bool NoModuleLoader::onPrivAction(NoNick& Nick, NoString& sMessage)
{
    MODHALTCHK(onPrivAction(Nick, sMessage));
}
bool NoModuleLoader::onChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    MODHALTCHK(onChanAction(Nick, Channel, sMessage));
}
bool NoModuleLoader::onPrivMsg(NoNick& Nick, NoString& sMessage)
{
    MODHALTCHK(onPrivMsg(Nick, sMessage));
}
bool NoModuleLoader::onChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    MODHALTCHK(onChanMsg(Nick, Channel, sMessage));
}
bool NoModuleLoader::onPrivNotice(NoNick& Nick, NoString& sMessage)
{
    MODHALTCHK(onPrivNotice(Nick, sMessage));
}
bool NoModuleLoader::onChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    MODHALTCHK(onChanNotice(Nick, Channel, sMessage));
}
bool NoModuleLoader::onTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic)
{
    MODHALTCHK(onTopic(Nick, Channel, sTopic));
}
bool NoModuleLoader::onTimerAutoJoin(NoChannel& Channel)
{
    MODHALTCHK(onTimerAutoJoin(Channel));
}
bool NoModuleLoader::onAddNetwork(NoNetwork& Network, NoString& sErrorRet)
{
    MODHALTCHK(onAddNetwork(Network, sErrorRet));
}
bool NoModuleLoader::onDeleteNetwork(NoNetwork& Network)
{
    MODHALTCHK(onDeleteNetwork(Network));
}
bool NoModuleLoader::onSendToClient(NoString& line, NoClient& Client)
{
    MODHALTCHK(onSendToClient(line, Client));
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
bool NoModuleLoader::onModNotice(const NoString& sMessage)
{
    MODUNLOADCHK(onModNotice(sMessage));
    return false;
}
bool NoModuleLoader::onModCTCP(const NoString& sMessage)
{
    MODUNLOADCHK(onModCTCP(sMessage));
    return false;
}

// Why MODHALTCHK works only with functions returning ModRet ? :(
bool NoModuleLoader::onServerCapAvailable(const NoString& cap)
{
    bool bResult = false;
    for (NoModule* mod : d->modules) {
        try {
            NoClient* pOldClient = mod->client();
            mod->setClient(d->client);
            if (d->user) {
                NoUser* pOldUser = mod->user();
                mod->setUser(d->user);
                bResult |= mod->onServerCapAvailable(cap);
                mod->setUser(pOldUser);
            } else {
                // WTF? Is that possible?
                bResult |= mod->onServerCapAvailable(cap);
            }
            mod->setClient(pOldClient);
        } catch (const NoModule::ModException& e) {
            if (NoModule::UNLOAD == e) {
                unloadModule(mod->moduleName());
            }
        }
    }
    return bResult;
}

bool NoModuleLoader::onServerCapResult(const NoString& cap, bool bSuccess)
{
    MODUNLOADCHK(onServerCapResult(cap, bSuccess));
    return false;
}

////////////////////
// Global Modules //
////////////////////
bool NoModuleLoader::onAddUser(NoUser& User, NoString& sErrorRet)
{
    MODHALTCHK(onAddUser(User, sErrorRet));
}

bool NoModuleLoader::onDeleteUser(NoUser& User)
{
    MODHALTCHK(onDeleteUser(User));
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

bool NoModuleLoader::onFailedLogin(const NoString& sUsername, const NoString& sRemoteIP)
{
    MODUNLOADCHK(onFailedLogin(sUsername, sRemoteIP));
    return false;
}

bool NoModuleLoader::onUnknownUserRaw(NoClient* client, NoString& line)
{
    MODHALTCHK(onUnknownUserRaw(client, line));
}

bool NoModuleLoader::onClientCapLs(NoClient* client, NoStringSet& ssCaps)
{
    MODUNLOADCHK(onClientCapLs(client, ssCaps));
    return false;
}

// Maybe create new macro for this?
bool NoModuleLoader::isClientCapSupported(NoClient* client, const NoString& cap, bool bState)
{
    bool bResult = false;
    for (NoModule* mod : d->modules) {
        try {
            NoClient* pOldClient = mod->client();
            mod->setClient(d->client);
            if (d->user) {
                NoUser* pOldUser = mod->user();
                mod->setUser(d->user);
                bResult |= mod->isClientCapSupported(client, cap, bState);
                mod->setUser(pOldUser);
            } else {
                // WTF? Is that possible?
                bResult |= mod->isClientCapSupported(client, cap, bState);
            }
            mod->setClient(pOldClient);
        } catch (const NoModule::ModException& e) {
            if (NoModule::UNLOAD == e) {
                unloadModule(mod->moduleName());
            }
        }
    }
    return bResult;
}

bool NoModuleLoader::onClientCapRequest(NoClient* client, const NoString& cap, bool bState)
{
    MODUNLOADCHK(onClientCapRequest(client, cap, bState));
    return false;
}

bool NoModuleLoader::onModuleLoading(const NoString& sModName, const NoString& args, No::ModuleType eType, bool& bSuccess, NoString& sRetMsg)
{
    MODHALTCHK(onModuleLoading(sModName, args, eType, bSuccess, sRetMsg));
}

bool NoModuleLoader::onModuleUnloading(NoModule* pModule, bool& bSuccess, NoString& sRetMsg)
{
    MODHALTCHK(onModuleUnloading(pModule, bSuccess, sRetMsg));
}

bool NoModuleLoader::onGetModuleInfo(NoModuleInfo& ModInfo, const NoString& module, bool& bSuccess, NoString& sRetMsg)
{
    MODHALTCHK(onGetModuleInfo(ModInfo, module, bSuccess, sRetMsg));
}

bool NoModuleLoader::onGetAvailableModules(std::set<NoModuleInfo>& ssMods, No::ModuleType eType)
{
    MODUNLOADCHK(onGetAvailableModules(ssMods, eType));
    return false;
}


NoModule* NoModuleLoader::findModule(const NoString& module) const
{
    for (NoModule* mod : d->modules) {
        if (module.equals(mod->moduleName())) {
            return mod;
        }
    }

    return nullptr;
}

bool NoModuleLoader::loadModule(const NoString& module, const NoString& args, No::ModuleType eType, NoUser* user, NoNetwork* network, NoString& sRetMsg)
{
    sRetMsg = "";

    if (findModule(module) != nullptr) {
        sRetMsg = "Module [" + module + "] already loaded.";
        return false;
    }

    bool bSuccess;
    bool bHandled = false;
    _GLOBALMODULECALL(onModuleLoading(module, args, eType, bSuccess, sRetMsg), user, network, nullptr, &bHandled);
    if (bHandled)
        return bSuccess;

    NoString sModPath, sDataPath;
    bool bVersionMismatch;
    NoModuleInfo Info;

    if (!findModulePath(module, sModPath, sDataPath)) {
        sRetMsg = "Unable to find module [" + module + "]";
        return false;
    }

    NoModuleHandle p = OpenModule(module, sModPath, bVersionMismatch, Info, sRetMsg);

    if (!p)
        return false;

    if (bVersionMismatch) {
        dlclose(p);
        sRetMsg = "Version mismatch, recompile this module.";
        return false;
    }

    if (!Info.supportsType(eType)) {
        dlclose(p);
        sRetMsg = "Module [" + module + "] does not support module type [" + NoModuleInfo::moduleTypeToString(eType) + "].";
        return false;
    }

    if (!user && eType == No::UserModule) {
        dlclose(p);
        sRetMsg = "Module [" + module + "] requires a user.";
        return false;
    }

    if (!network && eType == No::NetworkModule) {
        dlclose(p);
        sRetMsg = "Module [" + module + "] requires a network.";
        return false;
    }

    NoModule* pModule = Info.loader()(p, user, network, module, sDataPath, eType);
    pModule->setDescription(Info.description());
    pModule->setArgs(args);
    pModule->setModulePath(NoDir::current().filePath(sModPath));
    d->modules.push_back(pModule);

    bool bLoaded;
    try {
        bLoaded = pModule->onLoad(args, sRetMsg);
    } catch (const NoModule::ModException&) {
        bLoaded = false;
        sRetMsg = "Caught an exception";
    }

    if (!bLoaded) {
        unloadModule(module, sModPath);
        if (!sRetMsg.empty())
            sRetMsg = "Module [" + module + "] aborted: " + sRetMsg;
        else
            sRetMsg = "Module [" + module + "] aborted.";
        return false;
    }

    if (!sRetMsg.empty()) {
        sRetMsg += " ";
    }
    sRetMsg += "[" + sModPath + "]";
    return true;
}

bool NoModuleLoader::unloadModule(const NoString& module)
{
    NoString s;
    return unloadModule(module, s);
}

bool NoModuleLoader::unloadModule(const NoString& module, NoString& sRetMsg)
{
    NoString sMod = module; // Make a copy incase the reference passed in is from NoModule::moduleName()
    NoModule* pModule = findModule(sMod);
    sRetMsg = "";

    if (!pModule) {
        sRetMsg = "Module [" + sMod + "] not loaded.";
        return false;
    }

    bool bSuccess;
    bool bHandled = false;
    _GLOBALMODULECALL(onModuleUnloading(pModule, bSuccess, sRetMsg), pModule->user(), pModule->network(), nullptr, &bHandled);
    if (bHandled)
        return bSuccess;

    NoModuleHandle p = pModule->GetDLL();

    if (p) {
        delete pModule;

        for (auto it = d->modules.begin(); it != d->modules.end(); ++it) {
            if (*it == pModule) {
                d->modules.erase(it);
                break;
            }
        }

        dlclose(p);
        sRetMsg = "Module [" + sMod + "] unloaded";

        return true;
    }

    sRetMsg = "Unable to unload module [" + sMod + "]";
    return false;
}

bool NoModuleLoader::reloadModule(const NoString& module, const NoString& args, NoUser* user, NoNetwork* network, NoString& sRetMsg)
{
    NoString sMod = module; // Make a copy incase the reference passed in is from NoModule::moduleName()
    NoModule* pModule = findModule(sMod);

    if (!pModule) {
        sRetMsg = "Module [" + sMod + "] not loaded";
        return false;
    }

    No::ModuleType eType = pModule->type();
    pModule = nullptr;

    sRetMsg = "";
    if (!unloadModule(sMod, sRetMsg)) {
        return false;
    }

    if (!loadModule(sMod, args, eType, user, network, sRetMsg)) {
        return false;
    }

    sRetMsg = "Reloaded module [" + sMod + "]";
    return true;
}

bool NoModuleLoader::moduleInfo(NoModuleInfo& ModInfo, const NoString& module, NoString& sRetMsg)
{
    NoString sModPath, sTmp;

    bool bSuccess;
    bool bHandled = false;
    GLOBALMODULECALL(onGetModuleInfo(ModInfo, module, bSuccess, sRetMsg), &bHandled);
    if (bHandled)
        return bSuccess;

    if (!findModulePath(module, sModPath, sTmp)) {
        sRetMsg = "Unable to find module [" + module + "]";
        return false;
    }

    return modulePath(ModInfo, module, sModPath, sRetMsg);
}

bool NoModuleLoader::modulePath(NoModuleInfo& ModInfo, const NoString& module, const NoString& sModPath, NoString& sRetMsg)
{
    bool bVersionMismatch;

    NoModuleHandle p = OpenModule(module, sModPath, bVersionMismatch, ModInfo, sRetMsg);

    if (!p)
        return false;

    ModInfo.setName(module);
    ModInfo.setPath(sModPath);

    if (bVersionMismatch) {
        ModInfo.setDescription("--- Version mismatch, recompile this module. ---");
    }

    dlclose(p);

    return true;
}

void NoModuleLoader::availableModules(std::set<NoModuleInfo>& ssMods, No::ModuleType eType)
{
    ssMods.clear();

    NoModDirList dirs = moduleDirs();

    while (!dirs.empty()) {
        NoDir Dir(dirs.front().first);
        dirs.pop();

        for (NoFile* file : Dir.files("*.so")) {
            NoString name = file->GetShortName();
            NoString sPath = file->GetLongName();
            NoModuleInfo ModInfo;
            name.rightChomp(3);

            NoString sIgnoreRetMsg;
            if (modulePath(ModInfo, name, sPath, sIgnoreRetMsg)) {
                if (ModInfo.supportsType(eType)) {
                    ssMods.insert(ModInfo);
                }
            }
        }
    }

    GLOBALMODULECALL(onGetAvailableModules(ssMods, eType), NOTHING);
}

void NoModuleLoader::defaultModules(std::set<NoModuleInfo>& ssMods, No::ModuleType eType)
{

    availableModules(ssMods, eType);

    const std::map<NoString, No::ModuleType> ns = { { "chansaver", No::UserModule },
                                                    { "controlpanel", No::UserModule },
                                                    { "simple_away", No::NetworkModule },
                                                    { "webadmin", No::GlobalModule } };

    auto it = ssMods.begin();
    while (it != ssMods.end()) {
        auto it2 = ns.find(it->name());
        if (it2 != ns.end() && it2->second == eType) {
            ++it;
        } else {
            it = ssMods.erase(it);
        }
    }
}

bool findModulePath(const NoString& module, NoString& sModPath, NoString& sDataPath)
{
    NoString sMod = module;
    NoString sDir = sMod;
    if (!module.contains("."))
        sMod += ".so";

    NoModDirList dirs = moduleDirs();

    while (!dirs.empty()) {
        sModPath = dirs.front().first + sMod;
        sDataPath = dirs.front().second;
        dirs.pop();

        if (NoFile::Exists(sModPath)) {
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

NoModuleHandle OpenModule(const NoString& module, const NoString& sModPath, bool& bVersionMismatch, NoModuleInfo& Info, NoString& sRetMsg)
{
    // Some sane defaults in case anything errors out below
    bVersionMismatch = false;
    sRetMsg.clear();

    for (uint a = 0; a < module.length(); a++) {
        if (((module[a] < '0') || (module[a] > '9')) && ((module[a] < 'a') || (module[a] > 'z')) &&
            ((module[a] < 'A') || (module[a] > 'Z')) && (module[a] != '_')) {
            sRetMsg = "Module names can only contain letters, numbers and underscores, [" + module + "] is invalid.";
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
    NoModuleHandle p = dlopen((sModPath).c_str(), RTLD_NOW | RTLD_GLOBAL);

    if (!p) {
        // dlerror() returns pointer to static buffer, which may be overwritten very soon with another dl call
        // also it may just return null.
        const char* cDlError = dlerror();
        NoString sDlError = cDlError ? cDlError : "Unknown error";
        sRetMsg = "Unable to open module [" + module + "] [" + sDlError + "]";
        return nullptr;
    }

    typedef bool (*InfoFP)(double, NoModuleInfo&);
    InfoFP no_moduleInfo = (InfoFP)dlsym(p, "no_moduleInfo");

    if (!no_moduleInfo) {
        dlclose(p);
        sRetMsg = "Could not find no_moduleInfo() in module [" + module + "]";
        return nullptr;
    }

    if (no_moduleInfo(NoModule::GetCoreVersion(), Info)) {
        sRetMsg = "";
        bVersionMismatch = false;
    } else {
        bVersionMismatch = true;
        sRetMsg = "Version mismatch, recompile this module.";
    }

    return p;
}
