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
#include "nodir.h"
#include "noapp.h"
#include <dlfcn.h>

bool ZNC_NO_NEED_TO_DO_ANYTHING_ON_MODULE_CALL_EXITER;

#ifndef RTLD_LOCAL
#define RTLD_LOCAL 0
#warning "your crap box doesnt define RTLD_LOCAL !?"
#endif

#define MODUNLOADCHK(func)                              \
    for (NoModule * pMod : d->modules) {                      \
        try {                                           \
            NoClient* pOldClient = pMod->GetClient();    \
            pMod->SetClient(d->client);                 \
            NoUser* pOldUser = nullptr;                  \
            if (d->user) {                              \
                pOldUser = pMod->GetUser();             \
                pMod->SetUser(d->user);                 \
            }                                           \
            NoNetwork* pNetwork = nullptr;            \
            if (d->network) {                           \
                pNetwork = pMod->GetNetwork();          \
                pMod->SetNetwork(d->network);           \
            }                                           \
            pMod->func;                                 \
            if (d->user) pMod->SetUser(pOldUser);       \
            if (d->network) pMod->SetNetwork(pNetwork); \
            pMod->SetClient(pOldClient);                \
        } catch (const NoModule::ModException& e) {     \
            if (e == NoModule::UNLOAD) {                 \
                unloadModule(pMod->GetModName());       \
            }                                           \
        }                                               \
    }


#define MODHALTCHK(func)                                \
    bool bHaltCore = false;                             \
    for (NoModule * pMod : d->modules) {                      \
        try {                                           \
            NoModule::ModRet e = NoModule::CONTINUE;     \
            NoClient* pOldClient = pMod->GetClient();    \
            pMod->SetClient(d->client);                 \
            NoUser* pOldUser = nullptr;                  \
            if (d->user) {                              \
                pOldUser = pMod->GetUser();             \
                pMod->SetUser(d->user);                 \
            }                                           \
            NoNetwork* pNetwork = nullptr;            \
            if (d->network) {                           \
                pNetwork = pMod->GetNetwork();          \
                pMod->SetNetwork(d->network);           \
            }                                           \
            e = pMod->func;                             \
            if (d->user) pMod->SetUser(pOldUser);       \
            if (d->network) pMod->SetNetwork(pNetwork); \
            pMod->SetClient(pOldClient);                \
            if (e == NoModule::HALTMODS) {               \
                break;                                  \
            } else if (e == NoModule::HALTCORE) {        \
                bHaltCore = true;                       \
            } else if (e == NoModule::HALT) {            \
                bHaltCore = true;                       \
                break;                                  \
            }                                           \
        } catch (const NoModule::ModException& e) {     \
            if (e == NoModule::UNLOAD) {                 \
                unloadModule(pMod->GetModName());       \
            }                                           \
        }                                               \
    }                                                   \
    return bHaltCore;

// This returns the path to the .so and to the data dir
// which is where static data (webadmin skins) are saved
static bool findModulePath(const NoString& sModule, NoString& sModPath, NoString& sDataPath);
// Return a list of <module dir, data dir> pairs for directories in
// which modules can be found.
typedef std::queue<std::pair<NoString, NoString>> NoModDirList;
static NoModDirList moduleDirs();

static NoModuleHandle OpenModule(const NoString& sModule, const NoString& sModPath, bool& bVersionMismatch, NoModuleInfo& Info, NoString& sRetMsg);

class NoModuleLoaderPrivate
{
public:
    NoUser* user = nullptr;
    NoNetwork* network = nullptr;
    NoClient* client = nullptr;
    std::vector<NoModule*> modules;
};

NoModuleLoader::NoModuleLoader() : d(new NoModuleLoaderPrivate) {}

NoModuleLoader::~NoModuleLoader() { unloadAllModules(); }

bool NoModuleLoader::isEmpty() const { return d->modules.empty(); }

std::vector<NoModule*> NoModuleLoader::modules() const { return d->modules; }

void NoModuleLoader::setUser(NoUser* pUser) { d->user = pUser; }

void NoModuleLoader::setNetwork(NoNetwork* pNetwork) { d->network = pNetwork; }

void NoModuleLoader::setClient(NoClient* pClient) { d->client = pClient; }

NoUser* NoModuleLoader::user() const { return d->user; }

NoNetwork* NoModuleLoader::network() const { return d->network; }

NoClient* NoModuleLoader::client() const { return d->client; }

void NoModuleLoader::unloadAllModules()
{
    while (!d->modules.empty()) {
        NoString sRetMsg;
        NoString sModName = d->modules.back()->GetModName();
        unloadModule(sModName, sRetMsg);
    }
}

bool NoModuleLoader::onBoot()
{
    for (NoModule* pMod : d->modules) {
        try {
            if (!pMod->onBoot()) {
                return true;
            }
        } catch (const NoModule::ModException& e) {
            if (e == NoModule::UNLOAD) {
                unloadModule(pMod->GetModName());
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
bool NoModuleLoader::onIrcConnecting(NoIrcSocket* pIRCSock) { MODHALTCHK(onIrcConnecting(pIRCSock)); }
bool NoModuleLoader::onIrcConnectionError(NoIrcSocket* pIRCSock)
{
    MODUNLOADCHK(onIrcConnectionError(pIRCSock));
    return false;
}
bool NoModuleLoader::onIrcRegistration(NoString& sPass, NoString& sNick, NoString& sIdent, NoString& sRealName)
{
    MODHALTCHK(onIrcRegistration(sPass, sNick, sIdent, sRealName));
}
bool NoModuleLoader::onBroadcast(NoString& sMessage) { MODHALTCHK(onBroadcast(sMessage)); }
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
bool NoModuleLoader::onRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs)
{
    MODUNLOADCHK(onRawMode2(pOpNick, Channel, sModes, sArgs));
    return false;
}
bool NoModuleLoader::onRawMode(const NoNick& OpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs)
{
    MODUNLOADCHK(onRawMode(OpNick, Channel, sModes, sArgs));
    return false;
}
bool NoModuleLoader::onMode2(const NoNick* pOpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange)
{
    MODUNLOADCHK(onMode2(pOpNick, Channel, uMode, sArg, bAdded, bNoChange));
    return false;
}
bool NoModuleLoader::onMode(const NoNick& OpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange)
{
    MODUNLOADCHK(onMode(OpNick, Channel, uMode, sArg, bAdded, bNoChange));
    return false;
}
bool NoModuleLoader::onRaw(NoString& sLine) { MODHALTCHK(onRaw(sLine)); }

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
bool NoModuleLoader::onUserRaw(NoString& sLine) { MODHALTCHK(onUserRaw(sLine)); }
bool NoModuleLoader::onUserCtcpReply(NoString& sTarget, NoString& sMessage) { MODHALTCHK(onUserCtcpReply(sTarget, sMessage)); }
bool NoModuleLoader::onUserCtcp(NoString& sTarget, NoString& sMessage) { MODHALTCHK(onUserCtcp(sTarget, sMessage)); }
bool NoModuleLoader::onUserAction(NoString& sTarget, NoString& sMessage) { MODHALTCHK(onUserAction(sTarget, sMessage)); }
bool NoModuleLoader::onUserMsg(NoString& sTarget, NoString& sMessage) { MODHALTCHK(onUserMsg(sTarget, sMessage)); }
bool NoModuleLoader::onUserNotice(NoString& sTarget, NoString& sMessage) { MODHALTCHK(onUserNotice(sTarget, sMessage)); }
bool NoModuleLoader::onUserJoin(NoString& sChannel, NoString& sKey) { MODHALTCHK(onUserJoin(sChannel, sKey)); }
bool NoModuleLoader::onUserPart(NoString& sChannel, NoString& sMessage) { MODHALTCHK(onUserPart(sChannel, sMessage)); }
bool NoModuleLoader::onUserTopic(NoString& sChannel, NoString& sTopic) { MODHALTCHK(onUserTopic(sChannel, sTopic)); }
bool NoModuleLoader::onUserTopicRequest(NoString& sChannel) { MODHALTCHK(onUserTopicRequest(sChannel)); }
bool NoModuleLoader::onUserQuit(NoString& sMessage) { MODHALTCHK(onUserQuit(sMessage)); }

bool NoModuleLoader::onQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans)
{
    MODUNLOADCHK(onQuit(Nick, sMessage, vChans));
    return false;
}
bool NoModuleLoader::onNick(const NoNick& Nick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans)
{
    MODUNLOADCHK(onNick(Nick, sNewNick, vChans));
    return false;
}
bool NoModuleLoader::onKick(const NoNick& Nick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage)
{
    MODUNLOADCHK(onKick(Nick, sKickedNick, Channel, sMessage));
    return false;
}
bool NoModuleLoader::onJoining(NoChannel& Channel) { MODHALTCHK(onJoining(Channel)); }
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
bool NoModuleLoader::onInvite(const NoNick& Nick, const NoString& sChan) { MODHALTCHK(onInvite(Nick, sChan)); }
bool NoModuleLoader::onChanBufferStarting(NoChannel& Chan, NoClient& Client) { MODHALTCHK(onChanBufferStarting(Chan, Client)); }
bool NoModuleLoader::onChanBufferEnding(NoChannel& Chan, NoClient& Client) { MODHALTCHK(onChanBufferEnding(Chan, Client)); }
bool NoModuleLoader::onChanBufferPlayLine2(NoChannel& Chan, NoClient& Client, NoString& sLine, const timeval& tv)
{
    MODHALTCHK(onChanBufferPlayLine2(Chan, Client, sLine, tv));
}
bool NoModuleLoader::onChanBufferPlayLine(NoChannel& Chan, NoClient& Client, NoString& sLine)
{
    MODHALTCHK(onChanBufferPlayLine(Chan, Client, sLine));
}
bool NoModuleLoader::onPrivBufferPlayLine2(NoClient& Client, NoString& sLine, const timeval& tv)
{
    MODHALTCHK(onPrivBufferPlayLine2(Client, sLine, tv));
}
bool NoModuleLoader::onPrivBufferPlayLine(NoClient& Client, NoString& sLine)
{
    MODHALTCHK(onPrivBufferPlayLine(Client, sLine));
}
bool NoModuleLoader::onCtcpReply(NoNick& Nick, NoString& sMessage) { MODHALTCHK(onCtcpReply(Nick, sMessage)); }
bool NoModuleLoader::onPrivCtcp(NoNick& Nick, NoString& sMessage) { MODHALTCHK(onPrivCtcp(Nick, sMessage)); }
bool NoModuleLoader::onChanCtcp(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    MODHALTCHK(onChanCtcp(Nick, Channel, sMessage));
}
bool NoModuleLoader::onPrivAction(NoNick& Nick, NoString& sMessage) { MODHALTCHK(onPrivAction(Nick, sMessage)); }
bool NoModuleLoader::onChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    MODHALTCHK(onChanAction(Nick, Channel, sMessage));
}
bool NoModuleLoader::onPrivMsg(NoNick& Nick, NoString& sMessage) { MODHALTCHK(onPrivMsg(Nick, sMessage)); }
bool NoModuleLoader::onChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    MODHALTCHK(onChanMsg(Nick, Channel, sMessage));
}
bool NoModuleLoader::onPrivNotice(NoNick& Nick, NoString& sMessage) { MODHALTCHK(onPrivNotice(Nick, sMessage)); }
bool NoModuleLoader::onChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    MODHALTCHK(onChanNotice(Nick, Channel, sMessage));
}
bool NoModuleLoader::onTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic) { MODHALTCHK(onTopic(Nick, Channel, sTopic)); }
bool NoModuleLoader::onTimerAutoJoin(NoChannel& Channel) { MODHALTCHK(onTimerAutoJoin(Channel)); }
bool NoModuleLoader::onAddNetwork(NoNetwork& Network, NoString& sErrorRet) { MODHALTCHK(onAddNetwork(Network, sErrorRet)); }
bool NoModuleLoader::onDeleteNetwork(NoNetwork& Network) { MODHALTCHK(onDeleteNetwork(Network)); }
bool NoModuleLoader::onSendToClient(NoString& sLine, NoClient& Client) { MODHALTCHK(onSendToClient(sLine, Client)); }
bool NoModuleLoader::onSendToIrc(NoString& sLine) { MODHALTCHK(onSendToIrc(sLine)); }
bool NoModuleLoader::onStatusCommand(NoString& sCommand) { MODHALTCHK(onStatusCommand(sCommand)); }
bool NoModuleLoader::onModCommand(const NoString& sCommand)
{
    MODUNLOADCHK(onModCommand(sCommand));
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
bool NoModuleLoader::onServerCapAvailable(const NoString& sCap)
{
    bool bResult = false;
    for (NoModule* pMod : d->modules) {
        try {
            NoClient* pOldClient = pMod->GetClient();
            pMod->SetClient(d->client);
            if (d->user) {
                NoUser* pOldUser = pMod->GetUser();
                pMod->SetUser(d->user);
                bResult |= pMod->onServerCapAvailable(sCap);
                pMod->SetUser(pOldUser);
            } else {
                // WTF? Is that possible?
                bResult |= pMod->onServerCapAvailable(sCap);
            }
            pMod->SetClient(pOldClient);
        } catch (const NoModule::ModException& e) {
            if (NoModule::UNLOAD == e) {
                unloadModule(pMod->GetModName());
            }
        }
    }
    return bResult;
}

bool NoModuleLoader::onServerCapResult(const NoString& sCap, bool bSuccess)
{
    MODUNLOADCHK(onServerCapResult(sCap, bSuccess));
    return false;
}

////////////////////
// Global Modules //
////////////////////
bool NoModuleLoader::onAddUser(NoUser& User, NoString& sErrorRet) { MODHALTCHK(onAddUser(User, sErrorRet)); }

bool NoModuleLoader::onDeleteUser(NoUser& User) { MODHALTCHK(onDeleteUser(User)); }

bool NoModuleLoader::onClientConnect(NoSocket* pClient, const NoString& sHost, ushort uPort)
{
    MODUNLOADCHK(onClientConnect(pClient, sHost, uPort));
    return false;
}

bool NoModuleLoader::onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth) { MODHALTCHK(onLoginAttempt(Auth)); }

bool NoModuleLoader::onFailedLogin(const NoString& sUsername, const NoString& sRemoteIP)
{
    MODUNLOADCHK(onFailedLogin(sUsername, sRemoteIP));
    return false;
}

bool NoModuleLoader::onUnknownUserRaw(NoClient* pClient, NoString& sLine) { MODHALTCHK(onUnknownUserRaw(pClient, sLine)); }

bool NoModuleLoader::onClientCapLs(NoClient* pClient, NoStringSet& ssCaps)
{
    MODUNLOADCHK(onClientCapLs(pClient, ssCaps));
    return false;
}

// Maybe create new macro for this?
bool NoModuleLoader::isClientCapSupported(NoClient* pClient, const NoString& sCap, bool bState)
{
    bool bResult = false;
    for (NoModule* pMod : d->modules) {
        try {
            NoClient* pOldClient = pMod->GetClient();
            pMod->SetClient(d->client);
            if (d->user) {
                NoUser* pOldUser = pMod->GetUser();
                pMod->SetUser(d->user);
                bResult |= pMod->isClientCapSupported(pClient, sCap, bState);
                pMod->SetUser(pOldUser);
            } else {
                // WTF? Is that possible?
                bResult |= pMod->isClientCapSupported(pClient, sCap, bState);
            }
            pMod->SetClient(pOldClient);
        } catch (const NoModule::ModException& e) {
            if (NoModule::UNLOAD == e) {
                unloadModule(pMod->GetModName());
            }
        }
    }
    return bResult;
}

bool NoModuleLoader::onClientCapRequest(NoClient* pClient, const NoString& sCap, bool bState)
{
    MODUNLOADCHK(onClientCapRequest(pClient, sCap, bState));
    return false;
}

bool NoModuleLoader::onModuleLoading(const NoString& sModName, const NoString& sArgs, No::ModuleType eType, bool& bSuccess, NoString& sRetMsg)
{
    MODHALTCHK(onModuleLoading(sModName, sArgs, eType, bSuccess, sRetMsg));
}

bool NoModuleLoader::onModuleUnloading(NoModule* pModule, bool& bSuccess, NoString& sRetMsg)
{
    MODHALTCHK(onModuleUnloading(pModule, bSuccess, sRetMsg));
}

bool NoModuleLoader::onGetModuleInfo(NoModuleInfo& ModInfo, const NoString& sModule, bool& bSuccess, NoString& sRetMsg)
{
    MODHALTCHK(onGetModuleInfo(ModInfo, sModule, bSuccess, sRetMsg));
}

bool NoModuleLoader::onGetAvailableModules(std::set<NoModuleInfo>& ssMods, No::ModuleType eType)
{
    MODUNLOADCHK(onGetAvailableModules(ssMods, eType));
    return false;
}


NoModule* NoModuleLoader::findModule(const NoString& sModule) const
{
    for (NoModule* pMod : d->modules) {
        if (sModule.equals(pMod->GetModName())) {
            return pMod;
        }
    }

    return nullptr;
}

bool NoModuleLoader::loadModule(const NoString& sModule, const NoString& sArgs, No::ModuleType eType, NoUser* pUser, NoNetwork* pNetwork, NoString& sRetMsg)
{
    sRetMsg = "";

    if (findModule(sModule) != nullptr) {
        sRetMsg = "Module [" + sModule + "] already loaded.";
        return false;
    }

    bool bSuccess;
    bool bHandled = false;
    _GLOBALMODULECALL(onModuleLoading(sModule, sArgs, eType, bSuccess, sRetMsg), pUser, pNetwork, nullptr, &bHandled);
    if (bHandled) return bSuccess;

    NoString sModPath, sDataPath;
    bool bVersionMismatch;
    NoModuleInfo Info;

    if (!findModulePath(sModule, sModPath, sDataPath)) {
        sRetMsg = "Unable to find module [" + sModule + "]";
        return false;
    }

    NoModuleHandle p = OpenModule(sModule, sModPath, bVersionMismatch, Info, sRetMsg);

    if (!p) return false;

    if (bVersionMismatch) {
        dlclose(p);
        sRetMsg = "Version mismatch, recompile this module.";
        return false;
    }

    if (!Info.supportsType(eType)) {
        dlclose(p);
        sRetMsg =
        "Module [" + sModule + "] does not support module type [" + NoModuleInfo::moduleTypeToString(eType) + "].";
        return false;
    }

    if (!pUser && eType == No::UserModule) {
        dlclose(p);
        sRetMsg = "Module [" + sModule + "] requires a user.";
        return false;
    }

    if (!pNetwork && eType == No::NetworkModule) {
        dlclose(p);
        sRetMsg = "Module [" + sModule + "] requires a network.";
        return false;
    }

    NoModule* pModule = Info.loader()(p, pUser, pNetwork, sModule, sDataPath, eType);
    pModule->SetDescription(Info.description());
    pModule->SetArgs(sArgs);
    pModule->SetModPath(NoDir::ChangeDir(NoApp::Get().GetCurPath(), sModPath));
    d->modules.push_back(pModule);

    bool bLoaded;
    try {
        bLoaded = pModule->OnLoad(sArgs, sRetMsg);
    } catch (const NoModule::ModException&) {
        bLoaded = false;
        sRetMsg = "Caught an exception";
    }

    if (!bLoaded) {
        unloadModule(sModule, sModPath);
        if (!sRetMsg.empty())
            sRetMsg = "Module [" + sModule + "] aborted: " + sRetMsg;
        else
            sRetMsg = "Module [" + sModule + "] aborted.";
        return false;
    }

    if (!sRetMsg.empty()) {
        sRetMsg += " ";
    }
    sRetMsg += "[" + sModPath + "]";
    return true;
}

bool NoModuleLoader::unloadModule(const NoString& sModule)
{
    NoString s;
    return unloadModule(sModule, s);
}

bool NoModuleLoader::unloadModule(const NoString& sModule, NoString& sRetMsg)
{
    NoString sMod = sModule; // Make a copy incase the reference passed in is from NoModule::GetModName()
    NoModule* pModule = findModule(sMod);
    sRetMsg = "";

    if (!pModule) {
        sRetMsg = "Module [" + sMod + "] not loaded.";
        return false;
    }

    bool bSuccess;
    bool bHandled = false;
    _GLOBALMODULECALL(onModuleUnloading(pModule, bSuccess, sRetMsg), pModule->GetUser(), pModule->GetNetwork(), nullptr, &bHandled);
    if (bHandled) return bSuccess;

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

bool NoModuleLoader::reloadModule(const NoString& sModule, const NoString& sArgs, NoUser* pUser, NoNetwork* pNetwork, NoString& sRetMsg)
{
    NoString sMod = sModule; // Make a copy incase the reference passed in is from NoModule::GetModName()
    NoModule* pModule = findModule(sMod);

    if (!pModule) {
        sRetMsg = "Module [" + sMod + "] not loaded";
        return false;
    }

    No::ModuleType eType = pModule->GetType();
    pModule = nullptr;

    sRetMsg = "";
    if (!unloadModule(sMod, sRetMsg)) {
        return false;
    }

    if (!loadModule(sMod, sArgs, eType, pUser, pNetwork, sRetMsg)) {
        return false;
    }

    sRetMsg = "Reloaded module [" + sMod + "]";
    return true;
}

bool NoModuleLoader::moduleInfo(NoModuleInfo& ModInfo, const NoString& sModule, NoString& sRetMsg)
{
    NoString sModPath, sTmp;

    bool bSuccess;
    bool bHandled = false;
    GLOBALMODULECALL(onGetModuleInfo(ModInfo, sModule, bSuccess, sRetMsg), &bHandled);
    if (bHandled) return bSuccess;

    if (!findModulePath(sModule, sModPath, sTmp)) {
        sRetMsg = "Unable to find module [" + sModule + "]";
        return false;
    }

    return modulePath(ModInfo, sModule, sModPath, sRetMsg);
}

bool NoModuleLoader::modulePath(NoModuleInfo& ModInfo, const NoString& sModule, const NoString& sModPath, NoString& sRetMsg)
{
    bool bVersionMismatch;

    NoModuleHandle p = OpenModule(sModule, sModPath, bVersionMismatch, ModInfo, sRetMsg);

    if (!p) return false;

    ModInfo.setName(sModule);
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

    uint a = 0;
    NoDir Dir;

    NoModDirList dirs = moduleDirs();

    while (!dirs.empty()) {
        Dir.FillByWildcard(dirs.front().first, "*.so");
        dirs.pop();

        for (a = 0; a < Dir.size(); a++) {
            NoFile& File = *Dir[a];
            NoString sName = File.GetShortName();
            NoString sPath = File.GetLongName();
            NoModuleInfo ModInfo;
            sName.rightChomp(3);

            NoString sIgnoreRetMsg;
            if (modulePath(ModInfo, sName, sPath, sIgnoreRetMsg)) {
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

bool findModulePath(const NoString& sModule, NoString& sModPath, NoString& sDataPath)
{
    NoString sMod = sModule;
    NoString sDir = sMod;
    if (!sModule.contains(".")) sMod += ".so";

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
    sDir = NoApp::Get().GetModPath() + "/";
    ret.push(std::make_pair(sDir, sDir));

    // <moduledir> and <datadir> (<prefix>/lib/znc)
    ret.push(std::make_pair(_MODDIR_ + NoString("/"), _DATADIR_ + NoString("/modules/")));

    return ret;
}

NoModuleHandle OpenModule(const NoString& sModule, const NoString& sModPath, bool& bVersionMismatch, NoModuleInfo& Info, NoString& sRetMsg)
{
    // Some sane defaults in case anything errors out below
    bVersionMismatch = false;
    sRetMsg.clear();

    for (uint a = 0; a < sModule.length(); a++) {
        if (((sModule[a] < '0') || (sModule[a] > '9')) && ((sModule[a] < 'a') || (sModule[a] > 'z')) &&
            ((sModule[a] < 'A') || (sModule[a] > 'Z')) && (sModule[a] != '_')) {
            sRetMsg = "Module names can only contain letters, numbers and underscores, [" + sModule + "] is invalid.";
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
        sRetMsg = "Unable to open module [" + sModule + "] [" + sDlError + "]";
        return nullptr;
    }

    typedef bool (*InfoFP)(double, NoModuleInfo&);
    InfoFP no_moduleInfo = (InfoFP)dlsym(p, "no_moduleInfo");

    if (!no_moduleInfo) {
        dlclose(p);
        sRetMsg = "Could not find no_moduleInfo() in module [" + sModule + "]";
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
