/*
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

#include "nomodules.h"
#include "nodir.h"
#include "noapp.h"
#include <dlfcn.h>

bool ZNC_NO_NEED_TO_DO_ANYTHING_ON_MODULE_CALL_EXITER;

#ifndef RTLD_LOCAL
#define RTLD_LOCAL 0
#warning "your crap box doesnt define RTLD_LOCAL !?"
#endif

#define MODUNLOADCHK(func)                              \
    for (NoModule * pMod : *this) {                      \
        try {                                           \
            NoClient* pOldClient = pMod->GetClient();    \
            pMod->SetClient(m_client);                 \
            NoUser* pOldUser = nullptr;                  \
            if (m_user) {                              \
                pOldUser = pMod->GetUser();             \
                pMod->SetUser(m_user);                 \
            }                                           \
            NoNetwork* pNetwork = nullptr;            \
            if (m_network) {                           \
                pNetwork = pMod->GetNetwork();          \
                pMod->SetNetwork(m_network);           \
            }                                           \
            pMod->func;                                 \
            if (m_user) pMod->SetUser(pOldUser);       \
            if (m_network) pMod->SetNetwork(pNetwork); \
            pMod->SetClient(pOldClient);                \
        } catch (const NoModule::ModException& e) {     \
            if (e == NoModule::UNLOAD) {                 \
                UnloadModule(pMod->GetModName());       \
            }                                           \
        }                                               \
    }


#define MODHALTCHK(func)                                \
    bool bHaltCore = false;                             \
    for (NoModule * pMod : *this) {                      \
        try {                                           \
            NoModule::ModRet e = NoModule::CONTINUE;     \
            NoClient* pOldClient = pMod->GetClient();    \
            pMod->SetClient(m_client);                 \
            NoUser* pOldUser = nullptr;                  \
            if (m_user) {                              \
                pOldUser = pMod->GetUser();             \
                pMod->SetUser(m_user);                 \
            }                                           \
            NoNetwork* pNetwork = nullptr;            \
            if (m_network) {                           \
                pNetwork = pMod->GetNetwork();          \
                pMod->SetNetwork(m_network);           \
            }                                           \
            e = pMod->func;                             \
            if (m_user) pMod->SetUser(pOldUser);       \
            if (m_network) pMod->SetNetwork(pNetwork); \
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
                UnloadModule(pMod->GetModName());       \
            }                                           \
        }                                               \
    }                                                   \
    return bHaltCore;

NoModules::NoModules() : m_user(nullptr), m_network(nullptr), m_client(nullptr) {}

NoModules::~NoModules() { UnloadAll(); }

void NoModules::UnloadAll()
{
    while (size()) {
        NoString sRetMsg;
        NoString sModName = back()->GetModName();
        UnloadModule(sModName, sRetMsg);
    }
}

bool NoModules::OnBoot()
{
    for (NoModule* pMod : *this) {
        try {
            if (!pMod->OnBoot()) {
                return true;
            }
        } catch (const NoModule::ModException& e) {
            if (e == NoModule::UNLOAD) {
                UnloadModule(pMod->GetModName());
            }
        }
    }

    return false;
}

bool NoModules::OnPreRehash()
{
    MODUNLOADCHK(OnPreRehash());
    return false;
}
bool NoModules::OnPostRehash()
{
    MODUNLOADCHK(OnPostRehash());
    return false;
}
bool NoModules::OnIRCConnected()
{
    MODUNLOADCHK(OnIRCConnected());
    return false;
}
bool NoModules::OnIRCConnecting(NoIrcSocket* pIRCSock) { MODHALTCHK(OnIRCConnecting(pIRCSock)); }
bool NoModules::OnIRCConnectionError(NoIrcSocket* pIRCSock)
{
    MODUNLOADCHK(OnIRCConnectionError(pIRCSock));
    return false;
}
bool NoModules::OnIRCRegistration(NoString& sPass, NoString& sNick, NoString& sIdent, NoString& sRealName)
{
    MODHALTCHK(OnIRCRegistration(sPass, sNick, sIdent, sRealName));
}
bool NoModules::OnBroadcast(NoString& sMessage) { MODHALTCHK(OnBroadcast(sMessage)); }
bool NoModules::OnIRCDisconnected()
{
    MODUNLOADCHK(OnIRCDisconnected());
    return false;
}

bool NoModules::OnChanPermission2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange)
{
    MODUNLOADCHK(OnChanPermission2(pOpNick, Nick, Channel, uMode, bAdded, bNoChange));
    return false;
}
bool NoModules::OnChanPermission(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange)
{
    MODUNLOADCHK(OnChanPermission(OpNick, Nick, Channel, uMode, bAdded, bNoChange));
    return false;
}
bool NoModules::OnOp2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnOp2(pOpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModules::OnOp(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnOp(OpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModules::OnDeop2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnDeop2(pOpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModules::OnDeop(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnDeop(OpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModules::OnVoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnVoice2(pOpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModules::OnVoice(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnVoice(OpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModules::OnDevoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnDevoice2(pOpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModules::OnDevoice(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnDevoice(OpNick, Nick, Channel, bNoChange));
    return false;
}
bool NoModules::OnRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs)
{
    MODUNLOADCHK(OnRawMode2(pOpNick, Channel, sModes, sArgs));
    return false;
}
bool NoModules::OnRawMode(const NoNick& OpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs)
{
    MODUNLOADCHK(OnRawMode(OpNick, Channel, sModes, sArgs));
    return false;
}
bool NoModules::OnMode2(const NoNick* pOpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange)
{
    MODUNLOADCHK(OnMode2(pOpNick, Channel, uMode, sArg, bAdded, bNoChange));
    return false;
}
bool NoModules::OnMode(const NoNick& OpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange)
{
    MODUNLOADCHK(OnMode(OpNick, Channel, uMode, sArg, bAdded, bNoChange));
    return false;
}
bool NoModules::OnRaw(NoString& sLine) { MODHALTCHK(OnRaw(sLine)); }

bool NoModules::OnClientLogin()
{
    MODUNLOADCHK(OnClientLogin());
    return false;
}
bool NoModules::OnClientDisconnect()
{
    MODUNLOADCHK(OnClientDisconnect());
    return false;
}
bool NoModules::OnUserRaw(NoString& sLine) { MODHALTCHK(OnUserRaw(sLine)); }
bool NoModules::OnUserCTCPReply(NoString& sTarget, NoString& sMessage) { MODHALTCHK(OnUserCTCPReply(sTarget, sMessage)); }
bool NoModules::OnUserCTCP(NoString& sTarget, NoString& sMessage) { MODHALTCHK(OnUserCTCP(sTarget, sMessage)); }
bool NoModules::OnUserAction(NoString& sTarget, NoString& sMessage) { MODHALTCHK(OnUserAction(sTarget, sMessage)); }
bool NoModules::OnUserMsg(NoString& sTarget, NoString& sMessage) { MODHALTCHK(OnUserMsg(sTarget, sMessage)); }
bool NoModules::OnUserNotice(NoString& sTarget, NoString& sMessage) { MODHALTCHK(OnUserNotice(sTarget, sMessage)); }
bool NoModules::OnUserJoin(NoString& sChannel, NoString& sKey) { MODHALTCHK(OnUserJoin(sChannel, sKey)); }
bool NoModules::OnUserPart(NoString& sChannel, NoString& sMessage) { MODHALTCHK(OnUserPart(sChannel, sMessage)); }
bool NoModules::OnUserTopic(NoString& sChannel, NoString& sTopic) { MODHALTCHK(OnUserTopic(sChannel, sTopic)); }
bool NoModules::OnUserTopicRequest(NoString& sChannel) { MODHALTCHK(OnUserTopicRequest(sChannel)); }
bool NoModules::OnUserQuit(NoString& sMessage) { MODHALTCHK(OnUserQuit(sMessage)); }

bool NoModules::OnQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans)
{
    MODUNLOADCHK(OnQuit(Nick, sMessage, vChans));
    return false;
}
bool NoModules::OnNick(const NoNick& Nick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans)
{
    MODUNLOADCHK(OnNick(Nick, sNewNick, vChans));
    return false;
}
bool NoModules::OnKick(const NoNick& Nick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage)
{
    MODUNLOADCHK(OnKick(Nick, sKickedNick, Channel, sMessage));
    return false;
}
bool NoModules::OnJoining(NoChannel& Channel) { MODHALTCHK(OnJoining(Channel)); }
bool NoModules::OnJoin(const NoNick& Nick, NoChannel& Channel)
{
    MODUNLOADCHK(OnJoin(Nick, Channel));
    return false;
}
bool NoModules::OnPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage)
{
    MODUNLOADCHK(OnPart(Nick, Channel, sMessage));
    return false;
}
bool NoModules::OnInvite(const NoNick& Nick, const NoString& sChan) { MODHALTCHK(OnInvite(Nick, sChan)); }
bool NoModules::OnChanBufferStarting(NoChannel& Chan, NoClient& Client) { MODHALTCHK(OnChanBufferStarting(Chan, Client)); }
bool NoModules::OnChanBufferEnding(NoChannel& Chan, NoClient& Client) { MODHALTCHK(OnChanBufferEnding(Chan, Client)); }
bool NoModules::OnChanBufferPlayLine2(NoChannel& Chan, NoClient& Client, NoString& sLine, const timeval& tv)
{
    MODHALTCHK(OnChanBufferPlayLine2(Chan, Client, sLine, tv));
}
bool NoModules::OnChanBufferPlayLine(NoChannel& Chan, NoClient& Client, NoString& sLine)
{
    MODHALTCHK(OnChanBufferPlayLine(Chan, Client, sLine));
}
bool NoModules::OnPrivBufferPlayLine2(NoClient& Client, NoString& sLine, const timeval& tv)
{
    MODHALTCHK(OnPrivBufferPlayLine2(Client, sLine, tv));
}
bool NoModules::OnPrivBufferPlayLine(NoClient& Client, NoString& sLine)
{
    MODHALTCHK(OnPrivBufferPlayLine(Client, sLine));
}
bool NoModules::OnCTCPReply(NoNick& Nick, NoString& sMessage) { MODHALTCHK(OnCTCPReply(Nick, sMessage)); }
bool NoModules::OnPrivCTCP(NoNick& Nick, NoString& sMessage) { MODHALTCHK(OnPrivCTCP(Nick, sMessage)); }
bool NoModules::OnChanCTCP(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    MODHALTCHK(OnChanCTCP(Nick, Channel, sMessage));
}
bool NoModules::OnPrivAction(NoNick& Nick, NoString& sMessage) { MODHALTCHK(OnPrivAction(Nick, sMessage)); }
bool NoModules::OnChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    MODHALTCHK(OnChanAction(Nick, Channel, sMessage));
}
bool NoModules::OnPrivMsg(NoNick& Nick, NoString& sMessage) { MODHALTCHK(OnPrivMsg(Nick, sMessage)); }
bool NoModules::OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    MODHALTCHK(OnChanMsg(Nick, Channel, sMessage));
}
bool NoModules::OnPrivNotice(NoNick& Nick, NoString& sMessage) { MODHALTCHK(OnPrivNotice(Nick, sMessage)); }
bool NoModules::OnChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage)
{
    MODHALTCHK(OnChanNotice(Nick, Channel, sMessage));
}
bool NoModules::OnTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic) { MODHALTCHK(OnTopic(Nick, Channel, sTopic)); }
bool NoModules::OnTimerAutoJoin(NoChannel& Channel) { MODHALTCHK(OnTimerAutoJoin(Channel)); }
bool NoModules::OnAddNetwork(NoNetwork& Network, NoString& sErrorRet) { MODHALTCHK(OnAddNetwork(Network, sErrorRet)); }
bool NoModules::OnDeleteNetwork(NoNetwork& Network) { MODHALTCHK(OnDeleteNetwork(Network)); }
bool NoModules::OnSendToClient(NoString& sLine, NoClient& Client) { MODHALTCHK(OnSendToClient(sLine, Client)); }
bool NoModules::OnSendToIRC(NoString& sLine) { MODHALTCHK(OnSendToIRC(sLine)); }
bool NoModules::OnStatusCommand(NoString& sCommand) { MODHALTCHK(OnStatusCommand(sCommand)); }
bool NoModules::OnModCommand(const NoString& sCommand)
{
    MODUNLOADCHK(OnModCommand(sCommand));
    return false;
}
bool NoModules::OnModNotice(const NoString& sMessage)
{
    MODUNLOADCHK(OnModNotice(sMessage));
    return false;
}
bool NoModules::OnModCTCP(const NoString& sMessage)
{
    MODUNLOADCHK(OnModCTCP(sMessage));
    return false;
}

// Why MODHALTCHK works only with functions returning ModRet ? :(
bool NoModules::OnServerCapAvailable(const NoString& sCap)
{
    bool bResult = false;
    for (NoModule* pMod : *this) {
        try {
            NoClient* pOldClient = pMod->GetClient();
            pMod->SetClient(m_client);
            if (m_user) {
                NoUser* pOldUser = pMod->GetUser();
                pMod->SetUser(m_user);
                bResult |= pMod->OnServerCapAvailable(sCap);
                pMod->SetUser(pOldUser);
            } else {
                // WTF? Is that possible?
                bResult |= pMod->OnServerCapAvailable(sCap);
            }
            pMod->SetClient(pOldClient);
        } catch (const NoModule::ModException& e) {
            if (NoModule::UNLOAD == e) {
                UnloadModule(pMod->GetModName());
            }
        }
    }
    return bResult;
}

bool NoModules::OnServerCapResult(const NoString& sCap, bool bSuccess)
{
    MODUNLOADCHK(OnServerCapResult(sCap, bSuccess));
    return false;
}

////////////////////
// Global Modules //
////////////////////
bool NoModules::OnAddUser(NoUser& User, NoString& sErrorRet) { MODHALTCHK(OnAddUser(User, sErrorRet)); }

bool NoModules::OnDeleteUser(NoUser& User) { MODHALTCHK(OnDeleteUser(User)); }

bool NoModules::OnClientConnect(NoSocket* pClient, const NoString& sHost, ushort uPort)
{
    MODUNLOADCHK(OnClientConnect(pClient, sHost, uPort));
    return false;
}

bool NoModules::OnLoginAttempt(std::shared_ptr<NoAuthenticator> Auth) { MODHALTCHK(OnLoginAttempt(Auth)); }

bool NoModules::OnFailedLogin(const NoString& sUsername, const NoString& sRemoteIP)
{
    MODUNLOADCHK(OnFailedLogin(sUsername, sRemoteIP));
    return false;
}

bool NoModules::OnUnknownUserRaw(NoClient* pClient, NoString& sLine) { MODHALTCHK(OnUnknownUserRaw(pClient, sLine)); }

bool NoModules::OnClientCapLs(NoClient* pClient, NoStringSet& ssCaps)
{
    MODUNLOADCHK(OnClientCapLs(pClient, ssCaps));
    return false;
}

// Maybe create new macro for this?
bool NoModules::IsClientCapSupported(NoClient* pClient, const NoString& sCap, bool bState)
{
    bool bResult = false;
    for (NoModule* pMod : *this) {
        try {
            NoClient* pOldClient = pMod->GetClient();
            pMod->SetClient(m_client);
            if (m_user) {
                NoUser* pOldUser = pMod->GetUser();
                pMod->SetUser(m_user);
                bResult |= pMod->IsClientCapSupported(pClient, sCap, bState);
                pMod->SetUser(pOldUser);
            } else {
                // WTF? Is that possible?
                bResult |= pMod->IsClientCapSupported(pClient, sCap, bState);
            }
            pMod->SetClient(pOldClient);
        } catch (const NoModule::ModException& e) {
            if (NoModule::UNLOAD == e) {
                UnloadModule(pMod->GetModName());
            }
        }
    }
    return bResult;
}

bool NoModules::OnClientCapRequest(NoClient* pClient, const NoString& sCap, bool bState)
{
    MODUNLOADCHK(OnClientCapRequest(pClient, sCap, bState));
    return false;
}

bool NoModules::OnModuleLoading(const NoString& sModName, const NoString& sArgs, No::ModuleType eType, bool& bSuccess, NoString& sRetMsg)
{
    MODHALTCHK(OnModuleLoading(sModName, sArgs, eType, bSuccess, sRetMsg));
}

bool NoModules::OnModuleUnloading(NoModule* pModule, bool& bSuccess, NoString& sRetMsg)
{
    MODHALTCHK(OnModuleUnloading(pModule, bSuccess, sRetMsg));
}

bool NoModules::OnGetModInfo(NoModuleInfo& ModInfo, const NoString& sModule, bool& bSuccess, NoString& sRetMsg)
{
    MODHALTCHK(OnGetModInfo(ModInfo, sModule, bSuccess, sRetMsg));
}

bool NoModules::OnGetAvailableMods(std::set<NoModuleInfo>& ssMods, No::ModuleType eType)
{
    MODUNLOADCHK(OnGetAvailableMods(ssMods, eType));
    return false;
}


NoModule* NoModules::FindModule(const NoString& sModule) const
{
    for (NoModule* pMod : *this) {
        if (sModule.equals(pMod->GetModName())) {
            return pMod;
        }
    }

    return nullptr;
}

bool NoModules::LoadModule(const NoString& sModule, const NoString& sArgs, No::ModuleType eType, NoUser* pUser, NoNetwork* pNetwork, NoString& sRetMsg)
{
    sRetMsg = "";

    if (FindModule(sModule) != nullptr) {
        sRetMsg = "Module [" + sModule + "] already loaded.";
        return false;
    }

    bool bSuccess;
    bool bHandled = false;
    _GLOBALMODULECALL(OnModuleLoading(sModule, sArgs, eType, bSuccess, sRetMsg), pUser, pNetwork, nullptr, &bHandled);
    if (bHandled) return bSuccess;

    NoString sModPath, sDataPath;
    bool bVersionMismatch;
    NoModuleInfo Info;

    if (!FindModPath(sModule, sModPath, sDataPath)) {
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

    if (!Info.SupportsType(eType)) {
        dlclose(p);
        sRetMsg =
        "Module [" + sModule + "] does not support module type [" + NoModuleInfo::ModuleTypeToString(eType) + "].";
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

    NoModule* pModule = Info.GetLoader()(p, pUser, pNetwork, sModule, sDataPath, eType);
    pModule->SetDescription(Info.GetDescription());
    pModule->SetArgs(sArgs);
    pModule->SetModPath(NoDir::ChangeDir(NoApp::Get().GetCurPath(), sModPath));
    push_back(pModule);

    bool bLoaded;
    try {
        bLoaded = pModule->OnLoad(sArgs, sRetMsg);
    } catch (const NoModule::ModException&) {
        bLoaded = false;
        sRetMsg = "Caught an exception";
    }

    if (!bLoaded) {
        UnloadModule(sModule, sModPath);
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

bool NoModules::UnloadModule(const NoString& sModule)
{
    NoString s;
    return UnloadModule(sModule, s);
}

bool NoModules::UnloadModule(const NoString& sModule, NoString& sRetMsg)
{
    NoString sMod = sModule; // Make a copy incase the reference passed in is from NoModule::GetModName()
    NoModule* pModule = FindModule(sMod);
    sRetMsg = "";

    if (!pModule) {
        sRetMsg = "Module [" + sMod + "] not loaded.";
        return false;
    }

    bool bSuccess;
    bool bHandled = false;
    _GLOBALMODULECALL(OnModuleUnloading(pModule, bSuccess, sRetMsg), pModule->GetUser(), pModule->GetNetwork(), nullptr, &bHandled);
    if (bHandled) return bSuccess;

    NoModuleHandle p = pModule->GetDLL();

    if (p) {
        delete pModule;

        for (iterator it = begin(); it != end(); ++it) {
            if (*it == pModule) {
                erase(it);
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

bool NoModules::ReloadModule(const NoString& sModule, const NoString& sArgs, NoUser* pUser, NoNetwork* pNetwork, NoString& sRetMsg)
{
    NoString sMod = sModule; // Make a copy incase the reference passed in is from NoModule::GetModName()
    NoModule* pModule = FindModule(sMod);

    if (!pModule) {
        sRetMsg = "Module [" + sMod + "] not loaded";
        return false;
    }

    No::ModuleType eType = pModule->GetType();
    pModule = nullptr;

    sRetMsg = "";
    if (!UnloadModule(sMod, sRetMsg)) {
        return false;
    }

    if (!LoadModule(sMod, sArgs, eType, pUser, pNetwork, sRetMsg)) {
        return false;
    }

    sRetMsg = "Reloaded module [" + sMod + "]";
    return true;
}

bool NoModules::GetModInfo(NoModuleInfo& ModInfo, const NoString& sModule, NoString& sRetMsg)
{
    NoString sModPath, sTmp;

    bool bSuccess;
    bool bHandled = false;
    GLOBALMODULECALL(OnGetModInfo(ModInfo, sModule, bSuccess, sRetMsg), &bHandled);
    if (bHandled) return bSuccess;

    if (!FindModPath(sModule, sModPath, sTmp)) {
        sRetMsg = "Unable to find module [" + sModule + "]";
        return false;
    }

    return GetModPathInfo(ModInfo, sModule, sModPath, sRetMsg);
}

bool NoModules::GetModPathInfo(NoModuleInfo& ModInfo, const NoString& sModule, const NoString& sModPath, NoString& sRetMsg)
{
    bool bVersionMismatch;

    NoModuleHandle p = OpenModule(sModule, sModPath, bVersionMismatch, ModInfo, sRetMsg);

    if (!p) return false;

    ModInfo.SetName(sModule);
    ModInfo.SetPath(sModPath);

    if (bVersionMismatch) {
        ModInfo.SetDescription("--- Version mismatch, recompile this module. ---");
    }

    dlclose(p);

    return true;
}

void NoModules::GetAvailableMods(std::set<NoModuleInfo>& ssMods, No::ModuleType eType)
{
    ssMods.clear();

    uint a = 0;
    NoDir Dir;

    ModDirList dirs = GetModDirs();

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
            if (GetModPathInfo(ModInfo, sName, sPath, sIgnoreRetMsg)) {
                if (ModInfo.SupportsType(eType)) {
                    ssMods.insert(ModInfo);
                }
            }
        }
    }

    GLOBALMODULECALL(OnGetAvailableMods(ssMods, eType), NOTHING);
}

void NoModules::GetDefaultMods(std::set<NoModuleInfo>& ssMods, No::ModuleType eType)
{

    GetAvailableMods(ssMods, eType);

    const std::map<NoString, No::ModuleType> ns = { { "chansaver", No::UserModule },
                                                     { "controlpanel", No::UserModule },
                                                     { "simple_away", No::NetworkModule },
                                                     { "webadmin", No::GlobalModule } };

    auto it = ssMods.begin();
    while (it != ssMods.end()) {
        auto it2 = ns.find(it->GetName());
        if (it2 != ns.end() && it2->second == eType) {
            ++it;
        } else {
            it = ssMods.erase(it);
        }
    }
}

bool NoModules::FindModPath(const NoString& sModule, NoString& sModPath, NoString& sDataPath)
{
    NoString sMod = sModule;
    NoString sDir = sMod;
    if (sModule.find(".") == NoString::npos) sMod += ".so";

    ModDirList dirs = GetModDirs();

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

NoModules::ModDirList NoModules::GetModDirs()
{
    ModDirList ret;
    NoString sDir;

    // ~/.znc/modules
    sDir = NoApp::Get().GetModPath() + "/";
    ret.push(std::make_pair(sDir, sDir));

    // <moduledir> and <datadir> (<prefix>/lib/znc)
    ret.push(std::make_pair(_MODDIR_ + NoString("/"), _DATADIR_ + NoString("/modules/")));

    return ret;
}

NoModuleHandle NoModules::OpenModule(const NoString& sModule, const NoString& sModPath, bool& bVersionMismatch, NoModuleInfo& Info, NoString& sRetMsg)
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
