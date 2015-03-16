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
#include "noznc.h"
#include <dlfcn.h>

using std::map;
using std::set;
using std::vector;

bool ZNC_NO_NEED_TO_DO_ANYTHING_ON_MODULE_CALL_EXITER;

#ifndef RTLD_LOCAL
#define RTLD_LOCAL 0
#warning "your crap box doesnt define RTLD_LOCAL !?"
#endif

#define MODUNLOADCHK(func)                              \
    for (CModule * pMod : *this) {                      \
        try {                                           \
            CClient* pOldClient = pMod->GetClient();    \
            pMod->SetClient(m_pClient);                 \
            CUser* pOldUser = nullptr;                  \
            if (m_pUser) {                              \
                pOldUser = pMod->GetUser();             \
                pMod->SetUser(m_pUser);                 \
            }                                           \
            CNetwork* pNetwork = nullptr;            \
            if (m_pNetwork) {                           \
                pNetwork = pMod->GetNetwork();          \
                pMod->SetNetwork(m_pNetwork);           \
            }                                           \
            pMod->func;                                 \
            if (m_pUser) pMod->SetUser(pOldUser);       \
            if (m_pNetwork) pMod->SetNetwork(pNetwork); \
            pMod->SetClient(pOldClient);                \
        } catch (const CModule::EModException& e) {     \
            if (e == CModule::UNLOAD) {                 \
                UnloadModule(pMod->GetModName());       \
            }                                           \
        }                                               \
    }


#define MODHALTCHK(func)                                \
    bool bHaltCore = false;                             \
    for (CModule * pMod : *this) {                      \
        try {                                           \
            CModule::EModRet e = CModule::CONTINUE;     \
            CClient* pOldClient = pMod->GetClient();    \
            pMod->SetClient(m_pClient);                 \
            CUser* pOldUser = nullptr;                  \
            if (m_pUser) {                              \
                pOldUser = pMod->GetUser();             \
                pMod->SetUser(m_pUser);                 \
            }                                           \
            CNetwork* pNetwork = nullptr;            \
            if (m_pNetwork) {                           \
                pNetwork = pMod->GetNetwork();          \
                pMod->SetNetwork(m_pNetwork);           \
            }                                           \
            e = pMod->func;                             \
            if (m_pUser) pMod->SetUser(pOldUser);       \
            if (m_pNetwork) pMod->SetNetwork(pNetwork); \
            pMod->SetClient(pOldClient);                \
            if (e == CModule::HALTMODS) {               \
                break;                                  \
            } else if (e == CModule::HALTCORE) {        \
                bHaltCore = true;                       \
            } else if (e == CModule::HALT) {            \
                bHaltCore = true;                       \
                break;                                  \
            }                                           \
        } catch (const CModule::EModException& e) {     \
            if (e == CModule::UNLOAD) {                 \
                UnloadModule(pMod->GetModName());       \
            }                                           \
        }                                               \
    }                                                   \
    return bHaltCore;

CModules::CModules() : m_pUser(nullptr), m_pNetwork(nullptr), m_pClient(nullptr) {}

CModules::~CModules() { UnloadAll(); }

void CModules::UnloadAll()
{
    while (size()) {
        CString sRetMsg;
        CString sModName = back()->GetModName();
        UnloadModule(sModName, sRetMsg);
    }
}

bool CModules::OnBoot()
{
    for (CModule* pMod : *this) {
        try {
            if (!pMod->OnBoot()) {
                return true;
            }
        } catch (const CModule::EModException& e) {
            if (e == CModule::UNLOAD) {
                UnloadModule(pMod->GetModName());
            }
        }
    }

    return false;
}

bool CModules::OnPreRehash()
{
    MODUNLOADCHK(OnPreRehash());
    return false;
}
bool CModules::OnPostRehash()
{
    MODUNLOADCHK(OnPostRehash());
    return false;
}
bool CModules::OnIRCConnected()
{
    MODUNLOADCHK(OnIRCConnected());
    return false;
}
bool CModules::OnIRCConnecting(CIRCSock* pIRCSock) { MODHALTCHK(OnIRCConnecting(pIRCSock)); }
bool CModules::OnIRCConnectionError(CIRCSock* pIRCSock)
{
    MODUNLOADCHK(OnIRCConnectionError(pIRCSock));
    return false;
}
bool CModules::OnIRCRegistration(CString& sPass, CString& sNick, CString& sIdent, CString& sRealName)
{
    MODHALTCHK(OnIRCRegistration(sPass, sNick, sIdent, sRealName));
}
bool CModules::OnBroadcast(CString& sMessage) { MODHALTCHK(OnBroadcast(sMessage)); }
bool CModules::OnIRCDisconnected()
{
    MODUNLOADCHK(OnIRCDisconnected());
    return false;
}

bool CModules::OnChanPermission2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, unsigned char uMode, bool bAdded, bool bNoChange)
{
    MODUNLOADCHK(OnChanPermission2(pOpNick, Nick, Channel, uMode, bAdded, bNoChange));
    return false;
}
bool CModules::OnChanPermission(const CNick& OpNick, const CNick& Nick, CChannel& Channel, unsigned char uMode, bool bAdded, bool bNoChange)
{
    MODUNLOADCHK(OnChanPermission(OpNick, Nick, Channel, uMode, bAdded, bNoChange));
    return false;
}
bool CModules::OnOp2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnOp2(pOpNick, Nick, Channel, bNoChange));
    return false;
}
bool CModules::OnOp(const CNick& OpNick, const CNick& Nick, CChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnOp(OpNick, Nick, Channel, bNoChange));
    return false;
}
bool CModules::OnDeop2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnDeop2(pOpNick, Nick, Channel, bNoChange));
    return false;
}
bool CModules::OnDeop(const CNick& OpNick, const CNick& Nick, CChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnDeop(OpNick, Nick, Channel, bNoChange));
    return false;
}
bool CModules::OnVoice2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnVoice2(pOpNick, Nick, Channel, bNoChange));
    return false;
}
bool CModules::OnVoice(const CNick& OpNick, const CNick& Nick, CChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnVoice(OpNick, Nick, Channel, bNoChange));
    return false;
}
bool CModules::OnDevoice2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnDevoice2(pOpNick, Nick, Channel, bNoChange));
    return false;
}
bool CModules::OnDevoice(const CNick& OpNick, const CNick& Nick, CChannel& Channel, bool bNoChange)
{
    MODUNLOADCHK(OnDevoice(OpNick, Nick, Channel, bNoChange));
    return false;
}
bool CModules::OnRawMode2(const CNick* pOpNick, CChannel& Channel, const CString& sModes, const CString& sArgs)
{
    MODUNLOADCHK(OnRawMode2(pOpNick, Channel, sModes, sArgs));
    return false;
}
bool CModules::OnRawMode(const CNick& OpNick, CChannel& Channel, const CString& sModes, const CString& sArgs)
{
    MODUNLOADCHK(OnRawMode(OpNick, Channel, sModes, sArgs));
    return false;
}
bool CModules::OnMode2(const CNick* pOpNick, CChannel& Channel, char uMode, const CString& sArg, bool bAdded, bool bNoChange)
{
    MODUNLOADCHK(OnMode2(pOpNick, Channel, uMode, sArg, bAdded, bNoChange));
    return false;
}
bool CModules::OnMode(const CNick& OpNick, CChannel& Channel, char uMode, const CString& sArg, bool bAdded, bool bNoChange)
{
    MODUNLOADCHK(OnMode(OpNick, Channel, uMode, sArg, bAdded, bNoChange));
    return false;
}
bool CModules::OnRaw(CString& sLine) { MODHALTCHK(OnRaw(sLine)); }

bool CModules::OnClientLogin()
{
    MODUNLOADCHK(OnClientLogin());
    return false;
}
bool CModules::OnClientDisconnect()
{
    MODUNLOADCHK(OnClientDisconnect());
    return false;
}
bool CModules::OnUserRaw(CString& sLine) { MODHALTCHK(OnUserRaw(sLine)); }
bool CModules::OnUserCTCPReply(CString& sTarget, CString& sMessage) { MODHALTCHK(OnUserCTCPReply(sTarget, sMessage)); }
bool CModules::OnUserCTCP(CString& sTarget, CString& sMessage) { MODHALTCHK(OnUserCTCP(sTarget, sMessage)); }
bool CModules::OnUserAction(CString& sTarget, CString& sMessage) { MODHALTCHK(OnUserAction(sTarget, sMessage)); }
bool CModules::OnUserMsg(CString& sTarget, CString& sMessage) { MODHALTCHK(OnUserMsg(sTarget, sMessage)); }
bool CModules::OnUserNotice(CString& sTarget, CString& sMessage) { MODHALTCHK(OnUserNotice(sTarget, sMessage)); }
bool CModules::OnUserJoin(CString& sChannel, CString& sKey) { MODHALTCHK(OnUserJoin(sChannel, sKey)); }
bool CModules::OnUserPart(CString& sChannel, CString& sMessage) { MODHALTCHK(OnUserPart(sChannel, sMessage)); }
bool CModules::OnUserTopic(CString& sChannel, CString& sTopic) { MODHALTCHK(OnUserTopic(sChannel, sTopic)); }
bool CModules::OnUserTopicRequest(CString& sChannel) { MODHALTCHK(OnUserTopicRequest(sChannel)); }
bool CModules::OnUserQuit(CString& sMessage) { MODHALTCHK(OnUserQuit(sMessage)); }

bool CModules::OnQuit(const CNick& Nick, const CString& sMessage, const vector<CChannel*>& vChans)
{
    MODUNLOADCHK(OnQuit(Nick, sMessage, vChans));
    return false;
}
bool CModules::OnNick(const CNick& Nick, const CString& sNewNick, const vector<CChannel*>& vChans)
{
    MODUNLOADCHK(OnNick(Nick, sNewNick, vChans));
    return false;
}
bool CModules::OnKick(const CNick& Nick, const CString& sKickedNick, CChannel& Channel, const CString& sMessage)
{
    MODUNLOADCHK(OnKick(Nick, sKickedNick, Channel, sMessage));
    return false;
}
bool CModules::OnJoining(CChannel& Channel) { MODHALTCHK(OnJoining(Channel)); }
bool CModules::OnJoin(const CNick& Nick, CChannel& Channel)
{
    MODUNLOADCHK(OnJoin(Nick, Channel));
    return false;
}
bool CModules::OnPart(const CNick& Nick, CChannel& Channel, const CString& sMessage)
{
    MODUNLOADCHK(OnPart(Nick, Channel, sMessage));
    return false;
}
bool CModules::OnInvite(const CNick& Nick, const CString& sChan) { MODHALTCHK(OnInvite(Nick, sChan)); }
bool CModules::OnChanBufferStarting(CChannel& Chan, CClient& Client) { MODHALTCHK(OnChanBufferStarting(Chan, Client)); }
bool CModules::OnChanBufferEnding(CChannel& Chan, CClient& Client) { MODHALTCHK(OnChanBufferEnding(Chan, Client)); }
bool CModules::OnChanBufferPlayLine2(CChannel& Chan, CClient& Client, CString& sLine, const timeval& tv)
{
    MODHALTCHK(OnChanBufferPlayLine2(Chan, Client, sLine, tv));
}
bool CModules::OnChanBufferPlayLine(CChannel& Chan, CClient& Client, CString& sLine)
{
    MODHALTCHK(OnChanBufferPlayLine(Chan, Client, sLine));
}
bool CModules::OnPrivBufferPlayLine2(CClient& Client, CString& sLine, const timeval& tv)
{
    MODHALTCHK(OnPrivBufferPlayLine2(Client, sLine, tv));
}
bool CModules::OnPrivBufferPlayLine(CClient& Client, CString& sLine)
{
    MODHALTCHK(OnPrivBufferPlayLine(Client, sLine));
}
bool CModules::OnCTCPReply(CNick& Nick, CString& sMessage) { MODHALTCHK(OnCTCPReply(Nick, sMessage)); }
bool CModules::OnPrivCTCP(CNick& Nick, CString& sMessage) { MODHALTCHK(OnPrivCTCP(Nick, sMessage)); }
bool CModules::OnChanCTCP(CNick& Nick, CChannel& Channel, CString& sMessage)
{
    MODHALTCHK(OnChanCTCP(Nick, Channel, sMessage));
}
bool CModules::OnPrivAction(CNick& Nick, CString& sMessage) { MODHALTCHK(OnPrivAction(Nick, sMessage)); }
bool CModules::OnChanAction(CNick& Nick, CChannel& Channel, CString& sMessage)
{
    MODHALTCHK(OnChanAction(Nick, Channel, sMessage));
}
bool CModules::OnPrivMsg(CNick& Nick, CString& sMessage) { MODHALTCHK(OnPrivMsg(Nick, sMessage)); }
bool CModules::OnChanMsg(CNick& Nick, CChannel& Channel, CString& sMessage)
{
    MODHALTCHK(OnChanMsg(Nick, Channel, sMessage));
}
bool CModules::OnPrivNotice(CNick& Nick, CString& sMessage) { MODHALTCHK(OnPrivNotice(Nick, sMessage)); }
bool CModules::OnChanNotice(CNick& Nick, CChannel& Channel, CString& sMessage)
{
    MODHALTCHK(OnChanNotice(Nick, Channel, sMessage));
}
bool CModules::OnTopic(CNick& Nick, CChannel& Channel, CString& sTopic) { MODHALTCHK(OnTopic(Nick, Channel, sTopic)); }
bool CModules::OnTimerAutoJoin(CChannel& Channel) { MODHALTCHK(OnTimerAutoJoin(Channel)); }
bool CModules::OnAddNetwork(CNetwork& Network, CString& sErrorRet) { MODHALTCHK(OnAddNetwork(Network, sErrorRet)); }
bool CModules::OnDeleteNetwork(CNetwork& Network) { MODHALTCHK(OnDeleteNetwork(Network)); }
bool CModules::OnSendToClient(CString& sLine, CClient& Client) { MODHALTCHK(OnSendToClient(sLine, Client)); }
bool CModules::OnSendToIRC(CString& sLine) { MODHALTCHK(OnSendToIRC(sLine)); }
bool CModules::OnStatusCommand(CString& sCommand) { MODHALTCHK(OnStatusCommand(sCommand)); }
bool CModules::OnModCommand(const CString& sCommand)
{
    MODUNLOADCHK(OnModCommand(sCommand));
    return false;
}
bool CModules::OnModNotice(const CString& sMessage)
{
    MODUNLOADCHK(OnModNotice(sMessage));
    return false;
}
bool CModules::OnModCTCP(const CString& sMessage)
{
    MODUNLOADCHK(OnModCTCP(sMessage));
    return false;
}

// Why MODHALTCHK works only with functions returning EModRet ? :(
bool CModules::OnServerCapAvailable(const CString& sCap)
{
    bool bResult = false;
    for (CModule* pMod : *this) {
        try {
            CClient* pOldClient = pMod->GetClient();
            pMod->SetClient(m_pClient);
            if (m_pUser) {
                CUser* pOldUser = pMod->GetUser();
                pMod->SetUser(m_pUser);
                bResult |= pMod->OnServerCapAvailable(sCap);
                pMod->SetUser(pOldUser);
            } else {
                // WTF? Is that possible?
                bResult |= pMod->OnServerCapAvailable(sCap);
            }
            pMod->SetClient(pOldClient);
        } catch (const CModule::EModException& e) {
            if (CModule::UNLOAD == e) {
                UnloadModule(pMod->GetModName());
            }
        }
    }
    return bResult;
}

bool CModules::OnServerCapResult(const CString& sCap, bool bSuccess)
{
    MODUNLOADCHK(OnServerCapResult(sCap, bSuccess));
    return false;
}

////////////////////
// Global Modules //
////////////////////
bool CModules::OnAddUser(CUser& User, CString& sErrorRet) { MODHALTCHK(OnAddUser(User, sErrorRet)); }

bool CModules::OnDeleteUser(CUser& User) { MODHALTCHK(OnDeleteUser(User)); }

bool CModules::OnClientConnect(CZNCSock* pClient, const CString& sHost, unsigned short uPort)
{
    MODUNLOADCHK(OnClientConnect(pClient, sHost, uPort));
    return false;
}

bool CModules::OnLoginAttempt(std::shared_ptr<CAuthBase> Auth) { MODHALTCHK(OnLoginAttempt(Auth)); }

bool CModules::OnFailedLogin(const CString& sUsername, const CString& sRemoteIP)
{
    MODUNLOADCHK(OnFailedLogin(sUsername, sRemoteIP));
    return false;
}

bool CModules::OnUnknownUserRaw(CClient* pClient, CString& sLine) { MODHALTCHK(OnUnknownUserRaw(pClient, sLine)); }

bool CModules::OnClientCapLs(CClient* pClient, SCString& ssCaps)
{
    MODUNLOADCHK(OnClientCapLs(pClient, ssCaps));
    return false;
}

// Maybe create new macro for this?
bool CModules::IsClientCapSupported(CClient* pClient, const CString& sCap, bool bState)
{
    bool bResult = false;
    for (CModule* pMod : *this) {
        try {
            CClient* pOldClient = pMod->GetClient();
            pMod->SetClient(m_pClient);
            if (m_pUser) {
                CUser* pOldUser = pMod->GetUser();
                pMod->SetUser(m_pUser);
                bResult |= pMod->IsClientCapSupported(pClient, sCap, bState);
                pMod->SetUser(pOldUser);
            } else {
                // WTF? Is that possible?
                bResult |= pMod->IsClientCapSupported(pClient, sCap, bState);
            }
            pMod->SetClient(pOldClient);
        } catch (const CModule::EModException& e) {
            if (CModule::UNLOAD == e) {
                UnloadModule(pMod->GetModName());
            }
        }
    }
    return bResult;
}

bool CModules::OnClientCapRequest(CClient* pClient, const CString& sCap, bool bState)
{
    MODUNLOADCHK(OnClientCapRequest(pClient, sCap, bState));
    return false;
}

bool CModules::OnModuleLoading(const CString& sModName, const CString& sArgs, CModInfo::EModuleType eType, bool& bSuccess, CString& sRetMsg)
{
    MODHALTCHK(OnModuleLoading(sModName, sArgs, eType, bSuccess, sRetMsg));
}

bool CModules::OnModuleUnloading(CModule* pModule, bool& bSuccess, CString& sRetMsg)
{
    MODHALTCHK(OnModuleUnloading(pModule, bSuccess, sRetMsg));
}

bool CModules::OnGetModInfo(CModInfo& ModInfo, const CString& sModule, bool& bSuccess, CString& sRetMsg)
{
    MODHALTCHK(OnGetModInfo(ModInfo, sModule, bSuccess, sRetMsg));
}

bool CModules::OnGetAvailableMods(set<CModInfo>& ssMods, CModInfo::EModuleType eType)
{
    MODUNLOADCHK(OnGetAvailableMods(ssMods, eType));
    return false;
}


CModule* CModules::FindModule(const CString& sModule) const
{
    for (CModule* pMod : *this) {
        if (sModule.Equals(pMod->GetModName())) {
            return pMod;
        }
    }

    return nullptr;
}

bool CModules::LoadModule(const CString& sModule, const CString& sArgs, CModInfo::EModuleType eType, CUser* pUser, CNetwork* pNetwork, CString& sRetMsg)
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

    CString sModPath, sDataPath;
    bool bVersionMismatch;
    CModInfo Info;

    if (!FindModPath(sModule, sModPath, sDataPath)) {
        sRetMsg = "Unable to find module [" + sModule + "]";
        return false;
    }

    ModHandle p = OpenModule(sModule, sModPath, bVersionMismatch, Info, sRetMsg);

    if (!p) return false;

    if (bVersionMismatch) {
        dlclose(p);
        sRetMsg = "Version mismatch, recompile this module.";
        return false;
    }

    if (!Info.SupportsType(eType)) {
        dlclose(p);
        sRetMsg =
        "Module [" + sModule + "] does not support module type [" + CModInfo::ModuleTypeToString(eType) + "].";
        return false;
    }

    if (!pUser && eType == CModInfo::UserModule) {
        dlclose(p);
        sRetMsg = "Module [" + sModule + "] requires a user.";
        return false;
    }

    if (!pNetwork && eType == CModInfo::NetworkModule) {
        dlclose(p);
        sRetMsg = "Module [" + sModule + "] requires a network.";
        return false;
    }

    CModule* pModule = Info.GetLoader()(p, pUser, pNetwork, sModule, sDataPath, eType);
    pModule->SetDescription(Info.GetDescription());
    pModule->SetArgs(sArgs);
    pModule->SetModPath(CDir::ChangeDir(CZNC::Get().GetCurPath(), sModPath));
    push_back(pModule);

    bool bLoaded;
    try {
        bLoaded = pModule->OnLoad(sArgs, sRetMsg);
    } catch (const CModule::EModException&) {
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

bool CModules::UnloadModule(const CString& sModule)
{
    CString s;
    return UnloadModule(sModule, s);
}

bool CModules::UnloadModule(const CString& sModule, CString& sRetMsg)
{
    CString sMod = sModule; // Make a copy incase the reference passed in is from CModule::GetModName()
    CModule* pModule = FindModule(sMod);
    sRetMsg = "";

    if (!pModule) {
        sRetMsg = "Module [" + sMod + "] not loaded.";
        return false;
    }

    bool bSuccess;
    bool bHandled = false;
    _GLOBALMODULECALL(OnModuleUnloading(pModule, bSuccess, sRetMsg), pModule->GetUser(), pModule->GetNetwork(), nullptr, &bHandled);
    if (bHandled) return bSuccess;

    ModHandle p = pModule->GetDLL();

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

bool CModules::ReloadModule(const CString& sModule, const CString& sArgs, CUser* pUser, CNetwork* pNetwork, CString& sRetMsg)
{
    CString sMod = sModule; // Make a copy incase the reference passed in is from CModule::GetModName()
    CModule* pModule = FindModule(sMod);

    if (!pModule) {
        sRetMsg = "Module [" + sMod + "] not loaded";
        return false;
    }

    CModInfo::EModuleType eType = pModule->GetType();
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

bool CModules::GetModInfo(CModInfo& ModInfo, const CString& sModule, CString& sRetMsg)
{
    CString sModPath, sTmp;

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

bool CModules::GetModPathInfo(CModInfo& ModInfo, const CString& sModule, const CString& sModPath, CString& sRetMsg)
{
    bool bVersionMismatch;

    ModHandle p = OpenModule(sModule, sModPath, bVersionMismatch, ModInfo, sRetMsg);

    if (!p) return false;

    ModInfo.SetName(sModule);
    ModInfo.SetPath(sModPath);

    if (bVersionMismatch) {
        ModInfo.SetDescription("--- Version mismatch, recompile this module. ---");
    }

    dlclose(p);

    return true;
}

void CModules::GetAvailableMods(set<CModInfo>& ssMods, CModInfo::EModuleType eType)
{
    ssMods.clear();

    unsigned int a = 0;
    CDir Dir;

    ModDirList dirs = GetModDirs();

    while (!dirs.empty()) {
        Dir.FillByWildcard(dirs.front().first, "*.so");
        dirs.pop();

        for (a = 0; a < Dir.size(); a++) {
            CFile& File = *Dir[a];
            CString sName = File.GetShortName();
            CString sPath = File.GetLongName();
            CModInfo ModInfo;
            sName.RightChomp(3);

            CString sIgnoreRetMsg;
            if (GetModPathInfo(ModInfo, sName, sPath, sIgnoreRetMsg)) {
                if (ModInfo.SupportsType(eType)) {
                    ssMods.insert(ModInfo);
                }
            }
        }
    }

    GLOBALMODULECALL(OnGetAvailableMods(ssMods, eType), NOTHING);
}

void CModules::GetDefaultMods(set<CModInfo>& ssMods, CModInfo::EModuleType eType)
{

    GetAvailableMods(ssMods, eType);

    const map<CString, CModInfo::EModuleType> ns = { { "chansaver", CModInfo::UserModule },
                                                     { "controlpanel", CModInfo::UserModule },
                                                     { "simple_away", CModInfo::NetworkModule },
                                                     { "webadmin", CModInfo::GlobalModule } };

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

bool CModules::FindModPath(const CString& sModule, CString& sModPath, CString& sDataPath)
{
    CString sMod = sModule;
    CString sDir = sMod;
    if (sModule.find(".") == CString::npos) sMod += ".so";

    ModDirList dirs = GetModDirs();

    while (!dirs.empty()) {
        sModPath = dirs.front().first + sMod;
        sDataPath = dirs.front().second;
        dirs.pop();

        if (CFile::Exists(sModPath)) {
            sDataPath += sDir;
            return true;
        }
    }

    return false;
}

CModules::ModDirList CModules::GetModDirs()
{
    ModDirList ret;
    CString sDir;

    // ~/.znc/modules
    sDir = CZNC::Get().GetModPath() + "/";
    ret.push(std::make_pair(sDir, sDir));

    // <moduledir> and <datadir> (<prefix>/lib/znc)
    ret.push(std::make_pair(_MODDIR_ + CString("/"), _DATADIR_ + CString("/modules/")));

    return ret;
}

ModHandle CModules::OpenModule(const CString& sModule, const CString& sModPath, bool& bVersionMismatch, CModInfo& Info, CString& sRetMsg)
{
    // Some sane defaults in case anything errors out below
    bVersionMismatch = false;
    sRetMsg.clear();

    for (unsigned int a = 0; a < sModule.length(); a++) {
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
    ModHandle p = dlopen((sModPath).c_str(), RTLD_NOW | RTLD_GLOBAL);

    if (!p) {
        // dlerror() returns pointer to static buffer, which may be overwritten very soon with another dl call
        // also it may just return null.
        const char* cDlError = dlerror();
        CString sDlError = cDlError ? cDlError : "Unknown error";
        sRetMsg = "Unable to open module [" + sModule + "] [" + sDlError + "]";
        return nullptr;
    }

    typedef bool (*InfoFP)(double, CModInfo&);
    InfoFP ZNCModInfo = (InfoFP)dlsym(p, "ZNCModInfo");

    if (!ZNCModInfo) {
        dlclose(p);
        sRetMsg = "Could not find ZNCModInfo() in module [" + sModule + "]";
        return nullptr;
    }

    if (ZNCModInfo(CModule::GetCoreVersion(), Info)) {
        sRetMsg = "";
        bVersionMismatch = false;
    } else {
        bVersionMismatch = true;
        sRetMsg = "Version mismatch, recompile this module.";
    }

    return p;
}
