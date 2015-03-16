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

#ifndef ZNC_MODULES_H
#define ZNC_MODULES_H

#include <znc/noconfig.h>
#include <znc/nomodule.h>

class CAuthBase;
class CChannel;
class CNetwork;
class CClient;
class CWebSock;
class CTemplate;
class CIRCSock;
class CNick;

class CModules : public std::vector<CModule*>
{
public:
    CModules();
    ~CModules();

    CModules(const CModules&) = default;
    CModules& operator=(const CModules&) = default;

    void SetUser(CUser* pUser) { m_pUser = pUser; }
    void SetNetwork(CNetwork* pNetwork) { m_pNetwork = pNetwork; }
    void SetClient(CClient* pClient) { m_pClient = pClient; }
    CUser* GetUser() const { return m_pUser; }
    CNetwork* GetNetwork() const { return m_pNetwork; }
    CClient* GetClient() const { return m_pClient; }

    void UnloadAll();

    bool OnBoot();
    bool OnPreRehash();
    bool OnPostRehash();
    bool OnIRCDisconnected();
    bool OnIRCConnected();
    bool OnIRCConnecting(CIRCSock* pIRCSock);
    bool OnIRCConnectionError(CIRCSock* pIRCSock);
    bool OnIRCRegistration(CString& sPass, CString& sNick, CString& sIdent, CString& sRealName);
    bool OnBroadcast(CString& sMessage);

    bool OnChanPermission2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, unsigned char uMode, bool bAdded, bool bNoChange);
    bool OnChanPermission(const CNick& OpNick, const CNick& Nick, CChannel& Channel, unsigned char uMode, bool bAdded, bool bNoChange);
    bool OnOp2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange);
    bool OnOp(const CNick& OpNick, const CNick& Nick, CChannel& Channel, bool bNoChange);
    bool OnDeop2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange);
    bool OnDeop(const CNick& OpNick, const CNick& Nick, CChannel& Channel, bool bNoChange);
    bool OnVoice2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange);
    bool OnVoice(const CNick& OpNick, const CNick& Nick, CChannel& Channel, bool bNoChange);
    bool OnDevoice2(const CNick* pOpNick, const CNick& Nick, CChannel& Channel, bool bNoChange);
    bool OnDevoice(const CNick& OpNick, const CNick& Nick, CChannel& Channel, bool bNoChange);
    bool OnRawMode2(const CNick* pOpNick, CChannel& Channel, const CString& sModes, const CString& sArgs);
    bool OnRawMode(const CNick& OpNick, CChannel& Channel, const CString& sModes, const CString& sArgs);
    bool OnMode2(const CNick* pOpNick, CChannel& Channel, char uMode, const CString& sArg, bool bAdded, bool bNoChange);
    bool OnMode(const CNick& OpNick, CChannel& Channel, char uMode, const CString& sArg, bool bAdded, bool bNoChange);

    bool OnRaw(CString& sLine);

    bool OnStatusCommand(CString& sCommand);
    bool OnModCommand(const CString& sCommand);
    bool OnModNotice(const CString& sMessage);
    bool OnModCTCP(const CString& sMessage);

    bool OnQuit(const CNick& Nick, const CString& sMessage, const std::vector<CChannel*>& vChans);
    bool OnNick(const CNick& Nick, const CString& sNewNick, const std::vector<CChannel*>& vChans);
    bool OnKick(const CNick& Nick, const CString& sOpNick, CChannel& Channel, const CString& sMessage);
    bool OnJoining(CChannel& Channel);
    bool OnJoin(const CNick& Nick, CChannel& Channel);
    bool OnPart(const CNick& Nick, CChannel& Channel, const CString& sMessage);
    bool OnInvite(const CNick& Nick, const CString& sChan);

    bool OnChanBufferStarting(CChannel& Chan, CClient& Client);
    bool OnChanBufferEnding(CChannel& Chan, CClient& Client);
    bool OnChanBufferPlayLine2(CChannel& Chan, CClient& Client, CString& sLine, const timeval& tv);
    bool OnChanBufferPlayLine(CChannel& Chan, CClient& Client, CString& sLine);
    bool OnPrivBufferPlayLine2(CClient& Client, CString& sLine, const timeval& tv);
    bool OnPrivBufferPlayLine(CClient& Client, CString& sLine);

    bool OnClientLogin();
    bool OnClientDisconnect();
    bool OnUserRaw(CString& sLine);
    bool OnUserCTCPReply(CString& sTarget, CString& sMessage);
    bool OnUserCTCP(CString& sTarget, CString& sMessage);
    bool OnUserAction(CString& sTarget, CString& sMessage);
    bool OnUserMsg(CString& sTarget, CString& sMessage);
    bool OnUserNotice(CString& sTarget, CString& sMessage);
    bool OnUserJoin(CString& sChannel, CString& sKey);
    bool OnUserPart(CString& sChannel, CString& sMessage);
    bool OnUserTopic(CString& sChannel, CString& sTopic);
    bool OnUserTopicRequest(CString& sChannel);
    bool OnUserQuit(CString& sMessage);

    bool OnCTCPReply(CNick& Nick, CString& sMessage);
    bool OnPrivCTCP(CNick& Nick, CString& sMessage);
    bool OnChanCTCP(CNick& Nick, CChannel& Channel, CString& sMessage);
    bool OnPrivAction(CNick& Nick, CString& sMessage);
    bool OnChanAction(CNick& Nick, CChannel& Channel, CString& sMessage);
    bool OnPrivMsg(CNick& Nick, CString& sMessage);
    bool OnChanMsg(CNick& Nick, CChannel& Channel, CString& sMessage);
    bool OnPrivNotice(CNick& Nick, CString& sMessage);
    bool OnChanNotice(CNick& Nick, CChannel& Channel, CString& sMessage);
    bool OnTopic(CNick& Nick, CChannel& Channel, CString& sTopic);
    bool OnTimerAutoJoin(CChannel& Channel);

    bool OnAddNetwork(CNetwork& Network, CString& sErrorRet);
    bool OnDeleteNetwork(CNetwork& Network);

    bool OnSendToClient(CString& sLine, CClient& Client);
    bool OnSendToIRC(CString& sLine);

    bool OnServerCapAvailable(const CString& sCap);
    bool OnServerCapResult(const CString& sCap, bool bSuccess);

    CModule* FindModule(const CString& sModule) const;
    bool LoadModule(const CString& sModule, const CString& sArgs, CModInfo::EModuleType eType, CUser* pUser, CNetwork* pNetwork, CString& sRetMsg);
    bool UnloadModule(const CString& sModule);
    bool UnloadModule(const CString& sModule, CString& sRetMsg);
    bool ReloadModule(const CString& sModule, const CString& sArgs, CUser* pUser, CNetwork* pNetwork, CString& sRetMsg);

    static bool GetModInfo(CModInfo& ModInfo, const CString& sModule, CString& sRetMsg);
    static bool GetModPathInfo(CModInfo& ModInfo, const CString& sModule, const CString& sModPath, CString& sRetMsg);
    static void GetAvailableMods(std::set<CModInfo>& ssMods, CModInfo::EModuleType eType = CModInfo::UserModule);
    static void GetDefaultMods(std::set<CModInfo>& ssMods, CModInfo::EModuleType eType = CModInfo::UserModule);

    // This returns the path to the .so and to the data dir
    // which is where static data (webadmin skins) are saved
    static bool FindModPath(const CString& sModule, CString& sModPath, CString& sDataPath);
    // Return a list of <module dir, data dir> pairs for directories in
    // which modules can be found.
    typedef std::queue<std::pair<CString, CString>> ModDirList;
    static ModDirList GetModDirs();

    bool OnAddUser(CUser& User, CString& sErrorRet);
    bool OnDeleteUser(CUser& User);
    bool OnClientConnect(CZNCSock* pSock, const CString& sHost, unsigned short uPort);
    bool OnLoginAttempt(std::shared_ptr<CAuthBase> Auth);
    bool OnFailedLogin(const CString& sUsername, const CString& sRemoteIP);
    bool OnUnknownUserRaw(CClient* pClient, CString& sLine);
    bool OnClientCapLs(CClient* pClient, SCString& ssCaps);
    bool IsClientCapSupported(CClient* pClient, const CString& sCap, bool bState);
    bool OnClientCapRequest(CClient* pClient, const CString& sCap, bool bState);
    bool OnModuleLoading(const CString& sModName, const CString& sArgs, CModInfo::EModuleType eType, bool& bSuccess, CString& sRetMsg);
    bool OnModuleUnloading(CModule* pModule, bool& bSuccess, CString& sRetMsg);
    bool OnGetModInfo(CModInfo& ModInfo, const CString& sModule, bool& bSuccess, CString& sRetMsg);
    bool OnGetAvailableMods(std::set<CModInfo>& ssMods, CModInfo::EModuleType eType);

private:
    static ModHandle
    OpenModule(const CString& sModule, const CString& sModPath, bool& bVersionMismatch, CModInfo& Info, CString& sRetMsg);

    CUser* m_pUser;
    CNetwork* m_pNetwork;
    CClient* m_pClient;
};

#endif // !ZNC_MODULES_H
