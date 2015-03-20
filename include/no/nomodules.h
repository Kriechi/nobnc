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

#ifndef NOMODULES_H
#define NOMODULES_H

#include <no/noglobal.h>
#include <no/nomodule.h>

class NoAuthenticator;
class NoChannel;
class NoNetwork;
class NoClient;
class NoWebSock;
class NoTemplate;
class NoIrcConnection;
class NoNick;

class NO_EXPORT NoModules : public std::vector<NoModule*>
{
public:
    NoModules();
    ~NoModules();

    NoModules(const NoModules&) = default;
    NoModules& operator=(const NoModules&) = default;

    void SetUser(NoUser* pUser) { m_pUser = pUser; }
    void SetNetwork(NoNetwork* pNetwork) { m_pNetwork = pNetwork; }
    void SetClient(NoClient* pClient) { m_pClient = pClient; }
    NoUser* GetUser() const { return m_pUser; }
    NoNetwork* GetNetwork() const { return m_pNetwork; }
    NoClient* GetClient() const { return m_pClient; }

    void UnloadAll();

    bool OnBoot();
    bool OnPreRehash();
    bool OnPostRehash();
    bool OnIRCDisconnected();
    bool OnIRCConnected();
    bool OnIRCConnecting(NoIrcConnection* pIRCSock);
    bool OnIRCConnectionError(NoIrcConnection* pIRCSock);
    bool OnIRCRegistration(NoString& sPass, NoString& sNick, NoString& sIdent, NoString& sRealName);
    bool OnBroadcast(NoString& sMessage);

    bool OnChanPermission2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange);
    bool OnChanPermission(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange);
    bool OnOp2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool OnOp(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool OnDeop2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool OnDeop(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool OnVoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool OnVoice(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool OnDevoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool OnDevoice(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool OnRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs);
    bool OnRawMode(const NoNick& OpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs);
    bool OnMode2(const NoNick* pOpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange);
    bool OnMode(const NoNick& OpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange);

    bool OnRaw(NoString& sLine);

    bool OnStatusCommand(NoString& sCommand);
    bool OnModCommand(const NoString& sCommand);
    bool OnModNotice(const NoString& sMessage);
    bool OnModCTCP(const NoString& sMessage);

    bool OnQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans);
    bool OnNick(const NoNick& Nick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans);
    bool OnKick(const NoNick& Nick, const NoString& sOpNick, NoChannel& Channel, const NoString& sMessage);
    bool OnJoining(NoChannel& Channel);
    bool OnJoin(const NoNick& Nick, NoChannel& Channel);
    bool OnPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage);
    bool OnInvite(const NoNick& Nick, const NoString& sChan);

    bool OnChanBufferStarting(NoChannel& Chan, NoClient& Client);
    bool OnChanBufferEnding(NoChannel& Chan, NoClient& Client);
    bool OnChanBufferPlayLine2(NoChannel& Chan, NoClient& Client, NoString& sLine, const timeval& tv);
    bool OnChanBufferPlayLine(NoChannel& Chan, NoClient& Client, NoString& sLine);
    bool OnPrivBufferPlayLine2(NoClient& Client, NoString& sLine, const timeval& tv);
    bool OnPrivBufferPlayLine(NoClient& Client, NoString& sLine);

    bool OnClientLogin();
    bool OnClientDisconnect();
    bool OnUserRaw(NoString& sLine);
    bool OnUserCTCPReply(NoString& sTarget, NoString& sMessage);
    bool OnUserCTCP(NoString& sTarget, NoString& sMessage);
    bool OnUserAction(NoString& sTarget, NoString& sMessage);
    bool OnUserMsg(NoString& sTarget, NoString& sMessage);
    bool OnUserNotice(NoString& sTarget, NoString& sMessage);
    bool OnUserJoin(NoString& sChannel, NoString& sKey);
    bool OnUserPart(NoString& sChannel, NoString& sMessage);
    bool OnUserTopic(NoString& sChannel, NoString& sTopic);
    bool OnUserTopicRequest(NoString& sChannel);
    bool OnUserQuit(NoString& sMessage);

    bool OnCTCPReply(NoNick& Nick, NoString& sMessage);
    bool OnPrivCTCP(NoNick& Nick, NoString& sMessage);
    bool OnChanCTCP(NoNick& Nick, NoChannel& Channel, NoString& sMessage);
    bool OnPrivAction(NoNick& Nick, NoString& sMessage);
    bool OnChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage);
    bool OnPrivMsg(NoNick& Nick, NoString& sMessage);
    bool OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage);
    bool OnPrivNotice(NoNick& Nick, NoString& sMessage);
    bool OnChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage);
    bool OnTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic);
    bool OnTimerAutoJoin(NoChannel& Channel);

    bool OnAddNetwork(NoNetwork& Network, NoString& sErrorRet);
    bool OnDeleteNetwork(NoNetwork& Network);

    bool OnSendToClient(NoString& sLine, NoClient& Client);
    bool OnSendToIRC(NoString& sLine);

    bool OnServerCapAvailable(const NoString& sCap);
    bool OnServerCapResult(const NoString& sCap, bool bSuccess);

    NoModule* FindModule(const NoString& sModule) const;
    bool LoadModule(const NoString& sModule, const NoString& sArgs, NoModInfo::ModuleType eType, NoUser* pUser, NoNetwork* pNetwork, NoString& sRetMsg);
    bool UnloadModule(const NoString& sModule);
    bool UnloadModule(const NoString& sModule, NoString& sRetMsg);
    bool ReloadModule(const NoString& sModule, const NoString& sArgs, NoUser* pUser, NoNetwork* pNetwork, NoString& sRetMsg);

    static bool GetModInfo(NoModInfo& ModInfo, const NoString& sModule, NoString& sRetMsg);
    static bool GetModPathInfo(NoModInfo& ModInfo, const NoString& sModule, const NoString& sModPath, NoString& sRetMsg);
    static void GetAvailableMods(std::set<NoModInfo>& ssMods, NoModInfo::ModuleType eType = NoModInfo::UserModule);
    static void GetDefaultMods(std::set<NoModInfo>& ssMods, NoModInfo::ModuleType eType = NoModInfo::UserModule);

    // This returns the path to the .so and to the data dir
    // which is where static data (webadmin skins) are saved
    static bool FindModPath(const NoString& sModule, NoString& sModPath, NoString& sDataPath);
    // Return a list of <module dir, data dir> pairs for directories in
    // which modules can be found.
    typedef std::queue<std::pair<NoString, NoString>> ModDirList;
    static ModDirList GetModDirs();

    bool OnAddUser(NoUser& User, NoString& sErrorRet);
    bool OnDeleteUser(NoUser& User);
    bool OnClientConnect(NoSocket* pSock, const NoString& sHost, ushort uPort);
    bool OnLoginAttempt(std::shared_ptr<NoAuthenticator> Auth);
    bool OnFailedLogin(const NoString& sUsername, const NoString& sRemoteIP);
    bool OnUnknownUserRaw(NoClient* pClient, NoString& sLine);
    bool OnClientCapLs(NoClient* pClient, NoStringSet& ssCaps);
    bool IsClientCapSupported(NoClient* pClient, const NoString& sCap, bool bState);
    bool OnClientCapRequest(NoClient* pClient, const NoString& sCap, bool bState);
    bool OnModuleLoading(const NoString& sModName, const NoString& sArgs, NoModInfo::ModuleType eType, bool& bSuccess, NoString& sRetMsg);
    bool OnModuleUnloading(NoModule* pModule, bool& bSuccess, NoString& sRetMsg);
    bool OnGetModInfo(NoModInfo& ModInfo, const NoString& sModule, bool& bSuccess, NoString& sRetMsg);
    bool OnGetAvailableMods(std::set<NoModInfo>& ssMods, NoModInfo::ModuleType eType);

private:
    static ModHandle
    OpenModule(const NoString& sModule, const NoString& sModPath, bool& bVersionMismatch, NoModInfo& Info, NoString& sRetMsg);

    NoUser* m_pUser;
    NoNetwork* m_pNetwork;
    NoClient* m_pClient;
};

#endif // NOMODULES_H
