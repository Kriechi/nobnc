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

#include <no/noglobal.h>
#include <no/nomodule.h>
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

    NoModule* findModule(const NoString& sModule) const;
    bool loadModule(const NoString& sModule, const NoString& sArgs, No::ModuleType eType, NoUser* pUser, NoNetwork* pNetwork, NoString& sRetMsg);
    bool unloadModule(const NoString& sModule);
    bool unloadModule(const NoString& sModule, NoString& sRetMsg);
    bool reloadModule(const NoString& sModule, const NoString& sArgs, NoUser* pUser, NoNetwork* pNetwork, NoString& sRetMsg);
    void unloadAllModules();

    static bool moduleInfo(NoModuleInfo& ModInfo, const NoString& sModule, NoString& sRetMsg);
    static bool modulePath(NoModuleInfo& ModInfo, const NoString& sModule, const NoString& sModPath, NoString& sRetMsg);
    static void availableModules(std::set<NoModuleInfo>& ssMods, No::ModuleType eType = No::UserModule);
    static void defaultModules(std::set<NoModuleInfo>& ssMods, No::ModuleType eType = No::UserModule);

    bool onBoot();
    bool onPreRehash();
    bool onPostRehash();
    bool onIrcDisconnected();
    bool onIrcConnected();
    bool onIrcConnecting(NoIrcSocket* pIRCSock);
    bool onIrcConnectionError(NoIrcSocket* pIRCSock);
    bool onIrcRegistration(NoString& sPass, NoString& sNick, NoString& sIdent, NoString& sRealName);
    bool onBroadcast(NoString& sMessage);

    bool onChanPermission2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange);
    bool onChanPermission(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange);
    bool onOp2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool onOp(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool onDeop2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool onDeop(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool onVoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool onVoice(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool onDevoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool onDevoice(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    bool onRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs);
    bool onRawMode(const NoNick& OpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs);
    bool onMode2(const NoNick* pOpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange);
    bool onMode(const NoNick& OpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange);

    bool onRaw(NoString& sLine);

    bool onStatusCommand(NoString& sCommand);
    bool onModCommand(const NoString& sCommand);
    bool onModNotice(const NoString& sMessage);
    bool onModCTCP(const NoString& sMessage);

    bool onQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans);
    bool onNick(const NoNick& Nick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans);
    bool onKick(const NoNick& Nick, const NoString& sOpNick, NoChannel& Channel, const NoString& sMessage);
    bool onJoining(NoChannel& Channel);
    bool onJoin(const NoNick& Nick, NoChannel& Channel);
    bool onPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage);
    bool onInvite(const NoNick& Nick, const NoString& sChan);

    bool onChanBufferStarting(NoChannel& Chan, NoClient& Client);
    bool onChanBufferEnding(NoChannel& Chan, NoClient& Client);
    bool onChanBufferPlayLine2(NoChannel& Chan, NoClient& Client, NoString& sLine, const timeval& tv);
    bool onChanBufferPlayLine(NoChannel& Chan, NoClient& Client, NoString& sLine);
    bool onPrivBufferPlayLine2(NoClient& Client, NoString& sLine, const timeval& tv);
    bool onPrivBufferPlayLine(NoClient& Client, NoString& sLine);

    bool onClientLogin();
    bool onClientDisconnect();
    bool onUserRaw(NoString& sLine);
    bool onUserCtcpReply(NoString& sTarget, NoString& sMessage);
    bool onUserCtcp(NoString& sTarget, NoString& sMessage);
    bool onUserAction(NoString& sTarget, NoString& sMessage);
    bool onUserMsg(NoString& sTarget, NoString& sMessage);
    bool onUserNotice(NoString& sTarget, NoString& sMessage);
    bool onUserJoin(NoString& sChannel, NoString& sKey);
    bool onUserPart(NoString& sChannel, NoString& sMessage);
    bool onUserTopic(NoString& sChannel, NoString& sTopic);
    bool onUserTopicRequest(NoString& sChannel);
    bool onUserQuit(NoString& sMessage);

    bool onCtcpReply(NoNick& Nick, NoString& sMessage);
    bool onPrivCtcp(NoNick& Nick, NoString& sMessage);
    bool onChanCtcp(NoNick& Nick, NoChannel& Channel, NoString& sMessage);
    bool onPrivAction(NoNick& Nick, NoString& sMessage);
    bool onChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage);
    bool onPrivMsg(NoNick& Nick, NoString& sMessage);
    bool onChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage);
    bool onPrivNotice(NoNick& Nick, NoString& sMessage);
    bool onChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage);
    bool onTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic);
    bool onTimerAutoJoin(NoChannel& Channel);

    bool onAddNetwork(NoNetwork& Network, NoString& sErrorRet);
    bool onDeleteNetwork(NoNetwork& Network);

    bool onSendToClient(NoString& sLine, NoClient& Client);
    bool onSendToIrc(NoString& sLine);

    bool onServerCapAvailable(const NoString& sCap);
    bool onServerCapResult(const NoString& sCap, bool bSuccess);

    bool onAddUser(NoUser& User, NoString& sErrorRet);
    bool onDeleteUser(NoUser& User);
    bool onClientConnect(NoSocket* pSock, const NoString& sHost, ushort uPort);
    bool onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth);
    bool onFailedLogin(const NoString& sUsername, const NoString& sRemoteIP);
    bool onUnknownUserRaw(NoClient* pClient, NoString& sLine);
    bool onClientCapLs(NoClient* pClient, NoStringSet& ssCaps);
    bool isClientCapSupported(NoClient* pClient, const NoString& sCap, bool bState);
    bool onClientCapRequest(NoClient* pClient, const NoString& sCap, bool bState);
    bool onModuleLoading(const NoString& sModName, const NoString& sArgs, No::ModuleType eType, bool& bSuccess, NoString& sRetMsg);
    bool onModuleUnloading(NoModule* pModule, bool& bSuccess, NoString& sRetMsg);
    bool onGetModuleInfo(NoModuleInfo& ModInfo, const NoString& sModule, bool& bSuccess, NoString& sRetMsg);
    bool onGetAvailableModules(std::set<NoModuleInfo>& ssMods, No::ModuleType eType);

private:
    NoModuleLoader(const NoModuleLoader&) = delete;
    NoModuleLoader& operator=(const NoModuleLoader&) = delete;

    std::unique_ptr<NoModuleLoaderPrivate> d;
};

#endif // NOMODULELOADER_H
