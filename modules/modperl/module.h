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

#pragma once

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include <znc/nomodules.h>

#if HAVE_VISIBILITY
#pragma GCC visibility push(default)
#endif
class CPerlModule : public NoModule {
	SV* m_perlObj;
	VWebSubPages* _GetSubPages();
public:
	CPerlModule(NoUser* pUser, NoNetwork* pNetwork, const NoString& sModName, const NoString& sDataPath,
			NoModInfo::EModuleType eType, SV* perlObj)
			: NoModule(nullptr, pUser, pNetwork, sModName, sDataPath, eType) {
		m_perlObj = newSVsv(perlObj);
	}
	SV* GetPerlObj() {
		return sv_2mortal(newSVsv(m_perlObj));
	}

	bool OnBoot() override;
	bool WebRequiresLogin() override;
	bool WebRequiresAdmin() override;
	NoString GetWebMenuTitle() override;
	bool OnWebPreRequest(NoWebSock& WebSock, const NoString& sPageName) override;
	bool OnWebRequest(NoWebSock& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override;
	VWebSubPages& GetSubPages() override;
	void OnPreRehash() override;
	void OnPostRehash() override;
	void OnIRCDisconnected() override;
	void OnIRCConnected() override;
	EModRet OnIRCConnecting(NoIrcSock *pIRCSock) override;
	void OnIRCConnectionError(NoIrcSock *pIRCSock) override;
	EModRet OnIRCRegistration(NoString& sPass, NoString& sNick, NoString& sIdent, NoString& sRealName) override;
	EModRet OnBroadcast(NoString& sMessage) override;
	void OnChanPermission2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, unsigned char uMode, bool bAdded, bool bNoChange) override;
	void OnOp2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override;
	void OnDeop2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override;
	void OnVoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override;
	void OnDevoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override;
	void OnMode2(const NoNick* pOpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange) override;
	void OnRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs) override;
	EModRet OnRaw(NoString& sLine) override;
	EModRet OnStatusCommand(NoString& sCommand) override;
	void OnModCommand(const NoString& sCommand) override;
	void OnModNotice(const NoString& sMessage) override;
	void OnModCTCP(const NoString& sMessage) override;
	void OnQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans) override;
	void OnNick(const NoNick& Nick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans) override;
	void OnKick(const NoNick& OpNick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage) override;
	EModRet OnJoining(NoChannel& Channel) override;
	void OnJoin(const NoNick& Nick, NoChannel& Channel) override;
	void OnPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage) override;
	EModRet OnChanBufferStarting(NoChannel& Chan, NoClient& Client) override;
	EModRet OnChanBufferEnding(NoChannel& Chan, NoClient& Client) override;
	EModRet OnChanBufferPlayLine(NoChannel& Chan, NoClient& Client, NoString& sLine) override;
	EModRet OnPrivBufferPlayLine(NoClient& Client, NoString& sLine) override;
	void OnClientLogin() override;
	void OnClientDisconnect() override;
	EModRet OnUserRaw(NoString& sLine) override;
	EModRet OnUserCTCPReply(NoString& sTarget, NoString& sMessage) override;
	EModRet OnUserCTCP(NoString& sTarget, NoString& sMessage) override;
	EModRet OnUserAction(NoString& sTarget, NoString& sMessage) override;
	EModRet OnUserMsg(NoString& sTarget, NoString& sMessage) override;
	EModRet OnUserNotice(NoString& sTarget, NoString& sMessage) override;
	EModRet OnUserJoin(NoString& sChannel, NoString& sKey) override;
	EModRet OnUserPart(NoString& sChannel, NoString& sMessage) override;
	EModRet OnUserTopic(NoString& sChannel, NoString& sTopic) override;
	EModRet OnUserQuit(NoString& sMessage) override;
	EModRet OnUserTopicRequest(NoString& sChannel) override;
	EModRet OnCTCPReply(NoNick& Nick, NoString& sMessage) override;
	EModRet OnPrivCTCP(NoNick& Nick, NoString& sMessage) override;
	EModRet OnChanCTCP(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override;
	EModRet OnPrivAction(NoNick& Nick, NoString& sMessage) override;
	EModRet OnChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override;
	EModRet OnPrivMsg(NoNick& Nick, NoString& sMessage) override;
	EModRet OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override;
	EModRet OnPrivNotice(NoNick& Nick, NoString& sMessage) override;
	EModRet OnChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override;
	EModRet OnTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic) override;
	bool OnServerCapAvailable(const NoString& sCap) override;
	void OnServerCapResult(const NoString& sCap, bool bSuccess) override;
	EModRet OnTimerAutoJoin(NoChannel& Channel) override;
	bool OnEmbeddedWebRequest(NoWebSock&, const NoString&, NoTemplate&) override;
	EModRet OnAddNetwork(NoNetwork& Network, NoString& sErrorRet) override;
	EModRet OnDeleteNetwork(NoNetwork& Network) override;
	EModRet OnSendToClient(NoString& sLine, NoClient& Client) override;
	EModRet OnSendToIRC(NoString& sLine) override;
};

static inline CPerlModule* AsPerlModule(NoModule* p) {
	return dynamic_cast<CPerlModule*>(p);
}

enum ELoadPerlMod {
	Perl_NotFound,
	Perl_Loaded,
	Perl_LoadError,
};

class CPerlTimer : public NoTimer {
	SV* m_perlObj;
public:
	CPerlTimer(CPerlModule* pModule, unsigned int uInterval, unsigned int uCycles, const NoString& sLabel, const NoString& sDescription, SV* perlObj)
					: NoTimer (pModule, uInterval, uCycles, sLabel, sDescription), m_perlObj(newSVsv(perlObj)) {
		pModule->AddTimer(this);
	}
	void RunJob() override;
	SV* GetPerlObj() {
		return sv_2mortal(newSVsv(m_perlObj));
	}
	~CPerlTimer();
};

inline CPerlTimer* CreatePerlTimer(CPerlModule* pModule, unsigned int uInterval, unsigned int uCycles,
		const NoString& sLabel, const NoString& sDescription, SV* perlObj) {
	return new CPerlTimer(pModule, uInterval, uCycles, sLabel, sDescription, perlObj);
}

class CPerlSocket : public NoSocket {
	SV* m_perlObj;
public:
	CPerlSocket(CPerlModule* pModule, SV* perlObj) : NoSocket(pModule), m_perlObj(newSVsv(perlObj)) {}
	SV* GetPerlObj() {
		return sv_2mortal(newSVsv(m_perlObj));
	}
	~CPerlSocket();
	void Connected() override;
	void Disconnected() override;
	void Timeout() override;
	void ConnectionRefused() override;
	void ReadData(const char *data, size_t len) override;
	void ReadLine(const NoString& sLine) override;
	Csock* GetSockObj(const NoString& sHost, unsigned short uPort) override;
};

inline CPerlSocket* CreatePerlSocket(CPerlModule* pModule, SV* perlObj) {
	return new CPerlSocket(pModule, perlObj);
}

inline bool HaveIPv6() {
#ifdef HAVE_IPV6
	return true;
#endif
	return false;
}

inline bool HaveSSL() {
#ifdef HAVE_LIBSSL
	return true;
#endif
	return false;
}

inline bool HaveCharset() {
#ifdef HAVE_ICU
	return true;
#endif
	return false;
}

inline int _GetSOMAXCONN() {
	return SOMAXCONN;
}

inline int GetVersionMajor() {
	return NO_VERSION_MAJOR;
}

inline int GetVersionMinor() {
	return NO_VERSION_MINOR;
}

inline double GetVersion() {
	return NO_VERSION;
}

inline NoString GetVersionExtra() {
	return NO_VERSION_EXTRA;
}
#if HAVE_VISIBILITY
#pragma GCC visibility pop
#endif
