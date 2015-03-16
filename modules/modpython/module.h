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

class String {
public:
	NoString s;
};

class CModPython;

#if HAVE_VISIBILITY
#pragma GCC visibility push(default)
#endif
class CPyModule : public NoModule {
	PyObject* m_pyObj;
	CModPython* m_pModPython;
	VWebSubPages* _GetSubPages();
public:
	CPyModule(NoUser* pUser, NoNetwork* pNetwork, const NoString& sModName, const NoString& sDataPath,
			NoModInfo::EModuleType eType, PyObject* pyObj, CModPython* pModPython)
			: NoModule(nullptr, pUser, pNetwork, sModName, sDataPath, eType) {
		m_pyObj = pyObj;
		Py_INCREF(pyObj);
		m_pModPython = pModPython;
	}
	PyObject* GetPyObj() { // borrows
		return m_pyObj;
	}
	PyObject* GetNewPyObj() {
		Py_INCREF(m_pyObj);
		return m_pyObj;
	}
	void DeletePyModule() {
		Py_CLEAR(m_pyObj);
		delete this;
	}
	NoString GetPyExceptionStr();
	CModPython* GetModPython() {
		return m_pModPython;
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
	EModRet OnUserTopicRequest(NoString& sChannel) override;
	EModRet OnUserQuit(NoString& sMessage) override;
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

	// Global Modules
	EModRet OnAddUser(NoUser& User, NoString& sErrorRet) override;
	EModRet OnDeleteUser(NoUser& User) override;
	void OnClientConnect(NoBaseSocket* pSock, const NoString& sHost, unsigned short uPort) override;
	void OnFailedLogin(const NoString& sUsername, const NoString& sRemoteIP) override;
	EModRet OnUnknownUserRaw(NoClient* pClient, NoString& sLine) override;
	bool IsClientCapSupported(NoClient* pClient, const NoString& sCap, bool bState) override;
	void OnClientCapRequest(NoClient* pClient, const NoString& sCap, bool bState) override;
	virtual EModRet OnModuleLoading(const NoString& sModName, const NoString& sArgs,
			NoModInfo::EModuleType eType, bool& bSuccess, NoString& sRetMsg) override;
	EModRet OnModuleUnloading(NoModule* pModule, bool& bSuccess, NoString& sRetMsg) override;
	virtual EModRet OnGetModInfo(NoModInfo& ModInfo, const NoString& sModule,
			bool& bSuccess, NoString& sRetMsg) override;
	void OnGetAvailableMods(std::set<NoModInfo>& ssMods, NoModInfo::EModuleType eType) override;
	void OnClientCapLs(NoClient* pClient, NoStringSet& ssCaps) override;
	EModRet OnLoginAttempt(std::shared_ptr<NoAuthBase> Auth) override;
};

static inline CPyModule* AsPyModule(NoModule* p) {
	return dynamic_cast<CPyModule*>(p);
}

inline CPyModule* CreatePyModule(NoUser* pUser, NoNetwork* pNetwork, const NoString& sModName, const NoString& sDataPath, NoModInfo::EModuleType eType, PyObject* pyObj, CModPython* pModPython) {
	return new CPyModule(pUser, pNetwork, sModName, sDataPath, eType, pyObj, pModPython);
}

class CPyTimer : public NoTimer {
	PyObject* m_pyObj;
	CModPython* m_pModPython;
public:
	CPyTimer(CPyModule* pModule, unsigned int uInterval, unsigned int uCycles, const NoString& sLabel, const NoString& sDescription, PyObject* pyObj)
					: NoTimer (pModule, uInterval, uCycles, sLabel, sDescription), m_pyObj(pyObj) {
		Py_INCREF(pyObj);
		pModule->AddTimer(this);
		m_pModPython = pModule->GetModPython();
	}
	void RunJob() override;
	PyObject* GetPyObj() { return m_pyObj; }
	PyObject* GetNewPyObj() {
		Py_INCREF(m_pyObj);
		return m_pyObj;
	}
	~CPyTimer();
};

inline CPyTimer* CreatePyTimer(CPyModule* pModule, unsigned int uInterval, unsigned int uCycles,
		const NoString& sLabel, const NoString& sDescription, PyObject* pyObj) {
	return new CPyTimer(pModule, uInterval, uCycles, sLabel, sDescription, pyObj);
}

class CPySocket : public NoSocket {
	PyObject* m_pyObj;
	CModPython* m_pModPython;
public:
	CPySocket(CPyModule* pModule, PyObject* pyObj) : NoSocket(pModule), m_pyObj(pyObj) {
		Py_INCREF(pyObj);
		m_pModPython = pModule->GetModPython();
	}
	PyObject* GetPyObj() { return m_pyObj; }
	PyObject* GetNewPyObj() {
		Py_INCREF(m_pyObj);
		return m_pyObj;
	}
	~CPySocket();
	void Connected() override;
	void Disconnected() override;
	void Timeout() override;
	void ConnectionRefused() override;
	void ReadData(const char *data, size_t len) override;
	void ReadLine(const NoString& sLine) override;
	Csock* GetSockObj(const NoString& sHost, unsigned short uPort) override;
};

inline CPySocket* CreatePySocket(CPyModule* pModule, PyObject* pyObj) {
	return new CPySocket(pModule, pyObj);
}

inline bool HaveIPv6_() {
#ifdef HAVE_IPV6
	return true;
#endif
	return false;
}

inline bool HaveSSL_() {
#ifdef HAVE_LIBSSL
	return true;
#endif
	return false;
}

inline bool HaveCharset_() {
#ifdef HAVE_ICU
	return true;
#endif
	return false;
}

inline int GetSOMAXCONN() {
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

class NoStringMap_iter {
public:
	NoStringMap_iter() {}
	NoStringMap::iterator x;
	NoStringMap_iter(NoStringMap::iterator z) : x(z) {}
	void plusplus() {
		++x;
	}
	NoString get() {
		return x->first;
	}
	bool is_end(NoModule* m) {
		return m->EndNV() == x;
	}
};

class NoModulesIter {
public:
	NoModulesIter(NoModules *pModules) {
		m_pModules = pModules;
		m_it = pModules->begin();
	}

	void plusplus() {
		++m_it;
	}

	const NoModule* get() const {
		return *m_it;
	}

	bool is_end() const {
		return m_pModules->end() == m_it;
	}

	NoModules *m_pModules;
	NoModules::const_iterator m_it;
};

#if HAVE_VISIBILITY
#pragma GCC visibility pop
#endif
