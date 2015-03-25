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

#ifndef NOAPP_H
#define NOAPP_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <no/nosocketmanager.h>
#include <no/nomoduleloader.h>
#include <no/nocachemap.h>
#include <list>

class NoClient;
class NoAuthenticator;
class NoUser;
class NoNetwork;
class NoConnectQueueTimer;
class NoSettings;
class NoFile;
class NoListener;

class NO_EXPORT NoApp
{
public:
    NoApp();
    ~NoApp();

    NoApp(const NoApp&) = delete;
    NoApp& operator=(const NoApp&) = delete;

    enum ConfigState { ConfigNothing, ConfigNeedRehash, ConfigNeedWrite, ConfigNeedVerboseWrite };

    void DeleteUsers();
    void Loop();
    bool WritePidFile(int iPid);
    bool DeletePidFile();
    bool WaitForChildLock();
    bool IsHostAllowed(const NoString& sHostMask) const;
    // This returns false if there are too many anonymous connections from this ip
    bool AllowConnectionFrom(const NoString& sIP) const;
    void InitDirs(const NoString& sArgvPath, const NoString& sDataDir);
    bool onBoot();
    NoString ExpandConfigPath(const NoString& sConfigFile, bool bAllowMkDir = true);
    bool WriteNewConfig(const NoString& sConfigFile);
    bool WriteConfig();
    bool ParseConfig(const NoString& sConfig, NoString& sError);
    bool RehashConfig(NoString& sError);
    void BackupConfigOnce(const NoString& sSuffix);
    static NoString GetVersion();
    static NoString GetTag(bool bIncludeVersion = true, bool bHTML = false);
    static NoString GetCompileOptionsString();
    NoString GetUptime() const;
    void ClearBindHosts();
    bool AddBindHost(const NoString& sHost);
    bool RemBindHost(const NoString& sHost);
    void ClearTrustedProxies();
    bool AddTrustedProxy(const NoString& sHost);
    bool RemTrustedProxy(const NoString& sHost);
    void Broadcast(const NoString& sMessage, bool bAdminOnly = false, NoUser* pSkipUser = nullptr, NoClient* pSkipClient = nullptr);
    void AddBytesRead(ulonglong u);
    void AddBytesWritten(ulonglong u);
    ulonglong BytesRead() const;
    ulonglong BytesWritten() const;

    typedef std::pair<ulonglong, ulonglong> TrafficStatsPair;
    typedef std::map<NoString, TrafficStatsPair> TrafficStatsMap;
    // Returns a map which maps user names to <traffic in, traffic out>
    // while also providing the traffic of all users together, traffic which
    // couldn't be accounted to any particular user and the total traffic
    // generated through ZNC.
    TrafficStatsMap GetTrafficStats(TrafficStatsPair& Users, TrafficStatsPair& ZNC, TrafficStatsPair& Total);

    // The result is passed back via callbacks to NoAuthenticator.
    void AuthUser(std::shared_ptr<NoAuthenticator> AuthClass);

    void SetConfigState(ConfigState e);
    void SetSkinName(const NoString& s);
    void SetStatusPrefix(const NoString& s);
    void SetMaxBufferSize(uint i);
    void SetAnonIPLimit(uint i);
    void SetServerThrottle(uint i);
    void SetProtectWebSessions(bool b);
    void SetHideVersion(bool b);
    void SetConnectDelay(uint i);

    ConfigState GetConfigState() const;
    NoSocketManager& GetManager();
    const NoSocketManager& GetManager() const;
    NoModuleLoader* GetLoader() const;
    NoString GetSkinName() const;
    const NoString& GetStatusPrefix() const;
    const NoString& GetCurPath() const;
    const NoString& GetHomePath() const;
    const NoString& GetZNCPath() const;
    NoString GetConfPath(bool bAllowMkDir = true) const;
    NoString GetUserPath() const;
    NoString GetModPath() const;
    NoString GetPemLocation() const;
    const NoString& GetConfigFile() const;
    bool WritePemFile();
    const NoStringVector& GetBindHosts() const;
    const NoStringVector& GetTrustedProxies() const;
    const std::vector<NoListener*>& GetListeners() const;
    time_t TimeStarted() const;
    uint GetMaxBufferSize() const;
    uint GetAnonIPLimit() const;
    uint GetServerThrottle() const;
    uint GetConnectDelay() const;
    bool GetProtectWebSessions() const;
    bool GetHideVersion() const;
    NoString GetSSLCiphers() const;
    uint GetDisabledSSLProtocols() const;

    static void CreateInstance();
    static NoApp& Get();
    static void DestroyInstance();
    NoUser* FindUser(const NoString& sUsername);
    NoModule* FindModule(const NoString& sModName, const NoString& sUsername);
    NoModule* FindModule(const NoString& sModName, NoUser* pUser);

    /** Reload a module everywhere
     *
     * This method will unload a module globally, for a user and for each
     * network. It will then reload them all again.
     *
     * @param sModule The name of the module to reload
     */
    bool UpdateModule(const NoString& sModule);

    bool DeleteUser(const NoString& sUsername);
    bool AddUser(NoUser* pUser, NoString& sErrorRet);
    const std::map<NoString, NoUser*>& GetUserMap() const;

    NoListener* FindListener(u_short uPort, const NoString& sHost, No::AddressType eAddr);
    bool AddListener(NoListener*);
    bool AddListener(ushort uPort,
                     const NoString& sBindHost,
                     const NoString& sURIPrefix,
                     bool bSSL,
                     No::AddressType eAddr,
                     No::AcceptType eAccept,
                     NoString& sError);
    bool DelListener(NoListener*);

    void SetMotd(const NoString& sMessage);
    void AddMotd(const NoString& sMessage);
    void ClearMotd();
    const NoStringVector& GetMotd() const;

    void AddServerThrottle(NoString sName);
    bool GetServerThrottle(NoString sName);

    void AddNetworkToQueue(NoNetwork* pNetwork);
    std::list<NoNetwork*>& GetConnectionQueue();

    void EnableConnectQueue();
    void DisableConnectQueue();

    void PauseConnectQueue();
    void ResumeConnectQueue();

    // Never call this unless you are NoConnectQueueTimer::~NoConnectQueueTimer()
    void LeakConnectQueueTimer(NoConnectQueueTimer* pTimer);

    static void DumpConfig(const NoSettings* Config);

private:
    NoFile* InitPidFile();
    bool DoRehash(NoString& sError);
    // Returns true if something was done
    bool HandleUserDeletion();
    NoString MakeConfigHeader();
    bool AddListener(const NoString& sLine, NoString& sError);
    bool AddListener(NoSettings* pConfig, NoString& sError);

    time_t m_startTime;

    ConfigState m_configState;
    std::vector<NoListener*> m_listeners;
    std::map<NoString, NoUser*> m_users;
    std::map<NoString, NoUser*> m_delUsers;
    NoSocketManager m_manager;

    NoString m_curPath;
    NoString m_appPath;

    NoString m_configFile;
    NoString m_skinName;
    NoString m_statusPrefix;
    NoString m_pidFile;
    NoString m_sslCertFile;
    NoString m_sslCiphers;
    NoString m_sslProtocols;
    NoStringVector m_bindHosts;
    NoStringVector m_trustedProxies;
    NoStringVector m_motd;
    NoFile* m_lockFile;
    uint m_connectDelay;
    uint m_anonIpLimit;
    uint m_maxBufferSize;
    uint m_disabledSslProtocols;
    NoModuleLoader* m_modules;
    ulonglong m_bytesRead;
    ulonglong m_bytesWritten;
    std::list<NoNetwork*> m_connectQueue;
    NoConnectQueueTimer* m_connectQueueTimer;
    uint m_connectPaused;
    NoCacheMap<NoString> m_connectThrottle;
    bool m_protectWebSessions;
    bool m_hideVersion;
};

#endif // NOAPP_H
