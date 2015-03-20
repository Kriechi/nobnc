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

#ifndef NOAPP_H
#define NOAPP_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <no/nosocketmanager.h>
#include <no/nomodules.h>
#include <no/nolistener.h>

class NoClient;
class NoAuthBase;
class NoUser;
class NoNetwork;
class NoConnectQueueTimer;
class NoSettings;
class NoFile;

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
    bool OnBoot();
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
    void AddBytesRead(ulonglong u) { m_uBytesRead += u; }
    void AddBytesWritten(ulonglong u) { m_uBytesWritten += u; }
    ulonglong BytesRead() const { return m_uBytesRead; }
    ulonglong BytesWritten() const { return m_uBytesWritten; }

    typedef std::pair<ulonglong, ulonglong> TrafficStatsPair;
    typedef std::map<NoString, TrafficStatsPair> TrafficStatsMap;
    // Returns a map which maps user names to <traffic in, traffic out>
    // while also providing the traffic of all users together, traffic which
    // couldn't be accounted to any particular user and the total traffic
    // generated through ZNC.
    TrafficStatsMap GetTrafficStats(TrafficStatsPair& Users, TrafficStatsPair& ZNC, TrafficStatsPair& Total);

    // The result is passed back via callbacks to NoAuthBase.
    void AuthUser(std::shared_ptr<NoAuthBase> AuthClass);

    void SetConfigState(ConfigState e) { m_eConfigState = e; }
    void SetSkinName(const NoString& s) { m_sSkinName = s; }
    void SetStatusPrefix(const NoString& s) { m_sStatusPrefix = (s.empty()) ? "*" : s; }
    void SetMaxBufferSize(uint i) { m_uiMaxBufferSize = i; }
    void SetAnonIPLimit(uint i) { m_uiAnonIPLimit = i; }
    void SetServerThrottle(uint i) { m_sConnectThrottle.SetTTL(i * 1000); }
    void SetProtectWebSessions(bool b) { m_bProtectWebSessions = b; }
    void SetHideVersion(bool b) { m_bHideVersion = b; }
    void SetConnectDelay(uint i);

    ConfigState GetConfigState() const { return m_eConfigState; }
    NoSocketManager& GetManager() { return m_Manager; }
    const NoSocketManager& GetManager() const { return m_Manager; }
    NoModules& GetModules() { return *m_pModules; }
    NoString GetSkinName() const { return m_sSkinName; }
    const NoString& GetStatusPrefix() const { return m_sStatusPrefix; }
    const NoString& GetCurPath() const;
    const NoString& GetHomePath() const;
    const NoString& GetZNCPath() const;
    NoString GetConfPath(bool bAllowMkDir = true) const;
    NoString GetUserPath() const;
    NoString GetModPath() const;
    NoString GetPemLocation() const;
    const NoString& GetConfigFile() const { return m_sConfigFile; }
    bool WritePemFile();
    const NoStringVector& GetBindHosts() const { return m_vsBindHosts; }
    const NoStringVector& GetTrustedProxies() const { return m_vsTrustedProxies; }
    const std::vector<NoListener*>& GetListeners() const { return m_vpListeners; }
    time_t TimeStarted() const { return m_TimeStarted; }
    uint GetMaxBufferSize() const { return m_uiMaxBufferSize; }
    uint GetAnonIPLimit() const { return m_uiAnonIPLimit; }
    uint GetServerThrottle() const { return m_sConnectThrottle.GetTTL() / 1000; }
    uint GetConnectDelay() const { return m_uiConnectDelay; }
    bool GetProtectWebSessions() const { return m_bProtectWebSessions; }
    bool GetHideVersion() const { return m_bHideVersion; }
    NoString GetSSLCiphers() const { return m_sSSLCiphers; }
    uint GetDisabledSSLProtocols() const
    {
        return m_uDisabledSSLProtocols;
    }

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
    const std::map<NoString, NoUser*>& GetUserMap() const { return (m_msUsers); }

    NoListener* FindListener(u_short uPort, const NoString& BindHost, AddressType eAddr);
    bool AddListener(NoListener*);
    bool AddListener(ushort uPort,
                     const NoString& sBindHost,
                     const NoString& sURIPrefix,
                     bool bSSL,
                     AddressType eAddr,
                     NoListener::AcceptType eAccept,
                     NoString& sError);
    bool DelListener(NoListener*);

    void SetMotd(const NoString& sMessage)
    {
        ClearMotd();
        AddMotd(sMessage);
    }
    void AddMotd(const NoString& sMessage)
    {
        if (!sMessage.empty()) {
            m_vsMotd.push_back(sMessage);
        }
    }
    void ClearMotd() { m_vsMotd.clear(); }
    const NoStringVector& GetMotd() const { return m_vsMotd; }

    void AddServerThrottle(NoString sName) { m_sConnectThrottle.AddItem(sName, true); }
    bool GetServerThrottle(NoString sName)
    {
        bool* b = m_sConnectThrottle.GetItem(sName);
        return (b && *b);
    }

    void AddNetworkToQueue(NoNetwork* pNetwork);
    std::list<NoNetwork*>& GetConnectionQueue() { return m_lpConnectQueue; }

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

    time_t m_TimeStarted;

    ConfigState m_eConfigState;
    std::vector<NoListener*> m_vpListeners;
    std::map<NoString, NoUser*> m_msUsers;
    std::map<NoString, NoUser*> m_msDelUsers;
    NoSocketManager m_Manager;

    NoString m_sCurPath;
    NoString m_sZNCPath;

    NoString m_sConfigFile;
    NoString m_sSkinName;
    NoString m_sStatusPrefix;
    NoString m_sPidFile;
    NoString m_sSSLCertFile;
    NoString m_sSSLCiphers;
    NoString m_sSSLProtocols;
    NoStringVector m_vsBindHosts;
    NoStringVector m_vsTrustedProxies;
    NoStringVector m_vsMotd;
    NoFile* m_pLockFile;
    uint m_uiConnectDelay;
    uint m_uiAnonIPLimit;
    uint m_uiMaxBufferSize;
    uint m_uDisabledSSLProtocols;
    NoModules* m_pModules;
    ulonglong m_uBytesRead;
    ulonglong m_uBytesWritten;
    std::list<NoNetwork*> m_lpConnectQueue;
    NoConnectQueueTimer* m_pConnectQueueTimer;
    uint m_uiConnectPaused;
    NoCacheMap<NoString> m_sConnectThrottle;
    bool m_bProtectWebSessions;
    bool m_bHideVersion;
};

#endif // NOAPP_H
