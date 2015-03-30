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

    void deleteUsers();
    void loop();
    bool writePidFile(int iPid);
    bool deletePidFile();
    bool waitForChildLock();
    bool isHostAllowed(const NoString& sHostMask) const;
    // This returns false if there are too many anonymous connections from this ip
    bool allowConnectionFrom(const NoString& sIP) const;
    void initDirs(const NoString& sArgvPath, const NoString& sDataDir);
    bool onBoot();
    NoString expandConfigPath(const NoString& sConfigFile, bool bAllowMkDir = true);
    bool writeNewConfig(const NoString& sConfigFile);
    bool writeConfig();
    bool parseConfig(const NoString& sConfig, NoString& sError);
    bool rehashConfig(NoString& sError);
    void backupConfigOnce(const NoString& sSuffix);
    static NoString version();
    static NoString tag(bool bIncludeVersion = true, bool bHTML = false);
    static NoString compileOptionsString();
    NoString uptime() const;
    void clearBindHosts();
    bool addBindHost(const NoString& sHost);
    bool removeBindHost(const NoString& sHost);
    void clearTrustedProxies();
    bool addTrustedProxy(const NoString& sHost);
    bool removeTrustedProxy(const NoString& sHost);
    void broadcast(const NoString& sMessage, bool bAdminOnly = false, NoUser* pSkipUser = nullptr, NoClient* pSkipClient = nullptr);
    void addBytesRead(ulonglong u);
    void addBytesWritten(ulonglong u);
    ulonglong bytesRead() const;
    ulonglong bytesWritten() const;

    typedef std::pair<ulonglong, ulonglong> TrafficStatsPair;
    typedef std::map<NoString, TrafficStatsPair> TrafficStatsMap;
    // Returns a map which maps user names to <traffic in, traffic out>
    // while also providing the traffic of all users together, traffic which
    // couldn't be accounted to any particular user and the total traffic
    // generated through ZNC.
    TrafficStatsMap trafficStats(TrafficStatsPair& Users, TrafficStatsPair& ZNC, TrafficStatsPair& Total);

    // The result is passed back via callbacks to NoAuthenticator.
    void authUser(std::shared_ptr<NoAuthenticator> AuthClass);

    void setConfigState(ConfigState e);
    void setSkinName(const NoString& s);
    void setStatusPrefix(const NoString& s);
    void setMaxBufferSize(uint i);
    void setAnonIpLimit(uint i);
    void setServerThrottle(uint i);
    void setProtectWebSessions(bool b);
    void setHideVersion(bool b);
    void setConnectDelay(uint i);

    ConfigState configState() const;
    NoSocketManager& manager();
    const NoSocketManager& manager() const;
    NoModuleLoader* loader() const;
    NoString skinName() const;
    NoString statusPrefix() const;
    NoString currentPath() const;
    NoString appPath() const;
    NoString confPath(bool bAllowMkDir = true) const;
    NoString userPath() const;
    NoString modulePath() const;
    NoString pemLocation() const;
    NoString configFile() const;
    bool writePemFile();
    NoStringVector bindHosts() const;
    NoStringVector trustedProxies() const;
    std::vector<NoListener*> listeners() const;
    time_t timeStarted() const;
    uint maxBufferSize() const;
    uint anonIpLimit() const;
    uint serverThrottle() const;
    uint connectDelay() const;
    bool protectWebSessions() const;
    bool hideVersion() const;
    NoString sslCiphers() const;
    uint disabledSslProtocols() const;

    static void createInstance();
    static NoApp& instance();
    static void destroyInstance();

    NoUser* findUser(const NoString& sUsername);
    NoModule* findModule(const NoString& sModName, const NoString& sUsername);
    NoModule* findModule(const NoString& sModName, NoUser* pUser);

    /** Reload a module everywhere
     *
     * This method will unload a module globally, for a user and for each
     * network. It will then reload them all again.
     *
     * @param sModule The name of the module to reload
     */
    bool updateModule(const NoString& sModule);

    bool deleteUser(const NoString& sUsername);
    bool addUser(NoUser* pUser, NoString& sErrorRet);
    std::map<NoString, NoUser*> userMap() const;

    NoListener* findListener(u_short uPort, const NoString& sHost, No::AddressType eAddr);
    bool addListener(NoListener*);
    bool addListener(ushort uPort,
                     const NoString& sBindHost,
                     const NoString& sURIPrefix,
                     bool bSSL,
                     No::AddressType eAddr,
                     No::AcceptType eAccept,
                     NoString& sError);
    bool removeListener(NoListener*);

    void setMotd(const NoString& sMessage);
    void addMotd(const NoString& sMessage);
    void clearMotd();
    NoStringVector motd() const;

    void addServerThrottle(NoString sName);
    bool serverThrottle(NoString sName);

    void addNetworkToQueue(NoNetwork* pNetwork);
    std::list<NoNetwork*>& connectionQueue();

    void enableConnectQueue();
    void disableConnectQueue();

    void pauseConnectQueue();
    void resumeConnectQueue();

    // Never call this unless you are NoConnectQueueTimer::~NoConnectQueueTimer()
    void leakConnectQueueTimer(NoConnectQueueTimer* pTimer);

    static void dumpConfig(const NoSettings* Config);

private:
    NoFile* initPidFile();
    bool doRehash(NoString& sError);
    // Returns true if something was done
    bool handleUserDeletion();
    NoString makeConfigHeader();
    bool addListener(const NoString& sLine, NoString& sError);
    bool addListener(NoSettings* pConfig, NoString& sError);

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
