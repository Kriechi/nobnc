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

#include "noapp.h"
#include "nodir.h"
#include "nofile.h"
#include "noircsocket.h"
#include "noauthenticator.h"
#include "noserverinfo.h"
#include "nouser.h"
#include "nonetwork.h"
#include "nosettings.h"
#include "noclient.h"
#include "nowebsocket.h"
#include "nolistener.h"
#include "noregistry.h"
#include <tuple>
#include <algorithm>
#include "Csocket/Csocket.h"

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#endif // HAVE_LIBSSL

static inline NoString FormatBindError()
{
    NoString sError = (errno == 0 ? NoString("unknown error, check the host name") : NoString(strerror(errno)));
    return "Unable to bind [" + sError + "]";
}

NoApp::NoApp()
    : m_startTime(time(nullptr)),
      m_configState(ConfigNothing),
      m_listeners(),
      m_users(),
      m_delUsers(),
      m_manager(),
      m_curPath(""),
      m_appPath(""),
      m_configFile(""),
      m_skinName(""),
      m_statusPrefix(""),
      m_pidFile(""),
      m_sslCertFile(""),
      m_sslCiphers(""),
      m_sslProtocols(""),
      m_bindHosts(),
      m_trustedProxies(),
      m_motd(),
      m_lockFile(nullptr),
      m_connectDelay(5),
      m_anonIpLimit(10),
      m_maxBufferSize(500),
      m_disabledSslProtocols(Csock::EDP_SSL),
      m_modules(new NoModuleLoader),
      m_bytesRead(0),
      m_bytesWritten(0),
      m_connectQueue(),
      m_connectQueueTimer(nullptr),
      m_connectPaused(0),
      m_connectThrottle(),
      m_protectWebSessions(true),
      m_hideVersion(false)
{
    if (!InitCsocket()) {
        No::printError("Could not initialize Csocket!");
        exit(-1);
    }
    m_connectThrottle.setExpiration(30000);
}

NoApp::~NoApp()
{
    m_modules->unloadAllModules();

    for (const auto& it : m_users) {
        it.second->loader()->unloadAllModules();

        const std::vector<NoNetwork*>& networks = it.second->networks();
        for (NoNetwork* pNetwork : networks) {
            pNetwork->loader()->unloadAllModules();
        }
    }

    for (NoListener* pListener : m_listeners) {
        delete pListener;
    }

    for (const auto& it : m_users) {
        it.second->setBeingDeleted(true);
    }

    m_connectQueueTimer = nullptr;
    // This deletes m_pConnectQueueTimer
    m_manager.cleanup();
    deleteUsers();

    delete m_modules;
    delete m_lockFile;

    ShutdownCsocket();
    deletePidFile();
}

NoString NoApp::version()
{
    return NoString(NO_VERSION_STR) + NoString(NO_VERSION_EXTRA);
}

NoString NoApp::tag(bool bIncludeVersion, bool bHTML)
{
    if (!instance().m_hideVersion) {
        bIncludeVersion = true;
    }
    NoString sAddress = bHTML ? "<a href=\"http://znc.in\">http://znc.in</a>" : "http://znc.in";

    if (!bIncludeVersion) {
        return "ZNC - " + sAddress;
    }

    NoString sVersion = version();

    return "ZNC - " + sVersion + " - " + sAddress;
}

NoString NoApp::compileOptionsString()
{
    return "IPv6: "
#ifdef HAVE_IPV6
           "yes"
#else
           "no"
#endif
           ", SSL: "
#ifdef HAVE_LIBSSL
           "yes"
#else
           "no"
#endif
           ", DNS: "
#ifdef HAVE_THREADED_DNS
           "threads"
#else
           "blocking"
#endif
           ", charset: "
#ifdef HAVE_ICU
           "yes"
#else
           "no"
#endif
    ;
}

NoString NoApp::uptime() const
{
    time_t now = time(nullptr);
    return No::toTimeStr(now - timeStarted());
}

bool NoApp::onBoot()
{
    bool bFail = false;
    ALLMODULECALL(onBoot(), &bFail);
    if (bFail)
        return false;

    return true;
}

bool NoApp::handleUserDeletion()
{
    if (m_delUsers.empty())
        return false;

    for (const auto& it : m_delUsers) {
        NoUser* pUser = it.second;
        pUser->setBeingDeleted(true);

        if (loader()->onDeleteUser(*pUser)) {
            pUser->setBeingDeleted(false);
            continue;
        }
        m_users.erase(pUser->userName());
        NoWebSocket::finishUserSessions(*pUser);
        delete pUser;
    }

    m_delUsers.clear();

    return true;
}

void NoApp::loop()
{
    while (true) {
        NoString sError;

        ConfigState eState = configState();
        switch (eState) {
        case ConfigNeedRehash:
            setConfigState(ConfigNothing);

            if (rehashConfig(sError)) {
                broadcast("Rehashing succeeded", true);
            } else {
                broadcast("Rehashing failed: " + sError, true);
                broadcast("ZNC is in some possibly inconsistent state!", true);
            }
            break;
        case ConfigNeedWrite:
        case ConfigNeedVerboseWrite:
            setConfigState(ConfigNothing);

            if (!writeConfig()) {
                broadcast("Writing the config file failed", true);
            } else if (eState == ConfigNeedVerboseWrite) {
                broadcast("Writing the config succeeded", true);
            }
            break;
        case ConfigNothing:
            break;
        }

        // Check for users that need to be deleted
        if (handleUserDeletion()) {
            // Also remove those user(s) from the config file
            writeConfig();
        }

        // Csocket wants micro seconds
        // 100 msec to 600 sec
        m_manager.dynamicSelectLoop(100 * 1000, 600 * 1000 * 1000);
    }
}

NoFile* NoApp::initPidFile()
{
    if (!m_pidFile.empty()) {
        NoString sFile;

        // absolute path or relative to the data dir?
        if (m_pidFile[0] != '/')
            sFile = appPath() + "/" + m_pidFile;
        else
            sFile = m_pidFile;

        return new NoFile(sFile);
    }

    return nullptr;
}

bool NoApp::writePidFile(int iPid)
{
    NoFile* File = initPidFile();
    if (File == nullptr)
        return false;

    No::printAction("Writing pid file [" + File->GetLongName() + "]");

    bool bRet = false;
    if (File->Open(O_WRONLY | O_TRUNC | O_CREAT)) {
        File->Write(NoString(iPid) + "\n");
        File->Close();
        bRet = true;
    }

    delete File;
    No::printStatus(bRet);
    return bRet;
}

bool NoApp::deletePidFile()
{
    NoFile* File = initPidFile();
    if (File == nullptr)
        return false;

    No::printAction("Deleting pid file [" + File->GetLongName() + "]");

    bool bRet = File->Delete();

    delete File;
    No::printStatus(bRet);
    return bRet;
}

#ifdef HAVE_LIBSSL
// Generated by "openssl dhparam 2048"
constexpr const char* szDefaultDH2048 = "-----BEGIN DH PARAMETERS-----\n"
                                        "MIIBCAKCAQEAtS/K3TMY8IHzcCATQSjUF3rDidjDDQmT+mLxyxRORmzMPjFIFkKH\n"
                                        "MOmxZvyCBArdaoCCEBBOzrldl/bBLn5TOeZb+MW7mpBLANTuQSOu97DDM7EzbnqC\n"
                                        "b6z3QgixZ2+UqxdmQAu4nBPLFwym6W/XPFEHpz6iHISSvjzzo4cfI0xwWTcoAvFQ\n"
                                        "r/ZU5BXSXp7XuDxSyyAqaaKUxquElf+x56QWrpNJypjzPpslg5ViAKwWQS0TnCrU\n"
                                        "sVuhFtbNlZjqW1tMSBxiWFltS1HoEaaI79MEpf1Ps25OrQl8xqqCGKkZcHlNo4oF\n"
                                        "cvUyzAEcCQYHmiYjp2hoZbSa8b690TQaAwIBAg==\n"
                                        "-----END DH PARAMETERS-----\n";

static void GenerateCert(FILE* pOut, const NoString& sHost)
{
    EVP_PKEY* pKey = nullptr;
    X509* pCert = nullptr;
    X509_NAME* pName = nullptr;
    const int days = 365;
    const int years = 10;

    uint uSeed = (uint)time(nullptr);
    int serial = (rand_r(&uSeed) % 9999);

    RSA* pRSA = RSA_generate_key(2048, 0x10001, nullptr, nullptr);
    if ((pKey = EVP_PKEY_new())) {
        if (!EVP_PKEY_assign_RSA(pKey, pRSA)) {
            EVP_PKEY_free(pKey);
            return;
        }

        PEM_write_RSAPrivateKey(pOut, pRSA, nullptr, nullptr, 0, nullptr, nullptr);

        if (!(pCert = X509_new())) {
            EVP_PKEY_free(pKey);
            return;
        }

        X509_set_version(pCert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(pCert), serial);
        X509_gmtime_adj(X509_get_notBefore(pCert), 0);
        X509_gmtime_adj(X509_get_notAfter(pCert), (long)60 * 60 * 24 * days * years);
        X509_set_pubkey(pCert, pKey);

        pName = X509_get_subject_name(pCert);

        const char* pLogName = getenv("LOGNAME");
        const char* pHostName = nullptr;

        if (!sHost.empty()) {
            pHostName = sHost.c_str();
        }

        if (!pHostName) {
            pHostName = getenv("HOSTNAME");
        }

        if (!pLogName) {
            pLogName = "Unknown";
        }

        if (!pHostName) {
            pHostName = "host.unknown";
        }

        NoString sEmailAddr = pLogName;
        sEmailAddr += "@";
        sEmailAddr += pHostName;

        X509_NAME_add_entry_by_txt(pName, "OU", MBSTRING_ASC, (uchar*)pLogName, -1, -1, 0);
        X509_NAME_add_entry_by_txt(pName, "CN", MBSTRING_ASC, (uchar*)pHostName, -1, -1, 0);
        X509_NAME_add_entry_by_txt(pName, "emailAddress", MBSTRING_ASC, (uchar*)sEmailAddr.c_str(), -1, -1, 0);

        X509_set_subject_name(pCert, pName);
        X509_set_issuer_name(pCert, pName);

        if (!X509_sign(pCert, pKey, EVP_sha256())) {
            X509_free(pCert);
            EVP_PKEY_free(pKey);
            return;
        }

        PEM_write_X509(pOut, pCert);
        X509_free(pCert);
        EVP_PKEY_free(pKey);

        fprintf(pOut, "%s", szDefaultDH2048);
    }
}
#endif // HAVE_LIBSSL

bool NoApp::writePemFile()
{
#ifndef HAVE_LIBSSL
    No::PrintError("ZNC was not compiled with ssl support.");
    return false;
#else
    NoString sPemFile = pemLocation();

    No::printAction("Writing Pem file [" + sPemFile + "]");
#ifndef _WIN32
    int fd = creat(sPemFile.c_str(), 0600);
    if (fd == -1) {
        No::printStatus(false, "Unable to open");
        return false;
    }
    FILE* f = fdopen(fd, "w");
#else
    FILE* f = fopen(sPemFile.c_str(), "w");
#endif

    if (!f) {
        No::printStatus(false, "Unable to open");
        return false;
    }

#ifdef HAVE_LIBSSL
    GenerateCert(f, "");
#endif
    fclose(f);

    No::printStatus(true);
    return true;
#endif
}

NoStringVector NoApp::bindHosts() const
{
    return m_bindHosts;
}

NoStringVector NoApp::trustedProxies() const
{
    return m_trustedProxies;
}

std::vector<NoListener*> NoApp::listeners() const
{
    return m_listeners;
}

time_t NoApp::timeStarted() const
{
    return m_startTime;
}

uint NoApp::maxBufferSize() const
{
    return m_maxBufferSize;
}

uint NoApp::anonIpLimit() const
{
    return m_anonIpLimit;
}

uint NoApp::serverThrottle() const
{
    return m_connectThrottle.expiration() / 1000;
}

uint NoApp::connectDelay() const
{
    return m_connectDelay;
}

bool NoApp::protectWebSessions() const
{
    return m_protectWebSessions;
}

bool NoApp::hideVersion() const
{
    return m_hideVersion;
}

NoString NoApp::sslCiphers() const
{
    return m_sslCiphers;
}

uint NoApp::disabledSslProtocols() const
{
    return m_disabledSslProtocols;
}

void NoApp::deleteUsers()
{
    for (const auto& it : m_users) {
        it.second->setBeingDeleted(true);
        delete it.second;
    }

    m_users.clear();
    disableConnectQueue();
}

bool NoApp::isHostAllowed(const NoString& sHostMask) const
{
    for (const auto& it : m_users) {
        if (it.second->isHostAllowed(sHostMask)) {
            return true;
        }
    }

    return false;
}

bool NoApp::allowConnectionFrom(const NoString& sIP) const
{
    if (m_anonIpLimit == 0)
        return true;
    return (manager().anonConnectionCount(sIP) < m_anonIpLimit);
}

void NoApp::initDirs(const NoString& sArgvPath, const NoString& sDataDir)
{
    // If the bin was not ran from the current directory, we need to add that dir onto our cwd
    NoString::size_type uPos = sArgvPath.rfind('/');
    if (uPos == NoString::npos)
        m_curPath = "./";
    else
        m_curPath = NoDir("./").filePath(sArgvPath.left(uPos));

    if (sDataDir.empty()) {
        m_appPath = NoDir::home().filePath(".znc");
    } else {
        m_appPath = sDataDir;
    }

    m_sslCertFile = m_appPath + "/znc.pem";
}

NoString NoApp::confPath(bool bAllowMkDir) const
{
    NoString sConfPath = m_appPath + "/configs";
    if (bAllowMkDir && !NoFile::Exists(sConfPath)) {
        NoDir::mkpath(sConfPath);
    }

    return sConfPath;
}

NoString NoApp::userPath() const
{
    NoString sUserPath = m_appPath + "/users";
    if (!NoFile::Exists(sUserPath)) {
        NoDir::mkpath(sUserPath);
    }

    return sUserPath;
}

NoString NoApp::modulePath() const
{
    NoString sModPath = m_appPath + "/modules";

    return sModPath;
}

NoString NoApp::currentPath() const
{
    if (!NoFile::Exists(m_curPath)) {
        NoDir::mkpath(m_curPath);
    }
    return m_curPath;
}

NoString NoApp::appPath() const
{
    if (!NoFile::Exists(m_appPath)) {
        NoDir::mkpath(m_appPath);
    }
    return m_appPath;
}

NoString NoApp::pemLocation() const
{
    return NoDir("").filePath(m_sslCertFile);
}

NoString NoApp::configFile() const
{
    return m_configFile;
}

NoString NoApp::expandConfigPath(const NoString& sConfigFile, bool bAllowMkDir)
{
    NoString sRetPath;

    if (sConfigFile.empty()) {
        sRetPath = confPath(bAllowMkDir) + "/znc.conf";
    } else {
        if (sConfigFile.left(2) == "./" || sConfigFile.left(3) == "../") {
            sRetPath = currentPath() + "/" + sConfigFile;
        } else if (sConfigFile.left(1) != "/") {
            sRetPath = confPath(bAllowMkDir) + "/" + sConfigFile;
        } else {
            sRetPath = sConfigFile;
        }
    }

    return sRetPath;
}

bool NoApp::writeConfig()
{
    if (configFile().empty()) {
        NO_DEBUG("Config file name is empty?!");
        return false;
    }

    // We first write to a temporary file and then move it to the right place
    NoFile* pFile = new NoFile(configFile() + "~");

    if (!pFile->Open(O_WRONLY | O_CREAT | O_TRUNC, 0600)) {
        NO_DEBUG("Could not write config to " + configFile() + "~: " + NoString(strerror(errno)));
        delete pFile;
        return false;
    }

    // We have to "transfer" our lock on the config to the new file.
    // The old file (= inode) is going away and thus a lock on it would be
    // useless. These lock should always succeed (races, anyone?).
    if (!pFile->TryExLock()) {
        NO_DEBUG("Error while locking the new config file, errno says: " + NoString(strerror(errno)));
        pFile->Delete();
        delete pFile;
        return false;
    }

    pFile->Write(makeConfigHeader() + "\n");

    NoSettings config;
    config.AddKeyValuePair("AnonIPLimit", NoString(m_anonIpLimit));
    config.AddKeyValuePair("MaxBufferSize", NoString(m_maxBufferSize));
    config.AddKeyValuePair("SSLCertFile", NoString(m_sslCertFile));
    config.AddKeyValuePair("ProtectWebSessions", NoString(m_protectWebSessions));
    config.AddKeyValuePair("HideVersion", NoString(m_hideVersion));
    config.AddKeyValuePair("Version", NoString(NO_VERSION_STR));

    uint l = 0;
    for (NoListener* pListener : m_listeners) {
        NoSettings listenerConfig;

        listenerConfig.AddKeyValuePair("Host", pListener->host());
        listenerConfig.AddKeyValuePair("URIPrefix", pListener->uriPrefix() + "/");
        listenerConfig.AddKeyValuePair("Port", NoString(pListener->port()));

        listenerConfig.AddKeyValuePair("IPv4", NoString(pListener->addressType() != No::Ipv6Address));
        listenerConfig.AddKeyValuePair("IPv6", NoString(pListener->addressType() != No::Ipv4Address));

        listenerConfig.AddKeyValuePair("SSL", NoString(pListener->isSsl()));

        listenerConfig.AddKeyValuePair("AllowIRC", NoString(pListener->acceptType() != No::AcceptHttp));
        listenerConfig.AddKeyValuePair("AllowWeb", NoString(pListener->acceptType() != No::AcceptIrc));

        config.AddSubConfig("Listener", "listener" + NoString(l++), listenerConfig);
    }

    config.AddKeyValuePair("ConnectDelay", NoString(m_connectDelay));
    config.AddKeyValuePair("ServerThrottle", NoString(m_connectThrottle.expiration() / 1000));

    if (!m_pidFile.empty()) {
        config.AddKeyValuePair("PidFile", No::firstLine(m_pidFile));
    }

    if (!m_skinName.empty()) {
        config.AddKeyValuePair("Skin", No::firstLine(m_skinName));
    }

    if (!m_statusPrefix.empty()) {
        config.AddKeyValuePair("StatusPrefix", No::firstLine(m_statusPrefix));
    }

    if (!m_sslCiphers.empty()) {
        config.AddKeyValuePair("SSLCiphers", NoString(m_sslCiphers));
    }

    if (!m_sslProtocols.empty()) {
        config.AddKeyValuePair("SSLProtocols", m_sslProtocols);
    }

    for (const NoString& sLine : m_motd) {
        config.AddKeyValuePair("Motd", No::firstLine(sLine));
    }

    for (const NoString& sHost : m_bindHosts) {
        config.AddKeyValuePair("BindHost", No::firstLine(sHost));
    }

    for (const NoString& sProxy : m_trustedProxies) {
        config.AddKeyValuePair("TrustedProxy", No::firstLine(sProxy));
    }

    NoModuleLoader* Mods = loader();

    for (const NoModule* pMod : Mods->modules()) {
        NoString sName = pMod->moduleName();
        NoString sArgs = pMod->args();

        if (!sArgs.empty()) {
            sArgs = " " + No::firstLine(sArgs);
        }

        config.AddKeyValuePair("LoadModule", No::firstLine(sName) + sArgs);
    }

    for (const auto& it : m_users) {
        NoString sErr;

        if (!it.second->isValid(sErr)) {
            NO_DEBUG("** Error writing config for user [" << it.first << "] [" << sErr << "]");
            continue;
        }

        config.AddSubConfig("User", it.second->userName(), it.second->toConfig());
    }

    config.Write(*pFile);

    // If Sync() fails... well, let's hope nothing important breaks..
    pFile->Sync();

    if (pFile->HadError()) {
        NO_DEBUG("Error while writing the config, errno says: " + NoString(strerror(errno)));
        pFile->Delete();
        delete pFile;
        return false;
    }

    // We wrote to a temporary name, move it to the right place
    if (!pFile->Move(configFile(), true)) {
        NO_DEBUG("Error while replacing the config file with a new version, errno says " << strerror(errno));
        pFile->Delete();
        delete pFile;
        return false;
    }

    // Everything went fine, just need to update the saved path.
    pFile->SetFileName(configFile());

    // Make sure the lock is kept alive as long as we need it.
    delete m_lockFile;
    m_lockFile = pFile;

    return true;
}

NoString NoApp::makeConfigHeader()
{
    return "// WARNING\n"
           "//\n"
           "// Do NOT edit this file while ZNC is running!\n"
           "// Use webadmin or *controlpanel instead.\n"
           "//\n"
           "// Altering this file by hand will forfeit all support.\n"
           "//\n"
           "// But if you feel risky, you might want to read help on /znc saveconfig and /znc rehash.\n"
           "// Also check http://en.znc.in/wiki/Configuration\n";
}

bool NoApp::writeNewConfig(const NoString& sConfigFile)
{
    NoString sAnswer, sUser, sNetwork;
    NoStringVector vsLines;

    vsLines.push_back(makeConfigHeader());
    vsLines.push_back("Version = " + NoString(NO_VERSION_STR));

    m_configFile = expandConfigPath(sConfigFile);

    if (NoFile::Exists(m_configFile)) {
        No::printStatus(false, "WARNING: config [" + m_configFile + "] already exists.");
    }

    No::printMessage("");
    No::printMessage("-- Global settings --");
    No::printMessage("");

// Listen
#ifdef HAVE_IPV6
    bool b6 = true;
#else
    bool b6 = false;
#endif
    NoString sListenHost;
    NoString sURIPrefix;
    bool bListenSSL = false;
    uint uListenPort = 0;
    bool bSuccess;

    do {
        bSuccess = true;
        while (true) {
            if (!No::getNumInput("Listen on port", uListenPort, 1025, 65534)) {
                continue;
            }
            if (uListenPort == 6667) {
                No::printStatus(false, "WARNING: Some web browsers reject port 6667. If you intend to");
                No::printStatus(false, "use ZNC's web interface, you might want to use another port.");
                if (!No::getBoolInput("Proceed with port 6667 anyway?", true)) {
                    continue;
                }
            }
            break;
        }


#ifdef HAVE_LIBSSL
        bListenSSL = No::getBoolInput("Listen using SSL", bListenSSL);
#endif

#ifdef HAVE_IPV6
        b6 = No::getBoolInput("Listen using both IPv4 and IPv6", b6);
#endif

        // Don't ask for listen host, it may be configured later if needed.

        No::printAction("Verifying the listener");
        NoListener* pListener = new NoListener(sListenHost, (ushort)uListenPort);
        pListener->setUriPrefix(sURIPrefix);
        pListener->setSsl(bListenSSL);
        pListener->setAddressType(b6 ? No::Ipv4AndIpv6Address : No::Ipv4Address);
        if (!pListener->listen()) {
            No::printStatus(false, FormatBindError());
            bSuccess = false;
        } else
            No::printStatus(true);
        delete pListener;
    } while (!bSuccess);

#ifdef HAVE_LIBSSL
    NoString sPemFile = pemLocation();
    if (!NoFile::Exists(sPemFile)) {
        No::printMessage("Unable to locate pem file: [" + sPemFile + "], creating it");
        writePemFile();
    }
#endif

    vsLines.push_back("<Listener l>");
    vsLines.push_back("\tPort = " + NoString(uListenPort));
    vsLines.push_back("\tIPv4 = true");
    vsLines.push_back("\tIPv6 = " + NoString(b6));
    vsLines.push_back("\tSSL = " + NoString(bListenSSL));
    if (!sListenHost.empty()) {
        vsLines.push_back("\tHost = " + sListenHost);
    }
    vsLines.push_back("</Listener>");
    // !Listen

    std::set<NoModuleInfo> ssGlobalMods;
    loader()->defaultModules(ssGlobalMods, No::GlobalModule);
    std::vector<NoString> vsGlobalModNames;
    for (const NoModuleInfo& Info : ssGlobalMods) {
        vsGlobalModNames.push_back(Info.name());
        vsLines.push_back("LoadModule = " + Info.name());
    }
    No::printMessage("Enabled global modules [" + NoString(", ").join(vsGlobalModNames.begin(), vsGlobalModNames.end()) + "]");

    // User
    No::printMessage("");
    No::printMessage("-- Admin user settings --");
    No::printMessage("");

    vsLines.push_back("");
    NoString sNick;
    do {
        No::getInput("Username", sUser, "", "alphanumeric");
    } while (!NoUser::isValidUserName(sUser));

    vsLines.push_back("<User " + sUser + ">");
    NoString sSalt;
    sAnswer = No::getSaltedHashPass(sSalt);
    vsLines.push_back("\tPass       = " + No::defaultHash() + "#" + sAnswer + "#" + sSalt + "#");

    vsLines.push_back("\tAdmin      = true");

    No::getInput("Nick", sNick, NoUser::makeCleanUserName(sUser));
    vsLines.push_back("\tNick       = " + sNick);
    No::getInput("Alternate nick", sAnswer, sNick + "_");
    if (!sAnswer.empty()) {
        vsLines.push_back("\tAltNick    = " + sAnswer);
    }
    No::getInput("Ident", sAnswer, sUser);
    vsLines.push_back("\tIdent      = " + sAnswer);
    No::getInput("Real name", sAnswer, "Got ZNC?");
    vsLines.push_back("\tRealName   = " + sAnswer);
    No::getInput("Bind host", sAnswer, "", "optional");
    if (!sAnswer.empty()) {
        vsLines.push_back("\tBindHost   = " + sAnswer);
    }

    std::set<NoModuleInfo> ssUserMods;
    loader()->defaultModules(ssUserMods, No::UserModule);
    std::vector<NoString> vsUserModNames;
    for (const NoModuleInfo& Info : ssUserMods) {
        vsUserModNames.push_back(Info.name());
        vsLines.push_back("\tLoadModule = " + Info.name());
    }
    No::printMessage("Enabled user modules [" + NoString(", ").join(vsUserModNames.begin(), vsUserModNames.end()) + "]");

    No::printMessage("");
    if (No::getBoolInput("Set up a network?", true)) {
        vsLines.push_back("");

        No::printMessage("");
        No::printMessage("-- Network settings --");
        No::printMessage("");

        do {
            No::getInput("Name", sNetwork, "freenode");
        } while (!NoNetwork::isValidNetwork(sNetwork));

        vsLines.push_back("\t<Network " + sNetwork + ">");

        std::set<NoModuleInfo> ssNetworkMods;
        loader()->defaultModules(ssNetworkMods, No::NetworkModule);
        std::vector<NoString> vsNetworkModNames;
        for (const NoModuleInfo& Info : ssNetworkMods) {
            vsNetworkModNames.push_back(Info.name());
            vsLines.push_back("\t\tLoadModule = " + Info.name());
        }

        NoString sHost, sPass, sHint;
        bool bSSL = false;
        uint uServerPort = 0;

        if (sNetwork.equals("freenode")) {
            sHost = "chat.freenode.net";
#ifdef HAVE_LIBSSL
            bSSL = true;
#endif
        } else {
            sHint = "host only";
        }

        while (!No::getInput("Server host", sHost, sHost, sHint) || !NoServerInfo(sHost).isValid())
            ;
#ifdef HAVE_LIBSSL
        bSSL = No::getBoolInput("Server uses SSL?", bSSL);
#endif
        while (!No::getNumInput("Server port", uServerPort, 1, 65535, bSSL ? 6697 : 6667))
            ;
        No::getInput("Server password (probably empty)", sPass);

        vsLines.push_back("\t\tServer     = " + sHost + ((bSSL) ? " +" : " ") + NoString(uServerPort) + " " + sPass);

        NoString sChans;
        if (No::getInput("Initial channels", sChans)) {
            vsLines.push_back("");
            sChans.replace(",", " ");
            sChans.replace(";", " ");
            NoStringVector vsChans = sChans.split(" ", No::SkipEmptyParts);
            for (const NoString& sChan : vsChans) {
                vsLines.push_back("\t\t<Chan " + sChan.trim_n() + ">");
                vsLines.push_back("\t\t</Chan>");
            }
        }

        No::printMessage("Enabled network modules [" + NoString(", ").join(vsNetworkModNames.begin(), vsNetworkModNames.end()) + "]");

        vsLines.push_back("\t</Network>");
    }

    vsLines.push_back("</User>");

    No::printMessage("");
    // !User

    NoFile File;
    bool bFileOK, bFileOpen = false;
    do {
        No::printAction("Writing config [" + m_configFile + "]");

        bFileOK = true;
        if (NoFile::Exists(m_configFile)) {
            if (!File.TryExLock(m_configFile)) {
                No::printStatus(false, "ZNC is currently running on this config.");
                bFileOK = false;
            } else {
                File.Close();
                No::printStatus(false, "This config already exists.");
                if (No::getBoolInput("Are you sure you want to overwrite it?", false))
                    No::printAction("Overwriting config [" + m_configFile + "]");
                else
                    bFileOK = false;
            }
        }

        if (bFileOK) {
            File.SetFileName(m_configFile);
            if (File.Open(O_WRONLY | O_CREAT | O_TRUNC, 0600)) {
                bFileOpen = true;
            } else {
                No::printStatus(false, "Unable to open file");
                bFileOK = false;
            }
        }
        if (!bFileOK) {
            while (!No::getInput("Please specify an alternate location",
                                 m_configFile,
                                 "",
                                 "or \"stdout\" for "
                                 "displaying the config"))
                ;
            if (m_configFile.equals("stdout"))
                bFileOK = true;
            else
                m_configFile = expandConfigPath(m_configFile);
        }
    } while (!bFileOK);

    if (!bFileOpen) {
        No::printMessage("");
        No::printMessage("Printing the new config to stdout:");
        No::printMessage("");
        std::cout << std::endl << "----------------------------------------------------------------------------"
                  << std::endl << std::endl;
    }

    for (const NoString& sLine : vsLines) {
        if (bFileOpen) {
            File.Write(sLine + "\n");
        } else {
            std::cout << sLine << std::endl;
        }
    }

    if (bFileOpen) {
        File.Close();
        if (File.HadError())
            No::printStatus(false, "There was an error while writing the config");
        else
            No::printStatus(true);
    } else {
        std::cout << std::endl << "----------------------------------------------------------------------------"
                  << std::endl << std::endl;
    }

    if (File.HadError()) {
        bFileOpen = false;
        No::printMessage("Printing the new config to stdout instead:");
        std::cout << std::endl << "----------------------------------------------------------------------------"
                  << std::endl << std::endl;
        for (const NoString& sLine : vsLines) {
            std::cout << sLine << std::endl;
        }
        std::cout << std::endl << "----------------------------------------------------------------------------"
                  << std::endl << std::endl;
    }

    const NoString sProtocol(bListenSSL ? "https" : "http");
    const NoString sSSL(bListenSSL ? "+" : "");
    No::printMessage("");
    No::printMessage("To connect to this ZNC you need to connect to it as your IRC server", true);
    No::printMessage("using the port that you supplied.  You have to supply your login info", true);
    No::printMessage("as the IRC server password like this: user/network:pass.", true);
    No::printMessage("");
    No::printMessage("Try something like this in your IRC client...", true);
    No::printMessage("/server <znc_server_ip> " + sSSL + NoString(uListenPort) + " " + sUser + ":<pass>", true);
    No::printMessage("");
    No::printMessage("To manage settings, users and networks, point your web browser to", true);
    No::printMessage(sProtocol + "://<znc_server_ip>:" + NoString(uListenPort) + "/", true);
    No::printMessage("");

    File.UnLock();
    return bFileOpen && No::getBoolInput("Launch ZNC now?", true);
}

void NoApp::backupConfigOnce(const NoString& sSuffix)
{
    static bool didBackup = false;
    if (didBackup)
        return;
    didBackup = true;

    No::printAction("Creating a config backup");

    NoString sBackup = NoDir(m_configFile).filePath("../znc.conf." + sSuffix);
    if (NoFile::Copy(m_configFile, sBackup))
        No::printStatus(true, sBackup);
    else
        No::printStatus(false, strerror(errno));
}

bool NoApp::parseConfig(const NoString& sConfig, NoString& sError)
{
    m_configFile = expandConfigPath(sConfig, false);

    return doRehash(sError);
}

bool NoApp::rehashConfig(NoString& sError)
{
    ALLMODULECALL(onPreRehash(), NOTHING);

    // This clears m_msDelUsers
    handleUserDeletion();

    // Mark all users as going-to-be deleted
    m_delUsers = m_users;
    m_users.clear();

    if (doRehash(sError)) {
        ALLMODULECALL(onPostRehash(), NOTHING);

        return true;
    }

    // Rehashing failed, try to recover
    NoString s;
    while (!m_delUsers.empty()) {
        addUser(m_delUsers.begin()->second, s);
        m_delUsers.erase(m_delUsers.begin());
    }

    return false;
}

bool NoApp::doRehash(NoString& sError)
{
    sError.clear();

    No::printAction("Opening config [" + m_configFile + "]");

    if (!NoFile::Exists(m_configFile)) {
        sError = "No such file";
        No::printStatus(false, sError);
        No::printMessage("Restart ZNC with the --makeconf option if you wish to create this config.");
        return false;
    }

    if (!NoFile(m_configFile).IsReg()) {
        sError = "Not a file";
        No::printStatus(false, sError);
        return false;
    }

    NoFile* pFile = new NoFile(m_configFile);

    // need to open the config file Read/Write for fcntl()
    // exclusive locking to work properly!
    if (!pFile->Open(m_configFile, O_RDWR)) {
        sError = "Can not open config file";
        No::printStatus(false, sError);
        delete pFile;
        return false;
    }

    if (!pFile->TryExLock()) {
        sError = "ZNC is already running on this config.";
        No::printStatus(false, sError);
        delete pFile;
        return false;
    }

    // (re)open the config file
    delete m_lockFile;
    m_lockFile = pFile;
    NoFile& File = *pFile;

    NoSettings config;
    if (!config.Parse(File, sError)) {
        No::printStatus(false, sError);
        return false;
    }
    No::printStatus(true);

    NoString sSavedVersion;
    config.FindStringEntry("version", sSavedVersion);
    std::tuple<uint, uint> tSavedVersion =
    std::make_tuple(No::token(sSavedVersion, 0, ".").toUInt(), No::token(sSavedVersion, 1, ".").toUInt());
    std::tuple<uint, uint> tCurrentVersion = std::make_tuple(NO_VERSION_MAJOR, NO_VERSION_MINOR);
    if (tSavedVersion < tCurrentVersion) {
        if (sSavedVersion.empty()) {
            sSavedVersion = "< 0.203";
        }
        No::printMessage("Found old config from ZNC " + sSavedVersion + ". Saving a backup of it.");
        backupConfigOnce("pre-" + NoString(NO_VERSION_STR));
    } else if (tSavedVersion > tCurrentVersion) {
        No::printError("Config was saved from ZNC " + sSavedVersion + ". It may or may not work with current ZNC " + version());
    }

    m_bindHosts.clear();
    m_trustedProxies.clear();
    m_motd.clear();

    // Delete all listeners
    while (!m_listeners.empty()) {
        delete m_listeners[0];
        m_listeners.erase(m_listeners.begin());
    }

    NoStringMap msModules; // Modules are queued for later loading

    NoStringVector vsList;
    config.FindStringVector("loadmodule", vsList);
    for (const NoString& sModLine : vsList) {
        NoString sModName = No::token(sModLine, 0);
        NoString sArgs = No::tokens(sModLine, 1);

        if (sModName == "saslauth" && tSavedVersion < std::make_tuple(0, 207)) {
            // XXX compatibility crap, added in 0.207
            No::printMessage("saslauth module was renamed to cyrusauth. Loading cyrusauth instead.");
            sModName = "cyrusauth";
        }

        if (msModules.find(sModName) != msModules.end()) {
            sError = "Module [" + sModName + "] already loaded";
            No::printError(sError);
            return false;
        }
        NoString sModRet;
        NoModule* pOldMod;

        pOldMod = loader()->findModule(sModName);
        if (!pOldMod) {
            No::printAction("Loading global module [" + sModName + "]");

            bool bModRet = loader()->loadModule(sModName, sArgs, No::GlobalModule, nullptr, nullptr, sModRet);

            No::printStatus(bModRet, sModRet);
            if (!bModRet) {
                sError = sModRet;
                return false;
            }
        } else if (pOldMod->args() != sArgs) {
            No::printAction("Reloading global module [" + sModName + "]");

            bool bModRet = loader()->reloadModule(sModName, sArgs, nullptr, nullptr, sModRet);

            No::printStatus(bModRet, sModRet);
            if (!bModRet) {
                sError = sModRet;
                return false;
            }
        } else
            No::printMessage("Module [" + sModName + "] already loaded.");

        msModules[sModName] = sArgs;
    }

    NoString sISpoofFormat, sISpoofFile;
    config.FindStringEntry("ispoofformat", sISpoofFormat);
    config.FindStringEntry("ispooffile", sISpoofFile);
    if (!sISpoofFormat.empty() || !sISpoofFile.empty()) {
        NoModule* pIdentFileMod = loader()->findModule("identfile");
        if (!pIdentFileMod) {
            No::printAction("Loading global Module [identfile]");

            NoString sModRet;
            bool bModRet = loader()->loadModule("identfile", "", No::GlobalModule, nullptr, nullptr, sModRet);

            No::printStatus(bModRet, sModRet);
            if (!bModRet) {
                sError = sModRet;
                return false;
            }

            pIdentFileMod = loader()->findModule("identfile");
            msModules["identfile"] = "";
        }

        NoRegistry registry(pIdentFileMod);
        registry.setValue("File", sISpoofFile);
        registry.setValue("Format", sISpoofFormat);
    }

    config.FindStringVector("motd", vsList);
    for (const NoString& sMotd : vsList) {
        addMotd(sMotd);
    }

    config.FindStringVector("bindhost", vsList);
    for (const NoString& sHost : vsList) {
        addBindHost(sHost);
    }

    config.FindStringVector("trustedproxy", vsList);
    for (const NoString& sProxy : vsList) {
        addTrustedProxy(sProxy);
    }

    config.FindStringVector("vhost", vsList);
    for (const NoString& sHost : vsList) {
        addBindHost(sHost);
    }

    NoString sVal;
    if (config.FindStringEntry("pidfile", sVal))
        m_pidFile = sVal;
    if (config.FindStringEntry("statusprefix", sVal))
        m_statusPrefix = sVal;
    if (config.FindStringEntry("sslcertfile", sVal))
        m_sslCertFile = sVal;
    if (config.FindStringEntry("sslciphers", sVal))
        m_sslCiphers = sVal;
    if (config.FindStringEntry("skin", sVal))
        setSkinName(sVal);
    if (config.FindStringEntry("connectdelay", sVal))
        setConnectDelay(sVal.toUInt());
    if (config.FindStringEntry("serverthrottle", sVal))
        m_connectThrottle.setExpiration(sVal.toUInt() * 1000);
    if (config.FindStringEntry("anoniplimit", sVal))
        m_anonIpLimit = sVal.toUInt();
    if (config.FindStringEntry("maxbuffersize", sVal))
        m_maxBufferSize = sVal.toUInt();
    if (config.FindStringEntry("protectwebsessions", sVal))
        m_protectWebSessions = sVal.toBool();
    if (config.FindStringEntry("hideversion", sVal))
        m_hideVersion = sVal.toBool();

    if (config.FindStringEntry("sslprotocols", m_sslProtocols)) {
        NoStringVector vsProtocols = m_sslProtocols.split(" ", No::SkipEmptyParts);

        for (NoString& sProtocol : vsProtocols) {

            uint uFlag = 0;
            sProtocol.trim();
            bool bEnable = sProtocol.trimPrefix("+");
            bool bDisable = sProtocol.trimPrefix("-");

            if (sProtocol.equals("All")) {
                uFlag = ~0;
            } else if (sProtocol.equals("SSLv2")) {
                uFlag = Csock::EDP_SSLv2;
            } else if (sProtocol.equals("SSLv3")) {
                uFlag = Csock::EDP_SSLv3;
            } else if (sProtocol.equals("TLSv1")) {
                uFlag = Csock::EDP_TLSv1;
            } else if (sProtocol.equals("TLSv1.1")) {
                uFlag = Csock::EDP_TLSv1_1;
            } else if (sProtocol.equals("TLSv1.2")) {
                uFlag = Csock::EDP_TLSv1_2;
            } else {
                No::printError("Invalid SSLProtocols value [" + sProtocol + "]");
                No::printError("The syntax is [SSLProtocols = [+|-]<protocol> ...]");
                No::printError("Available protocols are [SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2]");
                return false;
            }

            if (bEnable) {
                m_disabledSslProtocols &= ~uFlag;
            } else if (bDisable) {
                m_disabledSslProtocols |= uFlag;
            } else {
                m_disabledSslProtocols = ~uFlag;
            }
        }
    }

    // This has to be after SSLCertFile is handled since it uses that value
    const char* szListenerEntries[] = { "listen", "listen6", "listen4", "listener", "listener6", "listener4" };

    for (const char* szEntry : szListenerEntries) {
        config.FindStringVector(szEntry, vsList);
        for (const NoString& sListener : vsList) {
            if (!addListener(szEntry + NoString(" ") + sListener, sError))
                return false;
        }
    }

    NoSettings::SubConfig subConf;
    NoSettings::SubConfig::const_iterator subIt;

    config.FindSubConfig("listener", subConf);
    for (subIt = subConf.begin(); subIt != subConf.end(); ++subIt) {
        NoSettings* pSubConf = subIt->second.m_subConfig;
        if (!addListener(pSubConf, sError))
            return false;
        if (!pSubConf->empty()) {
            sError = "Unhandled lines in Listener config!";
            No::printError(sError);

            NoApp::dumpConfig(pSubConf);
            return false;
        }
    }

    config.FindSubConfig("user", subConf);
    for (subIt = subConf.begin(); subIt != subConf.end(); ++subIt) {
        const NoString& sUserName = subIt->first;
        NoSettings* pSubConf = subIt->second.m_subConfig;
        NoUser* pRealUser = nullptr;

        No::printMessage("Loading user [" + sUserName + "]");

        // Either create a NoUser* or use an existing one
        std::map<NoString, NoUser*>::iterator it = m_delUsers.find(sUserName);

        if (it != m_delUsers.end()) {
            pRealUser = it->second;
            m_delUsers.erase(it);
        }

        NoUser* pUser = new NoUser(sUserName);

        if (!m_statusPrefix.empty()) {
            if (!pUser->setStatusPrefix(m_statusPrefix)) {
                sError = "Invalid StatusPrefix [" + m_statusPrefix + "] Must be 1-5 chars, no spaces.";
                No::printError(sError);
                return false;
            }
        }

        if (!pUser->parseConfig(pSubConf, sError)) {
            No::printError(sError);
            delete pUser;
            pUser = nullptr;
            return false;
        }

        if (!pSubConf->empty()) {
            sError = "Unhandled lines in config for User [" + sUserName + "]!";
            No::printError(sError);

            dumpConfig(pSubConf);
            return false;
        }

        NoString sErr;
        if (pRealUser) {
            if (!pRealUser->clone(*pUser, sErr) || !addUser(pRealUser, sErr)) {
                sError = "Invalid user [" + pUser->userName() + "] " + sErr;
                NO_DEBUG("NoUser::Clone() failed in rehash");
            }
            pUser->setBeingDeleted(true);
            delete pUser;
            pUser = nullptr;
        } else if (!addUser(pUser, sErr)) {
            sError = "Invalid user [" + pUser->userName() + "] " + sErr;
        }

        if (!sError.empty()) {
            No::printError(sError);
            if (pUser) {
                pUser->setBeingDeleted(true);
                delete pUser;
                pUser = nullptr;
            }
            return false;
        }

        pUser = nullptr;
        pRealUser = nullptr;
    }

    if (!config.empty()) {
        sError = "Unhandled lines in config!";
        No::printError(sError);

        dumpConfig(&config);
        return false;
    }


    // Unload modules which are no longer in the config
    std::set<NoString> ssUnload;
    for (NoModule* pCurMod : loader()->modules()) {
        if (msModules.find(pCurMod->moduleName()) == msModules.end())
            ssUnload.insert(pCurMod->moduleName());
    }

    for (const NoString& sMod : ssUnload) {
        if (loader()->unloadModule(sMod))
            No::printMessage("Unloaded global module [" + sMod + "]");
        else
            No::printMessage("Could not unload [" + sMod + "]");
    }

    if (m_users.empty()) {
        sError = "You must define at least one user in your config.";
        No::printError(sError);
        return false;
    }

    if (m_listeners.empty()) {
        sError = "You must supply at least one Listen port in your config.";
        No::printError(sError);
        return false;
    }

    return true;
}

void NoApp::dumpConfig(const NoSettings* pConfig)
{
    NoSettings::EntryMapIterator eit = pConfig->BeginEntries();
    for (; eit != pConfig->EndEntries(); ++eit) {
        const NoString& sKey = eit->first;
        const NoStringVector& vsList = eit->second;
        NoStringVector::const_iterator it = vsList.begin();
        for (; it != vsList.end(); ++it) {
            No::printError(sKey + " = " + *it);
        }
    }

    NoSettings::SubConfigMapIterator sit = pConfig->BeginSubConfigs();
    for (; sit != pConfig->EndSubConfigs(); ++sit) {
        const NoString& sKey = sit->first;
        const NoSettings::SubConfig& sSub = sit->second;
        NoSettings::SubConfig::const_iterator it = sSub.begin();

        for (; it != sSub.end(); ++it) {
            No::printError("SubConfig [" + sKey + " " + it->first + "]:");
            dumpConfig(it->second.m_subConfig);
        }
    }
}

void NoApp::clearBindHosts()
{
    m_bindHosts.clear();
}

bool NoApp::addBindHost(const NoString& sHost)
{
    if (sHost.empty()) {
        return false;
    }

    for (const NoString& sBindHost : m_bindHosts) {
        if (sBindHost.equals(sHost)) {
            return false;
        }
    }

    m_bindHosts.push_back(sHost);
    return true;
}

bool NoApp::removeBindHost(const NoString& sHost)
{
    NoStringVector::iterator it;
    for (it = m_bindHosts.begin(); it != m_bindHosts.end(); ++it) {
        if (sHost.equals(*it)) {
            m_bindHosts.erase(it);
            return true;
        }
    }

    return false;
}

void NoApp::clearTrustedProxies()
{
    m_trustedProxies.clear();
}

bool NoApp::addTrustedProxy(const NoString& sHost)
{
    if (sHost.empty()) {
        return false;
    }

    for (const NoString& sTrustedProxy : m_trustedProxies) {
        if (sTrustedProxy.equals(sHost)) {
            return false;
        }
    }

    m_trustedProxies.push_back(sHost);
    return true;
}

bool NoApp::removeTrustedProxy(const NoString& sHost)
{
    NoStringVector::iterator it;
    for (it = m_trustedProxies.begin(); it != m_trustedProxies.end(); ++it) {
        if (sHost.equals(*it)) {
            m_trustedProxies.erase(it);
            return true;
        }
    }

    return false;
}

void NoApp::broadcast(const NoString& sMessage, bool bAdminOnly, NoUser* pSkipUser, NoClient* pSkipClient)
{
    for (const auto& it : m_users) {
        if (bAdminOnly && !it.second->isAdmin())
            continue;

        if (it.second != pSkipUser) {
            NoString sMsg = sMessage;

            bool bContinue = false;
            USERMODULECALL(onBroadcast(sMsg), it.second, nullptr, &bContinue);
            if (bContinue)
                continue;

            it.second->putStatusNotice("*** " + sMsg, nullptr, pSkipClient);
        }
    }
}

void NoApp::addBytesRead(ulonglong u)
{
    m_bytesRead += u;
}

void NoApp::addBytesWritten(ulonglong u)
{
    m_bytesWritten += u;
}

ulonglong NoApp::bytesRead() const
{
    return m_bytesRead;
}

ulonglong NoApp::bytesWritten() const
{
    return m_bytesWritten;
}

NoModule* NoApp::findModule(const NoString& sModName, const NoString& sUsername)
{
    if (sUsername.empty()) {
        return NoApp::instance().loader()->findModule(sModName);
    }

    NoUser* pUser = findUser(sUsername);

    return (!pUser) ? nullptr : pUser->loader()->findModule(sModName);
}

NoModule* NoApp::findModule(const NoString& sModName, NoUser* pUser)
{
    if (pUser) {
        return pUser->loader()->findModule(sModName);
    }

    return NoApp::instance().loader()->findModule(sModName);
}

bool NoApp::updateModule(const NoString& sModule)
{
    NoModule* pModule;

    std::map<NoUser*, NoString> musLoaded;
    std::map<NoNetwork*, NoString> mnsLoaded;

    // Unload the module for every user and network
    for (const auto& it : m_users) {
        NoUser* pUser = it.second;

        pModule = pUser->loader()->findModule(sModule);
        if (pModule) {
            musLoaded[pUser] = pModule->args();
            pUser->loader()->unloadModule(sModule);
        }

        // See if the user has this module loaded to a network
        std::vector<NoNetwork*> vNetworks = pUser->networks();
        for (NoNetwork* pNetwork : vNetworks) {
            pModule = pNetwork->loader()->findModule(sModule);
            if (pModule) {
                mnsLoaded[pNetwork] = pModule->args();
                pNetwork->loader()->unloadModule(sModule);
            }
        }
    }

    // Unload the global module
    bool bGlobal = false;
    NoString sGlobalArgs;

    pModule = loader()->findModule(sModule);
    if (pModule) {
        bGlobal = true;
        sGlobalArgs = pModule->args();
        loader()->unloadModule(sModule);
    }

    // Lets reload everything
    bool bError = false;
    NoString sErr;

    // Reload the global module
    if (bGlobal) {
        if (!loader()->loadModule(sModule, sGlobalArgs, No::GlobalModule, nullptr, nullptr, sErr)) {
            NO_DEBUG("Failed to reload [" << sModule << "] globally [" << sErr << "]");
            bError = true;
        }
    }

    // Reload the module for all users
    for (const auto& it : musLoaded) {
        NoUser* pUser = it.first;
        const NoString& sArgs = it.second;

        if (!pUser->loader()->loadModule(sModule, sArgs, No::UserModule, pUser, nullptr, sErr)) {
            NO_DEBUG("Failed to reload [" << sModule << "] for [" << pUser->userName() << "] [" << sErr << "]");
            bError = true;
        }
    }

    // Reload the module for all networks
    for (const auto& it : mnsLoaded) {
        NoNetwork* pNetwork = it.first;
        const NoString& sArgs = it.second;

        if (!pNetwork->loader()->loadModule(sModule, sArgs, No::NetworkModule, pNetwork->user(), pNetwork, sErr)) {
            NO_DEBUG("Failed to reload [" << sModule << "] for [" << pNetwork->user()->userName() << "/"
                                          << pNetwork->name() << "] [" << sErr << "]");
            bError = true;
        }
    }

    return !bError;
}

NoUser* NoApp::findUser(const NoString& sUsername)
{
    std::map<NoString, NoUser*>::iterator it = m_users.find(sUsername);

    if (it != m_users.end()) {
        return it->second;
    }

    return nullptr;
}

bool NoApp::deleteUser(const NoString& sUsername)
{
    NoUser* pUser = findUser(sUsername);

    if (!pUser) {
        return false;
    }

    m_delUsers[pUser->userName()] = pUser;
    return true;
}

bool NoApp::addUser(NoUser* pUser, NoString& sErrorRet)
{
    if (findUser(pUser->userName()) != nullptr) {
        sErrorRet = "User already exists";
        NO_DEBUG("User [" << pUser->userName() << "] - already exists");
        return false;
    }
    if (!pUser->isValid(sErrorRet)) {
        NO_DEBUG("Invalid user [" << pUser->userName() << "] - [" << sErrorRet << "]");
        return false;
    }
    bool bFailed = false;
    GLOBALMODULECALL(onAddUser(*pUser, sErrorRet), &bFailed);
    if (bFailed) {
        NO_DEBUG("AddUser [" << pUser->userName() << "] aborted by a module [" << sErrorRet << "]");
        return false;
    }
    m_users[pUser->userName()] = pUser;
    return true;
}

std::map<NoString, NoUser*> NoApp::userMap() const
{
    return (m_users);
}

NoListener* NoApp::findListener(u_short uPort, const NoString& sHost, No::AddressType eAddr)
{
    for (NoListener* pListener : m_listeners) {
        if (pListener->port() != uPort)
            continue;
        if (pListener->host() != sHost)
            continue;
        if (pListener->addressType() != eAddr)
            continue;
        return pListener;
    }
    return nullptr;
}

bool NoApp::addListener(const NoString& sLine, NoString& sError)
{
    NoString sName = No::token(sLine, 0);
    NoString sValue = No::tokens(sLine, 1);

    No::AddressType eAddr = No::Ipv4AndIpv6Address;
    if (sName.equals("Listen4") || sName.equals("Listen") || sName.equals("Listener4")) {
        eAddr = No::Ipv4Address;
    }
    if (sName.equals("Listener6")) {
        eAddr = No::Ipv6Address;
    }

    No::AcceptType eAccept = No::AcceptAll;
    if (sValue.trimPrefix("irc_only "))
        eAccept = No::AcceptIrc;
    else if (sValue.trimPrefix("web_only "))
        eAccept = No::AcceptHttp;

    bool bSSL = false;
    NoString sPort;
    NoString sBindHost;

    if (No::Ipv4Address == eAddr) {
        sValue.replace(":", " ");
    }

    if (sValue.contains(" ")) {
        sBindHost = No::token(sValue, 0, " ");
        sPort = No::tokens(sValue, 1, " ");
    } else {
        sPort = sValue;
    }

    if (sPort.left(1) == "+") {
        sPort.leftChomp(1);
        bSSL = true;
    }

    // No support for URIPrefix for old-style configs.
    NoString sURIPrefix;
    ushort uPort = sPort.toUShort();
    return addListener(uPort, sBindHost, sURIPrefix, bSSL, eAddr, eAccept, sError);
}

bool NoApp::addListener(ushort uPort,
                        const NoString& sBindHost,
                        const NoString& sURIPrefixRaw,
                        bool bSSL,
                        No::AddressType eAddr,
                        No::AcceptType eAccept,
                        NoString& sError)
{
    NoString sHostComment;

    if (!sBindHost.empty()) {
        sHostComment = " on host [" + sBindHost + "]";
    }

    NoString sIPV6Comment;

    switch (eAddr) {
    case No::Ipv4AndIpv6Address:
        sIPV6Comment = "";
        break;
    case No::Ipv4Address:
        sIPV6Comment = " using ipv4";
        break;
    case No::Ipv6Address:
        sIPV6Comment = " using ipv6";
    }

    No::printAction("Binding to port [" + NoString((bSSL) ? "+" : "") + NoString(uPort) + "]" + sHostComment + sIPV6Comment);

#ifndef HAVE_IPV6
    if (ADDR_IPV6ONLY == eAddr) {
        sError = "IPV6 is not enabled";
        No::PrintStatus(false, sError);
        return false;
    }
#endif

#ifndef HAVE_LIBSSL
    if (bSSL) {
        sError = "SSL is not enabled";
        No::PrintStatus(false, sError);
        return false;
    }
#else
    NoString sPemFile = pemLocation();

    if (bSSL && !NoFile::Exists(sPemFile)) {
        sError = "Unable to locate pem file: [" + sPemFile + "]";
        No::printStatus(false, sError);

        // If stdin is e.g. /dev/null and we call GetBoolInput(),
        // we are stuck in an endless loop!
        if (isatty(0) && No::getBoolInput("Would you like to create a new pem file?", true)) {
            sError.clear();
            writePemFile();
        } else {
            return false;
        }

        No::printAction("Binding to port [+" + NoString(uPort) + "]" + sHostComment + sIPV6Comment);
    }
#endif
    if (!uPort) {
        sError = "Invalid port";
        No::printStatus(false, sError);
        return false;
    }

    // URIPrefix must start with a slash and end without one.
    NoString sURIPrefix = NoString(sURIPrefixRaw);
    if (!sURIPrefix.empty()) {
        if (!sURIPrefix.startsWith("/")) {
            sURIPrefix = "/" + sURIPrefix;
        }
        if (sURIPrefix.endsWith("/")) {
            sURIPrefix.trimRight("/");
        }
    }

    NoListener* pListener = new NoListener(sBindHost, uPort);
    pListener->setUriPrefix(sURIPrefix);
    pListener->setSsl(bSSL);
    pListener->setAddressType(eAddr);
    pListener->setAcceptType(eAccept);

    if (!pListener->listen()) {
        sError = FormatBindError();
        No::printStatus(false, sError);
        delete pListener;
        return false;
    }

    m_listeners.push_back(pListener);
    No::printStatus(true);

    return true;
}

bool NoApp::addListener(NoSettings* pConfig, NoString& sError)
{
    NoString sBindHost;
    NoString sURIPrefix;
    bool bSSL;
    bool b4;
#ifdef HAVE_IPV6
    bool b6 = true;
#else
    bool b6 = false;
#endif
    bool bIRC;
    bool bWeb;
    ushort uPort;
    if (!pConfig->FindUShortEntry("port", uPort)) {
        sError = "No port given";
        No::printError(sError);
        return false;
    }
    pConfig->FindStringEntry("host", sBindHost);
    pConfig->FindBoolEntry("ssl", bSSL, false);
    pConfig->FindBoolEntry("ipv4", b4, true);
    pConfig->FindBoolEntry("ipv6", b6, b6);
    pConfig->FindBoolEntry("allowirc", bIRC, true);
    pConfig->FindBoolEntry("allowweb", bWeb, true);
    pConfig->FindStringEntry("uriprefix", sURIPrefix);

    No::AddressType eAddr;
    if (b4 && b6) {
        eAddr = No::Ipv4AndIpv6Address;
    } else if (b4 && !b6) {
        eAddr = No::Ipv4Address;
    } else if (!b4 && b6) {
        eAddr = No::Ipv6Address;
    } else {
        sError = "No address family given";
        No::printError(sError);
        return false;
    }

    No::AcceptType eAccept;
    if (bIRC && bWeb) {
        eAccept = No::AcceptAll;
    } else if (bIRC && !bWeb) {
        eAccept = No::AcceptIrc;
    } else if (!bIRC && bWeb) {
        eAccept = No::AcceptHttp;
    } else {
        sError = "Either Web or IRC or both should be selected";
        No::printError(sError);
        return false;
    }

    return addListener(uPort, sBindHost, sURIPrefix, bSSL, eAddr, eAccept, sError);
}

bool NoApp::addListener(NoListener* pListener)
{
    if (!pListener->socket()) {
        // Listener doesnt actually listen
        delete pListener;
        return false;
    }

    // We don't check if there is an identical listener already listening
    // since one can't listen on e.g. the same port multiple times

    m_listeners.push_back(pListener);
    return true;
}

bool NoApp::removeListener(NoListener* pListener)
{
    auto it = std::find(m_listeners.begin(), m_listeners.end(), pListener);
    if (it != m_listeners.end()) {
        m_listeners.erase(it);
        delete pListener;
        return true;
    }

    return false;
}

void NoApp::setMotd(const NoString& sMessage)
{
    clearMotd();
    addMotd(sMessage);
}

void NoApp::addMotd(const NoString& sMessage)
{
    if (!sMessage.empty()) {
        m_motd.push_back(sMessage);
    }
}

void NoApp::clearMotd()
{
    m_motd.clear();
}

NoStringVector NoApp::motd() const
{
    return m_motd;
}

void NoApp::addServerThrottle(NoString sName)
{
    m_connectThrottle.insert(sName, true);
}

bool NoApp::serverThrottle(NoString sName)
{
    return m_connectThrottle.value(sName);
}

static NoApp* s_pZNC = nullptr;

void NoApp::createInstance()
{
    if (s_pZNC)
        abort();

    s_pZNC = new NoApp();
}

NoApp& NoApp::instance()
{
    return *s_pZNC;
}

void NoApp::destroyInstance()
{
    delete s_pZNC;
    s_pZNC = nullptr;
}

NoApp::TrafficStatsMap NoApp::trafficStats(TrafficStatsPair& Users, TrafficStatsPair& ZNC, TrafficStatsPair& Total)
{
    TrafficStatsMap ret;
    ulonglong uiUsers_in, uiUsers_out, uiZNC_in, uiZNC_out;
    const std::map<NoString, NoUser*>& msUsers = NoApp::instance().userMap();

    uiUsers_in = uiUsers_out = 0;
    uiZNC_in = bytesRead();
    uiZNC_out = bytesWritten();

    for (const auto& it : msUsers) {
        ret[it.first] = TrafficStatsPair(it.second->bytesRead(), it.second->bytesWritten());
        uiUsers_in += it.second->bytesRead();
        uiUsers_out += it.second->bytesWritten();
    }

    for (NoSocket* pSock : m_manager.sockets()) {
        NoUser* pUser = nullptr;
        if (pSock->name().left(5) == "IRC::") {
            pUser = ((NoIrcSocket*)pSock)->network()->user();
        } else if (pSock->name().left(5) == "USR::") {
            pUser = ((NoClient*)pSock)->user();
        }

        if (pUser) {
            ret[pUser->userName()].first += pSock->bytesRead();
            ret[pUser->userName()].second += pSock->bytesWritten();
            uiUsers_in += pSock->bytesRead();
            uiUsers_out += pSock->bytesWritten();
        } else {
            uiZNC_in += pSock->bytesRead();
            uiZNC_out += pSock->bytesWritten();
        }
    }

    Users = TrafficStatsPair(uiUsers_in, uiUsers_out);
    ZNC = TrafficStatsPair(uiZNC_in, uiZNC_out);
    Total = TrafficStatsPair(uiUsers_in + uiZNC_in, uiUsers_out + uiZNC_out);

    return ret;
}

void NoApp::authUser(std::shared_ptr<NoAuthenticator> AuthClass)
{
    // TODO unless the auth module calls it, NoUser::IsHostAllowed() is not honoured
    bool bReturn = false;
    GLOBALMODULECALL(onLoginAttempt(AuthClass), &bReturn);
    if (bReturn)
        return;

    NoUser* pUser = findUser(AuthClass->username());

    if (!pUser || !pUser->checkPass(AuthClass->password())) {
        AuthClass->refuseLogin("Invalid Password");
        return;
    }

    NoString sHost;
    NoSocket* pSock = AuthClass->socket();
    if (pSock)
        sHost = pSock->remoteAddress();

    if (!pUser->isHostAllowed(sHost)) {
        AuthClass->refuseLogin("Your host [" + sHost + "] is not allowed");
        return;
    }

    AuthClass->acceptLogin(pUser);
}

void NoApp::setConfigState(NoApp::ConfigState e)
{
    m_configState = e;
}

void NoApp::setSkinName(const NoString& s)
{
    m_skinName = s;
}

void NoApp::setStatusPrefix(const NoString& s)
{
    m_statusPrefix = (s.empty()) ? "*" : s;
}

void NoApp::setMaxBufferSize(uint i)
{
    m_maxBufferSize = i;
}

void NoApp::setAnonIpLimit(uint i)
{
    m_anonIpLimit = i;
}

void NoApp::setServerThrottle(uint i)
{
    m_connectThrottle.setExpiration(i * 1000);
}

void NoApp::setProtectWebSessions(bool b)
{
    m_protectWebSessions = b;
}

void NoApp::setHideVersion(bool b)
{
    m_hideVersion = b;
}

class NoConnectQueueTimer : public CCron
{
public:
    NoConnectQueueTimer(int iSecs) : CCron()
    {
        SetName("Connect users");
        Start(iSecs);
        // Don't wait iSecs seconds for first timer run
        m_bRunOnNextCall = true;
    }
    virtual ~NoConnectQueueTimer()
    {
        // This is only needed when ZNC shuts down:
        // NoApp::~NoApp() sets its NoConnectQueueTimer pointer to nullptr and
        // calls the manager's Cleanup() which destroys all sockets and
        // timers. If something calls NoApp::EnableConnectQueue() here
        // (e.g. because a NoIrcSock is destroyed), the socket manager
        // deletes that timer almost immediately, but NoApp now got a
        // dangling pointer to this timer which can crash later on.
        //
        // Unlikely but possible ;)
        NoApp::instance().leakConnectQueueTimer(this);
    }

protected:
    void RunJob() override
    {
        std::list<NoNetwork*> ConnectionQueue;
        std::list<NoNetwork*>& RealConnectionQueue = NoApp::instance().connectionQueue();

        // Problem: If a network can't connect right now because e.g. it
        // is throttled, it will re-insert itself into the connection
        // queue. However, we must only give each network a single
        // chance during this timer run.
        //
        // Solution: We move the connection queue to our local list at
        // the beginning and work from that.
        ConnectionQueue.swap(RealConnectionQueue);

        while (!ConnectionQueue.empty()) {
            NoNetwork* pNetwork = ConnectionQueue.front();
            ConnectionQueue.pop_front();

            if (pNetwork->connect()) {
                break;
            }
        }

        /* Now re-insert anything that is left in our local list into
         * the real connection queue.
         */
        RealConnectionQueue.splice(RealConnectionQueue.begin(), ConnectionQueue);

        if (RealConnectionQueue.empty()) {
            NO_DEBUG("ConnectQueueTimer done");
            NoApp::instance().disableConnectQueue();
        }
    }
};

void NoApp::setConnectDelay(uint i)
{
    if (i < 1) {
        // Don't hammer server with our failed connects
        i = 1;
    }
    if (m_connectDelay != i && m_connectQueueTimer != nullptr) {
        m_connectQueueTimer->Start(i);
    }
    m_connectDelay = i;
}

NoApp::ConfigState NoApp::configState() const
{
    return m_configState;
}

NoSocketManager& NoApp::manager()
{
    return m_manager;
}

const NoSocketManager& NoApp::manager() const
{
    return m_manager;
}

NoModuleLoader* NoApp::loader() const
{
    return m_modules;
}

NoString NoApp::skinName() const
{
    return m_skinName;
}

NoString NoApp::statusPrefix() const
{
    return m_statusPrefix;
}

void NoApp::enableConnectQueue()
{
    if (!m_connectQueueTimer && !m_connectPaused && !m_connectQueue.empty()) {
        m_connectQueueTimer = new NoConnectQueueTimer(m_connectDelay);
        manager().addCron(m_connectQueueTimer);
    }
}

void NoApp::disableConnectQueue()
{
    if (m_connectQueueTimer) {
        // This will kill the cron
        m_connectQueueTimer->Stop();
        m_connectQueueTimer = nullptr;
    }
}

void NoApp::pauseConnectQueue()
{
    NO_DEBUG("Connection queue paused");
    m_connectPaused++;

    if (m_connectQueueTimer) {
        m_connectQueueTimer->Pause();
    }
}

void NoApp::resumeConnectQueue()
{
    NO_DEBUG("Connection queue resumed");
    m_connectPaused--;

    enableConnectQueue();
    if (m_connectQueueTimer) {
        m_connectQueueTimer->UnPause();
    }
}

void NoApp::addNetworkToQueue(NoNetwork* pNetwork)
{
    // Make sure we are not already in the queue
    if (std::find(m_connectQueue.begin(), m_connectQueue.end(), pNetwork) != m_connectQueue.end()) {
        return;
    }

    m_connectQueue.push_back(pNetwork);
    enableConnectQueue();
}

std::list<NoNetwork*>& NoApp::connectionQueue()
{
    return m_connectQueue;
}

void NoApp::leakConnectQueueTimer(NoConnectQueueTimer* pTimer)
{
    if (m_connectQueueTimer == pTimer)
        m_connectQueueTimer = nullptr;
}

bool NoApp::waitForChildLock()
{
    return m_lockFile && m_lockFile->ExLock();
}
