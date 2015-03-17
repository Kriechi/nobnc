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

#include "noapp.h"
#include "nodir.h"
#include "nofile.h"
#include "noircsock.h"
#include "noserver.h"
#include "nouser.h"
#include "nonetwork.h"
#include "nosettings.h"
#include <tuple>
#include <algorithm>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#endif /* HAVE_LIBSSL */

static inline NoString FormatBindError()
{
    NoString sError = (errno == 0 ? NoString("unknown error, check the host name") : NoString(strerror(errno)));
    return "Unable to bind [" + sError + "]";
}

NoApp::NoApp()
    : m_TimeStarted(time(nullptr)), m_eConfigState(ECONFIG_NOTHING), m_vpListeners(), m_msUsers(), m_msDelUsers(),
      m_Manager(), m_sCurPath(""), m_sZNCPath(""), m_sConfigFile(""), m_sSkinName(""), m_sStatusPrefix(""),
      m_sPidFile(""), m_sSSLCertFile(""), m_sSSLCiphers(""), m_sSSLProtocols(""), m_vsBindHosts(), m_vsTrustedProxies(),
      m_vsMotd(), m_pLockFile(nullptr), m_uiConnectDelay(5), m_uiAnonIPLimit(10), m_uiMaxBufferSize(500),
      m_uDisabledSSLProtocols(Csock::EDP_SSL), m_pModules(new NoModules), m_uBytesRead(0), m_uBytesWritten(0),
      m_lpConnectQueue(), m_pConnectQueueTimer(nullptr), m_uiConnectPaused(0), m_sConnectThrottle(),
      m_bProtectWebSessions(true), m_bHideVersion(false)
{
    if (!InitCsocket()) {
        NoUtils::PrintError("Could not initialize Csocket!");
        exit(-1);
    }
    m_sConnectThrottle.SetTTL(30000);
}

NoApp::~NoApp()
{
    m_pModules->UnloadAll();

    for (const auto& it : m_msUsers) {
        it.second->GetModules().UnloadAll();

        const std::vector<NoNetwork*>& networks = it.second->GetNetworks();
        for (NoNetwork* pNetwork : networks) {
            pNetwork->GetModules().UnloadAll();
        }
    }

    for (NoListener* pListener : m_vpListeners) {
        delete pListener;
    }

    for (const auto& it : m_msUsers) {
        it.second->SetBeingDeleted(true);
    }

    m_pConnectQueueTimer = nullptr;
    // This deletes m_pConnectQueueTimer
    m_Manager.Cleanup();
    DeleteUsers();

    delete m_pModules;
    delete m_pLockFile;

    ShutdownCsocket();
    DeletePidFile();
}

NoString NoApp::GetVersion() { return NoString(NO_VERSION_STR) + NoString(NO_VERSION_EXTRA); }

NoString NoApp::GetTag(bool bIncludeVersion, bool bHTML)
{
    if (!Get().m_bHideVersion) {
        bIncludeVersion = true;
    }
    NoString sAddress = bHTML ? "<a href=\"http://znc.in\">http://znc.in</a>" : "http://znc.in";

    if (!bIncludeVersion) {
        return "ZNC - " + sAddress;
    }

    NoString sVersion = GetVersion();

    return "ZNC - " + sVersion + " - " + sAddress;
}

NoString NoApp::GetCompileOptionsString()
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

NoString NoApp::GetUptime() const
{
    time_t now = time(nullptr);
    return NoString::ToTimeStr(now - TimeStarted());
}

bool NoApp::OnBoot()
{
    bool bFail = false;
    ALLMODULECALL(OnBoot(), &bFail);
    if (bFail) return false;

    return true;
}

bool NoApp::HandleUserDeletion()
{
    if (m_msDelUsers.empty()) return false;

    for (const auto& it : m_msDelUsers) {
        NoUser* pUser = it.second;
        pUser->SetBeingDeleted(true);

        if (GetModules().OnDeleteUser(*pUser)) {
            pUser->SetBeingDeleted(false);
            continue;
        }
        m_msUsers.erase(pUser->GetUserName());
        NoWebSock::FinishUserSessions(*pUser);
        delete pUser;
    }

    m_msDelUsers.clear();

    return true;
}

void NoApp::Loop()
{
    while (true) {
        NoString sError;

        ConfigState eState = GetConfigState();
        switch (eState) {
        case ECONFIG_NEED_REHASH:
            SetConfigState(ECONFIG_NOTHING);

            if (RehashConfig(sError)) {
                Broadcast("Rehashing succeeded", true);
            } else {
                Broadcast("Rehashing failed: " + sError, true);
                Broadcast("ZNC is in some possibly inconsistent state!", true);
            }
            break;
        case ECONFIG_NEED_WRITE:
        case ECONFIG_NEED_VERBOSE_WRITE:
            SetConfigState(ECONFIG_NOTHING);

            if (!WriteConfig()) {
                Broadcast("Writing the config file failed", true);
            } else if (eState == ECONFIG_NEED_VERBOSE_WRITE) {
                Broadcast("Writing the config succeeded", true);
            }
            break;
        case ECONFIG_NOTHING:
            break;
        }

        // Check for users that need to be deleted
        if (HandleUserDeletion()) {
            // Also remove those user(s) from the config file
            WriteConfig();
        }

        // Csocket wants micro seconds
        // 100 msec to 600 sec
        m_Manager.DynamicSelectLoop(100 * 1000, 600 * 1000 * 1000);
    }
}

NoFile* NoApp::InitPidFile()
{
    if (!m_sPidFile.empty()) {
        NoString sFile;

        // absolute path or relative to the data dir?
        if (m_sPidFile[0] != '/')
            sFile = GetZNCPath() + "/" + m_sPidFile;
        else
            sFile = m_sPidFile;

        return new NoFile(sFile);
    }

    return nullptr;
}

bool NoApp::WritePidFile(int iPid)
{
    NoFile* File = InitPidFile();
    if (File == nullptr) return false;

    NoUtils::PrintAction("Writing pid file [" + File->GetLongName() + "]");

    bool bRet = false;
    if (File->Open(O_WRONLY | O_TRUNC | O_CREAT)) {
        File->Write(NoString(iPid) + "\n");
        File->Close();
        bRet = true;
    }

    delete File;
    NoUtils::PrintStatus(bRet);
    return bRet;
}

bool NoApp::DeletePidFile()
{
    NoFile* File = InitPidFile();
    if (File == nullptr) return false;

    NoUtils::PrintAction("Deleting pid file [" + File->GetLongName() + "]");

    bool bRet = File->Delete();

    delete File;
    NoUtils::PrintStatus(bRet);
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
#endif /* HAVE_LIBSSL */

bool NoApp::WritePemFile()
{
#ifndef HAVE_LIBSSL
    NoUtils::PrintError("ZNC was not compiled with ssl support.");
    return false;
#else
    NoString sPemFile = GetPemLocation();

    NoUtils::PrintAction("Writing Pem file [" + sPemFile + "]");
#ifndef _WIN32
    int fd = creat(sPemFile.c_str(), 0600);
    if (fd == -1) {
        NoUtils::PrintStatus(false, "Unable to open");
        return false;
    }
    FILE* f = fdopen(fd, "w");
#else
    FILE* f = fopen(sPemFile.c_str(), "w");
#endif

    if (!f) {
        NoUtils::PrintStatus(false, "Unable to open");
        return false;
    }

#ifdef HAVE_LIBSSL
    GenerateCert(f, "");
#endif
    fclose(f);

    NoUtils::PrintStatus(true);
    return true;
#endif
}

void NoApp::DeleteUsers()
{
    for (const auto& it : m_msUsers) {
        it.second->SetBeingDeleted(true);
        delete it.second;
    }

    m_msUsers.clear();
    DisableConnectQueue();
}

bool NoApp::IsHostAllowed(const NoString& sHostMask) const
{
    for (const auto& it : m_msUsers) {
        if (it.second->IsHostAllowed(sHostMask)) {
            return true;
        }
    }

    return false;
}

bool NoApp::AllowConnectionFrom(const NoString& sIP) const
{
    if (m_uiAnonIPLimit == 0) return true;
    return (GetManager().GetAnonConnectionCount(sIP) < m_uiAnonIPLimit);
}

void NoApp::InitDirs(const NoString& sArgvPath, const NoString& sDataDir)
{
    // If the bin was not ran from the current directory, we need to add that dir onto our cwd
    NoString::size_type uPos = sArgvPath.rfind('/');
    if (uPos == NoString::npos)
        m_sCurPath = "./";
    else
        m_sCurPath = NoDir::ChangeDir("./", sArgvPath.Left(uPos), "");

    // Try to set the user's home dir, default to binpath on failure
    NoFile::InitHomePath(m_sCurPath);

    if (sDataDir.empty()) {
        m_sZNCPath = NoFile::GetHomePath() + "/.znc";
    } else {
        m_sZNCPath = sDataDir;
    }

    m_sSSLCertFile = m_sZNCPath + "/znc.pem";
}

NoString NoApp::GetConfPath(bool bAllowMkDir) const
{
    NoString sConfPath = m_sZNCPath + "/configs";
    if (bAllowMkDir && !NoFile::Exists(sConfPath)) {
        NoDir::MakeDir(sConfPath);
    }

    return sConfPath;
}

NoString NoApp::GetUserPath() const
{
    NoString sUserPath = m_sZNCPath + "/users";
    if (!NoFile::Exists(sUserPath)) {
        NoDir::MakeDir(sUserPath);
    }

    return sUserPath;
}

NoString NoApp::GetModPath() const
{
    NoString sModPath = m_sZNCPath + "/modules";

    return sModPath;
}

const NoString& NoApp::GetCurPath() const
{
    if (!NoFile::Exists(m_sCurPath)) {
        NoDir::MakeDir(m_sCurPath);
    }
    return m_sCurPath;
}

const NoString& NoApp::GetHomePath() const { return NoFile::GetHomePath(); }

const NoString& NoApp::GetZNCPath() const
{
    if (!NoFile::Exists(m_sZNCPath)) {
        NoDir::MakeDir(m_sZNCPath);
    }
    return m_sZNCPath;
}

NoString NoApp::GetPemLocation() const { return NoDir::ChangeDir("", m_sSSLCertFile); }

NoString NoApp::ExpandConfigPath(const NoString& sConfigFile, bool bAllowMkDir)
{
    NoString sRetPath;

    if (sConfigFile.empty()) {
        sRetPath = GetConfPath(bAllowMkDir) + "/znc.conf";
    } else {
        if (sConfigFile.Left(2) == "./" || sConfigFile.Left(3) == "../") {
            sRetPath = GetCurPath() + "/" + sConfigFile;
        } else if (sConfigFile.Left(1) != "/") {
            sRetPath = GetConfPath(bAllowMkDir) + "/" + sConfigFile;
        } else {
            sRetPath = sConfigFile;
        }
    }

    return sRetPath;
}

bool NoApp::WriteConfig()
{
    if (GetConfigFile().empty()) {
        DEBUG("Config file name is empty?!");
        return false;
    }

    // We first write to a temporary file and then move it to the right place
    NoFile* pFile = new NoFile(GetConfigFile() + "~");

    if (!pFile->Open(O_WRONLY | O_CREAT | O_TRUNC, 0600)) {
        DEBUG("Could not write config to " + GetConfigFile() + "~: " + NoString(strerror(errno)));
        delete pFile;
        return false;
    }

    // We have to "transfer" our lock on the config to the new file.
    // The old file (= inode) is going away and thus a lock on it would be
    // useless. These lock should always succeed (races, anyone?).
    if (!pFile->TryExLock()) {
        DEBUG("Error while locking the new config file, errno says: " + NoString(strerror(errno)));
        pFile->Delete();
        delete pFile;
        return false;
    }

    pFile->Write(MakeConfigHeader() + "\n");

    NoSettings config;
    config.AddKeyValuePair("AnonIPLimit", NoString(m_uiAnonIPLimit));
    config.AddKeyValuePair("MaxBufferSize", NoString(m_uiMaxBufferSize));
    config.AddKeyValuePair("SSLCertFile", NoString(m_sSSLCertFile));
    config.AddKeyValuePair("ProtectWebSessions", NoString(m_bProtectWebSessions));
    config.AddKeyValuePair("HideVersion", NoString(m_bHideVersion));
    config.AddKeyValuePair("Version", NoString(NO_VERSION_STR));

    uint l = 0;
    for (NoListener* pListener : m_vpListeners) {
        NoSettings listenerConfig;

        listenerConfig.AddKeyValuePair("Host", pListener->GetBindHost());
        listenerConfig.AddKeyValuePair("URIPrefix", pListener->GetURIPrefix() + "/");
        listenerConfig.AddKeyValuePair("Port", NoString(pListener->GetPort()));

        listenerConfig.AddKeyValuePair("IPv4", NoString(pListener->GetAddrType() != ADDR_IPV6ONLY));
        listenerConfig.AddKeyValuePair("IPv6", NoString(pListener->GetAddrType() != ADDR_IPV4ONLY));

        listenerConfig.AddKeyValuePair("SSL", NoString(pListener->IsSSL()));

        listenerConfig.AddKeyValuePair("AllowIRC", NoString(pListener->GetAcceptType() != NoListener::ACCEPT_HTTP));
        listenerConfig.AddKeyValuePair("AllowWeb", NoString(pListener->GetAcceptType() != NoListener::ACCEPT_IRC));

        config.AddSubConfig("Listener", "listener" + NoString(l++), listenerConfig);
    }

    config.AddKeyValuePair("ConnectDelay", NoString(m_uiConnectDelay));
    config.AddKeyValuePair("ServerThrottle", NoString(m_sConnectThrottle.GetTTL() / 1000));

    if (!m_sPidFile.empty()) {
        config.AddKeyValuePair("PidFile", m_sPidFile.FirstLine());
    }

    if (!m_sSkinName.empty()) {
        config.AddKeyValuePair("Skin", m_sSkinName.FirstLine());
    }

    if (!m_sStatusPrefix.empty()) {
        config.AddKeyValuePair("StatusPrefix", m_sStatusPrefix.FirstLine());
    }

    if (!m_sSSLCiphers.empty()) {
        config.AddKeyValuePair("SSLCiphers", NoString(m_sSSLCiphers));
    }

    if (!m_sSSLProtocols.empty()) {
        config.AddKeyValuePair("SSLProtocols", m_sSSLProtocols);
    }

    for (const NoString& sLine : m_vsMotd) {
        config.AddKeyValuePair("Motd", sLine.FirstLine());
    }

    for (const NoString& sHost : m_vsBindHosts) {
        config.AddKeyValuePair("BindHost", sHost.FirstLine());
    }

    for (const NoString& sProxy : m_vsTrustedProxies) {
        config.AddKeyValuePair("TrustedProxy", sProxy.FirstLine());
    }

    NoModules& Mods = GetModules();

    for (const NoModule* pMod : Mods) {
        NoString sName = pMod->GetModName();
        NoString sArgs = pMod->GetArgs();

        if (!sArgs.empty()) {
            sArgs = " " + sArgs.FirstLine();
        }

        config.AddKeyValuePair("LoadModule", sName.FirstLine() + sArgs);
    }

    for (const auto& it : m_msUsers) {
        NoString sErr;

        if (!it.second->IsValid(sErr)) {
            DEBUG("** Error writing config for user [" << it.first << "] [" << sErr << "]");
            continue;
        }

        config.AddSubConfig("User", it.second->GetUserName(), it.second->ToConfig());
    }

    config.Write(*pFile);

    // If Sync() fails... well, let's hope nothing important breaks..
    pFile->Sync();

    if (pFile->HadError()) {
        DEBUG("Error while writing the config, errno says: " + NoString(strerror(errno)));
        pFile->Delete();
        delete pFile;
        return false;
    }

    // We wrote to a temporary name, move it to the right place
    if (!pFile->Move(GetConfigFile(), true)) {
        DEBUG("Error while replacing the config file with a new version, errno says " << strerror(errno));
        pFile->Delete();
        delete pFile;
        return false;
    }

    // Everything went fine, just need to update the saved path.
    pFile->SetFileName(GetConfigFile());

    // Make sure the lock is kept alive as long as we need it.
    delete m_pLockFile;
    m_pLockFile = pFile;

    return true;
}

NoString NoApp::MakeConfigHeader()
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

bool NoApp::WriteNewConfig(const NoString& sConfigFile)
{
    NoString sAnswer, sUser, sNetwork;
    NoStringVector vsLines;

    vsLines.push_back(MakeConfigHeader());
    vsLines.push_back("Version = " + NoString(NO_VERSION_STR));

    m_sConfigFile = ExpandConfigPath(sConfigFile);

    if (NoFile::Exists(m_sConfigFile)) {
        NoUtils::PrintStatus(false, "WARNING: config [" + m_sConfigFile + "] already exists.");
    }

    NoUtils::PrintMessage("");
    NoUtils::PrintMessage("-- Global settings --");
    NoUtils::PrintMessage("");

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
            if (!NoUtils::GetNumInput("Listen on port", uListenPort, 1025, 65534)) {
                continue;
            }
            if (uListenPort == 6667) {
                NoUtils::PrintStatus(false, "WARNING: Some web browsers reject port 6667. If you intend to");
                NoUtils::PrintStatus(false, "use ZNC's web interface, you might want to use another port.");
                if (!NoUtils::GetBoolInput("Proceed with port 6667 anyway?", true)) {
                    continue;
                }
            }
            break;
        }


#ifdef HAVE_LIBSSL
        bListenSSL = NoUtils::GetBoolInput("Listen using SSL", bListenSSL);
#endif

#ifdef HAVE_IPV6
        b6 = NoUtils::GetBoolInput("Listen using both IPv4 and IPv6", b6);
#endif

        // Don't ask for listen host, it may be configured later if needed.

        NoUtils::PrintAction("Verifying the listener");
        NoListener* pListener =
        new NoListener((ushort)uListenPort, sListenHost, sURIPrefix, bListenSSL, b6 ? ADDR_ALL : ADDR_IPV4ONLY, NoListener::ACCEPT_ALL);
        if (!pListener->Listen()) {
            NoUtils::PrintStatus(false, FormatBindError());
            bSuccess = false;
        } else
            NoUtils::PrintStatus(true);
        delete pListener;
    } while (!bSuccess);

#ifdef HAVE_LIBSSL
    NoString sPemFile = GetPemLocation();
    if (!NoFile::Exists(sPemFile)) {
        NoUtils::PrintMessage("Unable to locate pem file: [" + sPemFile + "], creating it");
        WritePemFile();
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

    std::set<NoModInfo> ssGlobalMods;
    GetModules().GetDefaultMods(ssGlobalMods, NoModInfo::GlobalModule);
    std::vector<NoString> vsGlobalModNames;
    for (const NoModInfo& Info : ssGlobalMods) {
        vsGlobalModNames.push_back(Info.GetName());
        vsLines.push_back("LoadModule = " + Info.GetName());
    }
    NoUtils::PrintMessage("Enabled global modules [" + NoString(", ").Join(vsGlobalModNames.begin(), vsGlobalModNames.end()) + "]");

    // User
    NoUtils::PrintMessage("");
    NoUtils::PrintMessage("-- Admin user settings --");
    NoUtils::PrintMessage("");

    vsLines.push_back("");
    NoString sNick;
    do {
        NoUtils::GetInput("Username", sUser, "", "alphanumeric");
    } while (!NoUser::IsValidUserName(sUser));

    vsLines.push_back("<User " + sUser + ">");
    NoString sSalt;
    sAnswer = NoUtils::GetSaltedHashPass(sSalt);
    vsLines.push_back("\tPass       = " + NoUtils::sDefaultHash + "#" + sAnswer + "#" + sSalt + "#");

    vsLines.push_back("\tAdmin      = true");

    NoUtils::GetInput("Nick", sNick, NoUser::MakeCleanUserName(sUser));
    vsLines.push_back("\tNick       = " + sNick);
    NoUtils::GetInput("Alternate nick", sAnswer, sNick + "_");
    if (!sAnswer.empty()) {
        vsLines.push_back("\tAltNick    = " + sAnswer);
    }
    NoUtils::GetInput("Ident", sAnswer, sUser);
    vsLines.push_back("\tIdent      = " + sAnswer);
    NoUtils::GetInput("Real name", sAnswer, "Got ZNC?");
    vsLines.push_back("\tRealName   = " + sAnswer);
    NoUtils::GetInput("Bind host", sAnswer, "", "optional");
    if (!sAnswer.empty()) {
        vsLines.push_back("\tBindHost   = " + sAnswer);
    }

    std::set<NoModInfo> ssUserMods;
    GetModules().GetDefaultMods(ssUserMods, NoModInfo::UserModule);
    std::vector<NoString> vsUserModNames;
    for (const NoModInfo& Info : ssUserMods) {
        vsUserModNames.push_back(Info.GetName());
        vsLines.push_back("\tLoadModule = " + Info.GetName());
    }
    NoUtils::PrintMessage("Enabled user modules [" + NoString(", ").Join(vsUserModNames.begin(), vsUserModNames.end()) + "]");

    NoUtils::PrintMessage("");
    if (NoUtils::GetBoolInput("Set up a network?", true)) {
        vsLines.push_back("");

        NoUtils::PrintMessage("");
        NoUtils::PrintMessage("-- Network settings --");
        NoUtils::PrintMessage("");

        do {
            NoUtils::GetInput("Name", sNetwork, "freenode");
        } while (!NoNetwork::IsValidNetwork(sNetwork));

        vsLines.push_back("\t<Network " + sNetwork + ">");

        std::set<NoModInfo> ssNetworkMods;
        GetModules().GetDefaultMods(ssNetworkMods, NoModInfo::NetworkModule);
        std::vector<NoString> vsNetworkModNames;
        for (const NoModInfo& Info : ssNetworkMods) {
            vsNetworkModNames.push_back(Info.GetName());
            vsLines.push_back("\t\tLoadModule = " + Info.GetName());
        }

        NoString sHost, sPass, sHint;
        bool bSSL = false;
        uint uServerPort = 0;

        if (sNetwork.Equals("freenode")) {
            sHost = "chat.freenode.net";
#ifdef HAVE_LIBSSL
            bSSL = true;
#endif
        } else {
            sHint = "host only";
        }

        while (!NoUtils::GetInput("Server host", sHost, sHost, sHint) || !NoServer::IsValidHostName(sHost))
            ;
#ifdef HAVE_LIBSSL
        bSSL = NoUtils::GetBoolInput("Server uses SSL?", bSSL);
#endif
        while (!NoUtils::GetNumInput("Server port", uServerPort, 1, 65535, bSSL ? 6697 : 6667))
            ;
        NoUtils::GetInput("Server password (probably empty)", sPass);

        vsLines.push_back("\t\tServer     = " + sHost + ((bSSL) ? " +" : " ") + NoString(uServerPort) + " " + sPass);

        NoString sChans;
        if (NoUtils::GetInput("Initial channels", sChans)) {
            vsLines.push_back("");
            NoStringVector vsChans;
            sChans.Replace(",", " ");
            sChans.Replace(";", " ");
            sChans.Split(" ", vsChans, false, "", "", true, true);
            for (const NoString& sChan : vsChans) {
                vsLines.push_back("\t\t<Chan " + sChan + ">");
                vsLines.push_back("\t\t</Chan>");
            }
        }

        NoUtils::PrintMessage("Enabled network modules [" +
                             NoString(", ").Join(vsNetworkModNames.begin(), vsNetworkModNames.end()) + "]");

        vsLines.push_back("\t</Network>");
    }

    vsLines.push_back("</User>");

    NoUtils::PrintMessage("");
    // !User

    NoFile File;
    bool bFileOK, bFileOpen = false;
    do {
        NoUtils::PrintAction("Writing config [" + m_sConfigFile + "]");

        bFileOK = true;
        if (NoFile::Exists(m_sConfigFile)) {
            if (!File.TryExLock(m_sConfigFile)) {
                NoUtils::PrintStatus(false, "ZNC is currently running on this config.");
                bFileOK = false;
            } else {
                File.Close();
                NoUtils::PrintStatus(false, "This config already exists.");
                if (NoUtils::GetBoolInput("Are you sure you want to overwrite it?", false))
                    NoUtils::PrintAction("Overwriting config [" + m_sConfigFile + "]");
                else
                    bFileOK = false;
            }
        }

        if (bFileOK) {
            File.SetFileName(m_sConfigFile);
            if (File.Open(O_WRONLY | O_CREAT | O_TRUNC, 0600)) {
                bFileOpen = true;
            } else {
                NoUtils::PrintStatus(false, "Unable to open file");
                bFileOK = false;
            }
        }
        if (!bFileOK) {
            while (!NoUtils::GetInput("Please specify an alternate location",
                                     m_sConfigFile,
                                     "",
                                     "or \"stdout\" for displaying the config"))
                ;
            if (m_sConfigFile.Equals("stdout"))
                bFileOK = true;
            else
                m_sConfigFile = ExpandConfigPath(m_sConfigFile);
        }
    } while (!bFileOK);

    if (!bFileOpen) {
        NoUtils::PrintMessage("");
        NoUtils::PrintMessage("Printing the new config to stdout:");
        NoUtils::PrintMessage("");
        std::cout << std::endl << "----------------------------------------------------------------------------" << std::endl << std::endl;
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
            NoUtils::PrintStatus(false, "There was an error while writing the config");
        else
            NoUtils::PrintStatus(true);
    } else {
        std::cout << std::endl << "----------------------------------------------------------------------------" << std::endl << std::endl;
    }

    if (File.HadError()) {
        bFileOpen = false;
        NoUtils::PrintMessage("Printing the new config to stdout instead:");
        std::cout << std::endl << "----------------------------------------------------------------------------" << std::endl << std::endl;
        for (const NoString& sLine : vsLines) {
            std::cout << sLine << std::endl;
        }
        std::cout << std::endl << "----------------------------------------------------------------------------" << std::endl << std::endl;
    }

    const NoString sProtocol(bListenSSL ? "https" : "http");
    const NoString sSSL(bListenSSL ? "+" : "");
    NoUtils::PrintMessage("");
    NoUtils::PrintMessage("To connect to this ZNC you need to connect to it as your IRC server", true);
    NoUtils::PrintMessage("using the port that you supplied.  You have to supply your login info", true);
    NoUtils::PrintMessage("as the IRC server password like this: user/network:pass.", true);
    NoUtils::PrintMessage("");
    NoUtils::PrintMessage("Try something like this in your IRC client...", true);
    NoUtils::PrintMessage("/server <znc_server_ip> " + sSSL + NoString(uListenPort) + " " + sUser + ":<pass>", true);
    NoUtils::PrintMessage("");
    NoUtils::PrintMessage("To manage settings, users and networks, point your web browser to", true);
    NoUtils::PrintMessage(sProtocol + "://<znc_server_ip>:" + NoString(uListenPort) + "/", true);
    NoUtils::PrintMessage("");

    File.UnLock();
    return bFileOpen && NoUtils::GetBoolInput("Launch ZNC now?", true);
}

void NoApp::BackupConfigOnce(const NoString& sSuffix)
{
    static bool didBackup = false;
    if (didBackup) return;
    didBackup = true;

    NoUtils::PrintAction("Creating a config backup");

    NoString sBackup = NoDir::ChangeDir(m_sConfigFile, "../znc.conf." + sSuffix);
    if (NoFile::Copy(m_sConfigFile, sBackup))
        NoUtils::PrintStatus(true, sBackup);
    else
        NoUtils::PrintStatus(false, strerror(errno));
}

bool NoApp::ParseConfig(const NoString& sConfig, NoString& sError)
{
    m_sConfigFile = ExpandConfigPath(sConfig, false);

    return DoRehash(sError);
}

bool NoApp::RehashConfig(NoString& sError)
{
    ALLMODULECALL(OnPreRehash(), NOTHING);

    // This clears m_msDelUsers
    HandleUserDeletion();

    // Mark all users as going-to-be deleted
    m_msDelUsers = m_msUsers;
    m_msUsers.clear();

    if (DoRehash(sError)) {
        ALLMODULECALL(OnPostRehash(), NOTHING);

        return true;
    }

    // Rehashing failed, try to recover
    NoString s;
    while (!m_msDelUsers.empty()) {
        AddUser(m_msDelUsers.begin()->second, s);
        m_msDelUsers.erase(m_msDelUsers.begin());
    }

    return false;
}

bool NoApp::DoRehash(NoString& sError)
{
    sError.clear();

    NoUtils::PrintAction("Opening config [" + m_sConfigFile + "]");

    if (!NoFile::Exists(m_sConfigFile)) {
        sError = "No such file";
        NoUtils::PrintStatus(false, sError);
        NoUtils::PrintMessage("Restart ZNC with the --makeconf option if you wish to create this config.");
        return false;
    }

    if (!NoFile::IsReg(m_sConfigFile)) {
        sError = "Not a file";
        NoUtils::PrintStatus(false, sError);
        return false;
    }

    NoFile* pFile = new NoFile(m_sConfigFile);

    // need to open the config file Read/Write for fcntl()
    // exclusive locking to work properly!
    if (!pFile->Open(m_sConfigFile, O_RDWR)) {
        sError = "Can not open config file";
        NoUtils::PrintStatus(false, sError);
        delete pFile;
        return false;
    }

    if (!pFile->TryExLock()) {
        sError = "ZNC is already running on this config.";
        NoUtils::PrintStatus(false, sError);
        delete pFile;
        return false;
    }

    // (re)open the config file
    delete m_pLockFile;
    m_pLockFile = pFile;
    NoFile& File = *pFile;

    NoSettings config;
    if (!config.Parse(File, sError)) {
        NoUtils::PrintStatus(false, sError);
        return false;
    }
    NoUtils::PrintStatus(true);

    NoString sSavedVersion;
    config.FindStringEntry("version", sSavedVersion);
    std::tuple<uint, uint> tSavedVersion =
    std::make_tuple(sSavedVersion.Token(0, false, ".").ToUInt(), sSavedVersion.Token(1, false, ".").ToUInt());
    std::tuple<uint, uint> tCurrentVersion = std::make_tuple(NO_VERSION_MAJOR, NO_VERSION_MINOR);
    if (tSavedVersion < tCurrentVersion) {
        if (sSavedVersion.empty()) {
            sSavedVersion = "< 0.203";
        }
        NoUtils::PrintMessage("Found old config from ZNC " + sSavedVersion + ". Saving a backup of it.");
        BackupConfigOnce("pre-" + NoString(NO_VERSION_STR));
    } else if (tSavedVersion > tCurrentVersion) {
        NoUtils::PrintError("Config was saved from ZNC " + sSavedVersion + ". It may or may not work with current ZNC " + GetVersion());
    }

    m_vsBindHosts.clear();
    m_vsTrustedProxies.clear();
    m_vsMotd.clear();

    // Delete all listeners
    while (!m_vpListeners.empty()) {
        delete m_vpListeners[0];
        m_vpListeners.erase(m_vpListeners.begin());
    }

    NoStringMap msModules; // Modules are queued for later loading

    NoStringVector vsList;
    config.FindStringVector("loadmodule", vsList);
    for (const NoString& sModLine : vsList) {
        NoString sModName = sModLine.Token(0);
        NoString sArgs = sModLine.Token(1, true);

        if (sModName == "saslauth" && tSavedVersion < std::make_tuple(0, 207)) {
            // XXX compatibility crap, added in 0.207
            NoUtils::PrintMessage("saslauth module was renamed to cyrusauth. Loading cyrusauth instead.");
            sModName = "cyrusauth";
        }

        if (msModules.find(sModName) != msModules.end()) {
            sError = "Module [" + sModName + "] already loaded";
            NoUtils::PrintError(sError);
            return false;
        }
        NoString sModRet;
        NoModule* pOldMod;

        pOldMod = GetModules().FindModule(sModName);
        if (!pOldMod) {
            NoUtils::PrintAction("Loading global module [" + sModName + "]");

            bool bModRet = GetModules().LoadModule(sModName, sArgs, NoModInfo::GlobalModule, nullptr, nullptr, sModRet);

            NoUtils::PrintStatus(bModRet, sModRet);
            if (!bModRet) {
                sError = sModRet;
                return false;
            }
        } else if (pOldMod->GetArgs() != sArgs) {
            NoUtils::PrintAction("Reloading global module [" + sModName + "]");

            bool bModRet = GetModules().ReloadModule(sModName, sArgs, nullptr, nullptr, sModRet);

            NoUtils::PrintStatus(bModRet, sModRet);
            if (!bModRet) {
                sError = sModRet;
                return false;
            }
        } else
            NoUtils::PrintMessage("Module [" + sModName + "] already loaded.");

        msModules[sModName] = sArgs;
    }

    NoString sISpoofFormat, sISpoofFile;
    config.FindStringEntry("ispoofformat", sISpoofFormat);
    config.FindStringEntry("ispooffile", sISpoofFile);
    if (!sISpoofFormat.empty() || !sISpoofFile.empty()) {
        NoModule* pIdentFileMod = GetModules().FindModule("identfile");
        if (!pIdentFileMod) {
            NoUtils::PrintAction("Loading global Module [identfile]");

            NoString sModRet;
            bool bModRet = GetModules().LoadModule("identfile", "", NoModInfo::GlobalModule, nullptr, nullptr, sModRet);

            NoUtils::PrintStatus(bModRet, sModRet);
            if (!bModRet) {
                sError = sModRet;
                return false;
            }

            pIdentFileMod = GetModules().FindModule("identfile");
            msModules["identfile"] = "";
        }

        pIdentFileMod->SetNV("File", sISpoofFile);
        pIdentFileMod->SetNV("Format", sISpoofFormat);
    }

    config.FindStringVector("motd", vsList);
    for (const NoString& sMotd : vsList) {
        AddMotd(sMotd);
    }

    config.FindStringVector("bindhost", vsList);
    for (const NoString& sHost : vsList) {
        AddBindHost(sHost);
    }

    config.FindStringVector("trustedproxy", vsList);
    for (const NoString& sProxy : vsList) {
        AddTrustedProxy(sProxy);
    }

    config.FindStringVector("vhost", vsList);
    for (const NoString& sHost : vsList) {
        AddBindHost(sHost);
    }

    NoString sVal;
    if (config.FindStringEntry("pidfile", sVal)) m_sPidFile = sVal;
    if (config.FindStringEntry("statusprefix", sVal)) m_sStatusPrefix = sVal;
    if (config.FindStringEntry("sslcertfile", sVal)) m_sSSLCertFile = sVal;
    if (config.FindStringEntry("sslciphers", sVal)) m_sSSLCiphers = sVal;
    if (config.FindStringEntry("skin", sVal)) SetSkinName(sVal);
    if (config.FindStringEntry("connectdelay", sVal)) SetConnectDelay(sVal.ToUInt());
    if (config.FindStringEntry("serverthrottle", sVal)) m_sConnectThrottle.SetTTL(sVal.ToUInt() * 1000);
    if (config.FindStringEntry("anoniplimit", sVal)) m_uiAnonIPLimit = sVal.ToUInt();
    if (config.FindStringEntry("maxbuffersize", sVal)) m_uiMaxBufferSize = sVal.ToUInt();
    if (config.FindStringEntry("protectwebsessions", sVal)) m_bProtectWebSessions = sVal.ToBool();
    if (config.FindStringEntry("hideversion", sVal)) m_bHideVersion = sVal.ToBool();

    if (config.FindStringEntry("sslprotocols", m_sSSLProtocols)) {
        NoStringVector vsProtocols;
        m_sSSLProtocols.Split(" ", vsProtocols, false, "", "", true, true);

        for (NoString& sProtocol : vsProtocols) {

            uint uFlag = 0;
            bool bEnable = sProtocol.TrimPrefix("+");
            bool bDisable = sProtocol.TrimPrefix("-");

            if (sProtocol.Equals("All")) {
                uFlag = ~0;
            } else if (sProtocol.Equals("SSLv2")) {
                uFlag = Csock::EDP_SSLv2;
            } else if (sProtocol.Equals("SSLv3")) {
                uFlag = Csock::EDP_SSLv3;
            } else if (sProtocol.Equals("TLSv1")) {
                uFlag = Csock::EDP_TLSv1;
            } else if (sProtocol.Equals("TLSv1.1")) {
                uFlag = Csock::EDP_TLSv1_1;
            } else if (sProtocol.Equals("TLSv1.2")) {
                uFlag = Csock::EDP_TLSv1_2;
            } else {
                NoUtils::PrintError("Invalid SSLProtocols value [" + sProtocol + "]");
                NoUtils::PrintError("The syntax is [SSLProtocols = [+|-]<protocol> ...]");
                NoUtils::PrintError("Available protocols are [SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2]");
                return false;
            }

            if (bEnable) {
                m_uDisabledSSLProtocols &= ~uFlag;
            } else if (bDisable) {
                m_uDisabledSSLProtocols |= uFlag;
            } else {
                m_uDisabledSSLProtocols = ~uFlag;
            }
        }
    }

    // This has to be after SSLCertFile is handled since it uses that value
    const char* szListenerEntries[] = { "listen", "listen6", "listen4", "listener", "listener6", "listener4" };

    for (const char* szEntry : szListenerEntries) {
        config.FindStringVector(szEntry, vsList);
        for (const NoString& sListener : vsList) {
            if (!AddListener(szEntry + NoString(" ") + sListener, sError)) return false;
        }
    }

    NoSettings::SubConfig subConf;
    NoSettings::SubConfig::const_iterator subIt;

    config.FindSubConfig("listener", subConf);
    for (subIt = subConf.begin(); subIt != subConf.end(); ++subIt) {
        NoSettings* pSubConf = subIt->second.m_pSubConfig;
        if (!AddListener(pSubConf, sError)) return false;
        if (!pSubConf->empty()) {
            sError = "Unhandled lines in Listener config!";
            NoUtils::PrintError(sError);

            NoApp::DumpConfig(pSubConf);
            return false;
        }
    }

    config.FindSubConfig("user", subConf);
    for (subIt = subConf.begin(); subIt != subConf.end(); ++subIt) {
        const NoString& sUserName = subIt->first;
        NoSettings* pSubConf = subIt->second.m_pSubConfig;
        NoUser* pRealUser = nullptr;

        NoUtils::PrintMessage("Loading user [" + sUserName + "]");

        // Either create a NoUser* or use an existing one
        std::map<NoString, NoUser*>::iterator it = m_msDelUsers.find(sUserName);

        if (it != m_msDelUsers.end()) {
            pRealUser = it->second;
            m_msDelUsers.erase(it);
        }

        NoUser* pUser = new NoUser(sUserName);

        if (!m_sStatusPrefix.empty()) {
            if (!pUser->SetStatusPrefix(m_sStatusPrefix)) {
                sError = "Invalid StatusPrefix [" + m_sStatusPrefix + "] Must be 1-5 chars, no spaces.";
                NoUtils::PrintError(sError);
                return false;
            }
        }

        if (!pUser->ParseConfig(pSubConf, sError)) {
            NoUtils::PrintError(sError);
            delete pUser;
            pUser = nullptr;
            return false;
        }

        if (!pSubConf->empty()) {
            sError = "Unhandled lines in config for User [" + sUserName + "]!";
            NoUtils::PrintError(sError);

            DumpConfig(pSubConf);
            return false;
        }

        NoString sErr;
        if (pRealUser) {
            if (!pRealUser->Clone(*pUser, sErr) || !AddUser(pRealUser, sErr)) {
                sError = "Invalid user [" + pUser->GetUserName() + "] " + sErr;
                DEBUG("NoUser::Clone() failed in rehash");
            }
            pUser->SetBeingDeleted(true);
            delete pUser;
            pUser = nullptr;
        } else if (!AddUser(pUser, sErr)) {
            sError = "Invalid user [" + pUser->GetUserName() + "] " + sErr;
        }

        if (!sError.empty()) {
            NoUtils::PrintError(sError);
            if (pUser) {
                pUser->SetBeingDeleted(true);
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
        NoUtils::PrintError(sError);

        DumpConfig(&config);
        return false;
    }


    // Unload modules which are no longer in the config
    std::set<NoString> ssUnload;
    for (NoModule* pCurMod : GetModules()) {
        if (msModules.find(pCurMod->GetModName()) == msModules.end()) ssUnload.insert(pCurMod->GetModName());
    }

    for (const NoString& sMod : ssUnload) {
        if (GetModules().UnloadModule(sMod))
            NoUtils::PrintMessage("Unloaded global module [" + sMod + "]");
        else
            NoUtils::PrintMessage("Could not unload [" + sMod + "]");
    }

    if (m_msUsers.empty()) {
        sError = "You must define at least one user in your config.";
        NoUtils::PrintError(sError);
        return false;
    }

    if (m_vpListeners.empty()) {
        sError = "You must supply at least one Listen port in your config.";
        NoUtils::PrintError(sError);
        return false;
    }

    return true;
}

void NoApp::DumpConfig(const NoSettings* pConfig)
{
    NoSettings::EntryMapIterator eit = pConfig->BeginEntries();
    for (; eit != pConfig->EndEntries(); ++eit) {
        const NoString& sKey = eit->first;
        const NoStringVector& vsList = eit->second;
        NoStringVector::const_iterator it = vsList.begin();
        for (; it != vsList.end(); ++it) {
            NoUtils::PrintError(sKey + " = " + *it);
        }
    }

    NoSettings::SubConfigMapIterator sit = pConfig->BeginSubConfigs();
    for (; sit != pConfig->EndSubConfigs(); ++sit) {
        const NoString& sKey = sit->first;
        const NoSettings::SubConfig& sSub = sit->second;
        NoSettings::SubConfig::const_iterator it = sSub.begin();

        for (; it != sSub.end(); ++it) {
            NoUtils::PrintError("SubConfig [" + sKey + " " + it->first + "]:");
            DumpConfig(it->second.m_pSubConfig);
        }
    }
}

void NoApp::ClearBindHosts() { m_vsBindHosts.clear(); }

bool NoApp::AddBindHost(const NoString& sHost)
{
    if (sHost.empty()) {
        return false;
    }

    for (const NoString& sBindHost : m_vsBindHosts) {
        if (sBindHost.Equals(sHost)) {
            return false;
        }
    }

    m_vsBindHosts.push_back(sHost);
    return true;
}

bool NoApp::RemBindHost(const NoString& sHost)
{
    NoStringVector::iterator it;
    for (it = m_vsBindHosts.begin(); it != m_vsBindHosts.end(); ++it) {
        if (sHost.Equals(*it)) {
            m_vsBindHosts.erase(it);
            return true;
        }
    }

    return false;
}

void NoApp::ClearTrustedProxies() { m_vsTrustedProxies.clear(); }

bool NoApp::AddTrustedProxy(const NoString& sHost)
{
    if (sHost.empty()) {
        return false;
    }

    for (const NoString& sTrustedProxy : m_vsTrustedProxies) {
        if (sTrustedProxy.Equals(sHost)) {
            return false;
        }
    }

    m_vsTrustedProxies.push_back(sHost);
    return true;
}

bool NoApp::RemTrustedProxy(const NoString& sHost)
{
    NoStringVector::iterator it;
    for (it = m_vsTrustedProxies.begin(); it != m_vsTrustedProxies.end(); ++it) {
        if (sHost.Equals(*it)) {
            m_vsTrustedProxies.erase(it);
            return true;
        }
    }

    return false;
}

void NoApp::Broadcast(const NoString& sMessage, bool bAdminOnly, NoUser* pSkipUser, NoClient* pSkipClient)
{
    for (const auto& it : m_msUsers) {
        if (bAdminOnly && !it.second->IsAdmin()) continue;

        if (it.second != pSkipUser) {
            NoString sMsg = sMessage;

            bool bContinue = false;
            USERMODULECALL(OnBroadcast(sMsg), it.second, nullptr, &bContinue);
            if (bContinue) continue;

            it.second->PutStatusNotice("*** " + sMsg, nullptr, pSkipClient);
        }
    }
}

NoModule* NoApp::FindModule(const NoString& sModName, const NoString& sUsername)
{
    if (sUsername.empty()) {
        return NoApp::Get().GetModules().FindModule(sModName);
    }

    NoUser* pUser = FindUser(sUsername);

    return (!pUser) ? nullptr : pUser->GetModules().FindModule(sModName);
}

NoModule* NoApp::FindModule(const NoString& sModName, NoUser* pUser)
{
    if (pUser) {
        return pUser->GetModules().FindModule(sModName);
    }

    return NoApp::Get().GetModules().FindModule(sModName);
}

bool NoApp::UpdateModule(const NoString& sModule)
{
    NoModule* pModule;

    std::map<NoUser*, NoString> musLoaded;
    std::map<NoNetwork*, NoString> mnsLoaded;

    // Unload the module for every user and network
    for (const auto& it : m_msUsers) {
        NoUser* pUser = it.second;

        pModule = pUser->GetModules().FindModule(sModule);
        if (pModule) {
            musLoaded[pUser] = pModule->GetArgs();
            pUser->GetModules().UnloadModule(sModule);
        }

        // See if the user has this module loaded to a network
        std::vector<NoNetwork*> vNetworks = pUser->GetNetworks();
        for (NoNetwork* pNetwork : vNetworks) {
            pModule = pNetwork->GetModules().FindModule(sModule);
            if (pModule) {
                mnsLoaded[pNetwork] = pModule->GetArgs();
                pNetwork->GetModules().UnloadModule(sModule);
            }
        }
    }

    // Unload the global module
    bool bGlobal = false;
    NoString sGlobalArgs;

    pModule = GetModules().FindModule(sModule);
    if (pModule) {
        bGlobal = true;
        sGlobalArgs = pModule->GetArgs();
        GetModules().UnloadModule(sModule);
    }

    // Lets reload everything
    bool bError = false;
    NoString sErr;

    // Reload the global module
    if (bGlobal) {
        if (!GetModules().LoadModule(sModule, sGlobalArgs, NoModInfo::GlobalModule, nullptr, nullptr, sErr)) {
            DEBUG("Failed to reload [" << sModule << "] globally [" << sErr << "]");
            bError = true;
        }
    }

    // Reload the module for all users
    for (const auto& it : musLoaded) {
        NoUser* pUser = it.first;
        const NoString& sArgs = it.second;

        if (!pUser->GetModules().LoadModule(sModule, sArgs, NoModInfo::UserModule, pUser, nullptr, sErr)) {
            DEBUG("Failed to reload [" << sModule << "] for [" << pUser->GetUserName() << "] [" << sErr << "]");
            bError = true;
        }
    }

    // Reload the module for all networks
    for (const auto& it : mnsLoaded) {
        NoNetwork* pNetwork = it.first;
        const NoString& sArgs = it.second;

        if (!pNetwork->GetModules().LoadModule(sModule, sArgs, NoModInfo::NetworkModule, pNetwork->GetUser(), pNetwork, sErr)) {
            DEBUG("Failed to reload [" << sModule << "] for [" << pNetwork->GetUser()->GetUserName() << "/"
                                       << pNetwork->GetName() << "] [" << sErr << "]");
            bError = true;
        }
    }

    return !bError;
}

NoUser* NoApp::FindUser(const NoString& sUsername)
{
    std::map<NoString, NoUser*>::iterator it = m_msUsers.find(sUsername);

    if (it != m_msUsers.end()) {
        return it->second;
    }

    return nullptr;
}

bool NoApp::DeleteUser(const NoString& sUsername)
{
    NoUser* pUser = FindUser(sUsername);

    if (!pUser) {
        return false;
    }

    m_msDelUsers[pUser->GetUserName()] = pUser;
    return true;
}

bool NoApp::AddUser(NoUser* pUser, NoString& sErrorRet)
{
    if (FindUser(pUser->GetUserName()) != nullptr) {
        sErrorRet = "User already exists";
        DEBUG("User [" << pUser->GetUserName() << "] - already exists");
        return false;
    }
    if (!pUser->IsValid(sErrorRet)) {
        DEBUG("Invalid user [" << pUser->GetUserName() << "] - [" << sErrorRet << "]");
        return false;
    }
    bool bFailed = false;
    GLOBALMODULECALL(OnAddUser(*pUser, sErrorRet), &bFailed);
    if (bFailed) {
        DEBUG("AddUser [" << pUser->GetUserName() << "] aborted by a module [" << sErrorRet << "]");
        return false;
    }
    m_msUsers[pUser->GetUserName()] = pUser;
    return true;
}

NoListener* NoApp::FindListener(u_short uPort, const NoString& sBindHost, EAddrType eAddr)
{
    for (NoListener* pListener : m_vpListeners) {
        if (pListener->GetPort() != uPort) continue;
        if (pListener->GetBindHost() != sBindHost) continue;
        if (pListener->GetAddrType() != eAddr) continue;
        return pListener;
    }
    return nullptr;
}

bool NoApp::AddListener(const NoString& sLine, NoString& sError)
{
    NoString sName = sLine.Token(0);
    NoString sValue = sLine.Token(1, true);

    EAddrType eAddr = ADDR_ALL;
    if (sName.Equals("Listen4") || sName.Equals("Listen") || sName.Equals("Listener4")) {
        eAddr = ADDR_IPV4ONLY;
    }
    if (sName.Equals("Listener6")) {
        eAddr = ADDR_IPV6ONLY;
    }

    NoListener::EAcceptType eAccept = NoListener::ACCEPT_ALL;
    if (sValue.TrimPrefix("irc_only "))
        eAccept = NoListener::ACCEPT_IRC;
    else if (sValue.TrimPrefix("web_only "))
        eAccept = NoListener::ACCEPT_HTTP;

    bool bSSL = false;
    NoString sPort;
    NoString sBindHost;

    if (ADDR_IPV4ONLY == eAddr) {
        sValue.Replace(":", " ");
    }

    if (sValue.find(" ") != NoString::npos) {
        sBindHost = sValue.Token(0, false, " ");
        sPort = sValue.Token(1, true, " ");
    } else {
        sPort = sValue;
    }

    if (sPort.Left(1) == "+") {
        sPort.LeftChomp();
        bSSL = true;
    }

    // No support for URIPrefix for old-style configs.
    NoString sURIPrefix;
    ushort uPort = sPort.ToUShort();
    return AddListener(uPort, sBindHost, sURIPrefix, bSSL, eAddr, eAccept, sError);
}

bool NoApp::AddListener(ushort uPort,
                       const NoString& sBindHost,
                       const NoString& sURIPrefixRaw,
                       bool bSSL,
                       EAddrType eAddr,
                       NoListener::EAcceptType eAccept,
                       NoString& sError)
{
    NoString sHostComment;

    if (!sBindHost.empty()) {
        sHostComment = " on host [" + sBindHost + "]";
    }

    NoString sIPV6Comment;

    switch (eAddr) {
    case ADDR_ALL:
        sIPV6Comment = "";
        break;
    case ADDR_IPV4ONLY:
        sIPV6Comment = " using ipv4";
        break;
    case ADDR_IPV6ONLY:
        sIPV6Comment = " using ipv6";
    }

    NoUtils::PrintAction("Binding to port [" + NoString((bSSL) ? "+" : "") + NoString(uPort) + "]" + sHostComment + sIPV6Comment);

#ifndef HAVE_IPV6
    if (ADDR_IPV6ONLY == eAddr) {
        sError = "IPV6 is not enabled";
        NoUtils::PrintStatus(false, sError);
        return false;
    }
#endif

#ifndef HAVE_LIBSSL
    if (bSSL) {
        sError = "SSL is not enabled";
        NoUtils::PrintStatus(false, sError);
        return false;
    }
#else
    NoString sPemFile = GetPemLocation();

    if (bSSL && !NoFile::Exists(sPemFile)) {
        sError = "Unable to locate pem file: [" + sPemFile + "]";
        NoUtils::PrintStatus(false, sError);

        // If stdin is e.g. /dev/null and we call GetBoolInput(),
        // we are stuck in an endless loop!
        if (isatty(0) && NoUtils::GetBoolInput("Would you like to create a new pem file?", true)) {
            sError.clear();
            WritePemFile();
        } else {
            return false;
        }

        NoUtils::PrintAction("Binding to port [+" + NoString(uPort) + "]" + sHostComment + sIPV6Comment);
    }
#endif
    if (!uPort) {
        sError = "Invalid port";
        NoUtils::PrintStatus(false, sError);
        return false;
    }

    // URIPrefix must start with a slash and end without one.
    NoString sURIPrefix = NoString(sURIPrefixRaw);
    if (!sURIPrefix.empty()) {
        if (!sURIPrefix.StartsWith("/")) {
            sURIPrefix = "/" + sURIPrefix;
        }
        if (sURIPrefix.EndsWith("/")) {
            sURIPrefix.TrimRight("/");
        }
    }

    NoListener* pListener = new NoListener(uPort, sBindHost, sURIPrefix, bSSL, eAddr, eAccept);

    if (!pListener->Listen()) {
        sError = FormatBindError();
        NoUtils::PrintStatus(false, sError);
        delete pListener;
        return false;
    }

    m_vpListeners.push_back(pListener);
    NoUtils::PrintStatus(true);

    return true;
}

bool NoApp::AddListener(NoSettings* pConfig, NoString& sError)
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
        NoUtils::PrintError(sError);
        return false;
    }
    pConfig->FindStringEntry("host", sBindHost);
    pConfig->FindBoolEntry("ssl", bSSL, false);
    pConfig->FindBoolEntry("ipv4", b4, true);
    pConfig->FindBoolEntry("ipv6", b6, b6);
    pConfig->FindBoolEntry("allowirc", bIRC, true);
    pConfig->FindBoolEntry("allowweb", bWeb, true);
    pConfig->FindStringEntry("uriprefix", sURIPrefix);

    EAddrType eAddr;
    if (b4 && b6) {
        eAddr = ADDR_ALL;
    } else if (b4 && !b6) {
        eAddr = ADDR_IPV4ONLY;
    } else if (!b4 && b6) {
        eAddr = ADDR_IPV6ONLY;
    } else {
        sError = "No address family given";
        NoUtils::PrintError(sError);
        return false;
    }

    NoListener::EAcceptType eAccept;
    if (bIRC && bWeb) {
        eAccept = NoListener::ACCEPT_ALL;
    } else if (bIRC && !bWeb) {
        eAccept = NoListener::ACCEPT_IRC;
    } else if (!bIRC && bWeb) {
        eAccept = NoListener::ACCEPT_HTTP;
    } else {
        sError = "Either Web or IRC or both should be selected";
        NoUtils::PrintError(sError);
        return false;
    }

    return AddListener(uPort, sBindHost, sURIPrefix, bSSL, eAddr, eAccept, sError);
}

bool NoApp::AddListener(NoListener* pListener)
{
    if (!pListener->GetSocket()) {
        // Listener doesnt actually listen
        delete pListener;
        return false;
    }

    // We don't check if there is an identical listener already listening
    // since one can't listen on e.g. the same port multiple times

    m_vpListeners.push_back(pListener);
    return true;
}

bool NoApp::DelListener(NoListener* pListener)
{
    auto it = std::find(m_vpListeners.begin(), m_vpListeners.end(), pListener);
    if (it != m_vpListeners.end()) {
        m_vpListeners.erase(it);
        delete pListener;
        return true;
    }

    return false;
}

static NoApp* s_pZNC = nullptr;

void NoApp::CreateInstance()
{
    if (s_pZNC) abort();

    s_pZNC = new NoApp();
}

NoApp& NoApp::Get() { return *s_pZNC; }

void NoApp::DestroyInstance()
{
    delete s_pZNC;
    s_pZNC = nullptr;
}

NoApp::TrafficStatsMap NoApp::GetTrafficStats(TrafficStatsPair& Users, TrafficStatsPair& ZNC, TrafficStatsPair& Total)
{
    TrafficStatsMap ret;
    ulonglong uiUsers_in, uiUsers_out, uiZNC_in, uiZNC_out;
    const std::map<NoString, NoUser*>& msUsers = NoApp::Get().GetUserMap();

    uiUsers_in = uiUsers_out = 0;
    uiZNC_in = BytesRead();
    uiZNC_out = BytesWritten();

    for (const auto& it : msUsers) {
        ret[it.first] = TrafficStatsPair(it.second->BytesRead(), it.second->BytesWritten());
        uiUsers_in += it.second->BytesRead();
        uiUsers_out += it.second->BytesWritten();
    }

    for (Csock* pSock : m_Manager) {
        NoUser* pUser = nullptr;
        if (pSock->GetSockName().Left(5) == "IRC::") {
            pUser = ((NoIrcSock*)pSock)->GetNetwork()->GetUser();
        } else if (pSock->GetSockName().Left(5) == "USR::") {
            pUser = ((NoClient*)pSock)->GetUser();
        }

        if (pUser) {
            ret[pUser->GetUserName()].first += pSock->GetBytesRead();
            ret[pUser->GetUserName()].second += pSock->GetBytesWritten();
            uiUsers_in += pSock->GetBytesRead();
            uiUsers_out += pSock->GetBytesWritten();
        } else {
            uiZNC_in += pSock->GetBytesRead();
            uiZNC_out += pSock->GetBytesWritten();
        }
    }

    Users = TrafficStatsPair(uiUsers_in, uiUsers_out);
    ZNC = TrafficStatsPair(uiZNC_in, uiZNC_out);
    Total = TrafficStatsPair(uiUsers_in + uiZNC_in, uiUsers_out + uiZNC_out);

    return ret;
}

void NoApp::AuthUser(std::shared_ptr<NoAuthBase> AuthClass)
{
    // TODO unless the auth module calls it, NoUser::IsHostAllowed() is not honoured
    bool bReturn = false;
    GLOBALMODULECALL(OnLoginAttempt(AuthClass), &bReturn);
    if (bReturn) return;

    NoUser* pUser = FindUser(AuthClass->GetUsername());

    if (!pUser || !pUser->CheckPass(AuthClass->GetPassword())) {
        AuthClass->RefuseLogin("Invalid Password");
        return;
    }

    NoString sHost = AuthClass->GetRemoteIP();

    if (!pUser->IsHostAllowed(sHost)) {
        AuthClass->RefuseLogin("Your host [" + sHost + "] is not allowed");
        return;
    }

    AuthClass->AcceptLogin(*pUser);
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
        NoApp::Get().LeakConnectQueueTimer(this);
    }

protected:
    void RunJob() override
    {
        std::list<NoNetwork*> ConnectionQueue;
        std::list<NoNetwork*>& RealConnectionQueue = NoApp::Get().GetConnectionQueue();

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

            if (pNetwork->Connect()) {
                break;
            }
        }

        /* Now re-insert anything that is left in our local list into
         * the real connection queue.
         */
        RealConnectionQueue.splice(RealConnectionQueue.begin(), ConnectionQueue);

        if (RealConnectionQueue.empty()) {
            DEBUG("ConnectQueueTimer done");
            NoApp::Get().DisableConnectQueue();
        }
    }
};

void NoApp::SetConnectDelay(uint i)
{
    if (i < 1) {
        // Don't hammer server with our failed connects
        i = 1;
    }
    if (m_uiConnectDelay != i && m_pConnectQueueTimer != nullptr) {
        m_pConnectQueueTimer->Start(i);
    }
    m_uiConnectDelay = i;
}

void NoApp::EnableConnectQueue()
{
    if (!m_pConnectQueueTimer && !m_uiConnectPaused && !m_lpConnectQueue.empty()) {
        m_pConnectQueueTimer = new NoConnectQueueTimer(m_uiConnectDelay);
        GetManager().AddCron(m_pConnectQueueTimer);
    }
}

void NoApp::DisableConnectQueue()
{
    if (m_pConnectQueueTimer) {
        // This will kill the cron
        m_pConnectQueueTimer->Stop();
        m_pConnectQueueTimer = nullptr;
    }
}

void NoApp::PauseConnectQueue()
{
    DEBUG("Connection queue paused");
    m_uiConnectPaused++;

    if (m_pConnectQueueTimer) {
        m_pConnectQueueTimer->Pause();
    }
}

void NoApp::ResumeConnectQueue()
{
    DEBUG("Connection queue resumed");
    m_uiConnectPaused--;

    EnableConnectQueue();
    if (m_pConnectQueueTimer) {
        m_pConnectQueueTimer->UnPause();
    }
}

void NoApp::AddNetworkToQueue(NoNetwork* pNetwork)
{
    // Make sure we are not already in the queue
    if (std::find(m_lpConnectQueue.begin(), m_lpConnectQueue.end(), pNetwork) != m_lpConnectQueue.end()) {
        return;
    }

    m_lpConnectQueue.push_back(pNetwork);
    EnableConnectQueue();
}

void NoApp::LeakConnectQueueTimer(NoConnectQueueTimer* pTimer)
{
    if (m_pConnectQueueTimer == pTimer) m_pConnectQueueTimer = nullptr;
}

bool NoApp::WaitForChildLock() { return m_pLockFile && m_pLockFile->ExLock(); }
