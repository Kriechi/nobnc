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
#include "noapp_p.h"
#include "nodir.h"
#include "nofile.h"
#include "noircsocket.h"
#include "noauthenticator.h"
#include "noserverinfo.h"
#include "nouser.h"
#include "nouser_p.h"
#include "nonetwork.h"
#include "nosettings.h"
#include "noclient.h"
#include "nowebsocket.h"
#include "nolistener.h"
#include "noregistry.h"
#include "nomodule_p.h"
#include <tuple>
#include <algorithm>
#include "Csocket/Csocket.h"

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#endif // HAVE_LIBSSL

NO_EXPORT void no_cleanup()
{
    NoAppPrivate* p = NoAppPrivate::get(noApp);

    p->modules->unloadAllModules();

    for (const auto& it : p->users) {
        it.second->loader()->unloadAllModules();

        const std::vector<NoNetwork*>& networks = it.second->networks();
        for (NoNetwork* network : networks) {
            network->loader()->unloadAllModules();
        }
    }

    for (NoListener* pListener : p->listeners)
        delete pListener;

    for (const auto& it : p->users)
       NoUserPrivate::get(it.second)->beingDeleted = true;

    p->connectQueueTimer = nullptr;
    // This deletes d->pConnectQueueTimer
    p->manager.cleanup();

    for (const auto& it : p->users) {
        NoUserPrivate::get(it.second)->beingDeleted = true;
        delete it.second;
    }

    p->users.clear();
    p->disableConnectQueue();

    delete p->modules;
    p->modules = nullptr;

    delete p->lockFile;
    p->lockFile = nullptr;

    ShutdownCsocket();
}

static inline NoString FormatBindError()
{
    NoString error = (errno == 0 ? NoString("unknown error, check the host name") : NoString(strerror(errno)));
    return "Unable to bind [" + error + "]";
}

NoApp* NoAppPrivate::instance = nullptr;

NoApp::NoApp() : d(new NoAppPrivate)
{
    NoAppPrivate::instance = this;

    if (!InitCsocket()) {
        No::printError("Could not initialize Csocket!");
        exit(-1);
    }
    d->startTime = time(nullptr);
    d->modules = new NoModuleLoader;
    d->disabledSslProtocols = Csock::EDP_SSL;
    d->connectThrottle.setExpiration(30000);
}

NoApp::~NoApp()
{
    no_cleanup();
    NoAppPrivate::instance = nullptr;
}

NoString NoApp::version()
{
    return NoString(NO_VERSION_STR) + NoString(NO_VERSION_EXTRA);
}

NoString NoApp::tag(bool includeVersion, bool bHTML)
{
    if (!instance()->d->hideVersion) {
        includeVersion = true;
    }
    NoString sAddress = bHTML ? "<a href=\"http://znc.in\">http://znc.in</a>" : "http://znc.in";

    if (!includeVersion) {
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

bool NoAppPrivate::handleUserDeletion()
{
    if (delUsers.empty())
        return false;

    for (const auto& it : delUsers) {
        NoUser* user = it.second;
        NoUserPrivate::get(user)->beingDeleted = true;

        if (noApp->loader()->onDeleteUser(user)) {
            NoUserPrivate::get(user)->beingDeleted = false;
            continue;
        }
        users.erase(user->userName());
        NoWebSocket::finishUserSessions(user);
        delete user;
    }

    delUsers.clear();

    return true;
}

int NoApp::exec()
{
    while (true) {
        NoString error;

        ConfigState eState = configState();
        switch (eState) {
        case ConfigNeedRehash:
            setConfigState(ConfigNothing);

            if (rehashConfig(error)) {
                broadcast("Rehashing succeeded", true);
            } else {
                broadcast("Rehashing failed: " + error, true);
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
        if (d->handleUserDeletion()) {
            // Also remove those user(s) from the config file
            writeConfig();
        }

        // Csocket wants micro seconds
        // 100 msec to 600 sec
        d->manager.dynamicSelectLoop(100 * 1000, 600 * 1000 * 1000);
    }
    return 0;
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

static void GenerateCert(FILE* pOut, const NoString& host)
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

        if (!host.empty()) {
            pHostName = host.c_str();
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
    return d->bindHosts;
}

NoStringVector NoApp::trustedProxies() const
{
    return d->trustedProxies;
}

std::vector<NoListener*> NoApp::listeners() const
{
    return d->listeners;
}

time_t NoApp::timeStarted() const
{
    return d->startTime;
}

uint NoApp::maxBufferSize() const
{
    return d->maxBufferSize;
}

uint NoApp::anonIpLimit() const
{
    return d->anonIpLimit;
}

uint NoApp::serverThrottle() const
{
    return d->connectThrottle.expiration() / 1000;
}

uint NoApp::connectDelay() const
{
    return d->connectDelay;
}

bool NoApp::protectWebSessions() const
{
    return d->protectWebSessions;
}

bool NoApp::hideVersion() const
{
    return d->hideVersion;
}

NoString NoApp::sslCiphers() const
{
    return d->sslCiphers;
}

uint NoApp::disabledSslProtocols() const
{
    return d->disabledSslProtocols;
}

bool NoApp::isHostAllowed(const NoString& hostMask) const
{
    for (const auto& it : d->users) {
        if (it.second->isHostAllowed(hostMask)) {
            return true;
        }
    }

    return false;
}

bool NoApp::allowConnectionFrom(const NoString& address) const
{
    if (d->anonIpLimit == 0)
        return true;
    return (manager()->anonConnectionCount(address) < d->anonIpLimit);
}

void NoApp::initDirs(const NoString& argvPath, const NoString& dataDir)
{
    // If the bin was not ran from the current directory, we need to add that dir onto our cwd
    NoString::size_type pos = argvPath.rfind('/');
    if (pos == NoString::npos)
        d->curPath = "./";
    else
        d->curPath = NoDir("./").filePath(argvPath.left(pos));

    if (dataDir.empty()) {
        d->appPath = NoDir::home().filePath(".znc");
    } else {
        d->appPath = dataDir;
    }

    d->sslCertFile = d->appPath + "/znc.pem";
}

NoString NoApp::confPath(bool allowMkDir) const
{
    NoString sConfPath = d->appPath + "/configs";
    if (allowMkDir && !NoFile::Exists(sConfPath)) {
        NoDir::mkpath(sConfPath);
    }

    return sConfPath;
}

NoString NoApp::userPath() const
{
    NoString sUserPath = d->appPath + "/users";
    if (!NoFile::Exists(sUserPath)) {
        NoDir::mkpath(sUserPath);
    }

    return sUserPath;
}

NoString NoApp::modulePath() const
{
    NoString path = d->appPath + "/modules";

    return path;
}

NoString NoApp::currentPath() const
{
    if (!NoFile::Exists(d->curPath)) {
        NoDir::mkpath(d->curPath);
    }
    return d->curPath;
}

NoString NoApp::appPath() const
{
    if (!NoFile::Exists(d->appPath)) {
        NoDir::mkpath(d->appPath);
    }
    return d->appPath;
}

NoString NoApp::pemLocation() const
{
    return NoDir("").filePath(d->sslCertFile);
}

NoString NoApp::configFile() const
{
    return d->configFile;
}

NoString NoAppPrivate::expandConfigPath(const NoString& configFile, bool allowMkDir)
{
    NoString sRetPath;

    if (configFile.empty()) {
        sRetPath = noApp->confPath(allowMkDir) + "/znc.conf";
    } else {
        if (configFile.left(2) == "./" || configFile.left(3) == "../") {
            sRetPath = noApp->currentPath() + "/" + configFile;
        } else if (configFile.left(1) != "/") {
            sRetPath = noApp->confPath(allowMkDir) + "/" + configFile;
        } else {
            sRetPath = configFile;
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

    pFile->Write(d->makeConfigHeader() + "\n");

    NoSettings config;
    config.AddKeyValuePair("AnonIPLimit", NoString(d->anonIpLimit));
    config.AddKeyValuePair("MaxBufferSize", NoString(d->maxBufferSize));
    config.AddKeyValuePair("SSLCertFile", NoString(d->sslCertFile));
    config.AddKeyValuePair("ProtectWebSessions", NoString(d->protectWebSessions));
    config.AddKeyValuePair("HideVersion", NoString(d->hideVersion));
    config.AddKeyValuePair("Version", NoString(NO_VERSION_STR));

    uint l = 0;
    for (NoListener* pListener : d->listeners) {
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

    config.AddKeyValuePair("ConnectDelay", NoString(d->connectDelay));
    config.AddKeyValuePair("ServerThrottle", NoString(d->connectThrottle.expiration() / 1000));

    if (!d->skinName.empty()) {
        config.AddKeyValuePair("Skin", No::firstLine(d->skinName));
    }

    if (!d->statusPrefix.empty()) {
        config.AddKeyValuePair("StatusPrefix", No::firstLine(d->statusPrefix));
    }

    if (!d->sslCiphers.empty()) {
        config.AddKeyValuePair("SSLCiphers", NoString(d->sslCiphers));
    }

    if (!d->sslProtocols.empty()) {
        config.AddKeyValuePair("SSLProtocols", d->sslProtocols);
    }

    for (const NoString& line : d->motd) {
        config.AddKeyValuePair("Motd", No::firstLine(line));
    }

    for (const NoString& host : d->bindHosts) {
        config.AddKeyValuePair("BindHost", No::firstLine(host));
    }

    for (const NoString& sProxy : d->trustedProxies) {
        config.AddKeyValuePair("TrustedProxy", No::firstLine(sProxy));
    }

    NoModuleLoader* Mods = loader();

    for (const NoModule* mod : Mods->modules()) {
        NoString name = mod->name();
        NoString args = mod->args();

        if (!args.empty()) {
            args = " " + No::firstLine(args);
        }

        config.AddKeyValuePair("LoadModule", No::firstLine(name) + args);
    }

    for (const auto& it : d->users) {
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
    delete d->lockFile;
    d->lockFile = pFile;

    return true;
}

NoString NoAppPrivate::makeConfigHeader()
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

bool NoApp::writeNewConfig(const NoString& configFile)
{
    NoString sAnswer, sUser, sNetwork;
    NoStringVector vsLines;

    vsLines.push_back(d->makeConfigHeader());
    vsLines.push_back("Version = " + NoString(NO_VERSION_STR));

    d->configFile = d->expandConfigPath(configFile);

    if (NoFile::Exists(d->configFile)) {
        No::printStatus(false, "WARNING: config [" + d->configFile + "] already exists.");
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
    NoString uriPrefix;
    bool bListenSSL = false;
    uint uListenPort = 0;
    bool success;

    do {
        success = true;
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
        pListener->setUriPrefix(uriPrefix);
        pListener->setSsl(bListenSSL);
        pListener->setAddressType(b6 ? No::Ipv4AndIpv6Address : No::Ipv4Address);
        if (!pListener->listen()) {
            No::printStatus(false, FormatBindError());
            success = false;
        } else
            No::printStatus(true);
        delete pListener;
    } while (!success);

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

    std::set<NoModuleInfo> ssGlobalMods = loader()->defaultModules(No::GlobalModule);
    std::vector<NoString> vsGlobalModNames;
    for (const NoModuleInfo& info : ssGlobalMods) {
        vsGlobalModNames.push_back(info.name());
        vsLines.push_back("LoadModule = " + info.name());
    }
    No::printMessage("Enabled global modules [" + NoString(", ").join(vsGlobalModNames.begin(), vsGlobalModNames.end()) + "]");

    // User
    No::printMessage("");
    No::printMessage("-- Admin user settings --");
    No::printMessage("");

    vsLines.push_back("");
    NoString nick;
    do {
        No::getInput("Username", sUser, "", "alphanumeric");
    } while (!NoUser::isValidUserName(sUser));

    vsLines.push_back("<User " + sUser + ">");
    NoString passwordSalt;
    NoString passwordHash = No::getSaltedHashPass(passwordSalt);

    vsLines.push_back("\tAdmin      = true");

    No::getInput("Nick", nick, NoUser::makeCleanUserName(sUser));
    vsLines.push_back("\tNick       = " + nick);
    No::getInput("Alternate nick", sAnswer, nick + "_");
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

    std::set<NoModuleInfo> ssUserMods = loader()->defaultModules(No::UserModule);
    std::vector<NoString> vsUserModNames;
    for (const NoModuleInfo& info : ssUserMods) {
        vsUserModNames.push_back(info.name());
        vsLines.push_back("\tLoadModule = " + info.name());
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

        std::set<NoModuleInfo> ssNetworkMods = loader()->defaultModules(No::NetworkModule);
        std::vector<NoString> vsNetworkModNames;
        for (const NoModuleInfo& info : ssNetworkMods) {
            vsNetworkModNames.push_back(info.name());
            vsLines.push_back("\t\tLoadModule = " + info.name());
        }

        NoString host, pass, hint;
        bool ssl = false;
        uint uServerPort = 0;

        if (sNetwork.equals("freenode")) {
            host = "chat.freenode.net";
#ifdef HAVE_LIBSSL
            ssl = true;
#endif
        } else {
            hint = "host only";
        }

        while (!No::getInput("Server host", host, host, hint) || !NoServerInfo(host).isValid())
            ;
#ifdef HAVE_LIBSSL
        ssl = No::getBoolInput("Server uses SSL?", ssl);
#endif
        while (!No::getNumInput("Server port", uServerPort, 1, 65535, ssl ? 6697 : 6667))
            ;
        No::getInput("Server password (probably empty)", pass);

        vsLines.push_back("\t\tServer     = " + host + ((ssl) ? " +" : " ") + NoString(uServerPort) + " " + pass);

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
        vsLines.push_back("\t</Network>");

        No::printMessage("Enabled network modules [" + NoString(", ").join(vsNetworkModNames.begin(), vsNetworkModNames.end()) + "]");

        vsLines.push_back("");
        vsLines.push_back("\t<Pass password>");
        vsLines.push_back("\t\tHash = " + passwordHash);
        vsLines.push_back("\t\tSalt = " + passwordSalt);
        vsLines.push_back("\t</Pass>");
    }

    vsLines.push_back("</User>");

    No::printMessage("");
    // !User

    NoFile File;
    bool bFileOK, bFileOpen = false;
    do {
        No::printAction("Writing config [" + d->configFile + "]");

        bFileOK = true;
        if (NoFile::Exists(d->configFile)) {
            if (!File.TryExLock(d->configFile)) {
                No::printStatus(false, "ZNC is currently running on this config.");
                bFileOK = false;
            } else {
                File.Close();
                No::printStatus(false, "This config already exists.");
                if (No::getBoolInput("Are you sure you want to overwrite it?", false))
                    No::printAction("Overwriting config [" + d->configFile + "]");
                else
                    bFileOK = false;
            }
        }

        if (bFileOK) {
            File.SetFileName(d->configFile);
            if (File.Open(O_WRONLY | O_CREAT | O_TRUNC, 0600)) {
                bFileOpen = true;
            } else {
                No::printStatus(false, "Unable to open file");
                bFileOK = false;
            }
        }
        if (!bFileOK) {
            while (!No::getInput("Please specify an alternate location",
                                 d->configFile,
                                 "",
                                 "or \"stdout\" for "
                                 "displaying the config"))
                ;
            if (d->configFile.equals("stdout"))
                bFileOK = true;
            else
                d->configFile = d->expandConfigPath(d->configFile);
        }
    } while (!bFileOK);

    if (!bFileOpen) {
        No::printMessage("");
        No::printMessage("Printing the new config to stdout:");
        No::printMessage("");
        std::cout << std::endl << "----------------------------------------------------------------------------"
                  << std::endl << std::endl;
    }

    for (const NoString& line : vsLines) {
        if (bFileOpen) {
            File.Write(line + "\n");
        } else {
            std::cout << line << std::endl;
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
        for (const NoString& line : vsLines) {
            std::cout << line << std::endl;
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

void NoAppPrivate::backupConfigOnce(const NoString& suffix)
{
    static bool didBackup = false;
    if (didBackup)
        return;
    didBackup = true;

    No::printAction("Creating a config backup");

    NoString sBackup = NoDir(configFile).filePath("../znc.conf." + suffix);
    if (NoFile::Copy(configFile, sBackup))
        No::printStatus(true, sBackup);
    else
        No::printStatus(false, strerror(errno));
}

bool NoApp::parseConfig(const NoString& config, NoString& error)
{
    d->configFile = d->expandConfigPath(config, false);

    return d->doRehash(error);
}

bool NoApp::rehashConfig(NoString& error)
{
    ALLMODULECALL(onPreRehash(), NOTHING);

    // This clears d->msDelUsers
    d->handleUserDeletion();

    // Mark all users as going-to-be deleted
    d->delUsers = d->users;
    d->users.clear();

    if (d->doRehash(error)) {
        ALLMODULECALL(onPostRehash(), NOTHING);

        return true;
    }

    // Rehashing failed, try to recover
    NoString s;
    while (!d->delUsers.empty()) {
        addUser(d->delUsers.begin()->second, s);
        d->delUsers.erase(d->delUsers.begin());
    }

    return false;
}

bool NoAppPrivate::doRehash(NoString& error)
{
    error.clear();

    No::printAction("Opening config [" + configFile + "]");

    if (!NoFile::Exists(configFile)) {
        error = "No such file";
        No::printStatus(false, error);
        No::printMessage("Restart ZNC with the --makeconf option if you wish to create this config.");
        return false;
    }

    if (!NoFile(configFile).IsReg()) {
        error = "Not a file";
        No::printStatus(false, error);
        return false;
    }

    NoFile* pFile = new NoFile(configFile);

    // need to open the config file Read/Write for fcntl()
    // exclusive locking to work properly!
    if (!pFile->Open(configFile, O_RDWR)) {
        error = "Can not open config file";
        No::printStatus(false, error);
        delete pFile;
        return false;
    }

    if (!pFile->TryExLock()) {
        error = "ZNC is already running on this config.";
        No::printStatus(false, error);
        delete pFile;
        return false;
    }

    // (re)open the config file
    delete lockFile;
    lockFile = pFile;
    NoFile& File = *pFile;

    NoSettings config;
    if (!config.Parse(File, error)) {
        No::printStatus(false, error);
        return false;
    }
    No::printStatus(true);

    NoString sSavedVersion;
    config.FindStringEntry("version", sSavedVersion);
    std::tuple<uint, uint> tSavedVersion =
    std::make_tuple(No::token(sSavedVersion, 0, ".").toUInt(), No::token(sSavedVersion, 1, ".").toUInt());
    std::tuple<uint, uint> tCurrentVersion = std::make_tuple(NO_VERSION_MAJOR, NO_VERSION_MINOR);
    if (tSavedVersion < tCurrentVersion) {
        No::printMessage("Found old config from ZNC " + sSavedVersion + ". Saving a backup of it.");
        backupConfigOnce("pre-" + NoString(NO_VERSION_STR));
    } else if (tSavedVersion > tCurrentVersion) {
        No::printError("Config was saved from ZNC " + sSavedVersion + ". It may or may not work with current ZNC " + noApp->version());
    }

    bindHosts.clear();
    trustedProxies.clear();
    motd.clear();

    // Delete all listeners
    while (!listeners.empty()) {
        delete listeners[0];
        listeners.erase(listeners.begin());
    }

    NoStringMap msModules; // Modules are queued for later loading

    NoStringVector lst;
    config.FindStringVector("loadmodule", lst);
    for (const NoString& sModLine : lst) {
        NoString name = No::token(sModLine, 0);
        NoString args = No::tokens(sModLine, 1);

        if (msModules.find(name) != msModules.end()) {
            error = "Module [" + name + "] already loaded";
            No::printError(error);
            return false;
        }
        NoString sModRet;
        NoModule* pOldMod;

        pOldMod = noApp->loader()->findModule(name);
        if (!pOldMod) {
            No::printAction("Loading global module [" + name + "]");

            bool bModRet = noApp->loader()->loadModule(name, args, No::GlobalModule, nullptr, nullptr, sModRet);

            No::printStatus(bModRet, sModRet);
            if (!bModRet) {
                error = sModRet;
                return false;
            }
        } else if (pOldMod->args() != args) {
            No::printAction("Reloading global module [" + name + "]");

            bool bModRet = noApp->loader()->reloadModule(name, args, nullptr, nullptr, sModRet);

            No::printStatus(bModRet, sModRet);
            if (!bModRet) {
                error = sModRet;
                return false;
            }
        } else
            No::printMessage("Module [" + name + "] already loaded.");

        msModules[name] = args;
    }

    config.FindStringVector("motd", lst);
    for (const NoString& sMotd : lst) {
        noApp->addMotd(sMotd);
    }

    config.FindStringVector("bindhost", lst);
    for (const NoString& host : lst) {
        noApp->addBindHost(host);
    }

    config.FindStringVector("trustedproxy", lst);
    for (const NoString& sProxy : lst) {
        noApp->addTrustedProxy(sProxy);
    }

    config.FindStringVector("vhost", lst);
    for (const NoString& host : lst) {
        noApp->addBindHost(host);
    }

    NoString sVal;
    if (config.FindStringEntry("statusprefix", sVal))
        statusPrefix = sVal;
    if (config.FindStringEntry("sslcertfile", sVal))
        sslCertFile = sVal;
    if (config.FindStringEntry("sslciphers", sVal))
        sslCiphers = sVal;
    if (config.FindStringEntry("skin", sVal))
        skinName = sVal;
    if (config.FindStringEntry("connectdelay", sVal))
        noApp->setConnectDelay(sVal.toUInt());
    if (config.FindStringEntry("serverthrottle", sVal))
        connectThrottle.setExpiration(sVal.toUInt() * 1000);
    if (config.FindStringEntry("anoniplimit", sVal))
        anonIpLimit = sVal.toUInt();
    if (config.FindStringEntry("maxbuffersize", sVal))
        maxBufferSize = sVal.toUInt();
    if (config.FindStringEntry("protectwebsessions", sVal))
        protectWebSessions = sVal.toBool();
    if (config.FindStringEntry("hideversion", sVal))
        hideVersion = sVal.toBool();

    if (config.FindStringEntry("sslprotocols", sslProtocols)) {
        NoStringVector vsProtocols = sslProtocols.split(" ", No::SkipEmptyParts);

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
                disabledSslProtocols &= ~uFlag;
            } else if (bDisable) {
                disabledSslProtocols |= uFlag;
            } else {
                disabledSslProtocols = ~uFlag;
            }
        }
    }

    NoSettings::SubConfig subConf;
    NoSettings::SubConfig::const_iterator subIt;

    config.FindSubConfig("listener", subConf);
    for (subIt = subConf.begin(); subIt != subConf.end(); ++subIt) {
        NoSettings* pSubConf = subIt->second.m_subConfig;
        if (!addListener(pSubConf, error))
            return false;
        if (!pSubConf->empty()) {
            error = "Unhandled lines in Listener config!";
            No::printError(error);

            NoApp::dumpConfig(pSubConf);
            return false;
        }
    }

    config.FindSubConfig("user", subConf);
    for (subIt = subConf.begin(); subIt != subConf.end(); ++subIt) {
        const NoString& userName = subIt->first;
        NoSettings* pSubConf = subIt->second.m_subConfig;
        NoUser* pRealUser = nullptr;

        No::printMessage("Loading user [" + userName + "]");

        // Either create a NoUser* or use an existing one
        std::map<NoString, NoUser*>::iterator it = delUsers.find(userName);

        if (it != delUsers.end()) {
            pRealUser = it->second;
            delUsers.erase(it);
        }

        NoUser* user = new NoUser(userName);

        if (!statusPrefix.empty()) {
            if (!user->setStatusPrefix(statusPrefix)) {
                error = "Invalid StatusPrefix [" + statusPrefix + "] Must be 1-5 chars, no spaces.";
                No::printError(error);
                return false;
            }
        }

        if (!user->parseConfig(pSubConf, error)) {
            No::printError(error);
            delete user;
            user = nullptr;
            return false;
        }

        if (!pSubConf->empty()) {
            error = "Unhandled lines in config for User [" + userName + "]!";
            No::printError(error);

            noApp->dumpConfig(pSubConf);
            return false;
        }

        NoString sErr;
        if (pRealUser) {
            if (!pRealUser->clone(user, sErr) || !noApp->addUser(pRealUser, sErr)) {
                error = "Invalid user [" + user->userName() + "] " + sErr;
                NO_DEBUG("NoUser::Clone() failed in rehash");
            }
            NoUserPrivate::get(user)->beingDeleted = true;
            delete user;
            user = nullptr;
        } else if (!noApp->addUser(user, sErr)) {
            error = "Invalid user [" + user->userName() + "] " + sErr;
        }

        if (!error.empty()) {
            No::printError(error);
            if (user) {
                NoUserPrivate::get(user)->beingDeleted = true;
                delete user;
                user = nullptr;
            }
            return false;
        }

        user = nullptr;
        pRealUser = nullptr;
    }

    if (!config.empty()) {
        error = "Unhandled lines in config!";
        No::printError(error);

        noApp->dumpConfig(&config);
        return false;
    }


    // Unload modules which are no longer in the config
    std::set<NoString> ssUnload;
    for (NoModule* pCurMod : noApp->loader()->modules()) {
        if (msModules.find(pCurMod->name()) == msModules.end())
            ssUnload.insert(pCurMod->name());
    }

    for (const NoString& sMod : ssUnload) {
        if (noApp->loader()->unloadModule(sMod))
            No::printMessage("Unloaded global module [" + sMod + "]");
        else
            No::printMessage("Could not unload [" + sMod + "]");
    }

    if (users.empty()) {
        error = "You must define at least one user in your config.";
        No::printError(error);
        return false;
    }

    if (listeners.empty()) {
        error = "You must supply at least one Listen port in your config.";
        No::printError(error);
        return false;
    }

    return true;
}

void NoApp::dumpConfig(const NoSettings* settings)
{
    NoSettings::EntryMapIterator eit = settings->BeginEntries();
    for (; eit != settings->EndEntries(); ++eit) {
        const NoString& key = eit->first;
        const NoStringVector& lst = eit->second;
        NoStringVector::const_iterator it = lst.begin();
        for (; it != lst.end(); ++it) {
            No::printError(key + " = " + *it);
        }
    }

    NoSettings::SubConfigMapIterator sit = settings->BeginSubConfigs();
    for (; sit != settings->EndSubConfigs(); ++sit) {
        const NoString& key = sit->first;
        const NoSettings::SubConfig& sSub = sit->second;
        NoSettings::SubConfig::const_iterator it = sSub.begin();

        for (; it != sSub.end(); ++it) {
            No::printError("SubConfig [" + key + " " + it->first + "]:");
            dumpConfig(it->second.m_subConfig);
        }
    }
}

void NoApp::clearBindHosts()
{
    d->bindHosts.clear();
}

bool NoApp::addBindHost(const NoString& host)
{
    if (host.empty()) {
        return false;
    }

    for (const NoString& bindHost : d->bindHosts) {
        if (bindHost.equals(host)) {
            return false;
        }
    }

    d->bindHosts.push_back(host);
    return true;
}

bool NoApp::removeBindHost(const NoString& host)
{
    NoStringVector::iterator it;
    for (it = d->bindHosts.begin(); it != d->bindHosts.end(); ++it) {
        if (host.equals(*it)) {
            d->bindHosts.erase(it);
            return true;
        }
    }

    return false;
}

void NoApp::clearTrustedProxies()
{
    d->trustedProxies.clear();
}

bool NoApp::addTrustedProxy(const NoString& host)
{
    if (host.empty()) {
        return false;
    }

    for (const NoString& sTrustedProxy : d->trustedProxies) {
        if (sTrustedProxy.equals(host)) {
            return false;
        }
    }

    d->trustedProxies.push_back(host);
    return true;
}

bool NoApp::removeTrustedProxy(const NoString& host)
{
    NoStringVector::iterator it;
    for (it = d->trustedProxies.begin(); it != d->trustedProxies.end(); ++it) {
        if (host.equals(*it)) {
            d->trustedProxies.erase(it);
            return true;
        }
    }

    return false;
}

void NoApp::broadcast(const NoString& message, bool adminOnly, NoUser* skipUser, NoClient* skipClient)
{
    for (const auto& it : d->users) {
        if (adminOnly && !it.second->isAdmin())
            continue;

        if (it.second != skipUser) {
            NoString msg = message;

            bool bContinue = false;
            USERMODULECALL(onBroadcast(msg), it.second, nullptr, &bContinue);
            if (bContinue)
                continue;

            it.second->putStatusNotice("*** " + msg, nullptr, skipClient);
        }
    }
}

void NoAppPrivate::addBytesRead(ulonglong bytes)
{
    bytesRead += bytes;
}

void NoAppPrivate::addBytesWritten(ulonglong bytes)
{
    bytesWritten += bytes;
}

ulonglong NoApp::bytesRead() const
{
    return d->bytesRead;
}

ulonglong NoApp::bytesWritten() const
{
    return d->bytesWritten;
}

NoModule* NoApp::findModule(const NoString& name, const NoString& username)
{
    if (username.empty()) {
        return noApp->loader()->findModule(name);
    }

    NoUser* user = findUser(username);

    return (!user) ? nullptr : user->loader()->findModule(name);
}

NoModule* NoApp::findModule(const NoString& name, NoUser* user)
{
    if (user) {
        return user->loader()->findModule(name);
    }

    return noApp->loader()->findModule(name);
}

bool NoApp::updateModule(const NoString& name)
{
    NoModule* module;

    std::map<NoUser*, NoString> musLoaded;
    std::map<NoNetwork*, NoString> mnsLoaded;

    // Unload the module for every user and network
    for (const auto& it : d->users) {
        NoUser* user = it.second;

        module = user->loader()->findModule(name);
        if (module) {
            musLoaded[user] = module->args();
            user->loader()->unloadModule(name);
        }

        // See if the user has this module loaded to a network
        std::vector<NoNetwork*> vNetworks = user->networks();
        for (NoNetwork* network : vNetworks) {
            module = network->loader()->findModule(name);
            if (module) {
                mnsLoaded[network] = module->args();
                network->loader()->unloadModule(name);
            }
        }
    }

    // Unload the global module
    bool bGlobal = false;
    NoString sGlobalArgs;

    module = loader()->findModule(name);
    if (module) {
        bGlobal = true;
        sGlobalArgs = module->args();
        loader()->unloadModule(name);
    }

    // Lets reload everything
    bool bError = false;
    NoString sErr;

    // Reload the global module
    if (bGlobal) {
        if (!loader()->loadModule(name, sGlobalArgs, No::GlobalModule, nullptr, nullptr, sErr)) {
            NO_DEBUG("Failed to reload [" << name << "] globally [" << sErr << "]");
            bError = true;
        }
    }

    // Reload the module for all users
    for (const auto& it : musLoaded) {
        NoUser* user = it.first;
        const NoString& args = it.second;

        if (!user->loader()->loadModule(name, args, No::UserModule, user, nullptr, sErr)) {
            NO_DEBUG("Failed to reload [" << name << "] for [" << user->userName() << "] [" << sErr << "]");
            bError = true;
        }
    }

    // Reload the module for all networks
    for (const auto& it : mnsLoaded) {
        NoNetwork* network = it.first;
        const NoString& args = it.second;

        if (!network->loader()->loadModule(name, args, No::NetworkModule, network->user(), network, sErr)) {
            NO_DEBUG("Failed to reload [" << name << "] for [" << network->user()->userName() << "/"
                                          << network->name() << "] [" << sErr << "]");
            bError = true;
        }
    }

    return !bError;
}

NoUser* NoApp::findUser(const NoString& username)
{
    std::map<NoString, NoUser*>::iterator it = d->users.find(username);

    if (it != d->users.end()) {
        return it->second;
    }

    return nullptr;
}

bool NoApp::deleteUser(const NoString& username)
{
    NoUser* user = findUser(username);

    if (!user) {
        return false;
    }

    d->delUsers[user->userName()] = user;
    return true;
}

bool NoApp::addUser(NoUser* user, NoString& error)
{
    if (findUser(user->userName()) != nullptr) {
        error = "User already exists";
        NO_DEBUG("User [" << user->userName() << "] - already exists");
        return false;
    }
    if (!user->isValid(error)) {
        NO_DEBUG("Invalid user [" << user->userName() << "] - [" << error << "]");
        return false;
    }
    bool bFailed = false;
    GLOBALMODULECALL(onAddUser(user, error), &bFailed);
    if (bFailed) {
        NO_DEBUG("AddUser [" << user->userName() << "] aborted by a module [" << error << "]");
        return false;
    }
    d->users[user->userName()] = user;
    return true;
}

std::map<NoString, NoUser*> NoApp::userMap() const
{
    return (d->users);
}

NoListener* NoApp::findListener(u_short port, const NoString& host, No::AddressType addressType)
{
    for (NoListener* pListener : d->listeners) {
        if (pListener->port() != port)
            continue;
        if (pListener->host() != host)
            continue;
        if (pListener->addressType() != addressType)
            continue;
        return pListener;
    }
    return nullptr;
}

bool NoAppPrivate::addListener(const NoString& line, NoString& error)
{
    NoString name = No::token(line, 0);
    NoString value = No::tokens(line, 1);

    No::AddressType addressType = No::Ipv4AndIpv6Address;
    if (name.equals("Listen4") || name.equals("Listen") || name.equals("Listener4")) {
        addressType = No::Ipv4Address;
    }
    if (name.equals("Listener6")) {
        addressType = No::Ipv6Address;
    }

    No::AcceptType acceptType = No::AcceptAll;
    if (value.trimPrefix("irc_only "))
        acceptType = No::AcceptIrc;
    else if (value.trimPrefix("web_only "))
        acceptType = No::AcceptHttp;

    bool ssl = false;
    NoString sPort;
    NoString bindHost;

    if (No::Ipv4Address == addressType) {
        value.replace(":", " ");
    }

    if (value.contains(" ")) {
        bindHost = No::token(value, 0, " ");
        sPort = No::tokens(value, 1, " ");
    } else {
        sPort = value;
    }

    if (sPort.left(1) == "+") {
        sPort.leftChomp(1);
        ssl = true;
    }

    // No support for URIPrefix for old-style configs.
    NoString uriPrefix;
    ushort port = sPort.toUShort();
    return noApp->addListener(port, bindHost, uriPrefix, ssl, addressType, acceptType, error);
}

bool NoApp::addListener(ushort port,
                        const NoString& bindHost,
                        const NoString& sURIPrefixRaw,
                        bool ssl,
                        No::AddressType addressType,
                        No::AcceptType acceptType,
                        NoString& error)
{
    NoString sHostComment;

    if (!bindHost.empty()) {
        sHostComment = " on host [" + bindHost + "]";
    }

    NoString sIPV6Comment;

    switch (addressType) {
    case No::Ipv4AndIpv6Address:
        sIPV6Comment = "";
        break;
    case No::Ipv4Address:
        sIPV6Comment = " using ipv4";
        break;
    case No::Ipv6Address:
        sIPV6Comment = " using ipv6";
    }

    No::printAction("Binding to port [" + NoString((ssl) ? "+" : "") + NoString(port) + "]" + sHostComment + sIPV6Comment);

#ifndef HAVE_IPV6
    if (ADDR_IPV6ONLY == addressType) {
        error = "IPV6 is not enabled";
        No::PrintStatus(false, error);
        return false;
    }
#endif

#ifndef HAVE_LIBSSL
    if (ssl) {
        error = "SSL is not enabled";
        No::PrintStatus(false, error);
        return false;
    }
#else
    NoString sPemFile = pemLocation();

    if (ssl && !NoFile::Exists(sPemFile)) {
        error = "Unable to locate pem file: [" + sPemFile + "]";
        No::printStatus(false, error);

        // If stdin is e.g. /dev/null and we call GetBoolInput(),
        // we are stuck in an endless loop!
        if (isatty(0) && No::getBoolInput("Would you like to create a new pem file?", true)) {
            error.clear();
            writePemFile();
        } else {
            return false;
        }

        No::printAction("Binding to port [+" + NoString(port) + "]" + sHostComment + sIPV6Comment);
    }
#endif
    if (!port) {
        error = "Invalid port";
        No::printStatus(false, error);
        return false;
    }

    // URIPrefix must start with a slash and end without one.
    NoString uriPrefix = NoString(sURIPrefixRaw);
    if (!uriPrefix.empty()) {
        if (!uriPrefix.startsWith("/")) {
            uriPrefix = "/" + uriPrefix;
        }
        if (uriPrefix.endsWith("/")) {
            uriPrefix.trimRight("/");
        }
    }

    NoListener* pListener = new NoListener(bindHost, port);
    pListener->setUriPrefix(uriPrefix);
    pListener->setSsl(ssl);
    pListener->setAddressType(addressType);
    pListener->setAcceptType(acceptType);

    if (!pListener->listen()) {
        error = FormatBindError();
        No::printStatus(false, error);
        delete pListener;
        return false;
    }

    d->listeners.push_back(pListener);
    No::printStatus(true);

    return true;
}

bool NoAppPrivate::addListener(NoSettings* settings, NoString& error)
{
    NoString bindHost;
    NoString uriPrefix;
    bool ssl = false;
    bool ipv4 = true;
#ifdef HAVE_IPV6
    bool ipv6 = true;
#else
    bool ipv6 = false;
#endif
    bool irc = false;
    bool web = false;
    ushort port;
    if (!settings->FindUShortEntry("port", port)) {
        error = "No port given";
        No::printError(error);
        return false;
    }
    settings->FindStringEntry("host", bindHost);
    settings->FindBoolEntry("ssl", ssl, false);
    settings->FindBoolEntry("ipv4", ipv4, true);
    settings->FindBoolEntry("ipv6", ipv6, ipv6);
    settings->FindBoolEntry("allowirc", irc, true);
    settings->FindBoolEntry("allowweb", web, true);
    settings->FindStringEntry("uriprefix", uriPrefix);

    No::AddressType addressType;
    if (ipv4 && ipv6) {
        addressType = No::Ipv4AndIpv6Address;
    } else if (ipv4 && !ipv6) {
        addressType = No::Ipv4Address;
    } else if (!ipv4 && ipv6) {
        addressType = No::Ipv6Address;
    } else {
        error = "No address family given";
        No::printError(error);
        return false;
    }

    No::AcceptType acceptType;
    if (irc && web) {
        acceptType = No::AcceptAll;
    } else if (irc && !web) {
        acceptType = No::AcceptIrc;
    } else if (!irc && web) {
        acceptType = No::AcceptHttp;
    } else {
        error = "Either Web or IRC or both should be selected";
        No::printError(error);
        return false;
    }

    return noApp->addListener(port, bindHost, uriPrefix, ssl, addressType, acceptType, error);
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

    d->listeners.push_back(pListener);
    return true;
}

bool NoApp::removeListener(NoListener* pListener)
{
    auto it = std::find(d->listeners.begin(), d->listeners.end(), pListener);
    if (it != d->listeners.end()) {
        d->listeners.erase(it);
        delete pListener;
        return true;
    }

    return false;
}

void NoApp::setMotd(const NoString& message)
{
    clearMotd();
    addMotd(message);
}

void NoApp::addMotd(const NoString& message)
{
    if (!message.empty()) {
        d->motd.push_back(message);
    }
}

void NoApp::clearMotd()
{
    d->motd.clear();
}

NoStringVector NoApp::motd() const
{
    return d->motd;
}

void NoApp::addServerThrottle(const NoString& name)
{
    d->connectThrottle.insert(name, true);
}

bool NoApp::serverThrottle(const NoString& name)
{
    return d->connectThrottle.value(name);
}

NoApp* NoApp::instance()
{
    return NoAppPrivate::instance;
}

NoApp::TrafficStatsMap NoApp::trafficStats(TrafficStatsPair& Users, TrafficStatsPair& ZNC, TrafficStatsPair& Total)
{
    TrafficStatsMap ret;
    ulonglong uiUsers_in, uiUsers_out, uiZNC_in, uiZNC_out;
    const std::map<NoString, NoUser*>& msUsers = noApp->userMap();

    uiUsers_in = uiUsers_out = 0;
    uiZNC_in = bytesRead();
    uiZNC_out = bytesWritten();

    for (const auto& it : msUsers) {
        ret[it.first] = TrafficStatsPair(it.second->bytesRead(), it.second->bytesWritten());
        uiUsers_in += it.second->bytesRead();
        uiUsers_out += it.second->bytesWritten();
    }

    for (NoSocket* socket : d->manager.sockets()) {
        NoUser* user = nullptr;
        if (socket->name().left(5) == "IRC::") {
            user = ((NoIrcSocket*)socket)->network()->user();
        } else if (socket->name().left(5) == "USR::") {
            user = ((NoClient*)socket)->user();
        }

        if (user) {
            ret[user->userName()].first += socket->bytesRead();
            ret[user->userName()].second += socket->bytesWritten();
            uiUsers_in += socket->bytesRead();
            uiUsers_out += socket->bytesWritten();
        } else {
            uiZNC_in += socket->bytesRead();
            uiZNC_out += socket->bytesWritten();
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

    NoUser* user = findUser(AuthClass->username());

    if (!user || !user->checkPass(AuthClass->password())) {
        AuthClass->refuseLogin("Invalid Password");
        return;
    }

    NoString host;
    NoSocket* socket = AuthClass->socket();
    if (socket)
        host = socket->remoteAddress();

    if (!user->isHostAllowed(host)) {
        AuthClass->refuseLogin("Your host [" + host + "] is not allowed");
        return;
    }

    AuthClass->acceptLogin(user);
}

void NoApp::setConfigState(NoApp::ConfigState e)
{
    d->configState = e;
}

void NoApp::setSkinName(const NoString& s)
{
    d->skinName = s;
}

void NoApp::setStatusPrefix(const NoString& s)
{
    d->statusPrefix = (s.empty()) ? "*" : s;
}

void NoApp::setMaxBufferSize(uint i)
{
    d->maxBufferSize = i;
}

void NoApp::setAnonIpLimit(uint i)
{
    d->anonIpLimit = i;
}

void NoApp::setServerThrottle(uint i)
{
    d->connectThrottle.setExpiration(i * 1000);
}

void NoApp::setProtectWebSessions(bool b)
{
    d->protectWebSessions = b;
}

void NoApp::setHideVersion(bool b)
{
    d->hideVersion = b;
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
        NoAppPrivate::get(NoApp::instance())->leakConnectQueueTimer(this);
    }

protected:
    void RunJob() override
    {
        std::list<NoNetwork*> ConnectionQueue;
        std::list<NoNetwork*>& RealConnectionQueue = NoAppPrivate::get(NoApp::instance())->connectQueue;

        // Problem: If a network can't connect right now because e.g. it
        // is throttled, it will re-insert itself into the connection
        // queue. However, we must only give each network a single
        // chance during this timer run.
        //
        // Solution: We move the connection queue to our local list at
        // the beginning and work from that.
        ConnectionQueue.swap(RealConnectionQueue);

        while (!ConnectionQueue.empty()) {
            NoNetwork* network = ConnectionQueue.front();
            ConnectionQueue.pop_front();

            if (network->connect()) {
                break;
            }
        }

        /* Now re-insert anything that is left in our local list into
         * the real connection queue.
         */
        RealConnectionQueue.splice(RealConnectionQueue.begin(), ConnectionQueue);

        if (RealConnectionQueue.empty()) {
            NO_DEBUG("ConnectQueueTimer done");
            NoAppPrivate::get(NoApp::instance())->disableConnectQueue();
        }
    }
};

void NoApp::setConnectDelay(uint i)
{
    if (i < 1) {
        // Don't hammer server with our failed connects
        i = 1;
    }
    if (d->connectDelay != i && d->connectQueueTimer != nullptr) {
        d->connectQueueTimer->Start(i);
    }
    d->connectDelay = i;
}

NoApp::ConfigState NoApp::configState() const
{
    return d->configState;
}

NoSocketManager* NoApp::manager() const
{
    return &d->manager;
}

NoModuleLoader* NoApp::loader() const
{
    return d->modules;
}

NoString NoApp::skinName() const
{
    return d->skinName;
}

NoString NoApp::statusPrefix() const
{
    return d->statusPrefix;
}

void NoAppPrivate::enableConnectQueue()
{
    if (!connectQueueTimer && !connectPaused && !connectQueue.empty()) {
        connectQueueTimer = new NoConnectQueueTimer(connectDelay);
        manager.addCron(connectQueueTimer);
    }
}

void NoAppPrivate::disableConnectQueue()
{
    if (connectQueueTimer) {
        // This will kill the cron
        connectQueueTimer->Stop();
        connectQueueTimer = nullptr;
    }
}

void NoApp::pauseConnectQueue()
{
    NO_DEBUG("Connection queue paused");
    d->connectPaused++;

    if (d->connectQueueTimer) {
        d->connectQueueTimer->Pause();
    }
}

void NoApp::resumeConnectQueue()
{
    NO_DEBUG("Connection queue resumed");
    d->connectPaused--;

    d->enableConnectQueue();
    if (d->connectQueueTimer) {
        d->connectQueueTimer->UnPause();
    }
}

void NoApp::addNetworkToQueue(NoNetwork* network)
{
    // Make sure we are not already in the queue
    if (std::find(d->connectQueue.begin(), d->connectQueue.end(), network) != d->connectQueue.end()) {
        return;
    }

    d->connectQueue.push_back(network);
    d->enableConnectQueue();
}

void NoAppPrivate::leakConnectQueueTimer(NoConnectQueueTimer* timer)
{
    if (connectQueueTimer == timer)
        connectQueueTimer = nullptr;
}

bool NoApp::waitForChildLock()
{
    return d->lockFile && d->lockFile->ExLock();
}
