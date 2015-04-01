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

#include "nosocketmanager.h"
#include "nosocket.h"
#include "nosocket_p.h"
#include "nothread.h"
#include "nothread_p.h"
#include "nojob.h"
#include "noapp.h"
#include "Csocket/Csocket.h"
#include <algorithm>
#include <random>

#ifdef HAVE_LIBSSL
extern const char* ZNC_DefaultCipher;
#endif

#ifdef HAVE_PTHREAD
class NoDnsMonitorFD : public CSMonitorFD
{
public:
    NoDnsMonitorFD()
    {
        Add(NoThreadPrivate::get()->getReadFD(), CSocketManager::ECT_Read);
    }

    bool FDsThatTriggered(const std::map<int, short>& miiReadyFds) override
    {
        if (miiReadyFds.find(NoThreadPrivate::get()->getReadFD())->second) {
            NoThreadPrivate::get()->handlePipeReadable();
        }
        return true;
    }
};
#endif

#ifdef HAVE_THREADED_DNS
struct NoDnsTask
{
    NoDnsTask()
        : hostname(""),
          iPort(0),
          sSockName(""),
          iTimeout(0),
          ssl(false),
          sBindhost(""),
          pcSock(nullptr),
          bDoneTarget(false),
          bDoneBind(false),
          aiTarget(nullptr),
          aiBind(nullptr)
    {
    }

    NoDnsTask(const NoDnsTask&) = delete;
    NoDnsTask& operator=(const NoDnsTask&) = delete;

    NoString hostname;
    u_short iPort;
    NoString sSockName;
    int iTimeout;
    bool ssl;
    NoString sBindhost;
    NoSocket* pcSock;

    bool bDoneTarget;
    bool bDoneBind;
    addrinfo* aiTarget;
    addrinfo* aiBind;
};
class NoDnsJob : public NoJob
{
public:
    NoDnsJob() : hostname(""), task(nullptr), pManager(nullptr), bBind(false), iRes(0), aiResult(nullptr)
    {
    }

    NoDnsJob(const NoDnsJob&) = delete;
    NoDnsJob& operator=(const NoDnsJob&) = delete;

    NoString hostname;
    NoDnsTask* task;
    NoSocketManager* pManager;
    bool bBind;

    int iRes;
    addrinfo* aiResult;

    void run() override;
    void finished() override;
};

static void StartTDNSThread(NoSocketManager* manager, NoDnsTask* task, bool bBind);
static void SetTDNSThreadFinished(NoSocketManager* manager, NoDnsTask* task, bool bBind, addrinfo* aiResult);
static void FinishConnect(NoSocketManager* manager,
                          const NoString& hostname,
                          u_short iPort,
                          const NoString& sSockName,
                          int iTimeout,
                          bool ssl,
                          const NoString& bindHost,
                          NoSocket* pcSock);
#endif

NoSocketManager::NoSocketManager() : m_instance(new CSocketManager)
{
#ifdef HAVE_PTHREAD
    m_instance->MonitorFD(new NoDnsMonitorFD());
#endif
}

NoSocketManager::~NoSocketManager()
{
}

bool NoSocketManager::listenHost(u_short iPort,
                                 const NoString& sSockName,
                                 const NoString& bindHost,
                                 bool ssl,
                                 int iMaxConns,
                                 NoSocket* pcSock,
                                 u_int iTimeout,
                                 No::AddressType addressType)
{
    CSListener L(iPort, bindHost);

    L.SetSockName(sSockName);
    L.SetIsSSL(ssl);
    L.SetTimeout(iTimeout);
    L.SetMaxConns(iMaxConns);

#ifdef HAVE_IPV6
    switch (addressType) {
    case No::Ipv4Address:
        L.SetAFRequire(CSSockAddr::RAF_INET);
        break;
    case No::Ipv6Address:
        L.SetAFRequire(CSSockAddr::RAF_INET6);
        break;
    case No::Ipv4AndIpv6Address:
        L.SetAFRequire(CSSockAddr::RAF_ANY);
        break;
    }
#endif

    return m_instance->Listen(L, NoSocketPrivate::get(pcSock));
}

bool NoSocketManager::listenAll(u_short iPort, const NoString& sSockName, bool ssl, int iMaxConns, NoSocket* pcSock, u_int iTimeout, No::AddressType addressType)
{
    return listenHost(iPort, sSockName, "", ssl, iMaxConns, pcSock, iTimeout, addressType);
}

u_short NoSocketManager::listenRand(const NoString& sSockName,
                                    const NoString& bindHost,
                                    bool ssl,
                                    int iMaxConns,
                                    NoSocket* pcSock,
                                    u_int iTimeout,
                                    No::AddressType addressType)
{
    ushort port = 0;
    CSListener L(0, bindHost);

    L.SetSockName(sSockName);
    L.SetIsSSL(ssl);
    L.SetTimeout(iTimeout);
    L.SetMaxConns(iMaxConns);

#ifdef HAVE_IPV6
    switch (addressType) {
    case No::Ipv4Address:
        L.SetAFRequire(CSSockAddr::RAF_INET);
        break;
    case No::Ipv6Address:
        L.SetAFRequire(CSSockAddr::RAF_INET6);
        break;
    case No::Ipv4AndIpv6Address:
        L.SetAFRequire(CSSockAddr::RAF_ANY);
        break;
    }
#endif

    m_instance->Listen(L, NoSocketPrivate::get(pcSock), &port);

    return port;
}

u_short NoSocketManager::listenAllRand(const NoString& sSockName, bool ssl, int iMaxConns, NoSocket* pcSock, u_int iTimeout, No::AddressType addressType)
{
    return listenRand(sSockName, "", ssl, iMaxConns, pcSock, iTimeout, addressType);
}

void NoSocketManager::connect(const NoString& hostname,
                              u_short iPort,
                              const NoString& sSockName,
                              int iTimeout,
                              bool ssl,
                              const NoString& bindHost,
                              NoSocket* pcSock)
{
    if (pcSock) {
        pcSock->setHostToVerifySsl(hostname);
    }
#ifdef HAVE_THREADED_DNS
    NO_DEBUG("TDNS: initiating resolving of [" << hostname << "] and bindhost [" << bindHost << "]");
    NoDnsTask* task = new NoDnsTask;
    task->hostname = hostname;
    task->iPort = iPort;
    task->sSockName = sSockName;
    task->iTimeout = iTimeout;
    task->ssl = ssl;
    task->sBindhost = bindHost;
    task->pcSock = pcSock;
    if (bindHost.empty()) {
        task->bDoneBind = true;
    } else {
        StartTDNSThread(this, task, true);
    }
    StartTDNSThread(this, task, false);
#else // HAVE_THREADED_DNS
    // Just let Csocket handle DNS itself
    FinishConnect(this, hostname, iPort, sSockName, iTimeout, ssl, bindHost, pcSock);
#endif
}

std::vector<NoSocket*> NoSocketManager::sockets() const
{
    return m_sockets;
}

std::vector<NoSocket*> NoSocketManager::findSockets(const NoString& name)
{
    std::vector<NoSocket*> sockets;
    for (NoSocket* socket : m_sockets) {
        if (socket->name() == name)
            sockets.push_back(socket);
    }
    return sockets;
}

uint NoSocketManager::anonConnectionCount(const NoString& address) const
{
    uint ret = 0;

    for (Csock* socket : *m_instance) {
        // Logged in NoClients have "USR::<username>" as their sockname
        if (socket->GetType() == Csock::INBOUND && socket->GetRemoteIP() == address &&
            socket->GetSockName().left(5) != "USR::") {
            ret++;
        }
    }

    NO_DEBUG("There are [" << ret << "] clients from [" << address << "]");

    return ret;
}

void NoSocketManager::cleanup()
{
    m_instance->Cleanup();
}

void NoSocketManager::dynamicSelectLoop(uint64_t iLowerBounds, uint64_t iUpperBounds, time_t iMaxResolution)
{
    m_instance->DynamicSelectLoop(iLowerBounds, iUpperBounds, iMaxResolution);
}

void NoSocketManager::addSocket(NoSocket* pcSock, const NoString& sSockName)
{
    m_sockets.push_back(pcSock);
    m_instance->AddSock(NoSocketPrivate::get(pcSock), sSockName);
}

void NoSocketManager::removeSocket(NoSocket* socket)
{
    auto it = std::find(m_sockets.begin(), m_sockets.end(), socket);
    if (it != m_sockets.end())
        m_sockets.erase(it);
    m_instance->DelSockByAddr(NoSocketPrivate::get(socket));
}

bool NoSocketManager::swapSocket(Csock* newSocket, Csock* originalSocket)
{
    return m_instance->SwapSockByAddr(newSocket, originalSocket);
}

void NoSocketManager::addCron(CCron* cron)
{
    m_instance->AddCron(cron);
}

void NoSocketManager::removeCron(CCron* cron)
{
    m_instance->DelCronByAddr(cron);
}

void NoSocketManager::doConnect(const CSConnection& cCon, Csock* pcSock)
{
    m_instance->Connect(cCon, pcSock);
}

#ifdef HAVE_THREADED_DNS
void NoDnsJob::run()
{
    int iCount = 0;
    while (true) {
        addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_ADDRCONFIG;
        iRes = getaddrinfo(hostname.c_str(), nullptr, &hints, &aiResult);
        if (EAGAIN != iRes) {
            break;
        }

        iCount++;
        if (iCount > 5) {
            iRes = ETIMEDOUT;
            break;
        }
        sleep(5); // wait 5 seconds before next try
    }
}

void NoDnsJob::finished()
{
    if (0 != this->iRes) {
        NO_DEBUG("Error in threaded DNS: " << gai_strerror(this->iRes));
        if (this->aiResult) {
            NO_DEBUG("And aiResult is not nullptr...");
        }
        this->aiResult = nullptr; // just for case. Maybe to call freeaddrinfo()?
    }
    SetTDNSThreadFinished(this->pManager, this->task, this->bBind, this->aiResult);
}

void StartTDNSThread(NoSocketManager* manager, NoDnsTask* task, bool bBind)
{
    NoString hostname = bBind ? task->sBindhost : task->hostname;
    NoDnsJob* arg = new NoDnsJob;
    arg->hostname = hostname;
    arg->task = task;
    arg->bBind = bBind;
    arg->pManager = manager;

    NoThread::run(arg);
}

static NoString RandomFromSet(const NoStringSet& sSet, std::default_random_engine& gen)
{
    std::uniform_int_distribution<> distr(0, sSet.size() - 1);
    auto it = sSet.cbegin();
    std::advance(it, distr(gen));
    return *it;
}

static std::tuple<NoString, bool>
RandomFrom2SetsWithBias(const NoStringSet& ss4, const NoStringSet& ss6, std::default_random_engine& gen)
{
    // It's not quite what RFC says how to choose between IPv4 and IPv6, but proper way is harder to implement.
    // It would require to maintain some state between Csock objects.
    bool bUseIPv6;
    if (ss4.empty()) {
        bUseIPv6 = true;
    } else if (ss6.empty()) {
        bUseIPv6 = false;
    } else {
        // Let's prefer IPv6 :)
        std::discrete_distribution<> d({ 2, 3 });
        bUseIPv6 = d(gen);
    }
    const NoStringSet& sSet = bUseIPv6 ? ss6 : ss4;
    return std::make_tuple(RandomFromSet(sSet, gen), bUseIPv6);
}

void SetTDNSThreadFinished(NoSocketManager* manager, NoDnsTask* task, bool bBind, addrinfo* aiResult)
{
    if (bBind) {
        task->aiBind = aiResult;
        task->bDoneBind = true;
    } else {
        task->aiTarget = aiResult;
        task->bDoneTarget = true;
    }

    // Now that something is done, check if everything we needed is done
    if (!task->bDoneBind || !task->bDoneTarget) {
        return;
    }

    // All needed DNS is done, now collect the results
    NoStringSet ssTargets4;
    NoStringSet ssTargets6;
    for (addrinfo* ai = task->aiTarget; ai; ai = ai->ai_next) {
        char s[INET6_ADDRSTRLEN] = {};
        getnameinfo(ai->ai_addr, ai->ai_addrlen, s, sizeof(s), nullptr, 0, NI_NUMERICHOST);
        switch (ai->ai_family) {
        case AF_INET:
            ssTargets4.insert(s);
            break;
#ifdef HAVE_IPV6
        case AF_INET6:
            ssTargets6.insert(s);
            break;
#endif
        }
    }
    NoStringSet ssBinds4;
    NoStringSet ssBinds6;
    for (addrinfo* ai = task->aiBind; ai; ai = ai->ai_next) {
        char s[INET6_ADDRSTRLEN] = {};
        getnameinfo(ai->ai_addr, ai->ai_addrlen, s, sizeof(s), nullptr, 0, NI_NUMERICHOST);
        switch (ai->ai_family) {
        case AF_INET:
            ssBinds4.insert(s);
            break;
#ifdef HAVE_IPV6
        case AF_INET6:
            ssBinds6.insert(s);
            break;
#endif
        }
    }
    if (task->aiTarget)
        freeaddrinfo(task->aiTarget);
    if (task->aiBind)
        freeaddrinfo(task->aiBind);

    NoString sBindhost;
    NoString sTargetHost;
    std::random_device rd;
    std::default_random_engine gen(rd());

    try {
        if (ssTargets4.empty() && ssTargets6.empty()) {
            throw "Can't resolve server hostname";
        } else if (task->sBindhost.empty()) {
            // Choose random target
            std::tie(sTargetHost, std::ignore) = RandomFrom2SetsWithBias(ssTargets4, ssTargets6, gen);
        } else if (ssBinds4.empty() && ssBinds6.empty()) {
            throw "Can't resolve bind hostname. Try /znc ClearBindHost and /znc ClearUserBindHost";
        } else if (ssBinds4.empty()) {
            if (ssTargets6.empty()) {
                throw "Server address is IPv4-only, but bindhost is IPv6-only";
            } else {
                // Choose random target and bindhost from IPv6-only sets
                sTargetHost = RandomFromSet(ssTargets6, gen);
                sBindhost = RandomFromSet(ssBinds6, gen);
            }
        } else if (ssBinds6.empty()) {
            if (ssTargets4.empty()) {
                throw "Server address is IPv6-only, but bindhost is IPv4-only";
            } else {
                // Choose random target and bindhost from IPv4-only sets
                sTargetHost = RandomFromSet(ssTargets4, gen);
                sBindhost = RandomFromSet(ssBinds4, gen);
            }
        } else {
            // Choose random target
            bool bUseIPv6;
            std::tie(sTargetHost, bUseIPv6) = RandomFrom2SetsWithBias(ssTargets4, ssTargets6, gen);
            // Choose random bindhost matching chosen target
            const NoStringSet& ssBinds = bUseIPv6 ? ssBinds6 : ssBinds4;
            sBindhost = RandomFromSet(ssBinds, gen);
        }

        NO_DEBUG("TDNS: " << task->sSockName << ", connecting to [" << sTargetHost << "] using bindhost [" << sBindhost << "]");
        FinishConnect(manager, sTargetHost, task->iPort, task->sSockName, task->iTimeout, task->ssl, sBindhost, task->pcSock);
    } catch (const char* s) {
        NO_DEBUG(task->sSockName << ", dns resolving error: " << s);
        task->pcSock->setName(task->sSockName);
        NoSocketPrivate::get(task->pcSock)->SockError(-1, s);
        delete task->pcSock;
    }

    delete task;
}
#endif // HAVE_THREADED_DNS

void FinishConnect(NoSocketManager* manager,
                   const NoString& hostname,
                   u_short iPort,
                   const NoString& sSockName,
                   int iTimeout,
                   bool ssl,
                   const NoString& bindHost,
                   NoSocket* pcSock)
{
    CSConnection C(hostname, iPort, iTimeout);

    C.SetSockName(sSockName);
    C.SetIsSSL(ssl);
    C.SetBindHost(bindHost);
#ifdef HAVE_LIBSSL
    NoString sCipher = noApp->sslCiphers();
    if (sCipher.empty()) {
        sCipher = ZNC_DefaultCipher;
    }
    C.SetCipher(sCipher);
#endif

    manager->doConnect(C, NoSocketPrivate::get(pcSock));
}
