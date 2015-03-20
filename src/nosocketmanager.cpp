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

#include "nosocketmanager.h"
#include "nosocket.h"
#include "nothreads.h"
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
    NoDnsMonitorFD() { Add(NoThreadPool::Get().getReadFD(), CSocketManager::ECT_Read); }

    bool FDsThatTriggered(const std::map<int, short>& miiReadyFds) override
    {
        if (miiReadyFds.find(NoThreadPool::Get().getReadFD())->second) {
            NoThreadPool::Get().handlePipeReadable();
        }
        return true;
    }
};
#endif

#ifdef HAVE_THREADED_DNS
struct NoDnsTask
{
    NoDnsTask()
        : sHostname(""), iPort(0), sSockName(""), iTimeout(0), bSSL(false), sBindhost(""), pcSock(nullptr),
          bDoneTarget(false), bDoneBind(false), aiTarget(nullptr), aiBind(nullptr)
    {
    }

    NoDnsTask(const NoDnsTask&) = delete;
    NoDnsTask& operator=(const NoDnsTask&) = delete;

    NoString sHostname;
    u_short iPort;
    NoString sSockName;
    int iTimeout;
    bool bSSL;
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
    NoDnsJob() : sHostname(""), task(nullptr), pManager(nullptr), bBind(false), iRes(0), aiResult(nullptr) {}

    NoDnsJob(const NoDnsJob&) = delete;
    NoDnsJob& operator=(const NoDnsJob&) = delete;

    NoString sHostname;
    NoDnsTask* task;
    NoSocketManager* pManager;
    bool bBind;

    int iRes;
    addrinfo* aiResult;

    void runThread() override;
    void runMain() override;
};

static void StartTDNSThread(NoSocketManager* manager, NoDnsTask* task, bool bBind);
static void SetTDNSThreadFinished(NoSocketManager* manager, NoDnsTask* task, bool bBind, addrinfo* aiResult);
static void* TDNSThread(void* argument);
static void FinishConnect(NoSocketManager* manager, const NoString& sHostname, u_short iPort, const NoString& sSockName, int iTimeout, bool bSSL, const NoString& sBindHost, NoSocket* pcSock);
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

bool NoSocketManager::ListenHost(u_short iPort,
                const NoString& sSockName,
                const NoString& sBindHost,
                bool bSSL,
                int iMaxConns,
                NoSocket* pcSock,
                u_int iTimeout,
                No::AddressType eAddr)
{
    CSListener L(iPort, sBindHost);

    L.SetSockName(sSockName);
    L.SetIsSSL(bSSL);
    L.SetTimeout(iTimeout);
    L.SetMaxConns(iMaxConns);

#ifdef HAVE_IPV6
    switch (eAddr) {
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

    return m_instance->Listen(L, pcSock->GetHandle());
}

bool NoSocketManager::ListenAll(u_short iPort,
               const NoString& sSockName,
               bool bSSL,
               int iMaxConns,
               NoSocket* pcSock,
               u_int iTimeout,
               No::AddressType eAddr)
{
    return ListenHost(iPort, sSockName, "", bSSL, iMaxConns, pcSock, iTimeout, eAddr);
}

u_short NoSocketManager::ListenRand(const NoString& sSockName,
                   const NoString& sBindHost,
                   bool bSSL,
                   int iMaxConns,
                   NoSocket* pcSock,
                   u_int iTimeout,
                   No::AddressType eAddr)
{
    ushort uPort = 0;
    CSListener L(0, sBindHost);

    L.SetSockName(sSockName);
    L.SetIsSSL(bSSL);
    L.SetTimeout(iTimeout);
    L.SetMaxConns(iMaxConns);

#ifdef HAVE_IPV6
    switch (eAddr) {
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

    m_instance->Listen(L, pcSock->GetHandle(), &uPort);

    return uPort;
}

u_short NoSocketManager::ListenAllRand(const NoString& sSockName,
                      bool bSSL,
                      int iMaxConns,
                      NoSocket* pcSock,
                      u_int iTimeout,
                      No::AddressType eAddr)
{
    return ListenRand(sSockName, "", bSSL, iMaxConns, pcSock, iTimeout, eAddr);
}

void NoSocketManager::Connect(const NoString& sHostname, u_short iPort, const NoString& sSockName, int iTimeout, bool bSSL, const NoString& sBindHost, NoSocket* pcSock)
{
    if (pcSock) {
        pcSock->SetHostToVerifySSL(sHostname);
    }
#ifdef HAVE_THREADED_DNS
    NO_DEBUG("TDNS: initiating resolving of [" << sHostname << "] and bindhost [" << sBindHost << "]");
    NoDnsTask* task = new NoDnsTask;
    task->sHostname = sHostname;
    task->iPort = iPort;
    task->sSockName = sSockName;
    task->iTimeout = iTimeout;
    task->bSSL = bSSL;
    task->sBindhost = sBindHost;
    task->pcSock = pcSock;
    if (sBindHost.empty()) {
        task->bDoneBind = true;
    } else {
        StartTDNSThread(this, task, true);
    }
    StartTDNSThread(this, task, false);
#else /* HAVE_THREADED_DNS */
    // Just let Csocket handle DNS itself
    FinishConnect(this, sHostname, iPort, sSockName, iTimeout, bSSL, sBindHost, pcSock);
#endif
}

std::vector<NoSocket*> NoSocketManager::GetSockets() const
{
    return m_sockets;
}

std::vector<NoSocket*> NoSocketManager::FindSocksByName(const NoString& sName)
{
    std::vector<NoSocket*> sockets;
    for (NoSocket* socket : m_sockets) {
        if (socket->GetSockName() == sName)
            sockets.push_back(socket);
    }
    return sockets;
}

uint NoSocketManager::GetAnonConnectionCount(const NoString& sIP) const
{
    uint ret = 0;

    for (Csock* pSock : *m_instance) {
        // Logged in NoClients have "USR::<username>" as their sockname
        if (pSock->GetType() == Csock::INBOUND && pSock->GetRemoteIP() == sIP &&
            pSock->GetSockName().left(5) != "USR::") {
            ret++;
        }
    }

    NO_DEBUG("There are [" << ret << "] clients from [" << sIP << "]");

    return ret;
}

void NoSocketManager::Cleanup()
{
    m_instance->Cleanup();
}

void NoSocketManager::DynamicSelectLoop(uint64_t iLowerBounds, uint64_t iUpperBounds, time_t iMaxResolution)
{
    m_instance->DynamicSelectLoop(iLowerBounds, iUpperBounds, iMaxResolution);
}

void NoSocketManager::AddSock(NoSocket* pcSock, const NoString& sSockName)
{
    m_sockets.push_back(pcSock);
    m_instance->AddSock(pcSock->GetHandle(), sSockName);
}

void NoSocketManager::DelSockByAddr(NoSocket* socket)
{
    auto it = std::find(m_sockets.begin(), m_sockets.end(), socket);
    if (it != m_sockets.end())
        m_sockets.erase(it);
    m_instance->DelSockByAddr(socket->GetHandle());
    delete socket;
}

bool NoSocketManager::SwapSockByAddr(Csock* newSocket, Csock* originalSocket)
{
    return m_instance->SwapSockByAddr(newSocket, originalSocket);
}

void NoSocketManager::AddCron(CCron* cron)
{
    m_instance->AddCron(cron);
}

void NoSocketManager::DelCronByAddr(CCron* cron)
{
    m_instance->DelCronByAddr(cron);
}

void NoSocketManager::DoConnect(const CSConnection& cCon, Csock* pcSock)
{
    m_instance->Connect(cCon, pcSock);
}

#ifdef HAVE_THREADED_DNS
void NoDnsJob::runThread()
{
    int iCount = 0;
    while (true) {
        addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_ADDRCONFIG;
        iRes = getaddrinfo(sHostname.c_str(), nullptr, &hints, &aiResult);
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

void NoDnsJob::runMain()
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
    NoString sHostname = bBind ? task->sBindhost : task->sHostname;
    NoDnsJob* arg = new NoDnsJob;
    arg->sHostname = sHostname;
    arg->task = task;
    arg->bBind = bBind;
    arg->pManager = manager;

    NoThreadPool::Get().addJob(arg);
}

static NoString RandomFromSet(const NoStringSet& sSet, std::default_random_engine& gen)
{
    std::uniform_int_distribution<> distr(0, sSet.size() - 1);
    auto it = sSet.cbegin();
    std::advance(it, distr(gen));
    return *it;
}

static std::tuple<NoString, bool> RandomFrom2SetsWithBias(const NoStringSet& ss4, const NoStringSet& ss6, std::default_random_engine& gen)
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
    if (task->aiTarget) freeaddrinfo(task->aiTarget);
    if (task->aiBind) freeaddrinfo(task->aiBind);

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
        FinishConnect(manager, sTargetHost, task->iPort, task->sSockName, task->iTimeout, task->bSSL, sBindhost, task->pcSock);
    } catch (const char* s) {
        NO_DEBUG(task->sSockName << ", dns resolving error: " << s);
        task->pcSock->SetSockName(task->sSockName);
        task->pcSock->SockErrorImpl(-1, s);
        delete task->pcSock;
    }

    delete task;
}
#endif /* HAVE_THREADED_DNS */

void FinishConnect(NoSocketManager* manager, const NoString& sHostname,
                                 u_short iPort,
                                 const NoString& sSockName,
                                 int iTimeout,
                                 bool bSSL,
                                 const NoString& sBindHost,
                                 NoSocket* pcSock)
{
    CSConnection C(sHostname, iPort, iTimeout);

    C.SetSockName(sSockName);
    C.SetIsSSL(bSSL);
    C.SetBindHost(sBindHost);
#ifdef HAVE_LIBSSL
    NoString sCipher = NoApp::Get().GetSSLCiphers();
    if (sCipher.empty()) {
        sCipher = ZNC_DefaultCipher;
    }
    C.SetCipher(sCipher);
#endif

    manager->DoConnect(C, pcSock->GetHandle());
}
