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

#include "nosocketmanager_p.h"
#include "nosocket.h"
#include "nosocket_p.h"
#include "nothreadpool_p.h"
#include "nojob_p.h"
#include "noapp.h"
#include "Csocket/Csocket.h"

#include <algorithm>
#include <random>
#include <sys/socket.h>

#ifdef HAVE_PTHREAD
class NoDnsMonitorFD : public CSMonitorFD
{
public:
    NoDnsMonitorFD()
    {
        Add(NoThreadPool::instance()->getReadFD(), CSocketManager::ECT_Read);
    }

    bool FDsThatTriggered(const std::map<int, short>& miiReadyFds) override
    {
        if (miiReadyFds.find(NoThreadPool::instance()->getReadFD())->second) {
            NoThreadPool::instance()->handlePipeReadable();
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
          port(0),
          name(""),
          timeout(0),
          ssl(false),
          bindhost(""),
          socket(nullptr),
          doneTarget(false),
          doneBind(false),
          target(nullptr),
          bind(nullptr)
    {
    }

    NoDnsTask(const NoDnsTask&) = delete;
    NoDnsTask& operator=(const NoDnsTask&) = delete;

    NoString hostname;
    u_short port;
    NoString name;
    int timeout;
    bool ssl;
    NoString bindhost;
    NoSocket* socket;

    bool doneTarget;
    bool doneBind;
    addrinfo* target;
    addrinfo* bind;
};

class NoDnsJob : public NoJob
{
public:
    NoDnsJob() : hostname(""), task(nullptr), manager(nullptr), bind(false), res(0), result(nullptr)
    {
    }

    NoDnsJob(const NoDnsJob&) = delete;
    NoDnsJob& operator=(const NoDnsJob&) = delete;

    NoString hostname;
    NoDnsTask* task;
    NoSocketManager* manager;
    bool bind;

    int res;
    addrinfo* result;

    void run() override;
    void finished() override;
};

static void startDnsThread(NoSocketManager* manager, NoDnsTask* task, bool bind);
static void finishDnsThread(NoSocketManager* manager, NoDnsTask* task, bool bind, addrinfo* aiResult);
static void finishConnect(NoSocketManager* manager,
                          const NoString& hostname,
                          u_short port,
                          const NoString& name,
                          int timeout,
                          bool ssl,
                          const NoString& bindHost,
                          NoSocket* socket);
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

bool NoSocketManager::listen(ushort port,
                             const NoString& name,
                             const NoString& bindHost,
                             bool ssl,
                             NoSocket* socket,
                             No::AddressType addressType)
{
    CSListener listener(port, bindHost);

    listener.SetSockName(name);
    listener.SetIsSSL(ssl);

#ifdef HAVE_IPV6
    switch (addressType) {
    case No::Ipv4Address:
        listener.SetAFRequire(CSSockAddr::RAF_INET);
        break;
    case No::Ipv6Address:
        listener.SetAFRequire(CSSockAddr::RAF_INET6);
        break;
    case No::Ipv4AndIpv6Address:
        listener.SetAFRequire(CSSockAddr::RAF_ANY);
        break;
    }
#endif

    if (port != 0)
        return m_instance->Listen(listener, NoSocketPrivate::get(socket));
    else
        return m_instance->Listen(listener, NoSocketPrivate::get(socket), &port);
}

void NoSocketManager::connect(const NoString& hostname,
                              ushort port,
                              const NoString& name,
                              bool ssl,
                              const NoString& bindHost,
                              NoSocket* socket)
{
    if (socket) {
        socket->setHostToVerifySsl(hostname);
    }
#ifdef HAVE_THREADED_DNS
    NO_DEBUG("TDNS: initiating resolving of [" << hostname << "] and bindhost [" << bindHost << "]");
    NoDnsTask* task = new NoDnsTask;
    task->hostname = hostname;
    task->port = port;
    task->name = name;
    task->timeout = 120;
    task->ssl = ssl;
    task->bindhost = bindHost;
    task->socket = socket;
    if (bindHost.empty()) {
        task->doneBind = true;
    } else {
        startDnsThread(this, task, true);
    }
    startDnsThread(this, task, false);
#else // HAVE_THREADED_DNS
    // Just let Csocket handle DNS itself
    finishConnect(this, hostname, port, name, timeout, ssl, bindHost, socket);
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
            !socket->GetSockName().startsWith("USR::")) {
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

void NoSocketManager::dynamicSelectLoop(uint64_t lowerBounds, uint64_t upperBounds, time_t maxResolution)
{
    m_instance->DynamicSelectLoop(lowerBounds, upperBounds, maxResolution);
}

void NoSocketManager::addSocket(NoSocket* socket, const NoString& name)
{
    m_sockets.push_back(socket);
    m_instance->AddSock(NoSocketPrivate::get(socket), name);
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

void NoSocketManager::doConnect(const CSConnection& connection, Csock* socket)
{
    m_instance->Connect(connection, socket);
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
        res = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
        if (EAGAIN != res) {
            break;
        }

        iCount++;
        if (iCount > 5) {
            res = ETIMEDOUT;
            break;
        }
        sleep(5); // wait 5 seconds before next try
    }
}

void NoDnsJob::finished()
{
    if (0 != this->res) {
        NO_DEBUG("Error in threaded DNS: " << gai_strerror(this->res));
        if (this->result) {
            NO_DEBUG("And aiResult is not nullptr...");
        }
        this->result = nullptr; // just for case. Maybe to call freeaddrinfo()?
    }
    finishDnsThread(this->manager, this->task, this->bind, this->result);
}

void startDnsThread(NoSocketManager* manager, NoDnsTask* task, bool bind)
{
    NoString hostname = bind ? task->bindhost : task->hostname;
    NoDnsJob* job = new NoDnsJob;
    job->hostname = hostname;
    job->task = task;
    job->bind = bind;
    job->manager = manager;

    job->start();
}

static NoString RandomFromSet(const NoStringSet& set, std::default_random_engine& gen)
{
    std::uniform_int_distribution<> distr(0, set.size() - 1);
    auto it = set.cbegin();
    std::advance(it, distr(gen));
    return *it;
}

static std::tuple<NoString, bool>
RandomFrom2SetsWithBias(const NoStringSet& ss4, const NoStringSet& ss6, std::default_random_engine& gen)
{
    // It's not quite what RFC says how to choose between IPv4 and IPv6, but proper way is harder to implement.
    // It would require to maintain some state between Csock objects.
    bool ipv6 = false;
    if (ss4.empty()) {
        ipv6 = true;
    } else if (ss6.empty()) {
        ipv6 = false;
    } else {
        // Let's prefer IPv6 :)
        std::discrete_distribution<> d({ 2, 3 });
        ipv6 = d(gen);
    }
    const NoStringSet& set = ipv6 ? ss6 : ss4;
    return std::make_tuple(RandomFromSet(set, gen), ipv6);
}

void finishDnsThread(NoSocketManager* manager, NoDnsTask* task, bool bind, addrinfo* result)
{
    if (bind) {
        task->bind = result;
        task->doneBind = true;
    } else {
        task->target = result;
        task->doneTarget = true;
    }

    // Now that something is done, check if everything we needed is done
    if (!task->doneBind || !task->doneTarget) {
        return;
    }

    // All needed DNS is done, now collect the results
    NoStringSet targets4;
    NoStringSet targets6;
    for (addrinfo* ai = task->target; ai; ai = ai->ai_next) {
        char s[INET6_ADDRSTRLEN] = {};
        getnameinfo(ai->ai_addr, ai->ai_addrlen, s, sizeof(s), nullptr, 0, NI_NUMERICHOST);
        switch (ai->ai_family) {
        case AF_INET:
            targets4.insert(s);
            break;
#ifdef HAVE_IPV6
        case AF_INET6:
            targets6.insert(s);
            break;
#endif
        }
    }
    NoStringSet binds4;
    NoStringSet binds6;
    for (addrinfo* ai = task->bind; ai; ai = ai->ai_next) {
        char s[INET6_ADDRSTRLEN] = {};
        getnameinfo(ai->ai_addr, ai->ai_addrlen, s, sizeof(s), nullptr, 0, NI_NUMERICHOST);
        switch (ai->ai_family) {
        case AF_INET:
            binds4.insert(s);
            break;
#ifdef HAVE_IPV6
        case AF_INET6:
            binds6.insert(s);
            break;
#endif
        }
    }
    if (task->target)
        freeaddrinfo(task->target);
    if (task->bind)
        freeaddrinfo(task->bind);

    NoString bindHost;
    NoString targetHost;
    std::random_device rd;
    std::default_random_engine gen(rd());

    try {
        if (targets4.empty() && targets6.empty()) {
            throw "Can't resolve server hostname";
        } else if (task->bindhost.empty()) {
            // Choose random target
            std::tie(targetHost, std::ignore) = RandomFrom2SetsWithBias(targets4, targets6, gen);
        } else if (binds4.empty() && binds6.empty()) {
            throw "Can't resolve bind hostname. Try /znc ClearBindHost and /znc ClearUserBindHost";
        } else if (binds4.empty()) {
            if (targets6.empty()) {
                throw "Server address is IPv4-only, but bindhost is IPv6-only";
            } else {
                // Choose random target and bindhost from IPv6-only sets
                targetHost = RandomFromSet(targets6, gen);
                bindHost = RandomFromSet(binds6, gen);
            }
        } else if (binds6.empty()) {
            if (targets4.empty()) {
                throw "Server address is IPv6-only, but bindhost is IPv4-only";
            } else {
                // Choose random target and bindhost from IPv4-only sets
                targetHost = RandomFromSet(targets4, gen);
                bindHost = RandomFromSet(binds4, gen);
            }
        } else {
            // Choose random target
            bool bUseIPv6;
            std::tie(targetHost, bUseIPv6) = RandomFrom2SetsWithBias(targets4, targets6, gen);
            // Choose random bindhost matching chosen target
            const NoStringSet& ssBinds = bUseIPv6 ? binds6 : binds4;
            bindHost = RandomFromSet(ssBinds, gen);
        }

        NO_DEBUG("TDNS: " << task->name << ", connecting to [" << targetHost << "] using bindhost [" << bindHost << "]");
        finishConnect(manager, targetHost, task->port, task->name, task->timeout, task->ssl, bindHost, task->socket);
    } catch (const char* s) {
        NO_DEBUG(task->name << ", dns resolving error: " << s);
        task->socket->setName(task->name);
        NoSocketPrivate::get(task->socket)->SockError(-1, s);
        delete task->socket;
    }

    delete task;
}
#endif // HAVE_THREADED_DNS

void finishConnect(NoSocketManager* manager,
                   const NoString& hostname,
                   u_short port,
                   const NoString& name,
                   int timeout,
                   bool ssl,
                   const NoString& bindHost,
                   NoSocket* socket)
{
    CSConnection connection(hostname, port, timeout);

    connection.SetSockName(name);
    connection.SetIsSSL(ssl);
    connection.SetBindHost(bindHost);
#ifdef HAVE_LIBSSL
    connection.SetCipher(noApp->sslCiphers());
#endif

    manager->doConnect(connection, NoSocketPrivate::get(socket));
}
