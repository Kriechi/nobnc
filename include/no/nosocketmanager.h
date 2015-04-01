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

#ifndef NOSOCKETMANAGER_H
#define NOSOCKETMANAGER_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <sys/socket.h>

class Csock;
class CCron;
class CSConnection;
class CSocketManager;
class NoSocket;

class NO_EXPORT NoSocketManager
{
public:
    NoSocketManager();
    ~NoSocketManager();

    bool listenHost(ushort iPort,
                    const NoString& sSockName,
                    const NoString& bindHost,
                    bool ssl = false,
                    int iMaxConns = SOMAXCONN,
                    NoSocket* pcSock = nullptr,
                    u_int iTimeout = 0,
                    No::AddressType addressType = No::Ipv4AndIpv6Address);

    bool listenAll(ushort iPort,
                   const NoString& sSockName,
                   bool ssl = false,
                   int iMaxConns = SOMAXCONN,
                   NoSocket* pcSock = nullptr,
                   u_int iTimeout = 0,
                   No::AddressType addressType = No::Ipv4AndIpv6Address);

    u_short listenRand(const NoString& sSockName,
                       const NoString& bindHost,
                       bool ssl = false,
                       int iMaxConns = SOMAXCONN,
                       NoSocket* pcSock = nullptr,
                       u_int iTimeout = 0,
                       No::AddressType addressType = No::Ipv4AndIpv6Address);

    u_short listenAllRand(const NoString& sSockName,
                          bool ssl = false,
                          int iMaxConns = SOMAXCONN,
                          NoSocket* pcSock = nullptr,
                          u_int iTimeout = 0,
                          No::AddressType addressType = No::Ipv4AndIpv6Address);

    void connect(const NoString& hostname,
                 ushort iPort,
                 const NoString& sSockName,
                 int iTimeout = 60,
                 bool ssl = false,
                 const NoString& bindHost = "",
                 NoSocket* pcSock = nullptr);

    std::vector<NoSocket*> sockets() const;
    std::vector<NoSocket*> findSockets(const NoString& name);
    uint anonConnectionCount(const NoString& address) const;

    void cleanup();
    void dynamicSelectLoop(uint64_t iLowerBounds, uint64_t iUpperBounds, time_t iMaxResolution = 3600);
    void addSocket(NoSocket* pcSock, const NoString& sSockName);
    void removeSocket(NoSocket* socket);
    bool swapSocket(Csock* newSocket, Csock* originalSocket);
    void addCron(CCron* cron);
    void removeCron(CCron* cron);
    void doConnect(const CSConnection& cCon, Csock* pcSock = NULL);

private:
    CSocketManager* m_instance;
    std::vector<NoSocket*> m_sockets;
};

#endif // NOSOCKETMANAGER_H
