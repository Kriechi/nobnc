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

    bool ListenHost(ushort iPort,
                    const NoString& sSockName,
                    const NoString& sBindHost,
                    bool bSSL = false,
                    int iMaxConns = SOMAXCONN,
                    NoSocket* pcSock = nullptr,
                    u_int iTimeout = 0,
                    No::AddressType eAddr = No::Ipv4AndIpv6Address);

    bool ListenAll(ushort iPort,
                   const NoString& sSockName,
                   bool bSSL = false,
                   int iMaxConns = SOMAXCONN,
                   NoSocket* pcSock = nullptr,
                   u_int iTimeout = 0,
                   No::AddressType eAddr = No::Ipv4AndIpv6Address);

    u_short ListenRand(const NoString& sSockName,
                       const NoString& sBindHost,
                       bool bSSL = false,
                       int iMaxConns = SOMAXCONN,
                       NoSocket* pcSock = nullptr,
                       u_int iTimeout = 0,
                       No::AddressType eAddr = No::Ipv4AndIpv6Address);

    u_short ListenAllRand(const NoString& sSockName,
                          bool bSSL = false,
                          int iMaxConns = SOMAXCONN,
                          NoSocket* pcSock = nullptr,
                          u_int iTimeout = 0,
                          No::AddressType eAddr = No::Ipv4AndIpv6Address);

    void Connect(const NoString& sHostname,
                 ushort iPort,
                 const NoString& sSockName,
                 int iTimeout = 60,
                 bool bSSL = false,
                 const NoString& sBindHost = "",
                 NoSocket* pcSock = nullptr);

    std::vector<NoSocket*> GetSockets() const;
    std::vector<NoSocket*> FindSocksByName(const NoString& sName);
    uint GetAnonConnectionCount(const NoString& sIP) const;

    void Cleanup();
    void DynamicSelectLoop( uint64_t iLowerBounds, uint64_t iUpperBounds, time_t iMaxResolution = 3600 );
    void AddSock(NoSocket* pcSock, const NoString& sSockName);
    void DelSockByAddr(NoSocket* socket);
    bool SwapSockByAddr(Csock* newSocket, Csock* originalSocket);
    void AddCron(CCron* cron);
    void DelCronByAddr(CCron* cron);
    void DoConnect(const CSConnection& cCon, Csock* pcSock = NULL);

private:
    CSocketManager* m_instance;
    std::vector<NoSocket*> m_sockets;
};

#endif // NOSOCKETMANAGER_H
