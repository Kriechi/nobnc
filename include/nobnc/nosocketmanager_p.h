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

#ifndef NOSOCKETMANAGER_P_H
#define NOSOCKETMANAGER_P_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>

class Csock;
class CCron;
class CSConnection;
class CSocketManager;
class NoSocket;

class NoSocketManager
{
public:
    NoSocketManager();
    ~NoSocketManager();

    bool listen(ushort port,
                const NoString& name,
                const NoString& bindHost,
                bool ssl = false,
                NoSocket* socket = nullptr,
                No::AddressType addressType = No::Ipv4AndIpv6Address);

    void connect(const NoString& hostname,
                 ushort port,
                 const NoString& name,
                 bool ssl = false,
                 const NoString& bindHost = "",
                 NoSocket* socket = nullptr);

    std::vector<NoSocket*> sockets() const;
    std::vector<NoSocket*> findSockets(const NoString& name);
    uint anonConnectionCount(const NoString& address) const;

    void cleanup();
    void dynamicSelectLoop(uint64_t lowerBounds, uint64_t upperBounds, time_t maxResolution = 3600);
    void addSocket(NoSocket* socket, const NoString& name);
    void removeSocket(NoSocket* socket);
    bool swapSocket(Csock* newSocket, Csock* originalSocket);
    void addCron(CCron* cron);
    void removeCron(CCron* cron);
    void doConnect(const CSConnection& connection, Csock* socket = NULL);

private:
    CSocketManager* m_instance;
    std::vector<NoSocket*> m_sockets;
};

#endif // NOSOCKETMANAGER_P_H
