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

#ifndef NOLISTENER_H
#define NOLISTENER_H

#include <no/noglobal.h>
#include <no/nosocket.h>
#include <no/nosocketmanager.h>

class NO_EXPORT NoListener
{
public:
    enum EAcceptType { ACCEPT_IRC, ACCEPT_HTTP, ACCEPT_ALL };

    NoListener(ushort uPort, const NoString& sBindHost, const NoString& sURIPrefix, bool bSSL, EAddrType eAddr, EAcceptType eAccept);
    ~NoListener();

    NoListener(const NoListener&) = delete;
    NoListener& operator=(const NoListener&) = delete;

    bool IsSSL() const;
    EAddrType GetAddrType() const;
    ushort GetPort() const;
    const NoString& GetBindHost() const;
    NoSocket* GetSocket() const;
    const NoString& GetURIPrefix() const;
    EAcceptType GetAcceptType() const;

    // It doesn't make sense to change any of the settings after Listen()
    // except this one, so don't add other setters!
    void SetAcceptType(EAcceptType eType);

    bool Listen();
    void ResetSocket();

private:
    bool m_bSSL;
    EAddrType m_eAddr;
    ushort m_uPort;
    NoString m_sBindHost;
    NoString m_sURIPrefix;
    NoSocket* m_pSocket;
    EAcceptType m_eAcceptType;
};

#endif // NOLISTENER_H
