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
#include <no/nostring.h>

class NoSocket;

class NO_EXPORT NoListener
{
public:
    NoListener(ushort uPort, const NoString& sBindHost, const NoString& sURIPrefix, bool bSSL, No::AddressType eAddr, No::AcceptType eAccept);
    ~NoListener();

    NoListener(const NoListener&) = delete;
    NoListener& operator=(const NoListener&) = delete;

    bool IsSSL() const;
    No::AddressType GetAddrType() const;
    ushort GetPort() const;
    const NoString& GetBindHost() const;
    NoSocket* GetSocket() const;
    const NoString& GetURIPrefix() const;
    No::AcceptType GetAcceptType() const;

    // It doesn't make sense to change any of the settings after Listen()
    // except this one, so don't add other setters!
    void SetAcceptType(No::AcceptType eType);

    bool Listen();
    void ResetSocket();

private:
    bool m_bSSL;
    No::AddressType m_eAddr;
    ushort m_uPort;
    NoString m_sBindHost;
    NoString m_sURIPrefix;
    NoSocket* m_pSocket;
    No::AcceptType m_eAcceptType;
};

#endif // NOLISTENER_H
