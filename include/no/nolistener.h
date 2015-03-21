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
    NoListener(ushort port, const NoString& bindHost, const NoString& uriPrefix, bool ssl, No::AddressType address, No::AcceptType accept);
    ~NoListener();

    NoListener(const NoListener&) = delete;
    NoListener& operator=(const NoListener&) = delete;

    bool isSsl() const;
    No::AddressType addressType() const;
    ushort port() const;
    const NoString& bindHost() const;
    NoSocket* socket() const;
    const NoString& uriPrefix() const;

    No::AcceptType acceptType() const;
    void setAcceptType(No::AcceptType type);

    bool listen();

private:
    void resetSocket();

    bool m_ssl;
    No::AddressType m_addressType;
    ushort m_port;
    NoString m_bindHost;
    NoString m_uriPrefix;
    NoSocket* m_socket;
    No::AcceptType m_acceptType;

    friend class NoRealListener;
};

#endif // NOLISTENER_H
