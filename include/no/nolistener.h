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
    NoListener(ushort port, const NoString& bindHost);
    ~NoListener();

    NoListener(const NoListener&) = delete;
    NoListener& operator=(const NoListener&) = delete;

    bool isSsl() const;
    void setSsl(bool ssl);

    ushort port() const;
    void setPort(ushort port);

    NoString bindHost() const;
    void setBindHost(const NoString& host);

    NoString uriPrefix() const;
    void setUriPrefix(const NoString& prefix);

    No::AddressType addressType() const;
    void setAddressType(No::AddressType type);

    No::AcceptType acceptType() const;
    void setAcceptType(No::AcceptType type);

    NoSocket* socket() const;

    bool listen();

private:
    bool m_ssl;
    ushort m_port;
    NoString m_bindHost;
    NoString m_uriPrefix;
    No::AcceptType m_acceptType;
    No::AddressType m_addressType;
    NoSocket* m_socket;

    friend class NoListenerSocket;
};

#endif // NOLISTENER_H
