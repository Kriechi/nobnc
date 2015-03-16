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

#include <znc/noconfig.h>
#include <znc/nosocket.h>

class NoRealListener;

class NoListener
{
public:
    typedef enum { ACCEPT_IRC, ACCEPT_HTTP, ACCEPT_ALL } EAcceptType;

    NoListener(unsigned short uPort, const NoString& sBindHost, const NoString& sURIPrefix, bool bSSL, EAddrType eAddr, EAcceptType eAccept)
        : m_bSSL(bSSL), m_eAddr(eAddr), m_uPort(uPort), m_sBindHost(sBindHost), m_sURIPrefix(sURIPrefix),
          m_pListener(nullptr), m_eAcceptType(eAccept)
    {
    }

    ~NoListener();

    NoListener(const NoListener&) = delete;
    NoListener& operator=(const NoListener&) = delete;

    bool IsSSL() const { return m_bSSL; }
    EAddrType GetAddrType() const { return m_eAddr; }
    unsigned short GetPort() const { return m_uPort; }
    const NoString& GetBindHost() const { return m_sBindHost; }
    NoRealListener* GetRealListener() const { return m_pListener; }
    const NoString& GetURIPrefix() const { return m_sURIPrefix; }
    EAcceptType GetAcceptType() const { return m_eAcceptType; }

    // It doesn't make sense to change any of the settings after Listen()
    // except this one, so don't add other setters!
    void SetAcceptType(EAcceptType eType) { m_eAcceptType = eType; }

    bool Listen();
    void ResetRealListener();

private:
    bool m_bSSL;
    EAddrType m_eAddr;
    unsigned short m_uPort;
    NoString m_sBindHost;
    NoString m_sURIPrefix;
    NoRealListener* m_pListener;
    EAcceptType m_eAcceptType;
};

class NoRealListener : public NoBaseSocket
{
public:
    NoRealListener(NoListener& listener) : NoBaseSocket(), m_Listener(listener) {}
    virtual ~NoRealListener();

    bool ConnectionFrom(const NoString& sHost, unsigned short uPort) override;
    Csock* GetSockObj(const NoString& sHost, unsigned short uPort) override;
    void SockError(int iErrno, const NoString& sDescription) override;

private:
    NoListener& m_Listener;
};

class NoIncomingConnection : public NoBaseSocket
{
public:
    NoIncomingConnection(const NoString& sHostname, unsigned short uPort, NoListener::EAcceptType eAcceptType, const NoString& sURIPrefix);
    virtual ~NoIncomingConnection() {}
    void ReadLine(const NoString& sData) override;
    void ReachedMaxBuffer() override;

private:
    NoListener::EAcceptType m_eAcceptType;
    const NoString m_sURIPrefix;
};

#endif // !NOLISTENER_H
