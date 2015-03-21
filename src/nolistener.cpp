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

#include "nolistener.h"
#include "noclient.h"
#include "nodebug.h"
#include "noapp.h"
#include "nowebsocket.h"

class NoRealListener : public NoSocket
{
public:
    NoRealListener(NoListener* listener);
    virtual ~NoRealListener();

    bool ConnectionFromImpl(const NoString& host, ushort port) override;
    NoSocket* GetSockObjImpl(const NoString& host, ushort port) override;
    void SockErrorImpl(int iErrno, const NoString& description) override;

private:
    NoListener* m_listener;
};

class NoIncomingConnection : public NoSocket
{
public:
    NoIncomingConnection(const NoString& hostname, ushort port, No::AcceptType accept, const NoString& uriPrefix);
    void ReadLineImpl(const NoString& data) override;
    void ReachedMaxBufferImpl() override;

private:
    No::AcceptType m_acceptType;
    const NoString m_uriPrefix;
};

NoListener::NoListener(ushort port, const NoString& bindHost, const NoString& uriPrefix, bool ssl, No::AddressType address, No::AcceptType accept)
    : m_ssl(ssl), m_addressType(address), m_port(port), m_bindHost(bindHost), m_uriPrefix(uriPrefix),
      m_socket(nullptr), m_acceptType(accept)
{
}

NoListener::~NoListener()
{
    if (m_socket)
        NoApp::Get().GetManager().DelSockByAddr(m_socket);
}

bool NoListener::isSsl() const
{
    return m_ssl;
}

No::AddressType NoListener::addressType() const
{
    return m_addressType;
}

ushort NoListener::port() const
{
    return m_port;
}

const NoString& NoListener::bindHost() const
{
    return m_bindHost;
}

NoSocket* NoListener::socket() const
{
    return m_socket;
}

const NoString& NoListener::uriPrefix() const
{
    return m_uriPrefix;
}

No::AcceptType NoListener::acceptType() const
{
    return m_acceptType;
}

void NoListener::setAcceptType(No::AcceptType type)
{
    m_acceptType = type;
}

bool NoListener::listen()
{
    if (!m_port || m_socket) {
        errno = EINVAL;
        return false;
    }

    m_socket = new NoRealListener(this);

    bool ssl = false;
#ifdef HAVE_LIBSSL
    if (isSsl()) {
        ssl = true;
        m_socket->SetPemLocation(NoApp::Get().GetPemLocation());
    }
#endif

    // If e.g. getaddrinfo() fails, the following might not set errno.
    // Make sure there is a consistent error message, not something random
    // which might even be "Error: Success".
    errno = EINVAL;
    return NoApp::Get().GetManager().ListenHost(m_port, "_LISTENER", m_bindHost, ssl, SOMAXCONN, m_socket, 0, m_addressType);
}

void NoListener::resetSocket()
{
    m_socket = nullptr;
}

NoRealListener::NoRealListener(NoListener* listener) : NoSocket(), m_listener(listener)
{
}

NoRealListener::~NoRealListener()
{
    m_listener->resetSocket();
}

bool NoRealListener::ConnectionFromImpl(const NoString& host, ushort port)
{
    bool allowed = NoApp::Get().IsHostAllowed(host);
    NO_DEBUG(GetSockName() << " == ConnectionFrom(" << host << ", " << port << ") ["
                        << (allowed ? "Allowed" : "Not allowed") << "]");
    return allowed;
}

NoSocket* NoRealListener::GetSockObjImpl(const NoString& host, ushort port)
{
    NoIncomingConnection* client = new NoIncomingConnection(host, port, m_listener->acceptType(), m_listener->uriPrefix());
    if (NoApp::Get().AllowConnectionFrom(host)) {
        GLOBALMODULECALL(OnClientConnect(client, host, port), NOTHING);
    } else {
        client->Write(":irc.znc.in 464 unknown-nick :Too many anonymous connections from your IP\r\n");
        client->Close(NoSocket::CLT_AFTERWRITE);
        GLOBALMODULECALL(OnFailedLogin("", host), NOTHING);
    }
    return client;
}

void NoRealListener::SockErrorImpl(int iErrno, const NoString& description)
{
    NO_DEBUG(GetSockName() << " == SockError(" << description << ", " << strerror(iErrno) << ")");
    if (iErrno == EMFILE) {
        // We have too many open fds, let's close this listening port to be able to continue
        // to work, next rehash will (try to) reopen it.
        NoApp::Get().Broadcast("We hit the FD limit, closing listening socket on [" + GetLocalIP() + " : " +
                              NoString(GetLocalPort()) + "]");
        NoApp::Get().Broadcast("An admin has to rehash to reopen the listening port");
        Close();
    }
}

NoIncomingConnection::NoIncomingConnection(const NoString& hostname, ushort port, No::AcceptType acceptType, const NoString& uriPrefix)
    : NoSocket(hostname, port), m_acceptType(acceptType), m_uriPrefix(uriPrefix)
{
    // The socket will time out in 120 secs, no matter what.
    // This has to be fixed up later, if desired.
    SetTimeout(120, 0);

    SetEncoding("UTF-8");
    EnableReadLine();
}

void NoIncomingConnection::ReachedMaxBufferImpl()
{
    if (GetCloseType() != CLT_DONT) return; // Already closing

    // We don't actually SetMaxBufferThreshold() because that would be
    // inherited by sockets after SwapSockByAddr().
    if (GetInternalReadBuffer().length() <= 4096) return;

    // We should never get here with legitimate requests :/
    Close();
}

void NoIncomingConnection::ReadLineImpl(const NoString& line)
{
    bool isHttp = (No::wildCmp(line, "GET * HTTP/1.?\r\n") || No::wildCmp(line, "POST * HTTP/1.?\r\n"));
    NoSocket* socket = nullptr;

    if (!isHttp) {
        // Let's assume it's an IRC connection

        if (!(m_acceptType & No::AcceptIrc)) {
            Write("ERROR :We don't take kindly to your types around here!\r\n");
            Close(CLT_AFTERWRITE);

            NO_DEBUG("Refused IRC connection to non IRC port");
            return;
        }

        socket = new NoClient();
        NoApp::Get().GetManager().SwapSockByAddr(socket->GetHandle(), GetHandle());

        // And don't forget to give it some sane name / timeout
        socket->SetSockName("USR::???");
    } else {
        // This is a HTTP request, let the webmods handle it

        if (!(m_acceptType & No::AcceptHttp)) {
            Write("HTTP/1.0 403 Access Denied\r\n\r\nWeb Access is not enabled.\r\n");
            Close(CLT_AFTERWRITE);

            NO_DEBUG("Refused HTTP connection to non HTTP port");
            return;
        }

        socket = new NoWebSocket(m_uriPrefix);
        NoApp::Get().GetManager().SwapSockByAddr(socket->GetHandle(), GetHandle());

        // And don't forget to give it some sane name / timeout
        socket->SetSockName("WebMod::Client");
    }

    // TODO can we somehow get rid of this?
    socket->ReadLineImpl(line);
    socket->PushBuffImpl("", 0, true);
}
