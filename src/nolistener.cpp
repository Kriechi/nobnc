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

class NoListenerSocket : public NoSocket
{
public:
    NoListenerSocket(NoListener* listener) : m_listener(listener) { }
    ~NoListenerSocket() { m_listener->m_socket = nullptr; }

    bool ConnectionFromImpl(const NoString& host, ushort port) override;
    NoSocket* GetSockObjImpl(const NoString& host, ushort port) override;
    void SockErrorImpl(int iErrno, const NoString& description) override;

private:
    NoListener* m_listener;
};

class NoClientSocket : public NoSocket
{
public:
    NoClientSocket(const NoString& hostname, ushort port, NoListener* listener);

    void ReadLineImpl(const NoString& data) override;
    void ReachedMaxBufferImpl() override;

private:
    NoListener* m_listener;
};

bool NoListenerSocket::ConnectionFromImpl(const NoString& host, ushort port)
{
    bool allowed = NoApp::Get().IsHostAllowed(host);
    if (allowed)
        NO_DEBUG("Connection " << GetSockName() << " from " << host << ":" << port << " allowed");
    else
        NO_DEBUG("Connection " << GetSockName() << " from " << host << ":" << port << " NOT allowed");
    return allowed;
}

NoSocket* NoListenerSocket::GetSockObjImpl(const NoString& host, ushort port)
{
    NoClientSocket* client = new NoClientSocket(host, port, m_listener);
    if (NoApp::Get().AllowConnectionFrom(host)) {
        GLOBALMODULECALL(OnClientConnect(client, host, port), NOTHING);
    } else {
        client->Write(":irc.znc.in 464 unknown-nick :Too many anonymous connections from your IP\r\n");
        client->Close(NoSocket::CLT_AFTERWRITE);
        GLOBALMODULECALL(OnFailedLogin("", host), NOTHING);
    }
    return client;
}

void NoListenerSocket::SockErrorImpl(int error, const NoString& description)
{
    NO_DEBUG("Error " << GetSockName() << " " << description << " (" << strerror(error) << ")");
    if (error == EMFILE) {
        // Too many open FDs, close the listening port to be able to continue
        // to work, next rehash will (try to) re-open it.
        NoApp::Get().Broadcast("The limit of file descriptors has been reached");
        NoApp::Get().Broadcast("Closing listening socket on " + GetLocalIP() + ":" + NoString(GetLocalPort()));
        NoApp::Get().Broadcast("An admin has to rehash to re-open the listening port");
        Close();
    }
}

NoClientSocket::NoClientSocket(const NoString& hostname, ushort port, NoListener* listener)
    : NoSocket(hostname, port), m_listener(listener)
{
    // The socket will time out in 120 secs, no matter what.
    // This has to be fixed up later, if desired.
    SetTimeout(120, 0);

    SetEncoding("UTF-8");
    EnableReadLine();
}

void NoClientSocket::ReachedMaxBufferImpl()
{
    if (GetCloseType() != CLT_DONT)
        return; // Already closing

    // We don't actually SetMaxBufferThreshold() because that would be
    // inherited by sockets after SwapSockByAddr().
    if (GetInternalReadBuffer().length() <= 4096)
        return;

    // We should never get here with legitimate requests :/
    Close();
}

void NoClientSocket::ReadLineImpl(const NoString& line)
{
    NoSocket* socket = nullptr;
    bool isHttp = No::wildCmp(line, "GET * HTTP/1.?\r\n") || No::wildCmp(line, "POST * HTTP/1.?\r\n");

    if (!isHttp) {
        if (!(m_listener->acceptType() & No::AcceptIrc)) {
            Write("ERROR :Access Denied. IRC access is not enabled.\r\n");
            Close(CLT_AFTERWRITE);
            NO_DEBUG("Refused IRC connection to non IRC port");
        } else {
            socket = new NoClient();
            NoApp::Get().GetManager().SwapSockByAddr(socket->GetHandle(), GetHandle());

            // And don't forget to give it some sane name / timeout
            socket->SetSockName("USR::???");
        }
    } else {
        if (!(m_listener->acceptType() & No::AcceptHttp)) {
            Write("HTTP/1.0 403 Access Denied\r\n\r\nWeb access is not enabled.\r\n");
            Close(CLT_AFTERWRITE);
            NO_DEBUG("Refused HTTP connection to non HTTP port");
        } else {
            socket = new NoWebSocket(m_listener->uriPrefix());
            NoApp::Get().GetManager().SwapSockByAddr(socket->GetHandle(), GetHandle());

            // And don't forget to give it some sane name / timeout
            socket->SetSockName("WebMod::Client");
        }
    }

    // TODO can we somehow get rid of this?
    socket->ReadLineImpl(line);
    socket->PushBuffImpl("", 0, true);
}

NoListener::NoListener(ushort port, const NoString& bindHost)
    : m_ssl(false), m_port(port), m_bindHost(bindHost), m_uriPrefix(""),
      m_addressType(No::Ipv4AndIpv6Address), m_acceptType(No::AcceptAll), m_socket(nullptr)
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

void NoListener::setSsl(bool ssl)
{
    // TODO: warning if (m_socket)
    m_ssl = ssl;
}

ushort NoListener::port() const
{
    return m_port;
}

void NoListener::setPort(ushort port)
{
    // TODO: warning if (m_socket)
    m_port = port;
}

NoString NoListener::bindHost() const
{
    return m_bindHost;
}

void NoListener::setBindHost(const NoString& host)
{
    // TODO: warning if (m_socket)
    m_bindHost = host;
}

NoString NoListener::uriPrefix() const
{
    return m_uriPrefix;
}

void NoListener::setUriPrefix(const NoString& prefix)
{
    // TODO: warning if (m_socket)
    m_uriPrefix = prefix;
}

No::AddressType NoListener::addressType() const
{
    return m_addressType;
}

void NoListener::setAddressType(No::AddressType type)
{
    // TODO: warning if (m_socket)
    m_addressType = type;
}

No::AcceptType NoListener::acceptType() const
{
    return m_acceptType;
}

void NoListener::setAcceptType(No::AcceptType type)
{
    m_acceptType = type;
}

NoSocket* NoListener::socket() const
{
    return m_socket;
}

bool NoListener::listen()
{
    if (!m_port || m_socket) {
        errno = EINVAL;
        return false;
    }

    m_socket = new NoListenerSocket(this);

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
