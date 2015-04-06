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

#include "nolistener.h"
#include "noclient.h"
#include "nodebug.h"
#include "noapp.h"
#include "nowebsocket.h"
#include "nosocket_p.h"
#include "nomodule_p.h"

class NoListenerPrivate
{
public:
    NoListenerPrivate(const NoString& host, ushort port) : port(port), host(host)
    {
    }

    bool ssl = false;
    ushort port = 0;
    NoString host = "";
    NoString uriPrefix = "";
    No::AcceptType acceptType = No::AcceptAll;
    No::AddressType addressType = No::Ipv4AndIpv6Address;
    NoSocket* socket = nullptr;
};

class NoListenerSocket : public NoSocket
{
public:
    NoListenerSocket(NoListenerPrivate* listener) : m_listener(listener)
    {
    }
    ~NoListenerSocket()
    {
        m_listener->socket = nullptr;
    }

    bool onConnectionFrom(const NoString& host, ushort port) override;
    NoSocket* createSocket(const NoString& host, ushort port) override;
    void onSocketError(int iErrno, const NoString& description) override;

private:
    NoListenerPrivate* m_listener;
};

class NoPeerSocket : public NoSocket
{
public:
    NoPeerSocket(const NoString& host, ushort port, NoListenerPrivate* listener);

    void readLine(const NoString& data) override;
    void onReachedMaxBuffer() override;

private:
    NoListenerPrivate* m_listener;
};

bool NoListenerSocket::onConnectionFrom(const NoString& host, ushort port)
{
    bool allowed = noApp->isHostAllowed(host);
    if (allowed)
        NO_DEBUG("Connection " << name() << " from " << host << ":" << port << " allowed");
    else
        NO_DEBUG("Connection " << name() << " from " << host << ":" << port << " NOT allowed");
    return allowed;
}

NoSocket* NoListenerSocket::createSocket(const NoString& host, ushort port)
{
    NoPeerSocket* socket = new NoPeerSocket(host, port, m_listener);
    if (noApp->allowConnectionFrom(host)) {
        GLOBALMODULECALL(onClientConnect(socket, host, port), NOTHING);
    } else {
        socket->write(":irc.znc.in 464 unknown-nick :Too many anonymous connections from your IP\r\n");
        socket->close(NoSocket::CloseAfterWrite);
        GLOBALMODULECALL(onFailedLogin("", host), NOTHING);
    }
    return socket;
}

void NoListenerSocket::onSocketError(int error, const NoString& description)
{
    NO_DEBUG("Error " << name() << " " << description << " (" << strerror(error) << ")");
    if (error == EMFILE) {
        // Too many open FDs, close the listening port to be able to continue
        // to work, next rehash will (try to) re-open it.
        noApp->broadcast("The limit of file descriptors has been reached");
        noApp->broadcast("Closing listening socket on " + localAddress() + ":" + NoString(localPort()));
        noApp->broadcast("An admin has to rehash to re-open the listening port");
        close();
    }
}

NoPeerSocket::NoPeerSocket(const NoString& host, ushort port, NoListenerPrivate* listener)
    : NoSocket(host, port), m_listener(listener)
{
    // The socket will time out in 120 secs, no matter what.
    // This has to be fixed up later, if desired.
    setTimeout(120);

    setEncoding("UTF-8");
    enableReadLine();
}

void NoPeerSocket::onReachedMaxBuffer()
{
    if (closeType() != NoClose)
        return; // Already closing

    // We don't actually SetMaxBufferThreshold() because that would be
    // inherited by sockets after SwapSockByAddr().
    if (internalReadBuffer().length() <= 4096)
        return;

    // We should never get here with legitimate requests :/
    close();
}

void NoPeerSocket::readLine(const NoString& line)
{
    NoSocket* socket = nullptr;
    bool isHttp = No::wildCmp(line, "GET * HTTP/1.?\r\n") || No::wildCmp(line, "POST * HTTP/1.?\r\n");

    if (!isHttp) {
        if (!(m_listener->acceptType & No::AcceptIrc)) {
            write("ERROR :Access Denied. IRC access is not enabled.\r\n");
            close(CloseAfterWrite);
            NO_DEBUG("Refused IRC connection to non IRC port");
        } else {
            NoClient* client = new NoClient;
            socket = client->socket();
            noApp->manager()->swapSocket(NoSocketPrivate::get(socket), NoSocketPrivate::get(this));

            // And don't forget to give it some sane name / timeout
            socket->setName("USR::???");
        }
    } else {
        if (!(m_listener->acceptType & No::AcceptHttp)) {
            write("HTTP/1.0 403 Access Denied\r\n\r\nWeb access is not enabled.\r\n");
            close(CloseAfterWrite);
            NO_DEBUG("Refused HTTP connection to non HTTP port");
        } else {
            socket = new NoWebSocket(m_listener->uriPrefix);
            noApp->manager()->swapSocket(NoSocketPrivate::get(socket), NoSocketPrivate::get(this));

            // And don't forget to give it some sane name / timeout
            socket->setName("WebMod::client");
        }
    }

    // TODO can we somehow get rid of this?
    socket->readLine(line);
    socket->pushBuffer("", 0, true);
}

NoListener::NoListener(const NoString& host, ushort port) : d(new NoListenerPrivate(host, port))
{
}

NoListener::~NoListener()
{
    if (d->socket)
        noApp->manager()->removeSocket(d->socket);
}

bool NoListener::isSsl() const
{
    return d->ssl;
}

void NoListener::setSsl(bool ssl)
{
    // TODO: warning if (d->socket)
    d->ssl = ssl;
}

ushort NoListener::port() const
{
    return d->port;
}

void NoListener::setPort(ushort port)
{
    // TODO: warning if (d->socket)
    d->port = port;
}

NoString NoListener::host() const
{
    return d->host;
}

void NoListener::setHost(const NoString& host)
{
    // TODO: warning if (d->socket)
    d->host = host;
}

NoString NoListener::uriPrefix() const
{
    return d->uriPrefix;
}

void NoListener::setUriPrefix(const NoString& prefix)
{
    // TODO: warning if (d->socket)
    d->uriPrefix = prefix;
}

No::AddressType NoListener::addressType() const
{
    return d->addressType;
}

void NoListener::setAddressType(No::AddressType type)
{
    // TODO: warning if (d->socket)
    d->addressType = type;
}

No::AcceptType NoListener::acceptType() const
{
    return d->acceptType;
}

void NoListener::setAcceptType(No::AcceptType type)
{
    d->acceptType = type;
}

NoSocket* NoListener::socket() const
{
    return d->socket;
}

bool NoListener::listen()
{
    if (!d->port || d->socket) {
        errno = EINVAL;
        return false;
    }

    d->socket = new NoListenerSocket(d.get());

    bool ssl = false;
#ifdef HAVE_LIBSSL
    if (isSsl()) {
        ssl = true;
        d->socket->setPemFile(noApp->pemLocation());
    }
#endif

    // If e.g. getaddrinfo() fails, the following might not set errno.
    // Make sure there is a consistent error message, not something random
    // which might even be "Error: Success".
    errno = EINVAL;
    return noApp->manager()->listenHost(d->port, "_LISTENER", d->host, ssl, d->socket, d->addressType);
}
