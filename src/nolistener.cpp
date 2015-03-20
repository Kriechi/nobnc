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

class NoRealListener : public NoSocket
{
public:
    NoRealListener(NoListener& listener);
    virtual ~NoRealListener();

    bool ConnectionFromImpl(const NoString& sHost, ushort uPort) override;
    NoSocket* GetSockObjImpl(const NoString& sHost, ushort uPort) override;
    void SockErrorImpl(int iErrno, const NoString& sDescription) override;

private:
    NoListener& m_Listener;
};

class NoIncomingConnection : public NoSocket
{
public:
    NoIncomingConnection(const NoString& sHostname, ushort uPort, NoListener::AcceptType eAcceptType, const NoString& sURIPrefix);
    void ReadLineImpl(const NoString& sData) override;
    void ReachedMaxBufferImpl() override;

private:
    NoListener::AcceptType m_eAcceptType;
    const NoString m_sURIPrefix;
};

NoListener::NoListener(ushort uPort, const NoString& sBindHost, const NoString& sURIPrefix, bool bSSL, No::AddressType eAddr, AcceptType eAccept)
    : m_bSSL(bSSL), m_eAddr(eAddr), m_uPort(uPort), m_sBindHost(sBindHost), m_sURIPrefix(sURIPrefix),
      m_pSocket(nullptr), m_eAcceptType(eAccept)
{
}

NoListener::~NoListener()
{
    if (m_pSocket)
        NoApp::Get().GetManager().DelSockByAddr(m_pSocket);
}

bool NoListener::IsSSL() const
{
    return m_bSSL;
}

No::AddressType NoListener::GetAddrType() const
{
    return m_eAddr;
}

ushort NoListener::GetPort() const
{
    return m_uPort;
}

const NoString& NoListener::GetBindHost() const
{
    return m_sBindHost;
}

NoSocket* NoListener::GetSocket() const
{
    return m_pSocket;
}

const NoString& NoListener::GetURIPrefix() const
{
    return m_sURIPrefix;
}

NoListener::AcceptType NoListener::GetAcceptType() const
{
    return m_eAcceptType;
}

void NoListener::SetAcceptType(AcceptType eType)
{
    m_eAcceptType = eType;
}

bool NoListener::Listen()
{
    if (!m_uPort || m_pSocket) {
        errno = EINVAL;
        return false;
    }

    m_pSocket = new NoRealListener(*this);

    bool bSSL = false;
#ifdef HAVE_LIBSSL
    if (IsSSL()) {
        bSSL = true;
        m_pSocket->SetPemLocation(NoApp::Get().GetPemLocation());
    }
#endif

    // If e.g. getaddrinfo() fails, the following might not set errno.
    // Make sure there is a consistent error message, not something random
    // which might even be "Error: Success".
    errno = EINVAL;
    return NoApp::Get().GetManager().ListenHost(m_uPort, "_LISTENER", m_sBindHost, bSSL, SOMAXCONN, m_pSocket, 0, m_eAddr);
}

void NoListener::ResetSocket()
{
    m_pSocket = nullptr;
}

NoRealListener::NoRealListener(NoListener& listener) : NoSocket(), m_Listener(listener)
{
}

NoRealListener::~NoRealListener()
{
    m_Listener.ResetSocket();
}

bool NoRealListener::ConnectionFromImpl(const NoString& sHost, ushort uPort)
{
    bool bHostAllowed = NoApp::Get().IsHostAllowed(sHost);
    NO_DEBUG(GetSockName() << " == ConnectionFrom(" << sHost << ", " << uPort << ") ["
                        << (bHostAllowed ? "Allowed" : "Not allowed") << "]");
    return bHostAllowed;
}

NoSocket* NoRealListener::GetSockObjImpl(const NoString& sHost, ushort uPort)
{
    NoIncomingConnection* pClient = new NoIncomingConnection(sHost, uPort, m_Listener.GetAcceptType(), m_Listener.GetURIPrefix());
    if (NoApp::Get().AllowConnectionFrom(sHost)) {
        GLOBALMODULECALL(OnClientConnect(pClient, sHost, uPort), NOTHING);
    } else {
        pClient->Write(":irc.znc.in 464 unknown-nick :Too many anonymous connections from your IP\r\n");
        pClient->Close(NoSocket::CLT_AFTERWRITE);
        GLOBALMODULECALL(OnFailedLogin("", sHost), NOTHING);
    }
    return pClient;
}

void NoRealListener::SockErrorImpl(int iErrno, const NoString& sDescription)
{
    NO_DEBUG(GetSockName() << " == SockError(" << sDescription << ", " << strerror(iErrno) << ")");
    if (iErrno == EMFILE) {
        // We have too many open fds, let's close this listening port to be able to continue
        // to work, next rehash will (try to) reopen it.
        NoApp::Get().Broadcast("We hit the FD limit, closing listening socket on [" + GetLocalIP() + " : " +
                              NoString(GetLocalPort()) + "]");
        NoApp::Get().Broadcast("An admin has to rehash to reopen the listening port");
        Close();
    }
}

NoIncomingConnection::NoIncomingConnection(const NoString& sHostname, ushort uPort, NoListener::AcceptType eAcceptType, const NoString& sURIPrefix)
    : NoSocket(sHostname, uPort), m_eAcceptType(eAcceptType), m_sURIPrefix(sURIPrefix)
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

void NoIncomingConnection::ReadLineImpl(const NoString& sLine)
{
    bool bIsHTTP = (sLine.wildCmp("GET * HTTP/1.?\r\n") || sLine.wildCmp("POST * HTTP/1.?\r\n"));
    bool bAcceptHTTP = (m_eAcceptType == NoListener::AcceptAll) || (m_eAcceptType == NoListener::AcceptHttp);
    bool bAcceptIRC = (m_eAcceptType == NoListener::AcceptAll) || (m_eAcceptType == NoListener::AcceptIrc);
    NoSocket* pSock = nullptr;

    if (!bIsHTTP) {
        // Let's assume it's an IRC connection

        if (!bAcceptIRC) {
            Write("ERROR :We don't take kindly to your types around here!\r\n");
            Close(CLT_AFTERWRITE);

            NO_DEBUG("Refused IRC connection to non IRC port");
            return;
        }

        pSock = new NoClient();
        NoApp::Get().GetManager().SwapSockByAddr(pSock->GetHandle(), GetHandle());

        // And don't forget to give it some sane name / timeout
        pSock->SetSockName("USR::???");
    } else {
        // This is a HTTP request, let the webmods handle it

        if (!bAcceptHTTP) {
            Write("HTTP/1.0 403 Access Denied\r\n\r\nWeb Access is not enabled.\r\n");
            Close(CLT_AFTERWRITE);

            NO_DEBUG("Refused HTTP connection to non HTTP port");
            return;
        }

        pSock = new NoWebSock(m_sURIPrefix);
        NoApp::Get().GetManager().SwapSockByAddr(pSock->GetHandle(), GetHandle());

        // And don't forget to give it some sane name / timeout
        pSock->SetSockName("WebMod::Client");
    }

    // TODO can we somehow get rid of this?
    pSock->ReadLineImpl(sLine);
    pSock->PushBuffImpl("", 0, true);
}
