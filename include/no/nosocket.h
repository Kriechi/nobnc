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

#ifndef NOSOCKET_H
#define NOSOCKET_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <sys/socket.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#endif

#ifdef _WIN32
typedef SOCKET no_sock_t;
#else
typedef int no_sock_t;
#endif

class Csock;
class CCron;
class NoModule;
class NoSocketPrivate;

// All existing errno codes seem to be in range 1-300
enum {
    errnoBadSSLCert = 12569 // TODO
};

class NO_EXPORT NoSocket
{
public:
    NoSocket(const NoString& sHost = "", u_short port = 0, int timeout = 60);
    virtual ~NoSocket();

    Csock* GetHandle() const;

    NoString GetHostToVerifySSL() const;
    void SetHostToVerifySSL(const NoString& sHost);

    NoString GetSSLPeerFingerprint() const;

    NoStringSet GetSSLTrustedPeerFingerprints() const;
    void SetSSLTrustedPeerFingerprints(const NoStringSet& ssFPs);

    void SetEncoding(const NoString& sEncoding);
    virtual NoString GetRemoteIP() const;

    void SetPemLocation( const NoString & sPemFile );
    bool Write( const char *data, size_t len );
    bool Write( const NoString & sData );
    time_t GetTimeSinceLastDataTransaction( time_t iNow = 0 ) const;
    const NoString & GetSockName() const;
    const NoString & GetBindHost() const;
    void SetSockName( const NoString & sName );
    bool IsListener() const;
    bool IsOutbound() const;
    bool IsInbound() const;
    bool IsConnected() const;
    uint16_t GetPort() const;
    const NoString & GetHostName() const;
    uint16_t GetLocalPort() const;
    uint16_t GetRemotePort() const;
    bool GetSSL() const;
    void PauseRead();
    void UnPauseRead();
    NoString GetLocalIP() const;
#ifdef HAVE_LIBSSL
    void SetCipher( const NoString & sCipher );
    long GetPeerFingerprint( NoString & sFP ) const;
    void SetRequireClientCertFlags( uint32_t iRequireClientCertFlags );
    SSL_SESSION * GetSSLSession() const;
    X509 *GetX509() const;
#endif
    uint64_t GetBytesRead() const;
    void ResetBytesRead();
    uint64_t GetBytesWritten() const;
    void ResetBytesWritten();
    double GetAvgRead( uint64_t iSample = 1000 ) const;
    double GetAvgWrite( uint64_t iSample = 1000 ) const;
    uint64_t GetStartTime() const;
    bool Connect();
    bool Listen( uint16_t iPort, int iMaxConns = SOMAXCONN, const NoString & sBindHost = "", uint32_t iTimeout = 0, bool bDetach = false );
    void EnableReadLine();
    void DisableReadLine();
    void SetMaxBufferThreshold( uint32_t iThreshold );
    no_sock_t & GetRSock();
    void SetRSock( no_sock_t iSock );
    no_sock_t & GetWSock();
    void SetWSock( no_sock_t iSock );
    bool ConnectFD( int iReadFD, int iWriteFD, const NoString & sName, bool bIsSSL = false);
    enum { TMO_READ = 1, TMO_WRITE = 2, TMO_ACCEPT = 4, TMO_ALL = TMO_READ|TMO_WRITE|TMO_ACCEPT };
    void SetTimeout( int iTimeout, uint32_t iTimeoutType = TMO_ALL );
    virtual NoSocket* GetSockObjImpl(const NoString& sHost, ushort uPort);
    enum CloseType { CLT_DONT, CLT_NOW, CLT_AFTERWRITE, CLT_DEREFERENCE };
    CloseType GetCloseType() const;
    void Close(CloseType type = CLT_NOW);
    NoString & GetInternalReadBuffer();
    NoString & GetInternalWriteBuffer();
    virtual void ReadLineImpl( const NoString & sLine);
    virtual void ReadDataImpl(const char* data, size_t len);
    virtual void PushBuffImpl( const char *data, size_t len, bool bStartAtZero = false );
    void AddCron( CCron * pcCron );
    bool StartTLS();
    bool IsConOK() const;

    virtual void ConnectedImpl();
    virtual void TimeoutImpl();
    virtual void DisconnectedImpl();
    virtual void ConnectionRefusedImpl();

    virtual void ReadPausedImpl();
    virtual void ReachedMaxBufferImpl();
    virtual void SockErrorImpl(int iErrno, const NoString& sDescription);
    virtual bool ConnectionFromImpl(const NoString& sHost, ushort uPort);

private:
    NoSocket(const NoSocket&) = delete;
    NoSocket& operator=(const NoSocket&) = delete;
    std::unique_ptr<NoSocketPrivate> d;
    friend class NoSocketPrivate;
};

#endif // NOSOCKET_H
