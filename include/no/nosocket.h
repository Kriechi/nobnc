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
#include <no/Csocket.h>
#include <no/nothreads.h>

class NoModule;

class NO_EXPORT NoBaseSocket : public Csock
{
public:
    NoBaseSocket(int timeout = 60);
    NoBaseSocket(const NoString& sHost, u_short port, int timeout = 60);
    ~NoBaseSocket() {}

    int ConvertAddress(const struct sockaddr_storage* pAddr, socklen_t iAddrLen, CS_STRING& sIP, u_short* piPort) const override;
#ifdef HAVE_LIBSSL
    int VerifyPeerCertificate(int iPreVerify, X509_STORE_CTX* pStoreCTX) override;
    void SSLHandShakeFinished() override;
#endif
    void SetHostToVerifySSL(const NoString& sHost);
    NoString GetSSLPeerFingerprint() const;
    void SetSSLTrustedPeerFingerprints(const NoStringSet& ssFPs);

#ifndef HAVE_ICU
    // Don't fail to compile when ICU is not enabled
    void SetEncoding(const NoString&) {}
#endif
    virtual NoString GetRemoteIP() const { return Csock::GetRemoteIP(); }

protected:
    // All existing errno codes seem to be in range 1-300
    enum {
        errnoBadSSLCert = 12569,
    };

private:
    NoString m_HostToVerifySSL;
    NoStringSet m_ssTrustedFingerprints;
    NoStringSet m_ssCertVerificationErrors;
};

enum EAddrType { ADDR_IPV4ONLY, ADDR_IPV6ONLY, ADDR_ALL };

class NO_EXPORT NoSocketManager : private TSocketManager<NoBaseSocket>
{
public:
    NoSocketManager();
    virtual ~NoSocketManager();

    bool ListenHost(u_short iPort,
                    const NoString& sSockName,
                    const NoString& sBindHost,
                    bool bSSL = false,
                    int iMaxConns = SOMAXCONN,
                    NoBaseSocket* pcSock = nullptr,
                    u_int iTimeout = 0,
                    EAddrType eAddr = ADDR_ALL);

    bool ListenAll(u_short iPort,
                   const NoString& sSockName,
                   bool bSSL = false,
                   int iMaxConns = SOMAXCONN,
                   NoBaseSocket* pcSock = nullptr,
                   u_int iTimeout = 0,
                   EAddrType eAddr = ADDR_ALL);

    u_short ListenRand(const NoString& sSockName,
                       const NoString& sBindHost,
                       bool bSSL = false,
                       int iMaxConns = SOMAXCONN,
                       NoBaseSocket* pcSock = nullptr,
                       u_int iTimeout = 0,
                       EAddrType eAddr = ADDR_ALL);

    u_short ListenAllRand(const NoString& sSockName,
                          bool bSSL = false,
                          int iMaxConns = SOMAXCONN,
                          NoBaseSocket* pcSock = nullptr,
                          u_int iTimeout = 0,
                          EAddrType eAddr = ADDR_ALL);

    void Connect(const NoString& sHostname,
                 u_short iPort,
                 const NoString& sSockName,
                 int iTimeout = 60,
                 bool bSSL = false,
                 const NoString& sBindHost = "",
                 NoBaseSocket* pcSock = nullptr);

    std::vector<Csock*> GetSockets() const;
    std::vector<Csock*> FindSocksByName(const NoString& sName);
    uint GetAnonConnectionCount(const NoString& sIP) const;

    void Cleanup();
    void DynamicSelectLoop( uint64_t iLowerBounds, uint64_t iUpperBounds, time_t iMaxResolution = 3600 );
    void AddSock(Csock* pcSock, const NoString& sSockName);
    void DelSockByAddr(Csock* socket);
    bool SwapSockByAddr(Csock* newSocket, Csock* originalSocket);
    void AddCron(CCron* cron);
    void DelCronByAddr(CCron* cron);
    void DoConnect(const CSConnection& cCon, Csock* pcSock = NULL);
};

/**
 * @class NoSocket
 * @brief Base Csock implementation to be used by modules
 *
 * By all means, this class should be used as a base for sockets originating from modules. It handles removing instances
 *of itself
 * from the module as it unloads, and simplifies use in general.
 * - EnableReadLine is default to true in this class
 * - MaxBuffer for readline is set to 10240, in the event this is reached the socket is closed (@see ReachedMaxBuffer)
 */
class NO_EXPORT NoSocket : public NoBaseSocket
{
public:
    /**
     * @brief ctor
     * @param pModule the module this sock instance is associated to
     */
    NoSocket(NoModule* pModule);
    /**
     * @brief ctor
     * @param pModule the module this sock instance is associated to
     * @param sHostname the hostname being connected to
     * @param uPort the port being connected to
     * @param iTimeout the timeout period for this specific sock
     */
    NoSocket(NoModule* pModule, const NoString& sHostname, ushort uPort, int iTimeout = 60);
    virtual ~NoSocket();

    NoSocket(const NoSocket&) = delete;
    NoSocket& operator=(const NoSocket&) = delete;

    using Csock::Connect;
    using Csock::Listen;

    //! This defaults to closing the socket, feel free to override
    void ReachedMaxBuffer() override;
    void SockError(int iErrno, const NoString& sDescription) override;

    //! This limits the global connections from this IP to defeat DoS attacks, feel free to override. The ACL used is
    // provided by the main interface @see NoApp::AllowConnectionFrom
    bool ConnectionFrom(const NoString& sHost, ushort uPort) override;

    //! Ease of use Connect, assigns to the manager and is subsequently tracked
    bool Connect(const NoString& sHostname, ushort uPort, bool bSSL = false, uint uTimeout = 60);
    //! Ease of use Listen, assigned to the manager and is subsequently tracked
    bool Listen(ushort uPort, bool bSSL, uint uTimeout = 0);

    NoModule* GetModule() const;

private:
protected:
    NoModule* m_pModule; //!< pointer to the module that this sock instance belongs to
};

/**
 * @class NoIrcSocket
 * @brief Base IRC socket for client<->ZNC, and ZNC<->server
 */
class NO_EXPORT NoIrcSocket : public NoBaseSocket
{
public:
#ifdef HAVE_ICU
    /**
     * @brief Allow IRC control characters to appear even if protocol encoding explicitly disallows them.
     *
     * E.g. ISO-2022-JP disallows 0x0F, which in IRC means "reset format",
     * so by default it gets replaced with U+FFFD ("replacement character").
     * https://code.google.com/p/chromium/issues/detail?id=277062#c3
     *
     * In case if protocol encoding uses these code points for something else, the encoding takes preference,
     * and they are not IRC control characters anymore.
     */
    void IcuExtToUCallback(UConverterToUnicodeArgs* toArgs,
                           const char* codeUnits,
                           int32_t length,
                           UConverterCallbackReason reason,
                           UErrorCode* err) override;
    void IcuExtFromUCallback(UConverterFromUnicodeArgs* fromArgs,
                             const UChar* codeUnits,
                             int32_t length,
                             UChar32 codePoint,
                             UConverterCallbackReason reason,
                             UErrorCode* err) override;
#endif
};

#endif // NOSOCKET_H
