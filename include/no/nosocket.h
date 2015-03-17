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
    void SetHostToVerifySSL(const NoString& sHost) { m_HostToVerifySSL = sHost; }
    NoString GetSSLPeerFingerprint() const;
    void SetSSLTrustedPeerFingerprints(const NoStringSet& ssFPs) { m_ssTrustedFingerprints = ssFPs; }

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

class NO_EXPORT NoSocketManager : public TSocketManager<NoBaseSocket>
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
                    EAddrType eAddr = ADDR_ALL)
    {
        CSListener L(iPort, sBindHost);

        L.SetSockName(sSockName);
        L.SetIsSSL(bSSL);
        L.SetTimeout(iTimeout);
        L.SetMaxConns(iMaxConns);

#ifdef HAVE_IPV6
        switch (eAddr) {
        case ADDR_IPV4ONLY:
            L.SetAFRequire(CSSockAddr::RAF_INET);
            break;
        case ADDR_IPV6ONLY:
            L.SetAFRequire(CSSockAddr::RAF_INET6);
            break;
        case ADDR_ALL:
            L.SetAFRequire(CSSockAddr::RAF_ANY);
            break;
        }
#endif

        return Listen(L, pcSock);
    }

    bool ListenAll(u_short iPort,
                   const NoString& sSockName,
                   bool bSSL = false,
                   int iMaxConns = SOMAXCONN,
                   NoBaseSocket* pcSock = nullptr,
                   u_int iTimeout = 0,
                   EAddrType eAddr = ADDR_ALL)
    {
        return ListenHost(iPort, sSockName, "", bSSL, iMaxConns, pcSock, iTimeout, eAddr);
    }

    u_short ListenRand(const NoString& sSockName,
                       const NoString& sBindHost,
                       bool bSSL = false,
                       int iMaxConns = SOMAXCONN,
                       NoBaseSocket* pcSock = nullptr,
                       u_int iTimeout = 0,
                       EAddrType eAddr = ADDR_ALL)
    {
        ushort uPort = 0;
        CSListener L(0, sBindHost);

        L.SetSockName(sSockName);
        L.SetIsSSL(bSSL);
        L.SetTimeout(iTimeout);
        L.SetMaxConns(iMaxConns);

#ifdef HAVE_IPV6
        switch (eAddr) {
        case ADDR_IPV4ONLY:
            L.SetAFRequire(CSSockAddr::RAF_INET);
            break;
        case ADDR_IPV6ONLY:
            L.SetAFRequire(CSSockAddr::RAF_INET6);
            break;
        case ADDR_ALL:
            L.SetAFRequire(CSSockAddr::RAF_ANY);
            break;
        }
#endif

        Listen(L, pcSock, &uPort);

        return uPort;
    }

    u_short ListenAllRand(const NoString& sSockName,
                          bool bSSL = false,
                          int iMaxConns = SOMAXCONN,
                          NoBaseSocket* pcSock = nullptr,
                          u_int iTimeout = 0,
                          EAddrType eAddr = ADDR_ALL)
    {
        return (ListenRand(sSockName, "", bSSL, iMaxConns, pcSock, iTimeout, eAddr));
    }

    void Connect(const NoString& sHostname,
                 u_short iPort,
                 const NoString& sSockName,
                 int iTimeout = 60,
                 bool bSSL = false,
                 const NoString& sBindHost = "",
                 NoBaseSocket* pcSock = nullptr);

    uint GetAnonConnectionCount(const NoString& sIP) const;

private:
    void FinishConnect(const NoString& sHostname, u_short iPort, const NoString& sSockName, int iTimeout, bool bSSL, const NoString& sBindHost, NoBaseSocket* pcSock);

    class NoDnsMonitorFD;
    friend class NoDnsMonitorFD;
#ifdef HAVE_THREADED_DNS
    struct NoDnsTask
    {
        NoDnsTask()
            : sHostname(""), iPort(0), sSockName(""), iTimeout(0), bSSL(false), sBindhost(""), pcSock(nullptr),
              bDoneTarget(false), bDoneBind(false), aiTarget(nullptr), aiBind(nullptr)
        {
        }

        NoDnsTask(const NoDnsTask&) = delete;
        NoDnsTask& operator=(const NoDnsTask&) = delete;

        NoString sHostname;
        u_short iPort;
        NoString sSockName;
        int iTimeout;
        bool bSSL;
        NoString sBindhost;
        NoBaseSocket* pcSock;

        bool bDoneTarget;
        bool bDoneBind;
        addrinfo* aiTarget;
        addrinfo* aiBind;
    };
    class NoDnsJob : public NoJob
    {
    public:
        NoDnsJob() : sHostname(""), task(nullptr), pManager(nullptr), bBind(false), iRes(0), aiResult(nullptr) {}

        NoDnsJob(const NoDnsJob&) = delete;
        NoDnsJob& operator=(const NoDnsJob&) = delete;

        NoString sHostname;
        NoDnsTask* task;
        NoSocketManager* pManager;
        bool bBind;

        int iRes;
        addrinfo* aiResult;

        void runThread() override;
        void runMain() override;
    };
    void StartTDNSThread(NoDnsTask* task, bool bBind);
    void SetTDNSThreadFinished(NoDnsTask* task, bool bBind, addrinfo* aiResult);
    static void* TDNSThread(void* argument);
#endif
protected:
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
