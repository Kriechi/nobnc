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

class NO_EXPORT NoBaseSocket : private Csock
{
public:
    NoBaseSocket(int timeout = 60);
    NoBaseSocket(const NoString& sHost, u_short port, int timeout = 60);
    ~NoBaseSocket() {}

    Csock* GetHandle() const;

    int ConvertAddress(const struct sockaddr_storage* pAddr, socklen_t iAddrLen, CS_STRING& sIP, u_short* piPort) const override;
#ifdef HAVE_LIBSSL
    int VerifyPeerCertificate(int iPreVerify, X509_STORE_CTX* pStoreCTX) override;
    void SSLHandShakeFinished() override;
#endif
    void SetHostToVerifySSL(const NoString& sHost);
    NoString GetSSLPeerFingerprint() const;
    void SetSSLTrustedPeerFingerprints(const NoStringSet& ssFPs);

    void SetEncoding(const NoString& sEncoding)
    {
#ifdef HAVE_ICU
        Csock::SetEncoding(sEncoding);
#endif
    }
#ifdef HAVE_ICU
    void IcuExtToUCallback(UConverterToUnicodeArgs* toArgs, const char* codeUnits, int32_t length, UConverterCallbackReason reason, UErrorCode* err ) override
    {
        IcuExtToUCallbackImpl(toArgs, codeUnits, length, reason, err);
    }
    virtual void IcuExtToUCallbackImpl(UConverterToUnicodeArgs* toArgs, const char* codeUnits, int32_t length, UConverterCallbackReason reason, UErrorCode* err )
    {
        Csock::IcuExtToUCallback(toArgs, codeUnits, length, reason, err);
    }
    void IcuExtFromUCallback(UConverterFromUnicodeArgs* fromArgs, const UChar* codeUnits, int32_t length, UChar32 codePoint, UConverterCallbackReason reason, UErrorCode* err ) override
    {
        IcuExtFromUCallbackImpl(fromArgs, codeUnits, length, codePoint, reason, err);
    }
    virtual void IcuExtFromUCallbackImpl(UConverterFromUnicodeArgs* fromArgs, const UChar* codeUnits, int32_t length, UChar32 codePoint, UConverterCallbackReason reason, UErrorCode* err )
    {
        Csock::IcuExtFromUCallback(fromArgs, codeUnits, length, codePoint, reason, err);
    }
#endif
    virtual NoString GetRemoteIP() const { return Csock::GetRemoteIP(); }

    void SetPemLocation( const NoString & sPemFile ) { Csock::SetPemLocation(sPemFile); }
    bool Write( const char *data, size_t len ) override { return Csock::Write(data, len); }
    bool Write( const NoString & sData ) override { return Csock::Write(sData); }
    time_t GetTimeSinceLastDataTransaction( time_t iNow = 0 ) const { return Csock::GetTimeSinceLastDataTransaction(iNow); }
    const NoString & GetSockName() const { return Csock::GetSockName(); }
    void SetSockName( const NoString & sName ) { Csock::SetSockName(sName); }
    bool IsListener() const { return Csock::GetType() == Csock::LISTENER; }
    bool IsOutbound() const { return Csock::GetType() == Csock::OUTBOUND; }
    bool IsInbound() const { return Csock::GetType() == Csock::INBOUND; }
    bool IsConnected() const override { return Csock::IsConnected(); }
    uint16_t GetPort() const { return Csock::GetPort(); }
    const NoString & GetHostName() const { return Csock::GetHostName(); }
    uint16_t GetLocalPort() const { return Csock::GetLocalPort(); }
    uint16_t GetRemotePort() const { return Csock::GetRemotePort(); }
    bool GetSSL() const { return Csock::GetSSL(); }
    void SockError( int iErrno, const NoString & sDescription ) override { Csock::SockError(iErrno, sDescription); }
    void PauseRead() { Csock::PauseRead(); }
    void UnPauseRead() { Csock::UnPauseRead(); }
    NoString GetLocalIP() const { return Csock::GetLocalIP(); }
#ifdef HAVE_LIBSSL
    void SetCipher( const NoString & sCipher ) { Csock::SetCipher(sCipher); }
    long GetPeerFingerprint( NoString & sFP ) const { return Csock::GetPeerFingerprint(sFP); }
    void SetRequireClientCertFlags( uint32_t iRequireClientCertFlags ) { Csock::SetRequireClientCertFlags(iRequireClientCertFlags); }
    SSL_SESSION * GetSSLSession() const { return Csock::GetSSLSession(); }
    X509 *GetX509() const { return Csock::GetX509(); }
#endif
    uint64_t GetBytesRead() const { return Csock::GetBytesRead(); }
    void ResetBytesRead() { Csock::ResetBytesRead(); }
    uint64_t GetBytesWritten() const { return Csock::GetBytesWritten(); }
    void ResetBytesWritten() { Csock::ResetBytesWritten(); }
    double GetAvgRead( uint64_t iSample = 1000 ) const { return Csock::GetAvgRead(iSample); }
    double GetAvgWrite( uint64_t iSample = 1000 ) const { return Csock::GetAvgWrite(iSample); }
    uint64_t GetStartTime() const { return Csock::GetStartTime(); }
    bool Connect() override { return Csock::Connect(); }
    bool Listen( uint16_t iPort, int iMaxConns = SOMAXCONN, const NoString & sBindHost = "", uint32_t iTimeout = 0, bool bDetach = false ) override
    {
        return Csock::Listen(iPort, iMaxConns, sBindHost, iTimeout, bDetach);
    }
    void EnableReadLine() { Csock::EnableReadLine(); }
    void DisableReadLine() { Csock::DisableReadLine(); }
    void SetMaxBufferThreshold( uint32_t iThreshold ) { Csock::SetMaxBufferThreshold(iThreshold); }
    cs_sock_t & GetRSock() { return Csock::GetRSock(); }
    void SetRSock( cs_sock_t iSock ) { Csock::SetRSock(iSock); }
    cs_sock_t & GetWSock() { return Csock::GetWSock(); }
    void SetWSock( cs_sock_t iSock ) { Csock::SetWSock(iSock); }
    bool ConnectFD( int iReadFD, int iWriteFD, const CS_STRING & sName, bool bIsSSL = false)
    {
        return Csock::ConnectFD(iReadFD, iWriteFD, sName, bIsSSL, INBOUND);
    }
    enum
    {
        TMO_READ = 1,
        TMO_WRITE = 2,
        TMO_ACCEPT = 4,
        TMO_ALL = TMO_READ|TMO_WRITE|TMO_ACCEPT
    };
    void SetTimeout( int iTimeout, uint32_t iTimeoutType = TMO_ALL ) { Csock::SetTimeout(iTimeout, iTimeoutType); }

    Csock* GetSockObj(const NoString& sHost, ushort uPort) override
    {
        NoBaseSocket* sockObj = GetSockObjImpl(sHost, uPort);
        if (sockObj)
            return sockObj->GetHandle();
        return Csock::GetSockObj(sHost, uPort);
    }
    virtual NoBaseSocket* GetSockObjImpl(const NoString& sHost, ushort uPort) { return nullptr; }

    enum ECloseType { CLT_DONT, CLT_NOW, CLT_AFTERWRITE, CLT_DEREFERENCE };
    ECloseType GetCloseType() const { return static_cast<ECloseType>(Csock::GetCloseType()); }
    void Close(ECloseType type = CLT_NOW) { Csock::Close(static_cast<Csock::ECloseType>(type)); }
    NoString & GetInternalReadBuffer() { return Csock::GetInternalReadBuffer(); }
    NoString & GetInternalWriteBuffer() { return Csock::GetInternalWriteBuffer(); }
    void ReadLine( const NoString & sLine ) override { ReadLineImpl(sLine); }
    virtual void ReadLineImpl( const NoString & sLine) { }
    void PushBuff( const char *data, size_t len, bool bStartAtZero = false ) override
    {
        Csock::PushBuff(data, len, bStartAtZero);
    }
    void AddCron( CCron * pcCron ) override { Csock::AddCron(pcCron); }
    bool StartTLS() { return Csock::StartTLS(); }
    bool IsConOK() const { return GetConState() == CST_OK; }

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

    using NoBaseSocket::Connect;
    using NoBaseSocket::Listen;

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
    void IcuExtToUCallbackImpl(UConverterToUnicodeArgs* toArgs,
                           const char* codeUnits,
                           int32_t length,
                           UConverterCallbackReason reason,
                           UErrorCode* err) override;
    void IcuExtFromUCallbackImpl(UConverterFromUnicodeArgs* fromArgs,
                             const UChar* codeUnits,
                             int32_t length,
                             UChar32 codePoint,
                             UConverterCallbackReason reason,
                             UErrorCode* err) override;
#endif
};

#endif // NOSOCKET_H
