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

#include "nosocket.h"
#include "nouser.h"
#include "nonetwork.h"
#include "nosslverifyhost.h"
#include "noapp.h"
#include <signal.h>

#ifdef HAVE_ICU
#include <unicode/ucnv_cb.h>
#endif

#ifdef HAVE_LIBSSL
// Copypasted from https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29 at 22 Dec
// 2014
const char* ZNC_DefaultCipher =
           "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-"
           "GCM-SHA384:"
           "DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-"
           "SHA256:"
           "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-"
           "AES256-SHA:"
           "ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-"
           "SHA256:"
           "DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:"
           "AES128-SHA:"
           "AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-"
           "SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";
#endif

NoBaseSocket::NoBaseSocket(int timeout)
    : Csock(timeout), m_HostToVerifySSL(""), m_ssTrustedFingerprints(), m_ssCertVerificationErrors()
{
#ifdef HAVE_LIBSSL
    DisableSSLCompression();
    FollowSSLCipherServerPreference();
    DisableSSLProtocols(NoApp::Get().GetDisabledSSLProtocols());
    NoString sCipher = NoApp::Get().GetSSLCiphers();
    if (sCipher.empty()) {
        sCipher = ZNC_DefaultCipher;
    }
    SetCipher(sCipher);
#endif
}

NoBaseSocket::NoBaseSocket(const NoString& sHost, u_short port, int timeout)
    : Csock(sHost, port, timeout), m_HostToVerifySSL(""), m_ssTrustedFingerprints(), m_ssCertVerificationErrors()
{
#ifdef HAVE_LIBSSL
    DisableSSLCompression();
    FollowSSLCipherServerPreference();
    DisableSSLProtocols(NoApp::Get().GetDisabledSSLProtocols());
#endif
}

NoBaseSocket::~NoBaseSocket()
{
}

Csock* NoBaseSocket::GetHandle() const
{
    return const_cast<NoBaseSocket*>(this);
}

int NoBaseSocket::ConvertAddress(const struct sockaddr_storage* pAddr, socklen_t iAddrLen, CS_STRING& sIP, u_short* piPort) const
{
    int ret = Csock::ConvertAddress(pAddr, iAddrLen, sIP, piPort);
    if (ret == 0) sIP.TrimPrefix("::ffff:");
    return ret;
}

#ifdef HAVE_LIBSSL
int NoBaseSocket::VerifyPeerCertificate(int iPreVerify, X509_STORE_CTX* pStoreCTX)
{
    if (iPreVerify == 0) {
        m_ssCertVerificationErrors.insert(X509_verify_cert_error_string(X509_STORE_CTX_get_error(pStoreCTX)));
    }
    return 1;
}

void NoBaseSocket::SSLHandShakeFinished()
{
    if (GetType() != ETConn::OUTBOUND) {
        return;
    }

    X509* pCert = GetX509();
    if (!pCert) {
        DEBUG(GetSockName() + ": No cert");
        CallSockError(errnoBadSSLCert, "Anonymous SSL cert is not allowed");
        Close();
        return;
    }
    NoString sHostVerifyError;
    if (!ZNC_SSLVerifyHost(m_HostToVerifySSL, pCert, sHostVerifyError)) {
        m_ssCertVerificationErrors.insert(sHostVerifyError);
    }
    X509_free(pCert);
    if (m_ssCertVerificationErrors.empty()) {
        DEBUG(GetSockName() + ": Good cert");
        return;
    }
    NoString sFP = GetSSLPeerFingerprint();
    if (m_ssTrustedFingerprints.count(sFP) != 0) {
        DEBUG(GetSockName() + ": Cert explicitly trusted by user: " << sFP);
        return;
    }
    DEBUG(GetSockName() + ": Bad cert");
    NoString sErrorMsg = "Invalid SSL certificate: ";
    sErrorMsg += NoString(", ").Join(begin(m_ssCertVerificationErrors), end(m_ssCertVerificationErrors));
    CallSockError(errnoBadSSLCert, sErrorMsg);
    Close();
}
#endif

void NoBaseSocket::SetHostToVerifySSL(const NoString& sHost)
{
    m_HostToVerifySSL = sHost;
}

NoString NoBaseSocket::GetSSLPeerFingerprint() const
{
#ifdef HAVE_LIBSSL
    // Csocket's version returns insecure SHA-1
    // This one is SHA-256
    const EVP_MD* evp = EVP_sha256();
    X509* pCert = GetX509();
    if (!pCert) {
        DEBUG(GetSockName() + ": GetSSLPeerFingerprint: Anonymous cert");
        return "";
    }
    uchar buf[256 / 8];
    uint _32 = 256 / 8;
    int iSuccess = X509_digest(pCert, evp, buf, &_32);
    X509_free(pCert);
    if (!iSuccess) {
        DEBUG(GetSockName() + ": GetSSLPeerFingerprint: Couldn't find digest");
        return "";
    }
    return NoString(reinterpret_cast<const char*>(buf), sizeof buf).Escape_n(NoString::EASCII, NoString::EHEXCOLON);
#else
    return "";
#endif
}

void NoBaseSocket::SetSSLTrustedPeerFingerprints(const NoStringSet& ssFPs)
{
    m_ssTrustedFingerprints = ssFPs;
}

void NoBaseSocket::SetEncoding(const NoString& sEncoding)
{
#ifdef HAVE_ICU
    Csock::SetEncoding(sEncoding);
#endif
}
#ifdef HAVE_ICU
void NoBaseSocket::IcuExtToUCallback(UConverterToUnicodeArgs* toArgs, const char* codeUnits, int32_t length, UConverterCallbackReason reason, UErrorCode* err )
{
    IcuExtToUCallbackImpl(toArgs, codeUnits, length, reason, err);
}
void NoBaseSocket::IcuExtToUCallbackImpl(UConverterToUnicodeArgs* toArgs, const char* codeUnits, int32_t length, UConverterCallbackReason reason, UErrorCode* err )
{
    Csock::IcuExtToUCallback(toArgs, codeUnits, length, reason, err);
}
void NoBaseSocket::IcuExtFromUCallback(UConverterFromUnicodeArgs* fromArgs, const UChar* codeUnits, int32_t length, UChar32 codePoint, UConverterCallbackReason reason, UErrorCode* err )
{
    IcuExtFromUCallbackImpl(fromArgs, codeUnits, length, codePoint, reason, err);
}
void NoBaseSocket::IcuExtFromUCallbackImpl(UConverterFromUnicodeArgs* fromArgs, const UChar* codeUnits, int32_t length, UChar32 codePoint, UConverterCallbackReason reason, UErrorCode* err )
{
    Csock::IcuExtFromUCallback(fromArgs, codeUnits, length, codePoint, reason, err);
}
#endif
NoString NoBaseSocket::GetRemoteIP() const { return Csock::GetRemoteIP(); }

void NoBaseSocket::SetPemLocation( const NoString & sPemFile ) { Csock::SetPemLocation(sPemFile); }
bool NoBaseSocket::Write( const char *data, size_t len ) { return Csock::Write(data, len); }
bool NoBaseSocket::Write( const NoString & sData ) { return Csock::Write(sData); }
time_t NoBaseSocket::GetTimeSinceLastDataTransaction( time_t iNow ) const { return Csock::GetTimeSinceLastDataTransaction(iNow); }
const NoString & NoBaseSocket::GetSockName() const { return Csock::GetSockName(); }
void NoBaseSocket::SetSockName( const NoString & sName ) { Csock::SetSockName(sName); }
bool NoBaseSocket::IsListener() const { return Csock::GetType() == Csock::LISTENER; }
bool NoBaseSocket::IsOutbound() const { return Csock::GetType() == Csock::OUTBOUND; }
bool NoBaseSocket::IsInbound() const { return Csock::GetType() == Csock::INBOUND; }
bool NoBaseSocket::IsConnected() const { return Csock::IsConnected(); }
uint16_t NoBaseSocket::GetPort() const { return Csock::GetPort(); }
const NoString & NoBaseSocket::GetHostName() const { return Csock::GetHostName(); }
uint16_t NoBaseSocket::GetLocalPort() const { return Csock::GetLocalPort(); }
uint16_t NoBaseSocket::GetRemotePort() const { return Csock::GetRemotePort(); }
bool NoBaseSocket::GetSSL() const { return Csock::GetSSL(); }
void NoBaseSocket::SockError( int iErrno, const NoString & sDescription ) { Csock::SockError(iErrno, sDescription); }
void NoBaseSocket::PauseRead() { Csock::PauseRead(); }
void NoBaseSocket::UnPauseRead() { Csock::UnPauseRead(); }
NoString NoBaseSocket::GetLocalIP() const { return Csock::GetLocalIP(); }
#ifdef HAVE_LIBSSL
void NoBaseSocket::SetCipher( const NoString & sCipher ) { Csock::SetCipher(sCipher); }
long NoBaseSocket::GetPeerFingerprint( NoString & sFP ) const { return Csock::GetPeerFingerprint(sFP); }
void NoBaseSocket::SetRequireClientCertFlags( uint32_t iRequireClientCertFlags ) { Csock::SetRequireClientCertFlags(iRequireClientCertFlags); }
SSL_SESSION * NoBaseSocket::GetSSLSession() const { return Csock::GetSSLSession(); }
X509 *NoBaseSocket::GetX509() const { return Csock::GetX509(); }
#endif
uint64_t NoBaseSocket::GetBytesRead() const { return Csock::GetBytesRead(); }
void NoBaseSocket::ResetBytesRead() { Csock::ResetBytesRead(); }
uint64_t NoBaseSocket::GetBytesWritten() const { return Csock::GetBytesWritten(); }
void NoBaseSocket::ResetBytesWritten() { Csock::ResetBytesWritten(); }
double NoBaseSocket::GetAvgRead( uint64_t iSample ) const { return Csock::GetAvgRead(iSample); }
double NoBaseSocket::GetAvgWrite( uint64_t iSample ) const { return Csock::GetAvgWrite(iSample); }
uint64_t NoBaseSocket::GetStartTime() const { return Csock::GetStartTime(); }
bool NoBaseSocket::Connect() { return Csock::Connect(); }
bool NoBaseSocket::Listen( uint16_t iPort, int iMaxConns, const NoString & sBindHost, uint32_t iTimeout, bool bDetach )
{
    return Csock::Listen(iPort, iMaxConns, sBindHost, iTimeout, bDetach);
}
void NoBaseSocket::EnableReadLine() { Csock::EnableReadLine(); }
void NoBaseSocket::DisableReadLine() { Csock::DisableReadLine(); }
void NoBaseSocket::SetMaxBufferThreshold( uint32_t iThreshold ) { Csock::SetMaxBufferThreshold(iThreshold); }
cs_sock_t & NoBaseSocket::GetRSock() { return Csock::GetRSock(); }
void NoBaseSocket::SetRSock( cs_sock_t iSock ) { Csock::SetRSock(iSock); }
cs_sock_t & NoBaseSocket::GetWSock() { return Csock::GetWSock(); }
void NoBaseSocket::SetWSock( cs_sock_t iSock ) { Csock::SetWSock(iSock); }
bool NoBaseSocket::ConnectFD( int iReadFD, int iWriteFD, const CS_STRING & sName, bool bIsSSL)
{
    return Csock::ConnectFD(iReadFD, iWriteFD, sName, bIsSSL, INBOUND);
}
void NoBaseSocket::SetTimeout( int iTimeout, uint32_t iTimeoutType ) { Csock::SetTimeout(iTimeout, iTimeoutType); }

Csock* NoBaseSocket::GetSockObj(const NoString& sHost, ushort uPort)
{
    NoBaseSocket* sockObj = GetSockObjImpl(sHost, uPort);
    if (sockObj)
        return sockObj->GetHandle();
    return Csock::GetSockObj(sHost, uPort);
}
NoBaseSocket* NoBaseSocket::GetSockObjImpl(const NoString& sHost, ushort uPort) { return nullptr; }

NoBaseSocket::ECloseType NoBaseSocket::GetCloseType() const { return static_cast<ECloseType>(Csock::GetCloseType()); }
void NoBaseSocket::Close(ECloseType type) { Csock::Close(static_cast<Csock::ECloseType>(type)); }
NoString & NoBaseSocket::GetInternalReadBuffer() { return Csock::GetInternalReadBuffer(); }
NoString & NoBaseSocket::GetInternalWriteBuffer() { return Csock::GetInternalWriteBuffer(); }
void NoBaseSocket::ReadLine( const NoString & sLine ) { ReadLineImpl(sLine); }
void NoBaseSocket::ReadLineImpl( const NoString & sLine) { }
void NoBaseSocket::PushBuff( const char *data, size_t len, bool bStartAtZero )
{
    Csock::PushBuff(data, len, bStartAtZero);
}
void NoBaseSocket::AddCron( CCron * pcCron ) { Csock::AddCron(pcCron); }
bool NoBaseSocket::StartTLS() { return Csock::StartTLS(); }
bool NoBaseSocket::IsConOK() const { return GetConState() == CST_OK; }

/////////////////// NoSocket ///////////////////
NoSocket::NoSocket(NoModule* pModule) : NoBaseSocket(), m_pModule(pModule)
{
    if (m_pModule) m_pModule->AddSocket(this);
    EnableReadLine();
    SetMaxBufferThreshold(10240);
}

NoSocket::NoSocket(NoModule* pModule, const NoString& sHostname, ushort uPort, int iTimeout)
    : NoBaseSocket(sHostname, uPort, iTimeout), m_pModule(pModule)
{
    if (m_pModule) m_pModule->AddSocket(this);
    EnableReadLine();
    SetMaxBufferThreshold(10240);
}

NoSocket::~NoSocket()
{
    NoUser* pUser = nullptr;

    // NoWebSock could cause us to have a nullptr pointer here
    if (m_pModule) {
        pUser = m_pModule->GetUser();
        m_pModule->UnlinkSocket(this);
    }

    if (pUser && m_pModule && (m_pModule->GetType() != NoModInfo::GlobalModule)) {
        pUser->AddBytesWritten(GetBytesWritten());
        pUser->AddBytesRead(GetBytesRead());
    } else {
        NoApp::Get().AddBytesWritten(GetBytesWritten());
        NoApp::Get().AddBytesRead(GetBytesRead());
    }
}

void NoSocket::ReachedMaxBuffer()
{
    DEBUG(GetSockName() << " == ReachedMaxBuffer()");
    if (m_pModule) m_pModule->PutModule("Some socket reached its max buffer limit and was closed!");
    Close();
}

void NoSocket::SockError(int iErrno, const NoString& sDescription)
{
    DEBUG(GetSockName() << " == SockError(" << sDescription << ", " << strerror(iErrno) << ")");
    if (iErrno == EMFILE) {
        // We have too many open fds, this can cause a busy loop.
        Close();
    }
}

bool NoSocket::ConnectionFrom(const NoString& sHost, ushort uPort)
{
    return NoApp::Get().AllowConnectionFrom(sHost);
}

bool NoSocket::Connect(const NoString& sHostname, ushort uPort, bool bSSL, uint uTimeout)
{
    if (!m_pModule) {
        DEBUG("ERROR: NoSocket::Connect called on instance without m_pModule handle!");
        return false;
    }

    NoUser* pUser = m_pModule->GetUser();
    NoString sSockName = "MOD::C::" + m_pModule->GetModName();
    NoString sBindHost;

    if (pUser) {
        sSockName += "::" + pUser->GetUserName();
        sBindHost = pUser->GetBindHost();
        NoNetwork* pNetwork = m_pModule->GetNetwork();
        if (pNetwork) {
            sSockName += "::" + pNetwork->GetName();
            sBindHost = pNetwork->GetBindHost();
        }
    }

    // Don't overwrite the socket name if one is already set
    if (!GetSockName().empty()) {
        sSockName = GetSockName();
    }

    m_pModule->GetManager()->Connect(sHostname, uPort, sSockName, uTimeout, bSSL, sBindHost, this);
    return true;
}

bool NoSocket::Listen(ushort uPort, bool bSSL, uint uTimeout)
{
    if (!m_pModule) {
        DEBUG("ERROR: NoSocket::Listen called on instance without m_pModule handle!");
        return false;
    }

    NoUser* pUser = m_pModule->GetUser();
    NoString sSockName = "MOD::L::" + m_pModule->GetModName();

    if (pUser) {
        sSockName += "::" + pUser->GetUserName();
    }
    // Don't overwrite the socket name if one is already set
    if (!GetSockName().empty()) {
        sSockName = GetSockName();
    }

    return m_pModule->GetManager()->ListenAll(uPort, sSockName, bSSL, SOMAXCONN, this);
}

NoModule* NoSocket::GetModule() const { return m_pModule; }
/////////////////// !NoSocket ///////////////////

#ifdef HAVE_ICU
void NoIrcSocket::IcuExtToUCallbackImpl(UConverterToUnicodeArgs* toArgs,
                                   const char* codeUnits,
                                   int32_t length,
                                   UConverterCallbackReason reason,
                                   UErrorCode* err)
{
    // From http://www.mirc.com/colors.html
    // The Control+O key combination in mIRC inserts ascii character 15,
    // which turns off all previous attributes, including color, bold, underline, and italics.
    //
    // \x02 bold
    // \x03 mIRC-compatible color
    // \x04 RRGGBB color
    // \x0F normal/reset (turn off bold, colors, etc.)
    // \x12 reverse (weechat)
    // \x16 reverse (mirc, kvirc)
    // \x1D italic
    // \x1F underline
    // Also see http://www.visualirc.net/tech-attrs.php
    //
    // Keep in sync with NoUser::AddTimestamp and NoIrcSocket::IcuExtFromUCallback
    static const std::set<char> scAllowedChars = { '\x02', '\x03', '\x04', '\x0F', '\x12', '\x16', '\x1D', '\x1F' };
    if (reason == UCNV_ILLEGAL && length == 1 && scAllowedChars.count(*codeUnits)) {
        *err = U_ZERO_ERROR;
        UChar c = *codeUnits;
        ucnv_cbToUWriteUChars(toArgs, &c, 1, 0, err);
        return;
    }
    NoBaseSocket::IcuExtToUCallbackImpl(toArgs, codeUnits, length, reason, err);
}

void NoIrcSocket::IcuExtFromUCallbackImpl(UConverterFromUnicodeArgs* fromArgs,
                                     const UChar* codeUnits,
                                     int32_t length,
                                     UChar32 codePoint,
                                     UConverterCallbackReason reason,
                                     UErrorCode* err)
{
    // See comment in NoIrcSocket::IcuExtToUCallback
    static const std::set<UChar32> scAllowedChars = { 0x02, 0x03, 0x04, 0x0F, 0x12, 0x16, 0x1D, 0x1F };
    if (reason == UCNV_ILLEGAL && scAllowedChars.count(codePoint)) {
        *err = U_ZERO_ERROR;
        char c = codePoint;
        ucnv_cbFromUWriteBytes(fromArgs, &c, 1, 0, err);
        return;
    }
    NoBaseSocket::IcuExtFromUCallbackImpl(fromArgs, codeUnits, length, codePoint, reason, err);
}
#endif
