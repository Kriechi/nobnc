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
#include "nosocket_p.h"
#include "nosslverifyhost.h"
#include "noapp.h"
#include "noescape.h"
#include <signal.h>

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

NoSocketPrivate::NoSocketPrivate(NoSocket *q, const NoString& host, u_short port, int timeout)
    : Csock(host, port, timeout), q(q), allowControlCodes(false)
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

NoSocket::NoSocket(const NoString& host, u_short port, int timeout) : d(new NoSocketPrivate(this, host, port, timeout))
{
}

NoSocket::~NoSocket()
{
}

Csock* NoSocket::GetHandle() const
{
    return d->csock;
}

int NoSocketPrivate::ConvertAddress(const struct sockaddr_storage* pAddr, socklen_t iAddrLen, CS_STRING& sIP, u_short* piPort) const
{
    int ret = Csock::ConvertAddress(pAddr, iAddrLen, sIP, piPort);
    if (ret == 0) sIP.trimPrefix("::ffff:");
    return ret;
}

#ifdef HAVE_LIBSSL
int NoSocketPrivate::VerifyPeerCertificate(int iPreVerify, X509_STORE_CTX* pStoreCTX)
{
    if (iPreVerify == 0) {
        ssCertVerificationErrors.insert(X509_verify_cert_error_string(X509_STORE_CTX_get_error(pStoreCTX)));
    }
    return 1;
}

void NoSocketPrivate::SSLHandShakeFinished()
{
    if (GetType() != ETConn::OUTBOUND) {
        return;
    }

    X509* pCert = GetX509();
    if (!pCert) {
        NO_DEBUG(GetSockName() + ": No cert");
        CallSockError(errnoBadSSLCert, "Anonymous SSL cert is not allowed");
        Close();
        return;
    }
    NoString sHostVerifyError;
    if (!ZNC_SSLVerifyHost(q->GetHostToVerifySSL(), pCert, sHostVerifyError)) {
        ssCertVerificationErrors.insert(sHostVerifyError);
    }
    X509_free(pCert);
    if (ssCertVerificationErrors.empty()) {
        NO_DEBUG(GetSockName() + ": Good cert");
        return;
    }
    NoString sFP = q->GetSSLPeerFingerprint();
    if (q->GetSSLTrustedPeerFingerprints().count(sFP) != 0) {
        NO_DEBUG(GetSockName() + ": Cert explicitly trusted by user: " << sFP);
        return;
    }
    NO_DEBUG(GetSockName() + ": Bad cert");
    NoString sErrorMsg = "Invalid SSL certificate: ";
    sErrorMsg += NoString(", ").join(begin(ssCertVerificationErrors), end(ssCertVerificationErrors));
    CallSockError(errnoBadSSLCert, sErrorMsg);
    Close();
}
#endif

NoString NoSocket::GetHostToVerifySSL() const
{
    return d->hostToVerifySSL;
}

void NoSocket::SetHostToVerifySSL(const NoString& sHost)
{
    d->hostToVerifySSL = sHost;
}

NoString NoSocket::GetSSLPeerFingerprint() const
{
#ifdef HAVE_LIBSSL
    // Csocket's version returns insecure SHA-1
    // This one is SHA-256
    const EVP_MD* evp = EVP_sha256();
    X509* pCert = d->GetX509();
    if (!pCert) {
        NO_DEBUG(GetSockName() + ": GetSSLPeerFingerprint: Anonymous cert");
        return "";
    }
    uchar buf[256 / 8];
    uint _32 = 256 / 8;
    int iSuccess = X509_digest(pCert, evp, buf, &_32);
    X509_free(pCert);
    if (!iSuccess) {
        NO_DEBUG(GetSockName() + ": GetSSLPeerFingerprint: Couldn't find digest");
        return "";
    }
    return No::escape(NoString(reinterpret_cast<const char*>(buf), sizeof buf), No::AsciiFormat, No::HexColonFormat);
#else
    return "";
#endif
}

NoStringSet NoSocket::GetSSLTrustedPeerFingerprints() const
{
    return d->ssTrustedFingerprints;
}

void NoSocket::SetSSLTrustedPeerFingerprints(const NoStringSet& ssFPs)
{
    d->ssTrustedFingerprints = ssFPs;
}

void NoSocket::SetEncoding(const NoString& sEncoding)
{
#ifdef HAVE_ICU
    d->csock->SetEncoding(sEncoding);
#endif
}
#ifdef HAVE_ICU
void NoSocketPrivate::IcuExtToUCallback(UConverterToUnicodeArgs* toArgs, const char* codeUnits, int32_t length, UConverterCallbackReason reason, UErrorCode* err )
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
    // Keep in sync with NoUser::AddTimestamp and NoSocketPrivate::IcuExtFromUCallback
    static const std::set<char> scAllowedChars = { '\x02', '\x03', '\x04', '\x0F', '\x12', '\x16', '\x1D', '\x1F' };
    if (reason == UCNV_ILLEGAL && length == 1 && scAllowedChars.count(*codeUnits)) {
        *err = U_ZERO_ERROR;
        UChar c = *codeUnits;
        ucnv_cbToUWriteUChars(toArgs, &c, 1, 0, err);
        return;
    }
    Csock::IcuExtToUCallback(toArgs, codeUnits, length, reason, err);
}
void NoSocketPrivate::IcuExtFromUCallback(UConverterFromUnicodeArgs* fromArgs, const UChar* codeUnits, int32_t length, UChar32 codePoint, UConverterCallbackReason reason, UErrorCode* err )
{
    // See comment in NoSocketPrivate::IcuExtToUCallback
    static const std::set<UChar32> scAllowedChars = { 0x02, 0x03, 0x04, 0x0F, 0x12, 0x16, 0x1D, 0x1F };
    if (reason == UCNV_ILLEGAL && scAllowedChars.count(codePoint)) {
        *err = U_ZERO_ERROR;
        char c = codePoint;
        ucnv_cbFromUWriteBytes(fromArgs, &c, 1, 0, err);
        return;
    }
    Csock::IcuExtFromUCallback(fromArgs, codeUnits, length, codePoint, reason, err);
}
#endif
NoString NoSocket::GetRemoteIP() const { return d->csock->GetRemoteIP(); }

void NoSocket::SetPemLocation( const NoString & sPemFile ) { d->csock->SetPemLocation(sPemFile); }
bool NoSocket::Write( const char *data, size_t len ) { return d->csock->Write(data, len); }
bool NoSocket::Write( const NoString & sData ) { return d->csock->Write(sData); }
time_t NoSocket::GetTimeSinceLastDataTransaction( time_t iNow ) const { return d->csock->GetTimeSinceLastDataTransaction(iNow); }
const NoString & NoSocket::GetSockName() const { return d->csock->GetSockName(); }
const NoString & NoSocket::GetBindHost() const { return d->csock->GetBindHost(); }
void NoSocket::SetSockName( const NoString & sName ) { d->csock->SetSockName(sName); }
bool NoSocket::IsListener() const { return d->csock->GetType() == Csock::LISTENER; }
bool NoSocket::IsOutbound() const { return d->csock->GetType() == Csock::OUTBOUND; }
bool NoSocket::IsInbound() const { return d->csock->GetType() == Csock::INBOUND; }
bool NoSocket::IsConnected() const { return d->csock->IsConnected(); }
uint16_t NoSocket::GetPort() const { return d->csock->GetPort(); }
const NoString & NoSocket::GetHostName() const { return d->csock->GetHostName(); }
uint16_t NoSocket::GetLocalPort() const { return d->csock->GetLocalPort(); }
uint16_t NoSocket::GetRemotePort() const { return d->csock->GetRemotePort(); }
bool NoSocket::GetSSL() const { return d->csock->GetSSL(); }
void NoSocket::PauseRead() { d->csock->PauseRead(); }
void NoSocket::UnPauseRead() { d->csock->UnPauseRead(); }
NoString NoSocket::GetLocalIP() const { return d->csock->GetLocalIP(); }
#ifdef HAVE_LIBSSL
void NoSocket::SetCipher( const NoString & sCipher ) { d->csock->SetCipher(sCipher); }
long NoSocket::GetPeerFingerprint( NoString & sFP ) const { return d->csock->GetPeerFingerprint(sFP); }
void NoSocket::SetRequireClientCertFlags( uint32_t iRequireClientCertFlags ) { d->csock->SetRequireClientCertFlags(iRequireClientCertFlags); }
SSL_SESSION * NoSocket::GetSSLSession() const { return d->csock->GetSSLSession(); }
#endif
uint64_t NoSocket::GetBytesRead() const { return d->csock->GetBytesRead(); }
void NoSocket::ResetBytesRead() { d->csock->ResetBytesRead(); }
uint64_t NoSocket::GetBytesWritten() const { return d->csock->GetBytesWritten(); }
void NoSocket::ResetBytesWritten() { d->csock->ResetBytesWritten(); }
double NoSocket::GetAvgRead( uint64_t iSample ) const { return d->csock->GetAvgRead(iSample); }
double NoSocket::GetAvgWrite( uint64_t iSample ) const { return d->csock->GetAvgWrite(iSample); }
uint64_t NoSocket::GetStartTime() const { return d->csock->GetStartTime(); }
bool NoSocket::Connect() { return d->csock->Connect(); }
bool NoSocket::Listen( uint16_t iPort, int iMaxConns, const NoString & sBindHost, uint32_t iTimeout, bool bDetach )
{
    return d->csock->Listen(iPort, iMaxConns, sBindHost, iTimeout, bDetach);
}
void NoSocket::EnableReadLine() { d->csock->EnableReadLine(); }
void NoSocket::DisableReadLine() { d->csock->DisableReadLine(); }
void NoSocket::SetMaxBufferThreshold( uint32_t iThreshold ) { d->csock->SetMaxBufferThreshold(iThreshold); }
cs_sock_t & NoSocket::GetRSock() { return d->csock->GetRSock(); }
void NoSocket::SetRSock( cs_sock_t iSock ) { d->csock->SetRSock(iSock); }
cs_sock_t & NoSocket::GetWSock() { return d->csock->GetWSock(); }
void NoSocket::SetWSock( cs_sock_t iSock ) { d->csock->SetWSock(iSock); }
bool NoSocket::ConnectFD( int iReadFD, int iWriteFD, const CS_STRING & sName, bool bIsSSL)
{
    return d->csock->ConnectFD(iReadFD, iWriteFD, sName, bIsSSL, Csock::INBOUND);
}
void NoSocket::SetTimeout( int iTimeout, uint32_t iTimeoutType ) { d->csock->SetTimeout(iTimeout, iTimeoutType); }

Csock* NoSocketPrivate::GetSockObj(const NoString& sHost, ushort uPort)
{
    NoSocket* sockObj = q->GetSockObjImpl(sHost, uPort);
    if (sockObj)
        return sockObj->GetHandle();
    return Csock::GetSockObj(sHost, uPort);
}
NoSocket* NoSocket::GetSockObjImpl(const NoString& sHost, ushort uPort) { return nullptr; }

NoSocket::CloseType NoSocket::GetCloseType() const { return static_cast<CloseType>(d->csock->GetCloseType()); }
void NoSocket::Close(CloseType type) { d->csock->Close(static_cast<Csock::ECloseType>(type)); }
NoString & NoSocket::GetInternalReadBuffer() { return d->csock->GetInternalReadBuffer(); }
NoString & NoSocket::GetInternalWriteBuffer() { return d->csock->GetInternalWriteBuffer(); }

void NoSocketPrivate::ReadLine(const NoString & sLine) { q->ReadLineImpl(sLine); }
void NoSocket::ReadLineImpl(const NoString & sLine) { d->csock->Csock::ReadLine(sLine); }

void NoSocketPrivate::ReadData(const char *data, size_t len) { q->ReadDataImpl(data, len); }
void NoSocket::ReadDataImpl(const char* data, size_t len) { return d->csock->Csock::ReadData(data, len); }

void NoSocketPrivate::PushBuff(const char *data, size_t len, bool bStartAtZero) { q->PushBuffImpl(data, len, bStartAtZero); }
void NoSocket::PushBuffImpl( const char *data, size_t len, bool bStartAtZero ) { d->csock->Csock::PushBuff(data, len, bStartAtZero); }

bool NoSocket::StartTLS() { return d->csock->StartTLS(); }
bool NoSocket::IsConOK() const { return d->csock->GetConState() == Csock::CST_OK; }

void NoSocket::ConnectedImpl() { d->csock->Csock::Connected(); }
void NoSocket::TimeoutImpl() { d->csock->Csock::Timeout(); }
void NoSocket::DisconnectedImpl() { d->csock->Csock::Disconnected(); }
void NoSocket::ConnectionRefusedImpl() { d->csock->Csock::ConnectionRefused(); }
void NoSocket::ReadPausedImpl() { d->csock->Csock::ReadPaused(); }
void NoSocket::ReachedMaxBufferImpl() { d->csock->Csock::ReachedMaxBuffer(); }
void NoSocket::SockErrorImpl(int iErrno, const NoString& sDescription) { d->csock->Csock::SockError(iErrno, sDescription); }
bool NoSocket::ConnectionFromImpl(const NoString& sHost, ushort uPort) { return d->csock->Csock::ConnectionFrom(sHost, uPort); }
