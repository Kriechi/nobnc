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

NoSocketImpl::NoSocketImpl(NoSocket* q, const NoString& host, u_short port)
    : Csock(host, port), q(q), allowControlCodes(false)
{
#ifdef HAVE_LIBSSL
    DisableSSLCompression();
    FollowSSLCipherServerPreference();
    DisableSSLProtocols(noApp->disabledSslProtocols());
    NoString sCipher = noApp->sslCiphers();
    if (sCipher.empty()) {
        sCipher = ZNC_DefaultCipher;
    }
    SetCipher(sCipher);
#endif
}

NoSocketImpl::~NoSocketImpl()
{
    // TODO: this is a bit reverse, but Csock instances are deleted by CSockManager
    // and for the time being nothing would cleanup the NoSocket instances, so we
    // do it by hand in here for the time being...
    delete q;
}

NoSocket::NoSocket(const NoString& host, u_short port) : d(new NoSocketPrivate)
{
    d->impl = new NoSocketImpl(this, host, port);
}

NoSocket::~NoSocket()
{
}

int NoSocketImpl::ConvertAddress(const struct sockaddr_storage* pAddr, socklen_t iAddrLen, CS_STRING& address, u_short* piPort) const
{
    int ret = Csock::ConvertAddress(pAddr, iAddrLen, address, piPort);
    if (ret == 0)
        address.trimPrefix("::ffff:");
    return ret;
}

#ifdef HAVE_LIBSSL
int NoSocketImpl::VerifyPeerCertificate(int iPreVerify, X509_STORE_CTX* pStoreCTX)
{
    if (iPreVerify == 0) {
        certVerificationErrors.insert(X509_verify_cert_error_string(X509_STORE_CTX_get_error(pStoreCTX)));
    }
    return 1;
}

void NoSocketImpl::SSLHandShakeFinished()
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
    if (!ZNC_SSLVerifyHost(q->hostToVerifySsl(), pCert, sHostVerifyError)) {
        certVerificationErrors.insert(sHostVerifyError);
    }
    X509_free(pCert);
    if (certVerificationErrors.empty()) {
        NO_DEBUG(GetSockName() + ": Good cert");
        return;
    }
    NoString fingerprint = q->fingerprint();
    if (q->trustedFingerprints().count(fingerprint) != 0) {
        NO_DEBUG(GetSockName() + ": Cert explicitly trusted by user: " << fingerprint);
        return;
    }
    NO_DEBUG(GetSockName() + ": Bad cert");
    NoString sErrorMsg = "Invalid SSL certificate: ";
    sErrorMsg += NoString(", ").join(begin(certVerificationErrors), end(certVerificationErrors));
    CallSockError(errnoBadSSLCert, sErrorMsg);
    Close();
}
#endif

NoString NoSocket::hostToVerifySsl() const
{
    return d->impl->hostToVerifySsl;
}

void NoSocket::setHostToVerifySsl(const NoString& host)
{
    d->impl->hostToVerifySsl = host;
}

NoString NoSocket::fingerprint() const
{
#ifdef HAVE_LIBSSL
    // Csocket's version returns insecure SHA-1
    // This one is SHA-256
    const EVP_MD* evp = EVP_sha256();
    X509* pCert = d->impl->GetX509();
    if (!pCert) {
        NO_DEBUG(name() + ": GetSSLPeerFingerprint: Anonymous cert");
        return "";
    }
    uchar buf[256 / 8];
    uint _32 = 256 / 8;
    int iSuccess = X509_digest(pCert, evp, buf, &_32);
    X509_free(pCert);
    if (!iSuccess) {
        NO_DEBUG(name() + ": GetSSLPeerFingerprint: Couldn't find digest");
        return "";
    }
    return No::escape(NoString(reinterpret_cast<const char*>(buf), sizeof buf), No::AsciiFormat, No::HexColonFormat);
#else
    return "";
#endif
}

NoStringSet NoSocket::trustedFingerprints() const
{
    return d->impl->trustedFingerprints;
}

void NoSocket::setTrustedFingerprints(const NoStringSet& ssFPs)
{
    d->impl->trustedFingerprints = ssFPs;
}

void NoSocket::setEncoding(const NoString& sEncoding)
{
#ifdef HAVE_ICU
    d->impl->SetEncoding(sEncoding);
#endif
}
#ifdef HAVE_ICU
void NoSocketImpl::IcuExtToUCallback(UConverterToUnicodeArgs* toArgs,
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
    // Keep in sync with NoUser::AddTimestamp and NoSocketImpl::IcuExtFromUCallback
    static const std::set<char> scAllowedChars = { '\x02', '\x03', '\x04', '\x0F', '\x12', '\x16', '\x1D', '\x1F' };
    if (reason == UCNV_ILLEGAL && length == 1 && scAllowedChars.count(*codeUnits)) {
        *err = U_ZERO_ERROR;
        UChar c = *codeUnits;
        ucnv_cbToUWriteUChars(toArgs, &c, 1, 0, err);
        return;
    }
    Csock::IcuExtToUCallback(toArgs, codeUnits, length, reason, err);
}
void NoSocketImpl::IcuExtFromUCallback(UConverterFromUnicodeArgs* fromArgs,
                                       const UChar* codeUnits,
                                       int32_t length,
                                       UChar32 codePoint,
                                       UConverterCallbackReason reason,
                                       UErrorCode* err)
{
    // See comment in NoSocketImpl::IcuExtToUCallback
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
NoString NoSocket::remoteAddress() const
{
    return d->impl->GetRemoteIP();
}

NoString NoSocket::pemFile() const
{
    return d->impl->GetPemLocation();
}

void NoSocket::setPemFile(const NoString& filePath)
{
    d->impl->SetPemLocation(filePath);
}

bool NoSocket::write(const char* data, ulong len)
{
    return d->impl->Write(data, len);
}
bool NoSocket::write(const NoString& data)
{
    return d->impl->Write(data);
}
NoString NoSocket::name() const
{
    return d->impl->GetSockName();
}
NoString NoSocket::bindHost() const
{
    return d->impl->GetBindHost();
}
void NoSocket::setName(const NoString& name)
{
    d->impl->SetSockName(name);
}
bool NoSocket::isListener() const
{
    return d->impl->GetType() == Csock::LISTENER;
}
bool NoSocket::isOutbound() const
{
    return d->impl->GetType() == Csock::OUTBOUND;
}
bool NoSocket::isInbound() const
{
    return d->impl->GetType() == Csock::INBOUND;
}
bool NoSocket::isConnected() const
{
    return d->impl->IsConnected();
}
ushort NoSocket::port() const
{
    return d->impl->GetPort();
}
NoString NoSocket::host() const
{
    return d->impl->GetHostName();
}
ushort NoSocket::localPort() const
{
    return d->impl->GetLocalPort();
}
ushort NoSocket::remotePort() const
{
    return d->impl->GetRemotePort();
}
bool NoSocket::isSsl() const
{
    return d->impl->GetSSL();
}
void NoSocket::pauseRead()
{
    d->impl->PauseRead();
}
void NoSocket::resumeRead()
{
    d->impl->UnPauseRead();
}
NoString NoSocket::localAddress() const
{
    return d->impl->GetLocalIP();
}
#ifdef HAVE_LIBSSL
NoString NoSocket::cipher() const
{
    return d->impl->GetCipher();
}
void NoSocket::setCipher(const NoString& sCipher)
{
    d->impl->SetCipher(sCipher);
}
long NoSocket::peerFingerprint(NoString& fingerprint) const
{
    return d->impl->GetPeerFingerprint(fingerprint);
}
uint NoSocket::requireClientCertFlags() const
{
    return d->impl->GetRequireClientCertFlags();
}
void NoSocket::setRequireClientCertFlags(uint iRequireClientCertFlags)
{
    d->impl->SetRequireClientCertFlags(iRequireClientCertFlags);
}
SSL_SESSION* NoSocket::sslSession() const
{
    return d->impl->GetSSLSession();
}
#endif
bool NoSocket::connect()
{
    return d->impl->Connect();
}
bool NoSocket::listen(ushort port, int maxConns, const NoString& bindHost, uint timeout, bool bDetach)
{
    return d->impl->Listen(port, maxConns, bindHost, timeout, bDetach);
}
void NoSocket::enableReadLine()
{
    d->impl->EnableReadLine();
}
void NoSocket::disableReadLine()
{
    d->impl->DisableReadLine();
}
uint NoSocket::maxBufferThreshold() const
{
    return d->impl->GetMaxBufferThreshold();
}
void NoSocket::setMaxBufferThreshold(uint iThreshold)
{
    d->impl->SetMaxBufferThreshold(iThreshold);
}
cs_sock_t& NoSocket::readDescriptor() const
{
    return d->impl->GetRSock();
}
void NoSocket::setReadDescriptor(cs_sock_t iSock)
{
    d->impl->SetRSock(iSock);
}
cs_sock_t& NoSocket::writeDescriptor() const
{
    return d->impl->GetWSock();
}
void NoSocket::setWriteDescriptor(cs_sock_t iSock)
{
    d->impl->SetWSock(iSock);
}
int NoSocket::timeout() const
{
    return d->impl->GetTimeout();
}
void NoSocket::setTimeout(int timeout, TimeoutType type)
{
    d->impl->SetTimeout(timeout, type);
}

Csock* NoSocketImpl::GetSockObj(const NoString& host, ushort port)
{
    NoSocket* sockObj = q->createSocket(host, port);
    if (sockObj)
        return NoSocketPrivate::get(sockObj);
    return Csock::GetSockObj(host, port);
}
NoSocket* NoSocket::createSocket(const NoString& host, ushort port)
{
    return nullptr;
}

NoSocket::CloseType NoSocket::closeType() const
{
    return static_cast<CloseType>(d->impl->GetCloseType());
}
void NoSocket::close(CloseType type)
{
    d->impl->Close(static_cast<Csock::ECloseType>(type));
}
NoString& NoSocket::internalReadBuffer()
{
    return d->impl->GetInternalReadBuffer();
}
NoString& NoSocket::internalWriteBuffer()
{
    return d->impl->GetInternalWriteBuffer();
}

void NoSocketImpl::ReadLine(const NoString& line)
{
    q->readLine(line);
}
void NoSocket::readLine(const NoString& line)
{
    d->impl->Csock::ReadLine(line);
}

void NoSocketImpl::ReadData(const char* data, size_t len)
{
    q->readData(data, len);
}
void NoSocket::readData(const char* data, ulong len)
{
    return d->impl->Csock::ReadData(data, len);
}

void NoSocketImpl::PushBuff(const char* data, size_t len, bool bStartAtZero)
{
    q->pushBuffer(data, len, bStartAtZero);
}
void NoSocket::pushBuffer(const char* data, ulong len, bool bStartAtZero)
{
    d->impl->Csock::PushBuff(data, len, bStartAtZero);
}

bool NoSocket::startTls()
{
    return d->impl->StartTLS();
}
bool NoSocket::isReady() const
{
    return d->impl->GetConState() == Csock::CST_OK;
}

void NoSocket::onConnected()
{
    d->impl->Csock::Connected();
}
void NoSocket::onTimeout()
{
    d->impl->Csock::Timeout();
}
void NoSocket::onDisconnected()
{
    d->impl->Csock::Disconnected();
}
void NoSocket::onConnectionRefused()
{
    d->impl->Csock::ConnectionRefused();
}
void NoSocket::onReadPaused()
{
    d->impl->Csock::ReadPaused();
}
void NoSocket::onReachedMaxBuffer()
{
    d->impl->Csock::ReachedMaxBuffer();
}
void NoSocket::onSocketError(int iErrno, const NoString& description)
{
    d->impl->Csock::SockError(iErrno, description);
}
bool NoSocket::onConnectionFrom(const NoString& host, ushort port)
{
    return d->impl->Csock::ConnectionFrom(host, port);
}
