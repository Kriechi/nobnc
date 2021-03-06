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
#include "nosslverifyhost_p.h"
#include "nosocketinfo.h"
#include "nomodule_p.h"
#include "nonetwork.h"
#include "nouser_p.h"
#include "noapp.h"
#include "noapp_p.h"
#include "noutils.h"
#include <signal.h>

NoSocketImpl::NoSocketImpl(NoSocket* q) : q(q), allowControlCodes(false)
{
#ifdef HAVE_LIBSSL
    DisableSSLCompression();
    FollowSSLCipherServerPreference();
    DisableSSLProtocols(noApp->disabledSslProtocols());
    SetCipher(noApp->sslCiphers());
#endif
}

NoSocketImpl::~NoSocketImpl()
{
    // TODO: this is a bit reverse, but Csock instances are deleted by CSockManager
    // and for the time being nothing would cleanup the NoSocket instances, so we
    // do it by hand in here for the time being...
    delete q;
}

NoSocket::NoSocket(NoModule* module) : d(new NoSocketPrivate)
{
    d->module = module;
    d->impl = new NoSocketImpl(this);

    if (module) {
        NoModulePrivate::get(module)->sockets.insert(this);
        enableReadLine();
        setMaxBufferThreshold(10240);
    }
}

NoSocket::~NoSocket()
{
    if (d->module) {
        NoModulePrivate::get(d->module)->sockets.erase(this);
        NoAppPrivate::get(noApp)->manager.removeSocket(this);

        NoSocketInfo info(this);
        NoUser* user = d->module->user();

        if (user && d->module->type() != No::GlobalModule) {
            NoUserPrivate::get(user)->addBytesWritten(info.bytesWritten());
            NoUserPrivate::get(user)->addBytesRead(info.bytesRead());
        } else {
            NoAppPrivate::get(noApp)->addBytesWritten(info.bytesWritten());
            NoAppPrivate::get(noApp)->addBytesRead(info.bytesRead());
        }
    }
}

NoModule* NoSocket::module() const
{
    return d->module;
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
    if (!No::sslVerifyHost(q->hostToVerifySsl(), pCert, sHostVerifyError)) {
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
void NoSocket::setBindHost(const NoString& bindHost)
{
    return d->impl->SetBindHost(bindHost);
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
void NoSocket::setPort(ushort port)
{
    return d->impl->SetPort(port);
}
NoString NoSocket::host() const
{
    return d->impl->GetHostName();
}
void NoSocket::setHost(const NoString& host)
{
    d->impl->SetHostName(host);
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
void NoSocket::setSsl(bool ssl)
{
    d->impl->SetSSL(ssl);
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

static NoString no_socketName(NoModule* module, const NoString& infix)
{
    NoString name = "MOD::" + infix + "::" + module->name();
    NoUser* user = module->user();
    if (user)
        name += "::" + user->userName();
    NoNetwork* network = module->network();
    if (network)
        name += "::" + network->name();
    return name;
}

void NoSocket::connect()
{
    if (d->module && name().empty())
        setName(no_socketName(d->module, "C"));

    NoString bindHost = NoSocket::bindHost();
    if (d->module) {
        NoUser* user = d->module->user();
        if (user) {
            bindHost = user->bindHost();
            NoNetwork* network = d->module->network();
            if (network)
                bindHost = network->bindHost();
        }
    }

    NoAppPrivate::get(noApp)->manager.connect(host(), port(), name(), isSsl(), bindHost, this);
}
bool NoSocket::listen(ushort port)
{
    if (d->module && name().empty())
        setName(no_socketName(d->module, "L"));

    return NoAppPrivate::get(noApp)->manager.listen(port, name(), bindHost(), isSsl(), this);
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
void NoSocket::setTimeout(int timeout)
{
    d->impl->SetTimeout(timeout, Csock::TMO_ALL);
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

bool NoSocket::isClosed() const
{
    return d->impl->GetCloseType() != Csock::CLT_DONT;
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
    NO_DEBUG(name() << " == ReachedMaxBuffer()");
    if (d->module) {
        d->module->putModule("Socket (" + name() + ") reached its max buffer limit and was closed!");
        close();
    }
}
void NoSocket::onSocketError(int error, const NoString& description)
{
    NO_DEBUG(name() << " == SockError(" << description << ", " << strerror(error) << ")");
    if (d->module && error == EMFILE) {
        // We have too many open fds, this can cause a busy loop.
        close();
    }
}
bool NoSocket::onConnectionFrom(const NoString& host, ushort port)
{
    return !d->module || noApp->allowConnectionFrom(host);
}
