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
#include "nosslverifyhost.h"
#include "noapp.h"
#include "noescape.h"
#include "Csocket/Csocket.h"
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

class NoCsock : public Csock
{
public:
    NoCsock(NoSocket *q, const NoString& host, u_short port, int timeout);

    int ConvertAddress(const struct sockaddr_storage* pAddr, socklen_t iAddrLen, CS_STRING& sIP, u_short* piPort) const override;
#ifdef HAVE_LIBSSL
    int VerifyPeerCertificate(int iPreVerify, X509_STORE_CTX* pStoreCTX) override;
    void SSLHandShakeFinished() override;
#endif

#ifdef HAVE_ICU
    void IcuExtToUCallback(UConverterToUnicodeArgs* toArgs, const char* codeUnits, int32_t length, UConverterCallbackReason reason, UErrorCode* err ) override;
    void IcuExtFromUCallback(UConverterFromUnicodeArgs* fromArgs, const UChar* codeUnits, int32_t length, UChar32 codePoint, UConverterCallbackReason reason, UErrorCode* err ) override;
#endif

    Csock* GetSockObj(const NoString& sHost, ushort uPort) override;

    void ReadLine( const NoString & sLine ) override;
    void ReadData(const char* data, size_t len) override;
    void PushBuff( const char *data, size_t len, bool bStartAtZero = false ) override;

    void SockError( int iErrno, const NoString & sDescription ) override { q_ptr->SockErrorImpl(iErrno, sDescription); }

    void Connected() override { q_ptr->ConnectedImpl(); }
    void Timeout() override { q_ptr->TimeoutImpl(); }
    void Disconnected() override { q_ptr->DisconnectedImpl(); }
    void ConnectionRefused() override { q_ptr->ConnectionRefusedImpl(); }

    void ReadPaused() override { q_ptr->ReadPausedImpl(); }
    void ReachedMaxBuffer() override { q_ptr->ReachedMaxBufferImpl(); }
    bool ConnectionFrom(const NoString& sHost, ushort uPort) override { return q_ptr->ConnectionFromImpl(sHost, uPort); }

private:
    NoSocket* q_ptr;
    NoStringSet m_ssCertVerificationErrors;
};

NoCsock::NoCsock(NoSocket *q, const NoString& host, u_short port, int timeout) : Csock(host, port, timeout), q_ptr(q)
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

NoSocket::NoSocket(int timeout) :
    m_csock(new NoCsock(this, "", 0, timeout)), m_ssTrustedFingerprints()
{
}

NoSocket::NoSocket(const NoString& host, u_short port, int timeout) :
    m_csock(new NoCsock(this, host, port, timeout)), m_ssTrustedFingerprints()
{
}

NoSocket::~NoSocket()
{
}

Csock* NoSocket::GetHandle() const
{
    return m_csock;
}

int NoCsock::ConvertAddress(const struct sockaddr_storage* pAddr, socklen_t iAddrLen, CS_STRING& sIP, u_short* piPort) const
{
    int ret = Csock::ConvertAddress(pAddr, iAddrLen, sIP, piPort);
    if (ret == 0) sIP.trimPrefix("::ffff:");
    return ret;
}

#ifdef HAVE_LIBSSL
int NoCsock::VerifyPeerCertificate(int iPreVerify, X509_STORE_CTX* pStoreCTX)
{
    if (iPreVerify == 0) {
        m_ssCertVerificationErrors.insert(X509_verify_cert_error_string(X509_STORE_CTX_get_error(pStoreCTX)));
    }
    return 1;
}

void NoCsock::SSLHandShakeFinished()
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
    if (!ZNC_SSLVerifyHost(q_ptr->GetHostToVerifySSL(), pCert, sHostVerifyError)) {
        m_ssCertVerificationErrors.insert(sHostVerifyError);
    }
    X509_free(pCert);
    if (m_ssCertVerificationErrors.empty()) {
        NO_DEBUG(GetSockName() + ": Good cert");
        return;
    }
    NoString sFP = q_ptr->GetSSLPeerFingerprint();
    if (q_ptr->GetSSLTrustedPeerFingerprints().count(sFP) != 0) {
        NO_DEBUG(GetSockName() + ": Cert explicitly trusted by user: " << sFP);
        return;
    }
    NO_DEBUG(GetSockName() + ": Bad cert");
    NoString sErrorMsg = "Invalid SSL certificate: ";
    sErrorMsg += NoString(", ").join(begin(m_ssCertVerificationErrors), end(m_ssCertVerificationErrors));
    CallSockError(errnoBadSSLCert, sErrorMsg);
    Close();
}
#endif

NoString NoSocket::GetHostToVerifySSL() const
{
    return m_HostToVerifySSL;
}

void NoSocket::SetHostToVerifySSL(const NoString& sHost)
{
    m_HostToVerifySSL = sHost;
}

NoString NoSocket::GetSSLPeerFingerprint() const
{
#ifdef HAVE_LIBSSL
    // Csocket's version returns insecure SHA-1
    // This one is SHA-256
    const EVP_MD* evp = EVP_sha256();
    X509* pCert = GetX509();
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
    return m_ssTrustedFingerprints;
}

void NoSocket::SetSSLTrustedPeerFingerprints(const NoStringSet& ssFPs)
{
    m_ssTrustedFingerprints = ssFPs;
}

void NoSocket::SetEncoding(const NoString& sEncoding)
{
#ifdef HAVE_ICU
    m_csock->SetEncoding(sEncoding);
#endif
}
#ifdef HAVE_ICU
void NoCsock::IcuExtToUCallback(UConverterToUnicodeArgs* toArgs, const char* codeUnits, int32_t length, UConverterCallbackReason reason, UErrorCode* err )
{
    q_ptr->IcuExtToUCallbackImpl(toArgs, codeUnits, length, reason, err);
}
void NoSocket::IcuExtToUCallbackImpl(UConverterToUnicodeArgs* toArgs, const char* codeUnits, int32_t length, UConverterCallbackReason reason, UErrorCode* err )
{
    m_csock->Csock::IcuExtToUCallback(toArgs, codeUnits, length, reason, err);
}
void NoCsock::IcuExtFromUCallback(UConverterFromUnicodeArgs* fromArgs, const UChar* codeUnits, int32_t length, UChar32 codePoint, UConverterCallbackReason reason, UErrorCode* err )
{
    q_ptr->IcuExtFromUCallbackImpl(fromArgs, codeUnits, length, codePoint, reason, err);
}
void NoSocket::IcuExtFromUCallbackImpl(UConverterFromUnicodeArgs* fromArgs, const UChar* codeUnits, int32_t length, UChar32 codePoint, UConverterCallbackReason reason, UErrorCode* err )
{
    m_csock->Csock::IcuExtFromUCallback(fromArgs, codeUnits, length, codePoint, reason, err);
}
#endif
NoString NoSocket::GetRemoteIP() const { return m_csock->GetRemoteIP(); }

void NoSocket::SetPemLocation( const NoString & sPemFile ) { m_csock->SetPemLocation(sPemFile); }
bool NoSocket::Write( const char *data, size_t len ) { return m_csock->Write(data, len); }
bool NoSocket::Write( const NoString & sData ) { return m_csock->Write(sData); }
time_t NoSocket::GetTimeSinceLastDataTransaction( time_t iNow ) const { return m_csock->GetTimeSinceLastDataTransaction(iNow); }
const NoString & NoSocket::GetSockName() const { return m_csock->GetSockName(); }
const NoString & NoSocket::GetBindHost() const { return m_csock->GetBindHost(); }
void NoSocket::SetSockName( const NoString & sName ) { m_csock->SetSockName(sName); }
bool NoSocket::IsListener() const { return m_csock->GetType() == Csock::LISTENER; }
bool NoSocket::IsOutbound() const { return m_csock->GetType() == Csock::OUTBOUND; }
bool NoSocket::IsInbound() const { return m_csock->GetType() == Csock::INBOUND; }
bool NoSocket::IsConnected() const { return m_csock->IsConnected(); }
uint16_t NoSocket::GetPort() const { return m_csock->GetPort(); }
const NoString & NoSocket::GetHostName() const { return m_csock->GetHostName(); }
uint16_t NoSocket::GetLocalPort() const { return m_csock->GetLocalPort(); }
uint16_t NoSocket::GetRemotePort() const { return m_csock->GetRemotePort(); }
bool NoSocket::GetSSL() const { return m_csock->GetSSL(); }
void NoSocket::PauseRead() { m_csock->PauseRead(); }
void NoSocket::UnPauseRead() { m_csock->UnPauseRead(); }
NoString NoSocket::GetLocalIP() const { return m_csock->GetLocalIP(); }
#ifdef HAVE_LIBSSL
void NoSocket::SetCipher( const NoString & sCipher ) { m_csock->SetCipher(sCipher); }
long NoSocket::GetPeerFingerprint( NoString & sFP ) const { return m_csock->GetPeerFingerprint(sFP); }
void NoSocket::SetRequireClientCertFlags( uint32_t iRequireClientCertFlags ) { m_csock->SetRequireClientCertFlags(iRequireClientCertFlags); }
SSL_SESSION * NoSocket::GetSSLSession() const { return m_csock->GetSSLSession(); }
X509 *NoSocket::GetX509() const { return m_csock->GetX509(); }
#endif
uint64_t NoSocket::GetBytesRead() const { return m_csock->GetBytesRead(); }
void NoSocket::ResetBytesRead() { m_csock->ResetBytesRead(); }
uint64_t NoSocket::GetBytesWritten() const { return m_csock->GetBytesWritten(); }
void NoSocket::ResetBytesWritten() { m_csock->ResetBytesWritten(); }
double NoSocket::GetAvgRead( uint64_t iSample ) const { return m_csock->GetAvgRead(iSample); }
double NoSocket::GetAvgWrite( uint64_t iSample ) const { return m_csock->GetAvgWrite(iSample); }
uint64_t NoSocket::GetStartTime() const { return m_csock->GetStartTime(); }
bool NoSocket::Connect() { return m_csock->Connect(); }
bool NoSocket::Listen( uint16_t iPort, int iMaxConns, const NoString & sBindHost, uint32_t iTimeout, bool bDetach )
{
    return m_csock->Listen(iPort, iMaxConns, sBindHost, iTimeout, bDetach);
}
void NoSocket::EnableReadLine() { m_csock->EnableReadLine(); }
void NoSocket::DisableReadLine() { m_csock->DisableReadLine(); }
void NoSocket::SetMaxBufferThreshold( uint32_t iThreshold ) { m_csock->SetMaxBufferThreshold(iThreshold); }
cs_sock_t & NoSocket::GetRSock() { return m_csock->GetRSock(); }
void NoSocket::SetRSock( cs_sock_t iSock ) { m_csock->SetRSock(iSock); }
cs_sock_t & NoSocket::GetWSock() { return m_csock->GetWSock(); }
void NoSocket::SetWSock( cs_sock_t iSock ) { m_csock->SetWSock(iSock); }
bool NoSocket::ConnectFD( int iReadFD, int iWriteFD, const CS_STRING & sName, bool bIsSSL)
{
    return m_csock->ConnectFD(iReadFD, iWriteFD, sName, bIsSSL, Csock::INBOUND);
}
void NoSocket::SetTimeout( int iTimeout, uint32_t iTimeoutType ) { m_csock->SetTimeout(iTimeout, iTimeoutType); }

Csock* NoCsock::GetSockObj(const NoString& sHost, ushort uPort)
{
    NoSocket* sockObj = q_ptr->GetSockObjImpl(sHost, uPort);
    if (sockObj)
        return sockObj->GetHandle();
    return Csock::GetSockObj(sHost, uPort);
}
NoSocket* NoSocket::GetSockObjImpl(const NoString& sHost, ushort uPort) { return nullptr; }

NoSocket::CloseType NoSocket::GetCloseType() const { return static_cast<CloseType>(m_csock->GetCloseType()); }
void NoSocket::Close(CloseType type) { m_csock->Close(static_cast<Csock::ECloseType>(type)); }
NoString & NoSocket::GetInternalReadBuffer() { return m_csock->GetInternalReadBuffer(); }
NoString & NoSocket::GetInternalWriteBuffer() { return m_csock->GetInternalWriteBuffer(); }

void NoCsock::ReadLine(const NoString & sLine) { q_ptr->ReadLineImpl(sLine); }
void NoSocket::ReadLineImpl(const NoString & sLine) { m_csock->Csock::ReadLine(sLine); }

void NoCsock::ReadData(const char *data, size_t len) { q_ptr->ReadDataImpl(data, len); }
void NoSocket::ReadDataImpl(const char* data, size_t len) { return m_csock->Csock::ReadData(data, len); }

void NoCsock::PushBuff(const char *data, size_t len, bool bStartAtZero) { q_ptr->PushBuffImpl(data, len, bStartAtZero); }
void NoSocket::PushBuffImpl( const char *data, size_t len, bool bStartAtZero ) { m_csock->Csock::PushBuff(data, len, bStartAtZero); }

void NoSocket::AddCron( CCron * pcCron ) { m_csock->AddCron(pcCron); }
bool NoSocket::StartTLS() { return m_csock->StartTLS(); }
bool NoSocket::IsConOK() const { return m_csock->GetConState() == Csock::CST_OK; }

void NoSocket::ConnectedImpl() { m_csock->Csock::Connected(); }
void NoSocket::TimeoutImpl() { m_csock->Csock::Timeout(); }
void NoSocket::DisconnectedImpl() { m_csock->Csock::Disconnected(); }
void NoSocket::ConnectionRefusedImpl() { m_csock->Csock::ConnectionRefused(); }
void NoSocket::ReadPausedImpl() { m_csock->Csock::ReadPaused(); }
void NoSocket::ReachedMaxBufferImpl() { m_csock->Csock::ReachedMaxBuffer(); }
void NoSocket::SockErrorImpl(int iErrno, const NoString& sDescription) { m_csock->Csock::SockError(iErrno, sDescription); }
bool NoSocket::ConnectionFromImpl(const NoString& sHost, ushort uPort) { return m_csock->Csock::ConnectionFrom(sHost, uPort); }
