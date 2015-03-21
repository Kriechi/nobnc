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

#ifndef NOSOCKET_P_H
#define NOSOCKET_P_H

#include "nosocket.h"
#include "Csocket/Csocket.h"

#ifdef HAVE_ICU
#include <unicode/ucnv.h>
#include <unicode/ucnv_cb.h>
#endif

class NoSocketPrivate : public Csock
{
public:
    NoSocketPrivate(NoSocket *q, const NoString& host, u_short port, int timeout);

    static NoSocketPrivate* get(NoSocket* socket) { return socket->d.get(); }

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

    void SockError( int iErrno, const NoString & sDescription ) override { q->SockErrorImpl(iErrno, sDescription); }

    void Connected() override { q->ConnectedImpl(); }
    void Timeout() override { q->TimeoutImpl(); }
    void Disconnected() override { q->DisconnectedImpl(); }
    void ConnectionRefused() override { q->ConnectionRefusedImpl(); }

    void ReadPaused() override { q->ReadPausedImpl(); }
    void ReachedMaxBuffer() override { q->ReachedMaxBufferImpl(); }
    bool ConnectionFrom(const NoString& sHost, ushort uPort) override { return q->ConnectionFromImpl(sHost, uPort); }

    NoSocket* q;
    Csock* csock;
    NoString hostToVerifySSL;
    NoStringSet ssTrustedFingerprints;
    NoStringSet ssCertVerificationErrors;
};

#endif // NOSOCKET_P_H
