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

#ifndef NOSOCKET_P_H
#define NOSOCKET_P_H

#include "nosocket.h"
#include "Csocket/Csocket.h"

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#endif

#ifdef HAVE_ICU
#include <unicode/ucnv.h>
#include <unicode/ucnv_cb.h>
#endif

// All existing errno codes seem to be in range 1-300
enum {
    errnoBadSSLCert = 12569 // TODO
};

class NoSocketImpl : public Csock
{
public:
    NoSocketImpl(NoSocket* q, const NoString& host, u_short port);
    ~NoSocketImpl();

    int ConvertAddress(const struct sockaddr_storage* pAddr, socklen_t iAddrLen, CS_STRING& address, u_short* piPort) const override;
#ifdef HAVE_LIBSSL
    int VerifyPeerCertificate(int iPreVerify, X509_STORE_CTX* pStoreCTX) override;
    void SSLHandShakeFinished() override;
#endif

#ifdef HAVE_ICU
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

    Csock* GetSockObj(const NoString& host, ushort port) override;

    void ReadLine(const NoString& line) override;
    void ReadData(const char* data, size_t len) override;
    void PushBuff(const char* data, size_t len, bool bStartAtZero = false) override;

    void SockError(int iErrno, const NoString& description) override
    {
        q->onSocketError(iErrno, description);
    }

    void Connected() override
    {
        q->onConnected();
    }
    void Timeout() override
    {
        q->onTimeout();
    }
    void Disconnected() override
    {
        q->onDisconnected();
    }
    void ConnectionRefused() override
    {
        q->onConnectionRefused();
    }

    void ReadPaused() override
    {
        q->onReadPaused();
    }
    void ReachedMaxBuffer() override
    {
        q->onReachedMaxBuffer();
    }
    bool ConnectionFrom(const NoString& host, ushort port) override
    {
        return q->onConnectionFrom(host, port);
    }

    NoSocket* q;
    bool allowControlCodes;
    NoString hostToVerifySsl;
    NoStringSet trustedFingerprints;
    NoStringSet certVerificationErrors;
};

class NoSocketPrivate
{
public:
    static NoSocketImpl* get(NoSocket* socket)
    {
        return socket->d->impl;
    }

    NoSocketImpl* impl;
};

#endif // NOSOCKET_P_H
