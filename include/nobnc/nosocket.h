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

#ifndef NOSOCKET_H
#define NOSOCKET_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
#include <memory>

class NoModule;
class NoSocketPrivate;

#ifdef _WIN32
typedef SOCKET no_sock_t;
#else
typedef int no_sock_t;
#endif

typedef struct ssl_session_st SSL_SESSION;

class NO_EXPORT NoSocket
{
public:
    NoSocket(NoModule* module);
    virtual ~NoSocket();

    NoModule* module() const;

    ushort port() const;
    void setPort(ushort port);

    NoString host() const;
    void setHost(const NoString& host);

    bool isSsl() const;
    void setSsl(bool ssl);

    NoString name() const;
    void setName(const NoString& name);

    bool isListener() const;
    bool isOutbound() const;
    bool isInbound() const;
    bool isConnected() const;
    bool isReady() const;
    bool isClosed() const;

    ushort localPort() const;
    NoString localAddress() const;

    ushort remotePort() const;
    virtual NoString remoteAddress() const;

    NoString bindHost() const;
    void setBindHost(const NoString& bindHost);

    NoString hostToVerifySsl() const;
    void setHostToVerifySsl(const NoString& host);

    NoString fingerprint() const;
    long peerFingerprint(NoString& fingerprint) const; // TODO

    NoStringSet trustedFingerprints() const;
    void setTrustedFingerprints(const NoStringSet& fingerprints);

    void setEncoding(const NoString& encoding);

    NoString pemFile() const;
    void setPemFile(const NoString& filePath);

    bool write(const char* data, ulong len);
    bool write(const NoString& data);

    void pauseRead();
    void resumeRead();

    NoString cipher() const;
    void setCipher(const NoString& cipher);

    uint requireClientCertFlags() const;
    void setRequireClientCertFlags(uint flags);

    SSL_SESSION* sslSession() const;

    void connect();
    bool listen(ushort port);

    void enableReadLine();
    void disableReadLine();

    uint maxBufferThreshold() const;
    void setMaxBufferThreshold(uint threshold);

    no_sock_t& readDescriptor() const;
    void setReadDescriptor(no_sock_t descriptor);

    no_sock_t& writeDescriptor() const;
    void setWriteDescriptor(no_sock_t descriptor);

    int timeout() const;
    void setTimeout(int timeout);

    enum CloseType { CloseImmediately = 1, CloseAfterWrite = 2 };
    void close(CloseType type = CloseImmediately);

    bool startTls();

    virtual void readLine(const NoString& line);
    virtual void readData(const char* data, ulong len);
    virtual void pushBuffer(const char* data, ulong len, bool startAtZero = false);

protected:
    virtual void onConnected();
    virtual void onTimeout();
    virtual void onDisconnected();
    virtual void onConnectionRefused();

    virtual void onReadPaused();
    virtual void onReachedMaxBuffer();
    virtual void onSocketError(int error, const NoString& description);
    virtual bool onConnectionFrom(const NoString& host, ushort port);

    virtual NoSocket* createSocket(const NoString& host, ushort port);

    NoString& internalReadBuffer();
    NoString& internalWriteBuffer();

private:
    NoSocket(const NoSocket&) = delete;
    NoSocket& operator=(const NoSocket&) = delete;
    std::unique_ptr<NoSocketPrivate> d;
    friend class NoSocketPrivate;
    friend class NoSocketImpl;
};

#endif // NOSOCKET_H
