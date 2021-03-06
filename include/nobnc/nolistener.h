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

#ifndef NOLISTENER_H
#define NOLISTENER_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
#include <memory>

class NoSocket;
class NoListenerPrivate;

class NO_EXPORT NoListener
{
public:
    NoListener(const NoString& host = "", ushort port = 0);
    ~NoListener();

    bool isSsl() const;
    void setSsl(bool ssl);

    ushort port() const;
    void setPort(ushort port);

    NoString host() const;
    void setHost(const NoString& host);

    NoString uriPrefix() const;
    void setUriPrefix(const NoString& prefix);

    No::AddressType addressType() const;
    void setAddressType(No::AddressType type);

    bool listen();
    NoSocket* socket() const;

private:
    NoListener(const NoListener&) = delete;
    NoListener& operator=(const NoListener&) = delete;

    std::unique_ptr<NoListenerPrivate> d;
};

#endif // NOLISTENER_H
