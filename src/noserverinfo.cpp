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

#include "noserverinfo.h"

class NoServerInfoPrivate
{
public:
    bool ssl = false;
    ushort port = 6667;
    NoString host = "";
    NoString password = "";
};

NoServerInfo::NoServerInfo(const NoString& host, ushort port) : d(new NoServerInfoPrivate)
{
    d->host = host;
    d->port = port;
}

NoServerInfo::NoServerInfo(const NoServerInfo& other) : d(new NoServerInfoPrivate)
{
    d->ssl = other.isSsl();
    d->port = other.port();
    d->host = other.host();
    d->password = other.password();
}

NoServerInfo& NoServerInfo::operator=(const NoServerInfo& other)
{
    if (this != &other) {
        d->ssl = other.isSsl();
        d->port = other.port();
        d->host = other.host();
        d->password = other.password();
    }
    return *this;
}

NoServerInfo::~NoServerInfo()
{
}

bool NoServerInfo::isValid() const
{
    return !d->host.empty() && !d->host.contains(" ");
}

NoString NoServerInfo::host() const
{
    return d->host;
}

void NoServerInfo::setHost(const NoString &host)
{
    d->host = host;
}

ushort NoServerInfo::port() const
{
    return d->port;
}

void NoServerInfo::setPort(ushort port)
{
    d->port = port;
}

NoString NoServerInfo::password() const
{
    return d->password;
}

void NoServerInfo::setPassword(const NoString& password)
{
    d->password = password;
}

bool NoServerInfo::isSsl() const
{
    return d->ssl;
}

void NoServerInfo::setSsl(bool ssl)
{
    d->ssl = ssl;
}

NoString NoServerInfo::toString() const
{
    NoStringVector parts;
    parts.push_back(d->host);

    NoString port(d->port);
    if (d->ssl)
        port = "+" + port;
    parts.push_back(port);

    if (!d->password.empty())
        parts.push_back(d->password);

    return NoString(" ").join(parts.begin(), parts.end());
}
