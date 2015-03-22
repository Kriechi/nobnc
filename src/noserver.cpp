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

#include "noserver.h"

class NoServerPrivate
{
public:
    bool ssl = false;
    ushort port = 6667;
    NoString host = "";
    NoString password = "";
};

NoServer::NoServer(const NoString& host, ushort port) : d(new NoServerPrivate)
{
    d->host = host;
    d->port = port;
}

NoServer::NoServer(const NoServer& other) : d(new NoServerPrivate)
{
    d->ssl = other.isSsl();
    d->port = other.port();
    d->host = other.host();
    d->password = other.password();
}

NoServer& NoServer::operator=(const NoServer& other)
{
    if (this != &other) {
        d->ssl = other.isSsl();
        d->port = other.port();
        d->host = other.host();
        d->password = other.password();
    }
    return *this;
}

NoServer::~NoServer()
{
}

bool NoServer::isValid() const
{
    return !d->host.empty() && !d->host.contains(" ");
}

NoString NoServer::host() const
{
    return d->host;
}

void NoServer::setHost(const NoString &host)
{
    d->host = host;
}

ushort NoServer::port() const
{
    return d->port;
}

void NoServer::setPort(ushort port)
{
    d->port = port;
}

NoString NoServer::password() const
{
    return d->password;
}

void NoServer::setPassword(const NoString& password)
{
    d->password = password;
}

bool NoServer::isSsl() const
{
    return d->ssl;
}

void NoServer::setSsl(bool ssl)
{
    d->ssl = ssl;
}

NoString NoServer::toString() const
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
