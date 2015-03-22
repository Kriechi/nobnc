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

NoServer::NoServer(const NoString& host, ushort port) : m_host(host), m_port(port)
{
}

NoServer::~NoServer()
{
}

bool NoServer::isValid() const
{
    return !m_host.empty() && !m_host.contains(" ");
}

NoString NoServer::host() const
{
    return m_host;
}

void NoServer::setHost(const NoString &host)
{
    m_host = host;
}

ushort NoServer::port() const
{
    return m_port;
}

void NoServer::setPort(ushort port)
{
    m_port = port;
}

NoString NoServer::password() const
{
    return m_password;
}

void NoServer::setPassword(const NoString& password)
{
    m_password = password;
}

bool NoServer::isSsl() const
{
    return m_ssl;
}

void NoServer::setSsl(bool ssl)
{
    m_ssl = ssl;
}

NoString NoServer::toString() const
{
    NoStringVector parts;
    parts.push_back(m_host);

    NoString port(m_port);
    if (m_ssl)
        port = "+" + port;
    parts.push_back(port);

    if (!m_password.empty())
        parts.push_back(m_password);

    return NoString(" ").join(parts.begin(), parts.end());
}
