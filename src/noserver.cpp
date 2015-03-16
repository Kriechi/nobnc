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

NoServer::NoServer(const NoString& sName, ushort uPort, const NoString& sPass, bool bSSL)
    : m_sName(sName), m_uPort((uPort) ? uPort : (ushort)6667), m_sPass(sPass), m_bSSL(bSSL)
{
}

NoServer::~NoServer() {}

bool NoServer::IsValidHostName(const NoString& sHostName)
{
    return (!sHostName.empty() && (sHostName.find(' ') == NoString::npos));
}

const NoString& NoServer::GetName() const { return m_sName; }
ushort NoServer::GetPort() const { return m_uPort; }
const NoString& NoServer::GetPass() const { return m_sPass; }
bool NoServer::IsSSL() const { return m_bSSL; }

NoString NoServer::GetString(bool bIncludePassword) const
{
    return m_sName + " " + NoString(m_bSSL ? "+" : "") + NoString(m_uPort) +
           NoString(bIncludePassword ? (m_sPass.empty() ? "" : " " + m_sPass) : "");
}
