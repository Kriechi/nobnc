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

#ifndef NOSERVER_H
#define NOSERVER_H

#include <no/noglobal.h>
#include <no/nostring.h>

class NO_EXPORT NoServer
{
public:
    NoServer(const NoString& sName, ushort uPort = 6667, const NoString& sPass = "", bool bSSL = false);
    ~NoServer();

    const NoString& GetName() const;
    ushort GetPort() const;
    const NoString& GetPass() const;
    bool IsSSL() const;
    NoString GetString(bool bIncludePassword = true) const;
    static bool IsValidHostName(const NoString& sHostName);

private:
    NoString m_sName;
    ushort m_uPort;
    NoString m_sPass;
    bool m_bSSL;
};

#endif // NOSERVER_H
