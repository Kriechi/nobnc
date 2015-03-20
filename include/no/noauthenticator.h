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

#ifndef NOAUTHENTICATOR_H
#define NOAUTHENTICATOR_H

#include <no/noglobal.h>
#include <no/nostring.h>

class NoUser;
class NoSocket;

class NO_EXPORT NoAuthBase
{
public:
    NoAuthBase(const NoString& sUsername, const NoString& sPassword, NoSocket* pSock);
    virtual ~NoAuthBase();

    NoAuthBase(const NoAuthBase&) = delete;
    NoAuthBase& operator=(const NoAuthBase&) = delete;

    virtual void SetLoginInfo(const NoString& sUsername, const NoString& sPassword, NoSocket* pSock);

    void AcceptLogin(NoUser& User);
    void RefuseLogin(const NoString& sReason);

    const NoString& GetUsername() const;
    const NoString& GetPassword() const;
    NoSocket* GetSocket() const;
    NoString GetRemoteIP() const;

    // Invalidate this NoAuthBase instance which means it will no longer use
    // m_pSock and AcceptLogin() or RefusedLogin() will have no effect.
    virtual void Invalidate();

protected:
    virtual void AcceptedLogin(NoUser& User) = 0;
    virtual void RefusedLogin(const NoString& sReason) = 0;

private:
    NoString m_sUsername;
    NoString m_sPassword;
    NoSocket* m_pSock;
};

#endif // NOAUTHENTICATOR_H
