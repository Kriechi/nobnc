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

#include "noauthenticator.h"
#include "nosocket.h"
#include "nouser.h"
#include "noapp.h"

NoString NoAuthenticator::GetRemoteIP() const
{
    if (m_pSock)
        return m_pSock->GetRemoteIP();
    return "";
}

void NoAuthenticator::Invalidate() { m_pSock = nullptr; }

NoAuthenticator::NoAuthenticator(const NoString& sUsername, const NoString& sPassword, NoSocket* pSock)
    : m_sUsername(sUsername), m_sPassword(sPassword), m_pSock(pSock)
{
}

NoAuthenticator::~NoAuthenticator()
{
}

void NoAuthenticator::AcceptLogin(NoUser& User)
{
    if (m_pSock) {
        AcceptedLogin(User);
        Invalidate();
    }
}

void NoAuthenticator::RefuseLogin(const NoString& sReason)
{
    if (!m_pSock) return;

    NoUser* pUser = NoApp::Get().FindUser(GetUsername());

    // If the username is valid, notify that user that someone tried to
    // login. Use sReason because there are other reasons than "wrong
    // password" for a login to be rejected (e.g. fail2ban).
    if (pUser) {
        pUser->PutStatus("A client from [" + GetRemoteIP() + "] attempted "
                                                             "to login as you, but was rejected [" +
                         sReason + "].");
    }

    GLOBALMODULECALL(OnFailedLogin(GetUsername(), GetRemoteIP()), NOTHING);
    RefusedLogin(sReason);
    Invalidate();
}

const NoString& NoAuthenticator::GetUsername() const { return m_sUsername; }

const NoString& NoAuthenticator::GetPassword() const { return m_sPassword; }

NoSocket* NoAuthenticator::GetSocket() const { return m_pSock; }
