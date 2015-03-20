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

class NO_EXPORT NoAuthenticator
{
public:
    NoAuthenticator(const NoString& username, const NoString& password, NoSocket* socket);
    virtual ~NoAuthenticator();

    NoAuthenticator(const NoAuthenticator&) = delete;
    NoAuthenticator& operator=(const NoAuthenticator&) = delete;

    NoString username() const;
    NoString password() const;
    NoSocket* socket() const;

    void acceptLogin(NoUser* user);
    void refuseLogin(const NoString& reason);

    virtual void invalidate();

protected:
    virtual void loginAccepted(NoUser* user) = 0;
    virtual void loginRefused(NoUser* user, const NoString& reason) = 0;

private:
    NoString m_username;
    NoString m_password;
    NoSocket* m_socket;
};

#endif // NOAUTHENTICATOR_H
