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

#include "noauthenticator.h"
#include "nosocket.h"
#include "nouser.h"
#include "noapp.h"

class NoAuthenticatorPrivate
{
public:
    NoString username = "";
    NoString password = "";
    NoSocket* socket = nullptr;
};

NoAuthenticator::NoAuthenticator(const NoString& username, const NoString& password, NoSocket* socket)
    : d(new NoAuthenticatorPrivate)
{
    d->username = username;
    d->password = password;
    d->socket = socket;
}

NoAuthenticator::~NoAuthenticator()
{
}

NoString NoAuthenticator::username() const
{
    return d->username;
}

NoString NoAuthenticator::password() const
{
    return d->password;
}

NoSocket* NoAuthenticator::socket() const
{
    return d->socket;
}

void NoAuthenticator::acceptLogin(NoUser* user)
{
    if (d->socket) {
        loginAccepted(user);
        invalidate();
    }
}

void NoAuthenticator::refuseLogin(const NoString& reason)
{
    if (!d->socket)
        return;

    NoUser* user = NoApp::instance().findUser(d->username);

    // If the username is valid, notify that user that someone tried to
    // login. Use reason because there are other reasons than "wrong
    // password" for a login to be rejected (e.g. fail2ban).
    if (user) {
        user->putStatus("A client from [" + d->socket->remoteAddress() + "] attempted "
                                                                       "to login as you, but was rejected [" +
                        reason + "].");
    }

    GLOBALMODULECALL(onFailedLogin(d->username, d->socket->remoteAddress()), NOTHING);
    loginRefused(user, reason);
    invalidate();
}

void NoAuthenticator::invalidate()
{
    d->socket = nullptr;
}
