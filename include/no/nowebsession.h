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

#ifndef NOWEBSESSION_H
#define NOWEBSESSION_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <memory>

class NoUser;
class NoTemplate;
class NoWebSessionPrivate;

class NO_EXPORT NoWebSession
{
public:
    NoWebSession(const NoString& sId, const NoString& address);
    ~NoWebSession();

    NoString host() const;
    NoString identifier() const;
    NoUser* user() const;
    time_t lastActive() const;
    bool isLoggedIn() const;
    bool isAdmin() const;
    void updateLastActive();

    NoUser* setUser(NoUser* p);

    void clearMessageLoops();
    void fillMessageLoops(NoTemplate& tmpl);
    size_t addError(const NoString& message);
    size_t addSuccess(const NoString& message);

private:
    NoWebSession(const NoWebSession& other) = delete;
    NoWebSession& operator=(const NoWebSession& other) = delete;
    std::unique_ptr<NoWebSessionPrivate> d;
};

#endif // NOWEBSESSION_H
