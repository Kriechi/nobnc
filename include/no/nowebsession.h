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
    NoWebSession(const NoString& sId, const NoString& sIP);
    ~NoWebSession();

    const NoString& GetId() const;
    const NoString& GetIP() const;
    NoUser* GetUser() const;
    time_t GetLastActive() const;
    bool IsLoggedIn() const;
    bool IsAdmin() const;
    void UpdateLastActive();

    NoUser* SetUser(NoUser* p);

    void ClearMessageLoops();
    void FillMessageLoops(NoTemplate& Tmpl);
    size_t AddError(const NoString& sMessage);
    size_t AddSuccess(const NoString& sMessage);

private:
    NoWebSession(const NoWebSession& other) = delete;
    NoWebSession& operator=(const NoWebSession& other) = delete;
    std::unique_ptr<NoWebSessionPrivate> d;
};

#endif // NOWEBSESSION_H
