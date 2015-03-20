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

#ifndef NOWEBSESSION_H
#define NOWEBSESSION_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <no/nouser.h>

class NoTemplate;

class NO_EXPORT NoWebSession
{
public:
    NoWebSession(const NoString& sId, const NoString& sIP);
    ~NoWebSession();

    NoWebSession(const NoWebSession&) = delete;
    NoWebSession& operator=(const NoWebSession&) = delete;

    const NoString& GetId() const { return m_sId; }
    const NoString& GetIP() const { return m_sIP; }
    NoUser* GetUser() const { return m_pUser; }
    time_t GetLastActive() const { return m_tmLastActive; }
    bool IsLoggedIn() const { return m_pUser != nullptr; }
    bool IsAdmin() const;
    void UpdateLastActive();

    NoUser* SetUser(NoUser* p)
    {
        m_pUser = p;
        return m_pUser;
    }

    void ClearMessageLoops();
    void FillMessageLoops(NoTemplate& Tmpl);
    size_t AddError(const NoString& sMessage);
    size_t AddSuccess(const NoString& sMessage);

private:
    NoString m_sId;
    NoString m_sIP;
    NoUser* m_pUser;
    NoStringVector m_vsErrorMsgs;
    NoStringVector m_vsSuccessMsgs;
    time_t m_tmLastActive;
};

#endif // NOWEBSESSION_H
