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

#ifndef NOTIMER_H
#define NOTIMER_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <no/Csocket.h>

class NoModule;

class NO_EXPORT NoTimer : public CCron
{
public:
    NoTimer(NoModule* pModule, uint uInterval, uint uCycles, const NoString& sLabel, const NoString& sDescription);

    virtual ~NoTimer();

    NoTimer(const NoTimer&) = delete;
    NoTimer& operator=(const NoTimer&) = delete;

    void SetModule(NoModule* p);
    void SetDescription(const NoString& s);

    NoModule* GetModule() const;
    const NoString& GetDescription() const;

private:
    NoModule* m_pModule;
    NoString m_sDescription;
};

class NoFPTimer;

typedef void (*FPTimer_t)(NoModule*, NoFPTimer*);

class NO_EXPORT NoFPTimer : public NoTimer
{
public:
    NoFPTimer(NoModule* pModule, uint uInterval, uint uCycles, const NoString& sLabel, const NoString& sDescription)
        : NoTimer(pModule, uInterval, uCycles, sLabel, sDescription), m_pFBCallback(nullptr)
    {
    }

    virtual ~NoFPTimer() {}

    void SetFPCallback(FPTimer_t p) { m_pFBCallback = p; }

protected:
    void RunJob() override
    {
        if (m_pFBCallback) {
            m_pFBCallback(GetModule(), this);
        }
    }

private:
    FPTimer_t m_pFBCallback;
};

#endif // NOTIMER_H
