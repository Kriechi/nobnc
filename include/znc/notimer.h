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

#include <znc/noconfig.h>
#include <znc/nostring.h>
#include <znc/Csocket.h>

class CModule;

class CTimer : public CCron
{
public:
    CTimer(CModule* pModule, unsigned int uInterval, unsigned int uCycles, const CString& sLabel, const CString& sDescription);

    virtual ~CTimer();

    CTimer(const CTimer&) = delete;
    CTimer& operator=(const CTimer&) = delete;

    void SetModule(CModule* p);
    void SetDescription(const CString& s);

    CModule* GetModule() const;
    const CString& GetDescription() const;

private:
    CModule* m_pModule;
    CString m_sDescription;
};

class CFPTimer;

typedef void (*FPTimer_t)(CModule*, CFPTimer*);

class CFPTimer : public CTimer
{
public:
    CFPTimer(CModule* pModule, unsigned int uInterval, unsigned int uCycles, const CString& sLabel, const CString& sDescription)
        : CTimer(pModule, uInterval, uCycles, sLabel, sDescription), m_pFBCallback(nullptr)
    {
    }

    virtual ~CFPTimer() {}

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

#endif // !NOTIMER_H
