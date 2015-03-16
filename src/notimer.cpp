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

#include "notimer.h"
#include "nomodules.h"

NoTimer::NoTimer(NoModule* pModule, unsigned int uInterval, unsigned int uCycles, const NoString& sLabel, const NoString& sDescription)
    : CCron(), m_pModule(pModule), m_sDescription(sDescription)
{
    SetName(sLabel);

    if (uCycles) {
        StartMaxCycles(uInterval, uCycles);
    } else {
        Start(uInterval);
    }
}

NoTimer::~NoTimer() { m_pModule->UnlinkTimer(this); }

void NoTimer::SetModule(NoModule* p) { m_pModule = p; }
void NoTimer::SetDescription(const NoString& s) { m_sDescription = s; }
NoModule* NoTimer::GetModule() const { return m_pModule; }
const NoString& NoTimer::GetDescription() const { return m_sDescription; }
