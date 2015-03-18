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
#include "Csocket/Csocket.h"

class NoCCron : public CCron
{
public:
    NoCCron(NoTimer* q) : q_ptr(q) { }
protected:
    void RunJob() override { q_ptr->RunJob(); }
private:
    NoTimer* q_ptr;
};

NoTimer::NoTimer(NoModule* module, uint interval, uint cycles, const NoString& label, const NoString& description)
    : m_cron(new NoCCron(this)), m_module(module), m_description(description)
{
    m_cron->SetName(label);

    if (cycles)
        m_cron->StartMaxCycles(interval, cycles);
    else
        m_cron->Start(interval);
}

NoTimer::~NoTimer()
{
    m_module->UnlinkTimer(this);
}

CCron* NoTimer::GetHandle() const
{
    return m_cron;
}

NoString NoTimer::GetName() const
{
    return m_cron->GetName();
}

uint NoTimer::GetCyclesLeft() const
{
    return m_cron->GetCyclesLeft();
}

timeval NoTimer::GetInterval() const
{
    return m_cron->GetInterval();
}

void NoTimer::Stop()
{
    m_cron->Stop();
}

NoModule* NoTimer::module() const
{
    return m_module;
}

void NoTimer::setModule(NoModule* module)
{
    m_module = module;
}

NoString NoTimer::description() const
{
    return m_description;
}

void NoTimer::setDescription(const NoString& description)
{
    m_description = description;
}

NoTimer::Callback NoTimer::callback() const
{
    return m_callback;
}

void NoTimer::setCallback(Callback callback)
{
    m_callback = callback;
}

void NoTimer::RunJob()
{
    if (m_callback)
        m_callback(m_module, this);
}
