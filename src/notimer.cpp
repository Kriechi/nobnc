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

NoTimer::NoTimer(NoModule* module, uint interval, uint cycles, const NoString& label, const NoString& description)
    : CCron(), m_module(module), m_description(description)
{
    SetName(label);

    if (cycles)
        StartMaxCycles(interval, cycles);
    else
        Start(interval);
}

NoTimer::~NoTimer()
{
    m_module->UnlinkTimer(this);
}

CCron* NoTimer::GetHandle() const
{
    return const_cast<NoTimer*>(this);
}

NoString NoTimer::GetName() const
{
    return CCron::GetName();
}

uint NoTimer::GetCyclesLeft() const
{
    return CCron::GetCyclesLeft();
}

timeval NoTimer::GetInterval() const
{
    return CCron::GetInterval();
}

void NoTimer::Stop()
{
    CCron::Stop();
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
