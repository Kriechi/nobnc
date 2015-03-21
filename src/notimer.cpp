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

class NoTimerPrivate : public CCron
{
public:
    NoTimerPrivate(NoModule* mod, NoTimer* q) : q(q), module(mod) { }

    void restart()
    {
        if (singleShot)
            StartMaxCycles(interval, 1);
        else
            Start(interval);
    }

    void RunJob() override { q->run(); }

    NoTimer* q;
    NoModule* module;
    NoString description = "";
    bool singleShot = false;
    uint interval = 60;
};

NoTimer::NoTimer(NoModule* module)
    : d(new NoTimerPrivate(module, this))
{
}

NoTimer::~NoTimer()
{
    d->module->UnlinkTimer(this);
}

void NoTimer::start(uint interval)
{
    if (interval > 0)
        d->interval = interval;
    d->restart();
}

void NoTimer::stop()
{
    d->Stop();
}

void NoTimer::pause()
{
    d->Pause();
}

void NoTimer::resume()
{
    d->UnPause();
}

bool NoTimer::isActive() const
{
    return d->isValid();
}

NoModule* NoTimer::module() const
{
    return d->module;
}

void NoTimer::setModule(NoModule* module)
{
    d->module = module;
}

NoString NoTimer::name() const
{
    return d->GetName();
}

void NoTimer::setName(const NoString& name)
{
    d->SetName(name);
}

NoString NoTimer::description() const
{
    return d->description;
}

void NoTimer::setDescription(const NoString& description)
{
    d->description = description;
}

uint NoTimer::interval() const
{
    return d->GetInterval().tv_sec;
}

void NoTimer::setInterval(uint secs)
{
    if (d->interval != secs) {
        d->interval = secs;
        if (d->isValid())
            d->restart();
    }
}

bool NoTimer::isSingleShot() const
{
    return d->singleShot;
}

void NoTimer::setSingleShot(bool single)
{
    if (d->singleShot != single) {
        d->singleShot = single;
        if (d->isValid())
            d->restart();
    }
}

void* NoTimer::handle() const
{
    return d.get();
}
