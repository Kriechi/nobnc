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

#include "notimer.h"
#include "nomodule.h"
#include "nomodule_p.h"
#include "nosocketmanager.h"
#include "Csocket/Csocket.h"

class NoTimerImpl : public CCron
{
public:
    NoTimerImpl(NoTimer* q) : q(q) { }

protected:
    void RunJob() override { q->run(); }

private:
    NoTimer* q;
};

class NoTimerPrivate
{
public:
    NoTimerPrivate(NoModule* mod) : module(mod) { }

    void restart()
    {
        if (singleShot)
            impl->StartMaxCycles(interval, 1);
        else
            impl->Start(interval);
    }

    NoModule* module;
    NoTimerImpl* impl;
    NoString description = "";
    bool singleShot = false;
    uint interval = 60;
};

NoTimer::NoTimer(NoModule* module)
    : d(new NoTimerPrivate(module))
{
    d->impl = new NoTimerImpl(this);

    if (module) {
        NoModulePrivate::get(module)->addTimer(this);
        module->GetManager()->AddCron(d->impl);
    }
}

NoTimer::~NoTimer()
{
    if (d->module) {
        NoModulePrivate::get(d->module)->removeTimer(this);
        d->module->GetManager()->DelCronByAddr(d->impl);
    }
}

NoModule* NoTimer::module() const
{
    return d->module;
}

void NoTimer::start(uint interval)
{
    if (interval > 0)
        d->interval = interval;
    d->restart();
}

void NoTimer::stop()
{
    d->impl->Stop();
}

void NoTimer::pause()
{
    d->impl->Pause();
}

void NoTimer::resume()
{
    d->impl->UnPause();
}

bool NoTimer::isActive() const
{
    return d->impl->isValid();
}

NoString NoTimer::name() const
{
    return d->impl->GetName();
}

void NoTimer::setName(const NoString& name)
{
    d->impl->SetName(name);
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
    return d->interval;
}

void NoTimer::setInterval(uint secs)
{
    if (d->interval != secs) {
        d->interval = secs;
        if (isActive())
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
        if (isActive())
            d->restart();
    }
}
