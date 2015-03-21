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
#include <memory>

class NoModule;
class NoTimerPrivate;
class CCron; // TODO: cleanup

class NO_EXPORT NoTimer
{
public:
    NoTimer(NoModule* module, uint interval, uint cycles, const NoString& label, const NoString& description);
    virtual ~NoTimer();

    CCron* GetHandle() const; // TODO: cleanup

    // TODO: revise the API
    NoString GetName() const;
    uint GetCyclesLeft() const;
    timeval GetInterval() const;
    void Stop();

    NoModule* module() const;
    void setModule(NoModule* module);

    NoString description() const;
    void setDescription(const NoString& description);

    typedef void (*Callback)(NoModule*, NoTimer*);
    Callback callback() const;
    void setCallback(Callback callback);

protected:
    virtual void RunJob();

private:
    NoTimer(const NoTimer&) = delete;
    NoTimer& operator=(const NoTimer&) = delete;
    std::unique_ptr<NoTimerPrivate> d;
    friend class NoTimerPrivate;
};

#endif // NOTIMER_H
