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

#ifndef NOTIMER_H
#define NOTIMER_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <memory>

class NoModule;
class NoTimerPrivate;

class NO_EXPORT NoTimer
{
public:
    NoTimer(NoModule* module);
    virtual ~NoTimer();

    NoModule* module() const;

    void start(uint interval = 0);
    void stop();

    void pause();
    void resume();

    bool isActive() const;

    NoString name() const;
    void setName(const NoString& name);

    NoString description() const;
    void setDescription(const NoString& description);

    uint interval() const;
    void setInterval(uint secs);

    bool isSingleShot() const;
    void setSingleShot(bool single);

protected:
    virtual void run() = 0;

private:
    NoTimer(const NoTimer&) = delete;
    NoTimer& operator=(const NoTimer&) = delete;
    std::unique_ptr<NoTimerPrivate> d;
    friend class NoTimerImpl;
};

#endif // NOTIMER_H
