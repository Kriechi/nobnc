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

#ifndef NOJOB_P_H
#define NOJOB_P_H

#include <nobnc/noglobal.h>

#ifdef HAVE_PTHREAD

class NO_EXPORT NoJob
{
public:
    enum JobState { Ready, Running, Done, Cancelled };

    NoJob() : m_state(Ready)
    {
    }
    virtual ~NoJob()
    {
    } /// Always called from the main thread.

    bool wasCancelled() const;

    void start();
    void cancel();

protected:
    virtual void run() = 0;
    virtual void finished() = 0;

private:
    NoJob(const NoJob&) = delete;
    NoJob& operator=(const NoJob&) = delete;

    // Synchronized via the thread pool's mutex! Do not access without that mutex!
    JobState m_state;
    friend class NoThread;
    friend class NoThreadPrivate;
};

#endif // HAVE_PTHREAD

#endif // NOJOB_P_H
