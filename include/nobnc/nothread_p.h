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

#ifndef NOTHREAD_P_H
#define NOTHREAD_P_H

#include "nothread.h"
#include "nomutex.h"
#include "noconditionvariable.h"
#include <list>

#ifdef HAVE_PTHREAD

class NoJob;

class NO_EXPORT NoThreadPrivate
{
public:
    NoThreadPrivate();
    ~NoThreadPrivate();

    static NoThreadPrivate* get();

    void cancelJobs(const std::set<NoJob*>& jobs);

    int getReadFD() const;

    void handlePipeReadable() const;

    void jobDone(NoJob* pJob);

    // Check if the calling thread is still needed, must be called with mutex held
    bool threadNeeded() const;

    NoJob* getJobFromPipe() const;
    void finishJob(NoJob*) const;

    void threadFunc();

    // mutex protecting all of these members
    NoMutex mutex;

    // condition variable for waiting idle threads
    NoConditionVariable cond;

    // condition variable for reporting finished cancellation
    NoConditionVariable cancellationCond;

    // condition variable for waiting running threads == 0
    NoConditionVariable exitCond;

    // when this is true, all threads should exit
    bool done;

    // total number of running threads
    size_t numThreads;

    // number of idle threads waiting on the condition variable
    size_t numIdle;

    // pipe for waking up the main thread
    int jobPipe[2];

    // list of pending jobs
    std::list<NoJob*> jobs;
};

#endif // HAVE_PTHREAD

#endif // NOTHREAD_P_H
