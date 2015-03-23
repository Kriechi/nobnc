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

#ifndef NOTHREADPOOL_H
#define NOTHREADPOOL_H

#include <no/noglobal.h>

#ifdef HAVE_PTHREAD

#include <no/nomutex.h>
#include <no/noconditionvariable.h>
#include <no/noutils.h>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <list>
#include <pthread.h>
#include <cassert>

class NoJob;

class NO_EXPORT NoThreadPool
{
private:
    friend class NoJob;

    NoThreadPool();
    ~NoThreadPool();

public:
    static NoThreadPool& Get();

    /// Add a job to the thread pool and run it. The job will be deleted when done.
    void addJob(NoJob* job);

    /// Cancel a job that was previously passed to addJob(). This *might*
    /// mean that runThread() and/or runMain() will not be called on the job.
    /// This function BLOCKS until the job finishes!
    void cancelJob(NoJob* job);

    /// Cancel some jobs that were previously passed to addJob(). This *might*
    /// mean that runThread() and/or runMain() will not be called on some of
    /// the jobs. This function BLOCKS until all jobs finish!
    void cancelJobs(const std::set<NoJob*>& jobs);

    int getReadFD() const { return m_jobPipe[0]; }

    void handlePipeReadable() const;

private:
    void jobDone(NoJob* pJob);

    // Check if the calling thread is still needed, must be called with m_mutex held
    bool threadNeeded() const;

    NoJob* getJobFromPipe() const;
    void finishJob(NoJob*) const;

    void threadFunc();
    static void* threadPoolFunc(void* arg)
    {
        NoThreadPool& pool = *reinterpret_cast<NoThreadPool*>(arg);
        pool.threadFunc();
        return nullptr;
    }

    // mutex protecting all of these members
    NoMutex m_mutex;

    // condition variable for waiting idle threads
    NoConditionVariable m_cond;

    // condition variable for reporting finished cancellation
    NoConditionVariable m_cancellationCond;

    // condition variable for waiting running threads == 0
    NoConditionVariable m_exitCond;

    // when this is true, all threads should exit
    bool m_done;

    // total number of running threads
    size_t m_numThreads;

    // number of idle threads waiting on the condition variable
    size_t m_numIdle;

    // pipe for waking up the main thread
    int m_jobPipe[2];

    // list of pending jobs
    std::list<NoJob*> m_jobs;
};

#endif // HAVE_PTHREAD

#endif // NOTHREADPOOL_H
