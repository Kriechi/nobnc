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

#ifndef NOJOB_H
#define NOJOB_H

#include <nobnc/noglobal.h>

#ifdef HAVE_PTHREAD

/**
 * A job is a task which should run without blocking the main thread. You do
 * this by inheriting from this class and implementing the pure virtual methods
 * runThread(), which gets executed in a separate thread and does not block the
 * main thread, and runMain() which gets automatically called from the main
 * thread after runThread() finishes.
 *
 * After you create a new instance of your class, you can pass it to
 * NoThread()::Get().addJob(job) to start it. The thread pool automatically
 * deletes your class after it finished.
 *
 * For modules you should use NoModuleJob instead.
 */
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

    /// This function is called in a separate thread and can do heavy, blocking work.
    virtual void run() = 0;

    /// This function is called from the main thread after runThread()
    /// finishes. It can be used to handle the results from runThread()
    /// without needing synchronization primitives.
    virtual void finished() = 0;

    /// This can be used to check if the job was cancelled. For example,
    /// runThread() can return early if this returns true.
    bool wasCancelled() const;

private:
    NoJob(const NoJob&) = delete;
    NoJob& operator=(const NoJob&) = delete;

    // Synchronized via the thread pool's mutex! Do not access without that mutex!
    JobState m_state;
    friend class NoThread;
    friend class NoThreadPrivate;
};

#endif // HAVE_PTHREAD

#endif // NOJOB_H