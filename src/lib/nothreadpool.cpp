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

#include "nothreadpool_p.h"
#include "nomutex_p.h"
#include "nomutexlocker_p.h"
#include "noconditionvariable_p.h"
#include "nojob_p.h"

#ifdef HAVE_PTHREAD

#include "nodebug.h"
#include <algorithm>
#include <unistd.h>

/* Just an arbitrary limit for the number of idle threads */
static const size_t MAX_IDLE_THREADS = 3;

/* Just an arbitrary limit for the number of running threads */
static const size_t MAX_TOTAL_THREADS = 20;

typedef void* ThreadFunc(void*);
static void startThread(ThreadFunc* func, void* arg)
{
    pthread_t thr;
    sigset_t old_sigmask, sigmask;

    /* Block all signals. The thread will inherit our signal mask
     * and thus won't ever try to handle signals.
     */
    int i = sigfillset(&sigmask);
    i |= pthread_sigmask(SIG_SETMASK, &sigmask, &old_sigmask);
    i |= pthread_create(&thr, nullptr, func, arg);
    i |= pthread_sigmask(SIG_SETMASK, &old_sigmask, nullptr);
    i |= pthread_detach(thr);
    if (i) {
        No::printError("Can't start new thread: " + NoString(strerror(errno)));
        exit(1);
    }
}

static void* threadPoolFunc(void* arg)
{
    NoThreadPool* thread = reinterpret_cast<NoThreadPool*>(arg);
    thread->threadFunc();
    return nullptr;
}

NoThreadPool* NoThreadPool::instance()
{
    // Beware! The following is not thread-safe! This function must
    // be called once any thread is started.
    static NoThreadPool thread;
    return &thread;
}

NoThreadPool::NoThreadPool() : done(false), numThreads(0), numIdle(0), jobPipe{ 0, 0 }
{
    if (pipe(jobPipe)) {
        NO_DEBUG("Ouch, can't open pipe for thread pool: " << strerror(errno));
        exit(1);
    }
}

void NoThreadPool::jobDone(NoJob* job)
{
    // This must be called with the mutex locked!

    enum NoJob::JobState oldState = job->m_state;
    job->m_state = NoJob::Done;

    if (oldState == NoJob::Cancelled) {
        // Signal the main thread that cancellation is done
        cancellationCond.signal();
        return;
    }

    // This write() must succeed because POSIX guarantees that writes of
    // less than PIPE_BUF are atomic (and PIPE_BUF is at least 512).
    // (Yes, this really wants to write a pointer(!) to the pipe.
    size_t w = write(jobPipe[1], &job, sizeof(job));
    if (w != sizeof(job)) {
        NO_DEBUG("Something bad happened during write() to a pipe for thread pool, wrote " << w << " bytes: " << strerror(errno));
        exit(1);
    }
}

void NoThreadPool::handlePipeReadable() const
{
    finishJob(getJobFromPipe());
}

NoJob* NoThreadPool::getJobFromPipe() const
{
    NoJob* a = nullptr;
    ssize_t need = sizeof(a);
    ssize_t r = read(jobPipe[0], &a, need);
    if (r != need) {
        NO_DEBUG("Something bad happened during read() from a pipe for thread pool: " << strerror(errno));
        exit(1);
    }
    return a;
}

void NoThreadPool::finishJob(NoJob* job) const
{
    job->finished();
    delete job;
}

NoThreadPool::~NoThreadPool()
{
    NoMutexLocker guard(mutex);
    done = true;

    while (numThreads > 0) {
        cond.broadcast();
        exitCond.wait(mutex);
    }
}

bool NoThreadPool::threadNeeded() const
{
    if (numIdle > MAX_IDLE_THREADS)
        return false;
    return !done;
}

void NoThreadPool::threadFunc()
{
    NoMutexLocker guard(mutex);
    // nuthreads was already increased
    numIdle++;

    while (true) {
        while (jobs.empty()) {
            if (!threadNeeded())
                break;
            cond.wait(mutex);
        }
        if (!threadNeeded())
            break;

        // Figure out a job to do
        NoJob* job = jobs.front();
        jobs.pop_front();

        // Now do the actual job
        numIdle--;
        job->m_state = NoJob::Running;
        guard.unlock();

        job->run();

        guard.lock();
        jobDone(job);
        numIdle++;
    }
    assert(numThreads > 0 && numIdle > 0);
    numThreads--;
    numIdle--;

    if (numThreads == 0 && done)
        exitCond.signal();
}

void NoJob::start()
{
    NoThreadPool* d = NoThreadPool::instance();
    NoMutexLocker guard(d->mutex);
    d->jobs.push_back(this);

    // Do we already have a thread which can handle this job?
    if (d->numIdle > 0) {
        d->cond.signal();
        return;
    }

    if (d->numThreads >= MAX_TOTAL_THREADS)
        // We can't start a new thread. The job will be handled once
        // some thread finishes its current job.
        return;

    // Start a new thread for our pool
    d->numThreads++;
    startThread(threadPoolFunc, d);
}

void NoJob::cancel()
{
    std::set<NoJob*> jobs;
    jobs.insert(this);
    NoThreadPool::instance()->cancelJobs(jobs);
}

void NoThreadPool::cancelJobs(const std::set<NoJob*>& cancel)
{
    // Thanks to the mutex, jobs cannot change state anymore. There are
    // three different states which can occur:
    //
    // READY: The job is still in our list of pending jobs and no threads
    // got it yet. Just clean up.
    //
    // DONE: The job finished running and was already written to the pipe
    // that is used for waking up finished jobs. We can just read from the
    // pipe until we see this job.
    //
    // RUNNING: This is the complicated case. The job is currently being
    // executed. We change its state to CANCELLED so that wasCancelled()
    // returns true. Afterwards we wait on a CV for the job to have finished
    // running. This CV is signaled by jobDone() which checks the job's
    // status and sees that the job was cancelled. It signals to us that
    // cancellation is done by changing the job's status to DONE.

    NoMutexLocker guard(mutex);
    std::set<NoJob*> wait, finished, deleteLater;
    std::set<NoJob*>::const_iterator it;

    // Start cancelling all jobs
    for (it = cancel.begin(); it != cancel.end(); ++it) {
        switch ((*it)->m_state) {
        case NoJob::Ready: {
            (*it)->m_state = NoJob::Cancelled;

            // Job wasn't started yet, must be in the queue
            std::list<NoJob*>::iterator it2 = std::find(jobs.begin(), jobs.end(), *it);
            assert(it2 != jobs.end());
            jobs.erase(it2);
            deleteLater.insert(*it);
            continue;
        }

        case NoJob::Running:
            (*it)->m_state = NoJob::Cancelled;
            wait.insert(*it);
            continue;

        case NoJob::Done:
            (*it)->m_state = NoJob::Cancelled;
            finished.insert(*it);
            continue;

        case NoJob::Cancelled:
        default:
            assert(0);
        }
    }

    // Now wait for cancellation to be done

    // Collect jobs that really were cancelled. Finished cancellation is
    // signaled by changing their state to DONE.
    while (!wait.empty()) {
        it = wait.begin();
        while (it != wait.end()) {
            if ((*it)->m_state != NoJob::Cancelled) {
                assert((*it)->m_state == NoJob::Done);
                // Re-set state for the destructor
                (*it)->m_state = NoJob::Cancelled;
                ;
                deleteLater.insert(*it);
                wait.erase(it++);
            } else
                it++;
        }

        if (wait.empty())
            break;

        // Then wait for more to be done
        cancellationCond.wait(mutex);
    }

    // We must call destructors with mutex unlocked so that they can call wasCancelled()
    guard.unlock();

    // Handle finished jobs. They must already be in the pipe.
    while (!finished.empty()) {
        NoJob* job = getJobFromPipe();
        if (finished.erase(job) > 0) {
            assert(job->m_state == NoJob::Cancelled);
            delete job;
        } else
            finishJob(job);
    }

    // Delete things that still need to be deleted
    while (!deleteLater.empty()) {
        delete *deleteLater.begin();
        deleteLater.erase(deleteLater.begin());
    }
}

int NoThreadPool::getReadFD() const
{
    return jobPipe[0];
}

bool NoJob::wasCancelled() const
{
    NoMutexLocker guard(NoThreadPool::instance()->mutex);
    return m_state == Cancelled;
}

#endif // HAVE_PTHREAD
