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

#ifndef NOCONDITIONVARIABLE_H
#define NOCONDITIONVARIABLE_H

#include <nobnc/noglobal.h>

#ifdef HAVE_PTHREAD

#include <nobnc/noutils.h>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <list>
#include <pthread.h>
#include <cassert>

/**
 * A condition variable makes it possible for threads to wait until some
 * condition is reached at which point the thread can wake up again.
 */
class NO_EXPORT NoConditionVariable
{
public:
    NoConditionVariable() : m_cond()
    {
        int i = pthread_cond_init(&m_cond, nullptr);
        if (i) {
            No::printError("Can't initialize condition variable: " + NoString(strerror(errno)));
            exit(1);
        }
    }

    ~NoConditionVariable()
    {
        int i = pthread_cond_destroy(&m_cond);
        if (i) {
            No::printError("Can't destroy condition variable: " + NoString(strerror(errno)));
            exit(1);
        }
    }

    void wait(NoMutex& mutex)
    {
        int i = pthread_cond_wait(&m_cond, &mutex.m_mutex);
        if (i) {
            No::printError("Can't wait on condition variable: " + NoString(strerror(errno)));
            exit(1);
        }
    }

    void signal()
    {
        int i = pthread_cond_signal(&m_cond);
        if (i) {
            No::printError("Can't signal condition variable: " + NoString(strerror(errno)));
            exit(1);
        }
    }

    void broadcast()
    {
        int i = pthread_cond_broadcast(&m_cond);
        if (i) {
            No::printError("Can't broadcast condition variable: " + NoString(strerror(errno)));
            exit(1);
        }
    }

private:
    NoConditionVariable(const NoConditionVariable&) = delete;
    NoConditionVariable& operator=(const NoConditionVariable&) = delete;

    pthread_cond_t m_cond;
};

#endif // HAVE_PTHREAD

#endif // NOCONDITIONVARIABLE_H
