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

#ifndef NOMUTEX_P_H
#define NOMUTEX_P_H

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
 * This class represents a non-recursive mutex. Only a single thread may own the
 * mutex at any point in time.
 */
class NO_EXPORT NoMutex
{
public:
    friend class NoConditionVariable;

    NoMutex() : m_mutex()
    {
        int i = pthread_mutex_init(&m_mutex, nullptr);
        if (i) {
            No::printError("Can't initialize mutex: " + NoString(strerror(errno)));
            exit(1);
        }
    }

    ~NoMutex()
    {
        int i = pthread_mutex_destroy(&m_mutex);
        if (i) {
            No::printError("Can't destroy mutex: " + NoString(strerror(errno)));
            exit(1);
        }
    }

    void lock()
    {
        int i = pthread_mutex_lock(&m_mutex);
        if (i) {
            No::printError("Can't lock mutex: " + NoString(strerror(errno)));
            exit(1);
        }
    }

    void unlock()
    {
        int i = pthread_mutex_unlock(&m_mutex);
        if (i) {
            No::printError("Can't unlock mutex: " + NoString(strerror(errno)));
            exit(1);
        }
    }

private:
    NoMutex(const NoMutex&) = delete;
    NoMutex& operator=(const NoMutex&) = delete;

    pthread_mutex_t m_mutex;
};

#endif // HAVE_PTHREAD

#endif // NOMUTEX_P_H
