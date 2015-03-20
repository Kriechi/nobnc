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

#ifndef NOMUTEXLOCKER_H
#define NOMUTEXLOCKER_H

#include <no/noglobal.h>

#ifdef HAVE_PTHREAD

#include <no/noutils.h>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <list>
#include <pthread.h>
#include <cassert>

/**
 * A mutex locker should always be used as an automatic variable. This
 * class makes sure that the mutex is unlocked when this class is destructed.
 * For example, this makes it easier to make code exception-safe.
 */
class NO_EXPORT NoMutexLocker
{
public:
    NoMutexLocker(NoMutex& mutex, bool initiallyLocked = true) : m_mutex(mutex), m_locked(false)
    {
        if (initiallyLocked) lock();
    }

    ~NoMutexLocker()
    {
        if (m_locked) unlock();
    }

    void lock()
    {
        assert(!m_locked);
        m_mutex.lock();
        m_locked = true;
    }

    void unlock()
    {
        assert(m_locked);
        m_locked = false;
        m_mutex.unlock();
    }

private:
    // Undefined copy constructor and assignment operator
    NoMutexLocker(const NoMutexLocker&);
    NoMutexLocker& operator=(const NoMutexLocker&);

    NoMutex& m_mutex;
    bool m_locked;
};

#endif // HAVE_PTHREAD

#endif // NOMUTEXLOCKER_H
