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

#ifndef NOTHREAD_H
#define NOTHREAD_H

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

class NO_EXPORT NoThread
{
public:
    typedef void* threadRoutine(void*);
    static void startThread(threadRoutine* func, void* arg)
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
            NoUtils::printError("Can't start new thread: " + NoString(strerror(errno)));
            exit(1);
        }
    }

private:
    // Undefined constructor
    NoThread();
};

#endif // HAVE_PTHREAD

#endif // NOTHREAD_H
