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

#ifndef NOTHREAD_H
#define NOTHREAD_H

#include <nobnc/noglobal.h>

#ifdef HAVE_PTHREAD

class NoJob;

class NO_EXPORT NoThread
{
public:
    /// Add a job to the thread pool and run it. The job will be deleted when done.
    static void run(NoJob* job);

    /// Cancel a job that was previously passed to addJob(). This *might*
    /// mean that NoJob::run() and/or NoJob::finished() will not be called.
    /// This function BLOCKS until the job finishes!
    static void cancel(NoJob* job);
};

#endif // HAVE_PTHREAD

#endif // NOTHREAD_H
