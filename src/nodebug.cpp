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

#include "nodebug.h"
#include <iostream>
#include <sys/time.h>
#include <stdio.h>

bool NoDebug::stdoutIsTTY = true;
#ifndef NDEBUG
bool NoDebug::debug = true;
#else
bool NoDebug::debug = false;
#endif

NoDebugStream::~NoDebugStream()
{
    timeval tTime;
    gettimeofday(&tTime, nullptr);
    time_t tSec = (time_t)tTime.tv_sec; // some systems (e.g. openbsd) define tv_sec as ulong instead of time_t
    tm tM;
    tzset(); // localtime_r requires this
    localtime_r(&tSec, &tM);
    char sTime[20] = {};
    strftime(sTime, sizeof(sTime), "%Y-%m-%d %H:%M:%S", &tM);
    char sUsec[7] = {};
    snprintf(sUsec, sizeof(sUsec), "%06lu", (ulong)tTime.tv_usec);
    std::cout << "[" << sTime << "." << sUsec << "] " << NoString(this->str()).Escape_n(No::DebugFormat) << std::endl;
}
