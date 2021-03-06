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

#ifndef NOSOCKETINFO_H
#define NOSOCKETINFO_H

#include <nobnc/noglobal.h>
#include <memory>
#include <ctime>

class NoSocket;
class NoSocketInfoPrivate;

class NO_EXPORT NoSocketInfo
{
public:
    NoSocketInfo(NoSocket* socket);
    NoSocketInfo(const NoSocketInfo& other);
    NoSocketInfo& operator=(const NoSocketInfo& other);
    ~NoSocketInfo();

    NoSocket* socket() const;

    ulonglong bytesRead() const;
    ulonglong bytesWritten() const;

    double averageReadSpeed() const;
    double averageWriteSpeed() const;

    ulonglong startTime() const;
    time_t timeSinceLastDataTransaction() const;

private:
    std::shared_ptr<NoSocketInfoPrivate> d;
};

#endif // NOSOCKETINFO_H
