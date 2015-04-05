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

#include "nosocketinfo.h"
#include "nosocket_p.h"

class NoSocketInfoPrivate
{
public:
    NoSocket* socket = nullptr;
};

NoSocketInfo::NoSocketInfo(NoSocket* socket) : d(new NoSocketInfoPrivate)
{
    d->socket = socket;
}

NoSocketInfo::NoSocketInfo(const NoSocketInfo& other) : d(new NoSocketInfoPrivate)
{
    d->socket = other.socket();
}

NoSocketInfo& NoSocketInfo::operator=(const NoSocketInfo& other)
{
    if (this != &other)
        d->socket = other.socket();
    return *this;
}

NoSocketInfo::~NoSocketInfo()
{
}

NoSocket* NoSocketInfo::socket() const
{
    return d->socket;
}

ulonglong NoSocketInfo::bytesRead() const
{
    if (!d->socket)
        return 0;
    return NoSocketPrivate::get(d->socket)->GetBytesRead();
}

ulonglong NoSocketInfo::bytesWritten() const
{
    if (!d->socket)
        return 0;
    return NoSocketPrivate::get(d->socket)->GetBytesWritten();
}

double NoSocketInfo::averageReadSpeed() const
{
    if (!d->socket)
        return 0;
    return NoSocketPrivate::get(d->socket)->GetAvgRead();
}

double NoSocketInfo::averageWriteSpeed() const
{
    if (!d->socket)
        return 0;
    return NoSocketPrivate::get(d->socket)->GetAvgWrite();
}
