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

#ifndef NOQUERY_H
#define NOQUERY_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
#include <memory>

class NoBuffer;
class NoClient;
class NoNetwork;
class NoQueryPrivate;

class NO_EXPORT NoQuery
{
public:
    NoQuery(const NoString& name, NoNetwork* network);
    ~NoQuery();

    NoString name() const;

    const NoBuffer& buffer() const;
    uint bufferCount() const;
    bool setBufferCount(uint count, bool force = false);
    size_t addBuffer(const NoString& format, const NoString& text = "", const timeval* ts = nullptr);
    void clearBuffer();

    void sendBuffer(NoClient* client);
    void sendBuffer(NoClient* client, const NoBuffer& buffer);

private:
    NoQuery(const NoQuery&) = delete;
    NoQuery& operator=(const NoQuery&) = delete;

    std::unique_ptr<NoQueryPrivate> d;
};

#endif // NOQUERY_H
