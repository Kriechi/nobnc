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

#ifndef NOBUFFER_H
#define NOBUFFER_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <sys/time.h>
#include <memory>

class NoClient; // TODO: get rid of this dep
class NoMessage;
class NoBufferPrivate;

class NO_EXPORT NoBuffer
{
public:
    NoBuffer(uint limit = 100);
    ~NoBuffer();

    uint addMessage(const NoString& format, const NoString& text = "", const timeval* ts = nullptr);
    uint updateMessage(const NoString& match, const NoString& format, const NoString& text = "");
    uint updateExactMessage(const NoString& format, const NoString& text = "");

    const NoMessage& message(uint idx) const;
    NoString message(uint idx, const NoClient& client, const NoStringMap& params = NoStringMap()) const;

    uint size() const;
    bool isEmpty() const;
    void clear();

    uint limit() const;
    bool setLimit(uint limit, bool force = false);

private:
    NoBuffer(const NoBuffer&) = delete;
    NoBuffer& operator=(const NoBuffer&) = delete;

    std::unique_ptr<NoBufferPrivate> d;
};

#endif // NOBUFFER_H
