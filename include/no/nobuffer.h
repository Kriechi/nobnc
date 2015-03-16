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

#ifndef NOBUFFER_H
#define NOBUFFER_H

#include <no/noconfig.h>
#include <no/nostring.h>
#include <no/nomessage.h>
#include <sys/time.h>
#include <deque>

class NoClient;

class NoBuffer
{
public:
    NoBuffer(unsigned int limit = 100);
    ~NoBuffer();

    unsigned int addMessage(const NoString& format, const NoString& text = "", const timeval* ts = nullptr);
    unsigned int updateMessage(const NoString& match, const NoString& format, const NoString& text = "");
    unsigned int updateExactMessage(const NoString& format, const NoString& text = "");

    const NoMessage& getMessage(unsigned int idx) const;
    NoString getMessage(unsigned int idx, const NoClient& client, const NoStringMap& params = NoStringMap::EmptyMap) const;

    unsigned int size() const;
    bool isEmpty() const;
    void clear();

    unsigned int getLimit() const;
    bool setLimit(unsigned int limit, bool force = false);

private:
    unsigned int m_limit;
    std::deque<NoMessage> m_lines;
};

#endif // NOBUFFER_H