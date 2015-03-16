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

#include <znc/noconfig.h>
#include <znc/nostring.h>
#include <znc/nomessage.h>
#include <sys/time.h>
#include <deque>

class NoClient;

class NoBuffer
{
public:
    NoBuffer(unsigned int limit = 100);
    ~NoBuffer();

    unsigned int AddLine(const NoString& format, const NoString& text = "", const timeval* ts = nullptr);
    /// Same as AddLine, but replaces a line whose format string starts with sMatch if there is one.
    unsigned int UpdateLine(const NoString& sMatch, const NoString& format, const NoString& text = "");
    /// Same as UpdateLine, but does nothing if this exact line already exists.
    /// We need this because "/version" sends us the 005 raws again
    unsigned int UpdateExactLine(const NoString& format, const NoString& text = "");
    const NoMessage& GetMessage(unsigned int idx) const;
    NoString GetLine(unsigned int idx, const NoClient& client, const NoStringMap& params = NoStringMap::EmptyMap) const;
    unsigned int Size() const { return m_lines.size(); }
    bool IsEmpty() const { return m_lines.empty(); }
    void Clear() { m_lines.clear(); }

    unsigned int GetLimit() const { return m_limit; }
    bool SetLimit(unsigned int limit, bool force = false);

private:
    unsigned int m_limit;
    std::deque<NoMessage> m_lines;
};

#endif // NOBUFFER_H