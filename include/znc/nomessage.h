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

#ifndef NOMESSAGE_H
#define NOMESSAGE_H

#include <znc/noconfig.h>
#include <znc/nostring.h>
#include <sys/time.h>

class NoClient;

class NoMessage
{
public:
    NoMessage(const NoString& format = "", const NoString& text = "", const timeval* ts = nullptr);
    ~NoMessage();

    NoString GetLine(const NoClient& client, const NoStringMap& params) const;

    NoString GetFormat() const { return m_format; }
    void SetFormat(const NoString& format) { m_format = format; }

    NoString GetText() const { return m_text; }
    void SetText(const NoString& text) { m_text = text; }

    timeval GetTime() const { return m_time; }
    void SetTime(const timeval& ts) { m_time = ts; }

    void UpdateTime();

private:
    NoString m_format;
    NoString m_text;
    timeval m_time;
};

#endif // NOMESSAGE_H