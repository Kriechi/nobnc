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

#ifndef ZNC_BUFFER_H
#define ZNC_BUFFER_H

#include <znc/zncconfig.h>
#include <znc/ZNCString.h>
#include <sys/time.h>
#include <deque>

class CClient;

class CBufLine
{
public:
    CBufLine(const CString& format = "", const CString& text = "", const timeval* ts = nullptr);
    ~CBufLine();

    CString GetLine(const CClient& client, const MCString& params) const;

    CString GetFormat() const { return m_format; }
    void SetFormat(const CString& format) { m_format = format; }

    CString GetText() const { return m_text; }
    void SetText(const CString& text) { m_text = text; }

    timeval GetTime() const { return m_time; }
    void SetTime(const timeval& ts) { m_time = ts; }

    void UpdateTime();

private:
    CString m_format;
    CString m_text;
    timeval m_time;
};

class CBuffer : private std::deque<CBufLine>
{
public:
    CBuffer(unsigned int uLineCount = 100);
    ~CBuffer();

    size_type AddLine(const CString& sFormat, const CString& sText = "", const timeval* ts = nullptr);
    /// Same as AddLine, but replaces a line whose format string starts with sMatch if there is one.
    size_type UpdateLine(const CString& sMatch, const CString& sFormat, const CString& sText = "");
    /// Same as UpdateLine, but does nothing if this exact line already exists.
    /// We need this because "/version" sends us the 005 raws again
    size_type UpdateExactLine(const CString& sFormat, const CString& sText = "");
    const CBufLine& GetBufLine(unsigned int uIdx) const;
    CString GetLine(size_type uIdx, const CClient& Client, const MCString& msParams = MCString::EmptyMap) const;
    size_type Size() const { return size(); }
    bool IsEmpty() const { return empty(); }
    void Clear() { clear(); }

    // Setters
    bool SetLineCount(unsigned int u, bool bForce = false);
    // !Setters

    // Getters
    unsigned int GetLineCount() const { return m_uLineCount; }
    // !Getters
private:
    unsigned int m_uLineCount;
};

#endif // !ZNC_BUFFER_H
