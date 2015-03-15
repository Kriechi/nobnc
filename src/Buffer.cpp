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

#include <znc/znc.h>
#include <znc/User.h>

CBufLine::CBufLine(const CString& format, const CString& text, const timeval* ts)
    : m_format(format), m_text(text), m_time()
{
    if (!ts)
        UpdateTime();
    else
        m_time = *ts;
}

CBufLine::~CBufLine()
{
}

void CBufLine::UpdateTime()
{
    if (!gettimeofday(&m_time, nullptr)) {
        m_time.tv_sec = time(nullptr);
        m_time.tv_usec = 0;
    }
}

CString CBufLine::GetLine(const CClient& client, const MCString& params) const
{
    MCString copy = params;

    if (client.HasServerTime()) {
        copy["text"] = m_text;
        CString str = CString::NamedFormat(m_format, copy);
        return "@time=" + CUtils::FormatServerTime(m_time) + " " + str;
    } else {
        copy["text"] = client.GetUser()->AddTimestamp(m_time.tv_sec, m_text);
        return CString::NamedFormat(m_format, copy);
    }
}

CBuffer::CBuffer(unsigned int uLineCount) : m_uLineCount(uLineCount) {}

CBuffer::~CBuffer() {}

CBuffer::size_type CBuffer::AddLine(const CString& sFormat, const CString& sText, const timeval* ts)
{
    if (!m_uLineCount) {
        return 0;
    }

    while (size() >= m_uLineCount) {
        erase(begin());
    }

    push_back(CBufLine(sFormat, sText, ts));
    return size();
}

CBuffer::size_type CBuffer::UpdateLine(const CString& sMatch, const CString& sFormat, const CString& sText)
{
    for (CBufLine& Line : *this) {
        if (Line.GetFormat().compare(0, sMatch.length(), sMatch) == 0) {
            Line.SetFormat(sFormat);
            Line.SetText(sText);
            Line.UpdateTime();
            return size();
        }
    }

    return AddLine(sFormat, sText);
}

CBuffer::size_type CBuffer::UpdateExactLine(const CString& sFormat, const CString& sText)
{
    for (const CBufLine& Line : *this) {
        if (Line.GetFormat() == sFormat && Line.GetText() == sText) {
            return size();
        }
    }

    return AddLine(sFormat, sText);
}

const CBufLine& CBuffer::GetBufLine(unsigned int uIdx) const { return (*this)[uIdx]; }

CString CBuffer::GetLine(size_type uIdx, const CClient& Client, const MCString& msParams) const
{
    return (*this)[uIdx].GetLine(Client, msParams);
}

bool CBuffer::SetLineCount(unsigned int u, bool bForce)
{
    if (!bForce && u > CZNC::Get().GetMaxBufferSize()) {
        return false;
    }

    m_uLineCount = u;

    // We may need to shrink the buffer if the allowed size got smaller
    while (size() > m_uLineCount) {
        erase(begin());
    }

    return true;
}
