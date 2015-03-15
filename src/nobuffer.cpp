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

#include "nobuffer.h"
#include "noclient.h"
#include "nouser.h"
#include "noznc.h"

CBuffer::CBuffer(unsigned int limit) : m_limit(limit)
{
}

CBuffer::~CBuffer()
{
}

unsigned int CBuffer::AddLine(const CString& format, const CString& text, const timeval* ts)
{
    if (!m_limit) {
        return 0;
    }

    while (m_lines.size() >= m_limit) {
        m_lines.erase(m_lines.begin());
    }

    m_lines.push_back(CMessage(format, text, ts));
    return m_lines.size();
}

unsigned int CBuffer::UpdateLine(const CString& match, const CString& format, const CString& text)
{
    for (CMessage& line : m_lines) {
        if (line.GetFormat().compare(0, match.length(), match) == 0) {
            line.SetFormat(format);
            line.SetText(text);
            line.UpdateTime();
            return m_lines.size();
        }
    }

    return AddLine(format, text);
}

unsigned int CBuffer::UpdateExactLine(const CString& format, const CString& text)
{
    for (const CMessage& line : m_lines) {
        if (line.GetFormat() == format && line.GetText() == text) {
            return m_lines.size();
        }
    }

    return AddLine(format, text);
}

const CMessage& CBuffer::GetMessage(unsigned int idx) const
{
    return m_lines[idx];
}

CString CBuffer::GetLine(unsigned int idx, const CClient& client, const MCString& params) const
{
    return m_lines[idx].GetLine(client, params);
}

bool CBuffer::SetLimit(unsigned int limit, bool force)
{
    if (!force && limit > CZNC::Get().GetMaxBufferSize()) {
        return false;
    }

    m_limit = limit;

    // We may need to shrink the buffer if the allowed size got smaller
    while (m_lines.size() > m_limit) {
        m_lines.erase(m_lines.begin());
    }

    return true;
}
