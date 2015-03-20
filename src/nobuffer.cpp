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
#include "noapp.h"

NoBuffer::NoBuffer(uint limit) : m_limit(limit)
{
}

NoBuffer::~NoBuffer()
{
}

uint NoBuffer::addMessage(const NoString& format, const NoString& text, const timeval* ts)
{
    if (!m_limit) {
        return 0;
    }

    while (m_lines.size() >= m_limit) {
        m_lines.erase(m_lines.begin());
    }

    m_lines.push_back(NoMessage(format, text, ts));
    return m_lines.size();
}

uint NoBuffer::updateMessage(const NoString& match, const NoString& format, const NoString& text)
{
    for (NoMessage& line : m_lines) {
        if (line.GetFormat().startsWith(match, No::CaseSensitive) == 0) {
            line.SetFormat(format);
            line.SetText(text);
            line.UpdateTime();
            return m_lines.size();
        }
    }

    return addMessage(format, text);
}

uint NoBuffer::updateExactMessage(const NoString& format, const NoString& text)
{
    for (const NoMessage& line : m_lines) {
        if (line.GetFormat() == format && line.GetText() == text) {
            return m_lines.size();
        }
    }

    return addMessage(format, text);
}

const NoMessage& NoBuffer::getMessage(uint idx) const
{
    return m_lines[idx];
}

NoString NoBuffer::getMessage(uint idx, const NoClient& client, const NoStringMap& params) const
{
    return m_lines[idx].GetLine(client, params);
}

uint NoBuffer::size() const
{
    return m_lines.size();
}

bool NoBuffer::isEmpty() const
{
    return m_lines.empty();
}

void NoBuffer::clear()
{
    m_lines.clear();
}

uint NoBuffer::getLimit() const
{
    return m_limit;
}

bool NoBuffer::setLimit(uint limit, bool force)
{
    if (!force && limit > NoApp::Get().GetMaxBufferSize()) {
        return false;
    }

    m_limit = limit;

    // We may need to shrink the buffer if the allowed size got smaller
    while (m_lines.size() > m_limit) {
        m_lines.erase(m_lines.begin());
    }

    return true;
}
