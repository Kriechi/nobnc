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

CMessage::CMessage(const CString& format, const CString& text, const timeval* ts)
    : m_format(format), m_text(text), m_time()
{
    if (!ts)
        UpdateTime();
    else
        m_time = *ts;
}

CMessage::~CMessage()
{
}

void CMessage::UpdateTime()
{
    if (!gettimeofday(&m_time, nullptr)) {
        m_time.tv_sec = time(nullptr);
        m_time.tv_usec = 0;
    }
}

CString CMessage::GetLine(const CClient& client, const MCString& params) const
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
