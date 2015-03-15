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

#ifndef ZNC_QUERY_H
#define ZNC_QUERY_H

#include <znc/noconfig.h>
#include <znc/nostring.h>
#include <znc/Buffer.h>

class CClient;
class CNetwork;

class CQuery
{
public:
    CQuery(const CString& sName, CNetwork* pNetwork);
    ~CQuery();

    CQuery(const CQuery&) = delete;
    CQuery& operator=(const CQuery&) = delete;

    const CBuffer& GetBuffer() const { return m_Buffer; }
    unsigned int GetBufferCount() const { return m_Buffer.GetLimit(); }
    bool SetBufferCount(unsigned int u, bool bForce = false) { return m_Buffer.SetLimit(u, bForce); }
    size_t AddBuffer(const CString& sFormat, const CString& sText = "", const timeval* ts = nullptr)
    {
        return m_Buffer.AddLine(sFormat, sText, ts);
    }
    void ClearBuffer() { m_Buffer.Clear(); }
    void SendBuffer(CClient* pClient);
    void SendBuffer(CClient* pClient, const CBuffer& Buffer);

    const CString& GetName() const { return m_sName; }

private:
    CString m_sName;
    CNetwork* m_pNetwork;
    CBuffer m_Buffer;
};

#endif // !ZNC_QUERY_H
