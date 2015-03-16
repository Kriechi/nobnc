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

#ifndef NOQUERY_H
#define NOQUERY_H

#include <no/noconfig.h>
#include <no/nostring.h>
#include <no/nobuffer.h>

class NoClient;
class NoNetwork;

class NoQuery
{
public:
    NoQuery(const NoString& sName, NoNetwork* pNetwork);
    ~NoQuery();

    NoQuery(const NoQuery&) = delete;
    NoQuery& operator=(const NoQuery&) = delete;

    const NoBuffer& getBuffer() const { return m_buffer; }
    unsigned int getBufferCount() const { return m_buffer.getLimit(); }
    bool setBufferCount(unsigned int u, bool bForce = false) { return m_buffer.setLimit(u, bForce); }
    size_t addBuffer(const NoString& sFormat, const NoString& sText = "", const timeval* ts = nullptr)
    {
        return m_buffer.addMessage(sFormat, sText, ts);
    }
    void clearBuffer() { m_buffer.clear(); }
    void sendBuffer(NoClient* pClient);
    void sendBuffer(NoClient* pClient, const NoBuffer& Buffer);

    const NoString& getName() const { return m_name; }

private:
    NoString m_name;
    NoNetwork* m_network;
    NoBuffer m_buffer;
};

#endif // NOQUERY_H
