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

    NoString getName() const;

    const NoBuffer& getBuffer() const;
    unsigned int getBufferCount() const;
    bool setBufferCount(unsigned int u, bool bForce = false);
    size_t addBuffer(const NoString& sFormat, const NoString& sText = "", const timeval* ts = nullptr);
    void clearBuffer();

    void sendBuffer(NoClient* pClient);
    void sendBuffer(NoClient* pClient, const NoBuffer& Buffer);

private:
    NoString m_name;
    NoNetwork* m_network;
    NoBuffer m_buffer;
};

#endif // NOQUERY_H
