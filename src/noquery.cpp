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

#include "noquery.h"
#include "nouser.h"
#include "nonetwork.h"

NoQuery::NoQuery(const NoString& name, NoNetwork* network) : m_name(name), m_network(network), m_buffer()
{
    setBufferCount(m_network->GetUser()->GetBufferCount(), true);
}

NoQuery::~NoQuery()
{
}

NoString NoQuery::getName() const
{
    return m_name;
}

const NoBuffer& NoQuery::getBuffer() const
{
    return m_buffer;
}

uint NoQuery::getBufferCount() const
{
    return m_buffer.getLimit();
}

bool NoQuery::setBufferCount(uint count, bool force)
{
    return m_buffer.setLimit(count, force);
}

size_t NoQuery::addBuffer(const NoString& format, const NoString& text, const timeval* ts)
{
    return m_buffer.addMessage(format, text, ts);
}

void NoQuery::clearBuffer()
{
    m_buffer.clear();
}

void NoQuery::sendBuffer(NoClient* client)
{
    sendBuffer(client, m_buffer);
}

void NoQuery::sendBuffer(NoClient* client, const NoBuffer& buffer)
{
    if (m_network && m_network->IsUserAttached()) {
        // Based on NoChannel::SendBuffer()
        if (!buffer.isEmpty()) {
            const std::vector<NoClient*>& clients = m_network->GetClients();
            for (NoClient* eachClient : clients) {
                NoClient* useClient = (client ? client : eachClient);

                NoStringMap params;
                params["target"] = useClient->GetNick();

                bool wasPlaybackActive = useClient->IsPlaybackActive();
                useClient->SetPlaybackActive(true);

                bool batch = useClient->HasBatch();
                NoString batchName = NoUtils::MD5(m_name);

                if (batch) {
                    m_network->PutUser(":znc.in BATCH +" + batchName + " znc.in/playback " + m_name, useClient);
                }

                size_t size = buffer.size();
                for (size_t uIdx = 0; uIdx < size; uIdx++) {
                    const NoMessage& message = buffer.getMessage(uIdx);

                    if (!useClient->HasSelfMessage()) {
                        NoNick sender(message.GetFormat().Token(0));
                        if (sender.NickEquals(useClient->GetNick())) {
                            continue;
                        }
                    }

                    NoString line = message.GetLine(*useClient, params);
                    if (batch) {
                        NoStringMap tags = NoUtils::GetMessageTags(line);
                        tags["batch"] = batchName;
                        NoUtils::SetMessageTags(line, tags);
                    }
                    bool skip = false;
                    NETWORKMODULECALL(OnPrivBufferPlayLine2(*useClient, line, message.GetTime()),
                                      m_network->GetUser(),
                                      m_network,
                                      nullptr,
                                      &skip);
                    if (skip) continue;
                    m_network->PutUser(line, useClient);
                }

                if (batch) {
                    m_network->PutUser(":znc.in BATCH -" + batchName, useClient);
                }

                useClient->SetPlaybackActive(wasPlaybackActive);

                if (client) break;
            }
        }
    }
}
