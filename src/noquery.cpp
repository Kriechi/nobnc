/*
 * Copyright (C) 2015 NoBNC
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
#include "noclient.h"
#include "nomodulecall.h"
#include "nomessage.h"
#include "noapp.h"
#include "nonick.h"
#include "nobuffer.h"

class NoQueryPrivate
{
public:
    NoString name = "";
    NoNetwork* network = nullptr;
    NoBuffer buffer;
};

NoQuery::NoQuery(const NoString& name, NoNetwork* network) : d(new NoQueryPrivate)
{
    d->name = name;
    d->network = network;
    setBufferCount(d->network->user()->bufferCount(), true);
}

NoQuery::~NoQuery()
{
}

NoString NoQuery::getName() const
{
    return d->name;
}

const NoBuffer& NoQuery::getBuffer() const
{
    return d->buffer;
}

uint NoQuery::getBufferCount() const
{
    return d->buffer.getLimit();
}

bool NoQuery::setBufferCount(uint count, bool force)
{
    return d->buffer.setLimit(count, force);
}

size_t NoQuery::addBuffer(const NoString& format, const NoString& text, const timeval* ts)
{
    return d->buffer.addMessage(format, text, ts);
}

void NoQuery::clearBuffer()
{
    d->buffer.clear();
}

void NoQuery::sendBuffer(NoClient* client)
{
    sendBuffer(client, d->buffer);
}

void NoQuery::sendBuffer(NoClient* client, const NoBuffer& buffer)
{
    if (d->network && d->network->isUserAttached()) {
        // Based on NoChannel::SendBuffer()
        if (!buffer.isEmpty()) {
            const std::vector<NoClient*>& clients = d->network->clients();
            for (NoClient* eachClient : clients) {
                NoClient* useClient = (client ? client : eachClient);

                NoStringMap params;
                params["target"] = useClient->GetNick();

                bool wasPlaybackActive = useClient->IsPlaybackActive();
                useClient->SetPlaybackActive(true);

                bool batch = useClient->HasBatch();
                NoString batchName = No::md5(d->name);

                if (batch) {
                    d->network->putUser(":znc.in BATCH +" + batchName + " znc.in/playback " + d->name, useClient);
                }

                size_t size = buffer.size();
                for (size_t uIdx = 0; uIdx < size; uIdx++) {
                    const NoMessage& message = buffer.getMessage(uIdx);

                    if (!useClient->HasSelfMessage()) {
                        NoNick sender(No::token(message.format(), 0));
                        if (sender.equals(useClient->GetNick())) {
                            continue;
                        }
                    }

                    NoString line = message.formatted(*useClient, params);
                    if (batch) {
                        NoStringMap tags = No::messageTags(line);
                        tags["batch"] = batchName;
                        No::setMessageTags(line, tags);
                    }
                    bool skip = false;
                    NETWORKMODULECALL(onPrivBufferPlayLine2(*useClient, line, message.timestamp()),
                                      d->network->user(),
                                      d->network,
                                      nullptr,
                                      &skip);
                    if (skip) continue;
                    d->network->putUser(line, useClient);
                }

                if (batch) {
                    d->network->putUser(":znc.in BATCH -" + batchName, useClient);
                }

                useClient->SetPlaybackActive(wasPlaybackActive);

                if (client) break;
            }
        }
    }
}
