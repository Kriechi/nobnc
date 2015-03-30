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

#include "nobuffer.h"
#include "nomessage.h"
#include "noclient.h"
#include "nouser.h"
#include "noapp.h"
#include <deque>

class NoBufferPrivate
{
public:
    uint limit = 100;
    std::deque<NoMessage> lines;
};

NoBuffer::NoBuffer(uint limit) : d(new NoBufferPrivate)
{
    d->limit = limit;
}

NoBuffer::~NoBuffer()
{
}

uint NoBuffer::addMessage(const NoString& format, const NoString& text, const timeval* ts)
{
    if (!d->limit)
        return 0;

    while (d->lines.size() >= d->limit)
        d->lines.erase(d->lines.begin());

    d->lines.push_back(NoMessage(format, text, ts));
    return d->lines.size();
}

#include "nomessage_p.h"
uint NoBuffer::updateMessage(const NoString& match, const NoString& format, const NoString& text)
{
    for (NoMessage& line : d->lines) {
        if (line.format().startsWith(match, No::CaseSensitive) == 0) {
            line.setFormat(format);
            line.setText(text);
            NoMessagePrivate::get(line)->updateTime();
            return d->lines.size();
        }
    }

    return addMessage(format, text);
}

uint NoBuffer::updateExactMessage(const NoString& format, const NoString& text)
{
    for (const NoMessage& line : d->lines) {
        if (line.format() == format && line.text() == text)
            return d->lines.size();
    }

    return addMessage(format, text);
}

const NoMessage& NoBuffer::message(uint idx) const
{
    return d->lines[idx];
}

NoString NoBuffer::message(uint idx, const NoClient& client, const NoStringMap& params) const
{
    return d->lines[idx].formatted(client, params);
}

uint NoBuffer::size() const
{
    return d->lines.size();
}

bool NoBuffer::isEmpty() const
{
    return d->lines.empty();
}

void NoBuffer::clear()
{
    d->lines.clear();
}

uint NoBuffer::limit() const
{
    return d->limit;
}

bool NoBuffer::setLimit(uint limit, bool force)
{
    if (!force && limit > NoApp::instance().maxBufferSize())
        return false;

    d->limit = limit;

    // We may need to shrink the buffer if the allowed size got smaller
    while (d->lines.size() > d->limit) {
        d->lines.erase(d->lines.begin());
    }

    return true;
}
