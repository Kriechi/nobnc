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

#include "nomessage.h"
#include "nomessage_p.h"
#include "nobuffer.h"
#include "noclient.h"
#include "noutils.h"
#include "nouser.h"
#include "noapp.h"

void NoMessagePrivate::updateTime()
{
    if (!gettimeofday(&ts, nullptr)) {
        ts.tv_sec = time(nullptr);
        ts.tv_usec = 0;
    }
}

NoMessage::NoMessage(const NoString& format, const NoString& text, const timeval* ts)
    : d(new NoMessagePrivate)
{
    d->format = format;
    d->text = text;

    if (!ts)
        d->updateTime();
    else
        d->ts = *ts;
}

NoMessage::NoMessage(const NoMessage& other) : d(new NoMessagePrivate)
{
    d->format = other.format();
    d->text = other.text();
    d->ts = other.timestamp();
}

NoMessage& NoMessage::operator=(const NoMessage& other)
{
    if (this != &other) {
        d->format = other.format();
        d->text = other.text();
        d->ts = other.timestamp();
    }
    return *this;
}

NoMessage::~NoMessage()
{
}

NoString NoMessage::formatted(const NoClient& client, const NoStringMap& params) const
{
    NoStringMap copy = params;

    if (client.HasServerTime()) {
        copy["text"] = d->text;
        NoString str = No::namedFormat(d->format, copy);
        return "@time=" + No::formatServerTime(d->ts) + " " + str;
    } else {
        copy["text"] = client.GetUser()->AddTimestamp(d->ts.tv_sec, d->text);
        return No::namedFormat(d->format, copy);
    }
}

NoString NoMessage::format() const
{
    return d->format;
}

void NoMessage::setFormat(const NoString& format)
{
    d->format = format;
}

NoString NoMessage::text() const
{
    return d->text;
}

void NoMessage::setText(const NoString& text)
{
    d->text = text;
}

timeval NoMessage::timestamp() const
{
    return d->ts;
}

void NoMessage::setTimestamp(const timeval& ts)
{
    d->ts = ts;
}
