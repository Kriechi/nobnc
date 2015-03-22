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

#include "nomessage.h"
#include "nobuffer.h"
#include "noclient.h"
#include "noutils.h"
#include "nouser.h"
#include "noapp.h"

class NoMessagePrivate
{
public:
    NoString format;
    NoString text;
    timeval time;
};

NoMessage::NoMessage(const NoString& format, const NoString& text, const timeval* ts)
    : d(new NoMessagePrivate)
{
    d->format = format;
    d->text = text;

    if (!ts)
        UpdateTime();
    else
        d->time = *ts;
}

NoMessage::NoMessage(const NoMessage& other) : d(new NoMessagePrivate)
{
    d->format = other.GetFormat();
    d->text = other.GetText();
    d->time = other.GetTime();
}

NoMessage& NoMessage::operator=(const NoMessage& other)
{
    if (this != &other) {
        d->format = other.GetFormat();
        d->text = other.GetText();
        d->time = other.GetTime();
    }
    return *this;
}

NoMessage::~NoMessage()
{
}

void NoMessage::UpdateTime()
{
    if (!gettimeofday(&d->time, nullptr)) {
        d->time.tv_sec = time(nullptr);
        d->time.tv_usec = 0;
    }
}

NoString NoMessage::GetLine(const NoClient& client, const NoStringMap& params) const
{
    NoStringMap copy = params;

    if (client.HasServerTime()) {
        copy["text"] = d->text;
        NoString str = No::namedFormat(d->format, copy);
        return "@time=" + No::formatServerTime(d->time) + " " + str;
    } else {
        copy["text"] = client.GetUser()->AddTimestamp(d->time.tv_sec, d->text);
        return No::namedFormat(d->format, copy);
    }
}

NoString NoMessage::GetFormat() const { return d->format; }

void NoMessage::SetFormat(const NoString& format) { d->format = format; }

NoString NoMessage::GetText() const { return d->text; }

void NoMessage::SetText(const NoString& text) { d->text = text; }

timeval NoMessage::GetTime() const { return d->time; }

void NoMessage::SetTime(const timeval& ts) { d->time = ts; }
