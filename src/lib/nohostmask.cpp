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

#include "nohostmask.h"

class NoHostMaskPrivate
{
public:
    void parse(const NoString& mask)
    {
        if (mask.empty())
            return;

        nick = mask;
        nick.trimLeft(":");

        ulong pos = mask.find('!');
        if (pos != NoString::npos) {
            nick.resize(pos);
            host = mask.substr(pos + 1);

            pos = host.find('@');
            if (pos != NoString::npos) {
                ident = host.substr(0, pos);
                host = host.substr(pos + 1);
            }
        }
    }

    NoString nick = "";
    NoString ident = "";
    NoString host = "";
};

NoHostMask::NoHostMask(const NoString& mask) : d(new NoHostMaskPrivate)
{
    d->parse(mask);
}

NoHostMask::NoHostMask(const NoHostMask& other) : d(new NoHostMaskPrivate)
{
    d->nick = other.nick();
    d->ident = other.ident();
    d->host = other.host();
}

NoHostMask& NoHostMask::operator=(const NoHostMask& other)
{
    if (this != &other) {
        d->nick = other.nick();
        d->ident = other.ident();
        d->host = other.host();
    }
    return *this;
}

NoHostMask::~NoHostMask()
{
}

bool NoHostMask::isNull() const
{
    return d->nick.empty() && d->ident.empty() && d->host.empty();
}

bool NoHostMask::isValid() const
{
    return !d->nick.empty();
}

NoString NoHostMask::toString() const
{
    NoString mask = d->nick;
    if (!d->host.empty()) {
        if (!d->ident.empty())
            mask += "!" + d->ident;
        mask += "@" + d->host;
    }
    return mask;
}

NoString NoHostMask::nick() const
{
    return d->nick;
}

void NoHostMask::setNick(const NoString& nick)
{
    d->nick = nick;
}

NoString NoHostMask::ident() const
{
    return d->ident;
}

void NoHostMask::setIdent(const NoString& ident)
{
    d->ident = ident;
}

NoString NoHostMask::host() const
{
    return d->host;
}

void NoHostMask::setHost(const NoString& host)
{
    d->host = host;
}
