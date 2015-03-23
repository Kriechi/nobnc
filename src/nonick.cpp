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

#include "nonick.h"
#include "noircsocket.h"
#include "nonetwork.h"

class NoNickPrivate
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
    NoString perms = "";
    NoNetwork* network = nullptr;
};

NoNick::NoNick(const NoString& mask) : d(new NoNickPrivate)
{
    d->parse(mask);
}

NoNick::NoNick(const NoNick& other) : d(new NoNickPrivate)
{
    d->nick = other.nick();
    d->ident = other.ident();
    d->host = other.host();
    d->perms = other.perms();
    d->network = other.network();
}

NoNick& NoNick::operator=(const NoNick& other)
{
    if (this != &other) {
        d->nick = other.nick();
        d->ident = other.ident();
        d->host = other.host();
        d->perms = other.perms();
        d->network = other.network();
    }
    return *this;
}

NoNick::~NoNick()
{
}

bool NoNick::equals(const NoString& nick) const
{
    // TODO add proper IRC case mapping here
    // https://tools.ietf.org/html/draft-brocklesby-irc-isupport-03#section-3.1
    return d->nick.equals(nick);
}

NoString NoNick::nick() const
{
    return d->nick;
}

void NoNick::setNick(const NoString& nick)
{
    d->nick = nick;
}

NoString NoNick::ident() const
{
    return d->ident;
}

void NoNick::setIdent(const NoString& ident)
{
    d->ident = ident;
}

NoString NoNick::host() const
{
    return d->host;
}

void NoNick::setHost(const NoString& host)
{
    d->host = host;
}

NoString NoNick::nickMask() const
{
    NoString mask = d->nick;
    if (!d->host.empty()) {
        if (!d->ident.empty())
            mask += "!" + d->ident;
        mask += "@" + d->host;
    }
    return mask;
}

NoString NoNick::hostMask() const
{
    NoString mask = d->nick;
    if (!d->ident.empty())
        mask += "!" + d->ident;
    if (!d->host.empty())
        mask += "@" + d->host;
    return mask;
}

NoNetwork* NoNick::network() const
{
    return d->network;
}

void NoNick::setNetwork(NoNetwork* network)
{
    d->network = network;
}

bool NoNick::hasPerm(uchar perm) const
{
    return perm && d->perms.contains(perm);
}

void NoNick::addPerm(uchar perm)
{
    if (perm && !hasPerm(perm))
        d->perms.append(1, perm);
}

void NoNick::removePerm(uchar perm)
{
    ulong pos = d->perms.find(perm);
    if (pos != NoString::npos)
        d->perms.erase(pos, 1);
}

static NoString availablePerms(NoNetwork* network)
{
    NoString perms = "@+";
    if (network) {
        NoIrcSocket* socket = network->GetIRCSock();
        if (socket)
            perms = socket->GetPerms();
    }
    return perms;
}

uchar NoNick::perm() const
{
    for (const uchar& perm : availablePerms(d->network)) {
        if (hasPerm(perm))
            return perm;
    }
    return '\0';
}

NoString NoNick::perms() const
{
    NoString perms;
    for (const uchar& perm : availablePerms(d->network)) {
        if (hasPerm(perm))
            perms += perm;
    }
    return perms;
}

void NoNick::reset()
{
    d->perms.clear();
    d->network = nullptr;
}
