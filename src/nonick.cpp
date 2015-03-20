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

#include "nonick.h"
#include "noircconnection.h"
#include "nonetwork.h"

NoNick::NoNick(const NoString& mask) : m_perms(""), m_network(nullptr), m_nick(""), m_ident(""), m_host("")
{
    parse(mask);
}

bool NoNick::equals(const NoString& nick) const
{
    // TODO add proper IRC case mapping here
    // https://tools.ietf.org/html/draft-brocklesby-irc-isupport-03#section-3.1
    return m_nick.equals(nick);
}

NoString NoNick::nick() const
{
    return m_nick;
}

void NoNick::setNick(const NoString& nick)
{
    m_nick = nick;
}

NoString NoNick::ident() const
{
    return m_ident;
}

void NoNick::setIdent(const NoString& ident)
{
    m_ident = ident;
}

NoString NoNick::host() const
{
    return m_host;
}

void NoNick::setHost(const NoString& host)
{
    m_host = host;
}

NoString NoNick::nickMask() const
{
    NoString mask = m_nick;
    if (!m_host.empty()) {
        if (!m_ident.empty())
            mask += "!" + m_ident;
        mask += "@" + m_host;
    }
    return mask;
}

NoString NoNick::hostMask() const
{
    NoString mask = m_nick;
    if (!m_ident.empty())
        mask += "!" + m_ident;
    if (!m_host.empty())
        mask += "@" + m_host;
    return mask;
}

NoNetwork* NoNick::network() const
{
    return m_network;
}

void NoNick::setNetwork(NoNetwork* network)
{
    m_network = network;
}

bool NoNick::hasPerm(uchar perm) const
{
    return perm && m_perms.find(perm) != NoString::npos;
}

void NoNick::addPerm(uchar perm)
{
    if (perm && !hasPerm(perm))
        m_perms.append(1, perm);
}

void NoNick::removePerm(uchar perm)
{
    ulong pos = m_perms.find(perm);
    if (pos != NoString::npos)
        m_perms.erase(pos, 1);
}

static NoString availablePerms(NoNetwork* network)
{
    NoString perms = "@+";
    if (network) {
        NoIrcConnection* socket = network->GetIRCSock();
        if (socket)
            perms = socket->GetPerms();
    }
    return perms;
}

uchar NoNick::perm() const
{
    for (const uchar& perm : availablePerms(m_network)) {
        if (hasPerm(perm))
            return perm;
    }
    return '\0';
}

NoString NoNick::perms() const
{
    NoString perms;
    for (const uchar& perm : availablePerms(m_network)) {
        if (hasPerm(perm))
            perms += perm;
    }
    return perms;
}

void NoNick::reset()
{
    m_perms.clear();
    m_network = nullptr;
}

void NoNick::parse(const NoString& mask)
{
    if (mask.empty())
        return;

    m_nick = mask;
    m_nick.trimLeft(":");

    ulong pos = mask.find('!');
    if (pos != NoString::npos) {
        m_nick.resize(pos);
        m_host = mask.substr(pos + 1);

        pos = m_host.find('@');
        if (pos != NoString::npos) {
            m_ident = m_host.substr(0, pos);
            m_host = m_host.substr(pos + 1);
        }
    }
}
