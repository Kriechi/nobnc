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
#include "nochannel.h"
#include "noircsock.h"
#include "nonetwork.h"

NoNick::NoNick() : m_sChanPerms(""), m_pNetwork(nullptr), m_sNick(""), m_sIdent(""), m_sHost("") {}

NoNick::NoNick(const NoString& sNick) : NoNick() { Parse(sNick); }

NoNick::~NoNick() {}

void NoNick::Reset()
{
    m_sChanPerms.clear();
    m_pNetwork = nullptr;
}

void NoNick::Parse(const NoString& sNickMask)
{
    if (sNickMask.empty()) {
        return;
    }

    NoString::size_type uPos = sNickMask.find('!');

    if (uPos == NoString::npos) {
        m_sNick = sNickMask.substr((sNickMask[0] == ':'));
        return;
    }

    m_sNick = sNickMask.substr((sNickMask[0] == ':'), uPos - (sNickMask[0] == ':'));
    m_sHost = sNickMask.substr(uPos + 1);

    if ((uPos = m_sHost.find('@')) != NoString::npos) {
        m_sIdent = m_sHost.substr(0, uPos);
        m_sHost = m_sHost.substr(uPos + 1);
    }
}

size_t NoNick::GetCommonChans(std::vector<NoChannel*>& vRetChans, NoNetwork* pNetwork) const
{
    vRetChans.clear();

    const std::vector<NoChannel*>& vChans = pNetwork->GetChans();

    for (NoChannel* pChan : vChans) {
        const std::map<NoString, NoNick>& msNicks = pChan->GetNicks();

        for (const auto& it : msNicks) {
            if (it.first.Equals(m_sNick)) {
                vRetChans.push_back(pChan);
                continue;
            }
        }
    }

    return vRetChans.size();
}

bool NoNick::NickEquals(const NoString& nickname) const
{
    // TODO add proper IRC case mapping here
    // https://tools.ietf.org/html/draft-brocklesby-irc-isupport-03#section-3.1
    return m_sNick.Equals(nickname);
}

void NoNick::SetNetwork(NoNetwork* pNetwork) { m_pNetwork = pNetwork; }
void NoNick::SetNick(const NoString& s) { m_sNick = s; }
void NoNick::SetIdent(const NoString& s) { m_sIdent = s; }
void NoNick::SetHost(const NoString& s) { m_sHost = s; }

bool NoNick::HasPerm(unsigned char uPerm) const { return (uPerm && m_sChanPerms.find(uPerm) != NoString::npos); }

bool NoNick::AddPerm(unsigned char uPerm)
{
    if (!uPerm || HasPerm(uPerm)) {
        return false;
    }

    m_sChanPerms.append(1, uPerm);

    return true;
}

bool NoNick::RemPerm(unsigned char uPerm)
{
    NoString::size_type uPos = m_sChanPerms.find(uPerm);
    if (uPos == NoString::npos) {
        return false;
    }

    m_sChanPerms.erase(uPos, 1);

    return true;
}

unsigned char NoNick::GetPermChar() const
{
    NoIrcSock* pIRCSock = (!m_pNetwork) ? nullptr : m_pNetwork->GetIRCSock();
    const NoString& sChanPerms = (!pIRCSock) ? "@+" : pIRCSock->GetPerms();

    for (unsigned int a = 0; a < sChanPerms.size(); a++) {
        const unsigned char& c = sChanPerms[a];
        if (HasPerm(c)) {
            return c;
        }
    }

    return '\0';
}

NoString NoNick::GetPermStr() const
{
    NoIrcSock* pIRCSock = (!m_pNetwork) ? nullptr : m_pNetwork->GetIRCSock();
    const NoString& sChanPerms = (!pIRCSock) ? "@+" : pIRCSock->GetPerms();
    NoString sRet;

    for (unsigned int a = 0; a < sChanPerms.size(); a++) {
        const unsigned char& c = sChanPerms[a];

        if (HasPerm(c)) {
            sRet += c;
        }
    }

    return sRet;
}
const NoString& NoNick::GetNick() const { return m_sNick; }
const NoString& NoNick::GetIdent() const { return m_sIdent; }
const NoString& NoNick::GetHost() const { return m_sHost; }
NoString NoNick::GetNickMask() const
{
    NoString sRet = m_sNick;

    if (!m_sHost.empty()) {
        if (!m_sIdent.empty()) sRet += "!" + m_sIdent;
        sRet += "@" + m_sHost;
    }

    return sRet;
}

NoString NoNick::GetHostMask() const
{
    NoString sRet = m_sNick;

    if (!m_sIdent.empty()) {
        sRet += "!" + m_sIdent;
    }

    if (!m_sHost.empty()) {
        sRet += "@" + m_sHost;
    }

    return (sRet);
}

void NoNick::Clone(const NoNick& SourceNick)
{
    SetNick(SourceNick.GetNick());
    SetIdent(SourceNick.GetIdent());
    SetHost(SourceNick.GetHost());

    m_sChanPerms = SourceNick.m_sChanPerms;
    m_pNetwork = SourceNick.m_pNetwork;
}
