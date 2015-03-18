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

#ifndef NONICK_H
#define NONICK_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <vector>

class NoNetwork;
class NoChannel;

class NO_EXPORT NoNick
{
public:
    NoNick(const NoString& sNick = "");

    NoNick(const NoNick&) = default;
    NoNick& operator=(const NoNick&) = default;

    void Reset();
    void Parse(const NoString& sNickMask);
    NoString GetHostMask() const;
    size_t GetCommonChans(std::vector<NoChannel*>& vChans, NoNetwork* pNetwork) const;
    bool NickEquals(const NoString& nickname) const;

    void SetNetwork(NoNetwork* pNetwork);
    void SetNick(const NoString& s);
    void SetIdent(const NoString& s);
    void SetHost(const NoString& s);
    bool AddPerm(uchar uPerm);
    bool RemPerm(uchar uPerm);

    NoString GetPermStr() const;
    uchar GetPermChar() const;
    bool HasPerm(uchar uPerm) const;
    const NoString& GetNick() const;
    const NoString& GetIdent() const;
    const NoString& GetHost() const;
    NoString GetNickMask() const;

    void Clone(const NoNick& SourceNick);

private:
    NoString m_sChanPerms;
    NoNetwork* m_pNetwork;
    NoString m_sNick;
    NoString m_sIdent;
    NoString m_sHost;
};

#endif // NONICK_H
