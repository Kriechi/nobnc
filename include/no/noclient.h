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

#ifndef NOCLIENT_H
#define NOCLIENT_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <memory>

class NoUser;
class NoTable;
class NoSocket;
class NoNetwork;
class NoIrcSocket;
class NoClientPrivate;

class NO_EXPORT NoClient
{
public:
    NoClient();
    ~NoClient();

    NoSocket* GetSocket() const;

    void SendRequiredPasswordNotice();
    void AcceptLogin(NoUser& User);
    void RefuseLogin(const NoString& sReason);

    NoString GetNick(bool bAllowIRCNick = true) const;
    NoString GetNickMask() const;
    NoString GetIdentifier() const;
    bool HasNamesx() const;
    bool HasUHNames() const;
    bool IsAway() const;
    bool HasServerTime() const;
    bool HasBatch() const;
    bool HasSelfMessage() const;

    static bool IsValidIdentifier(const NoString& sIdentifier);

    void UserCommand(NoString& sLine);
    void UserPortCommand(NoString& sLine);
    void StatusCTCP(const NoString& sCommand);
    void BouncedOff();
    bool IsAttached() const;

    bool IsPlaybackActive() const;
    void SetPlaybackActive(bool bActive);

    void putIrc(const NoString& sLine);
    void PutClient(const NoString& sLine);
    uint putStatus(const NoTable& table);
    void putStatus(const NoString& sLine);
    void putStatusNotice(const NoString& sLine);
    void putModule(const NoString& sModule, const NoString& sLine);
    void putModuleNotice(const NoString& sModule, const NoString& sLine);

    bool IsCapEnabled(const NoString& sCap) const;

    bool SendMotd();
    void HelpUser(const NoString& sFilter = "");
    void AuthUser();

    void SetNick(const NoString& s);
    void SetAway(bool bAway);
    NoUser* user() const;
    void SetNetwork(NoNetwork* pNetwork, bool bDisconnect = true, bool bReconnect = true);
    NoNetwork* network() const;
    std::vector<NoClient*> clients() const;
    NoIrcSocket* ircSocket() const;
    NoString GetFullName() const;

    void ReadLine(const NoString& sData);

private:
    void HandleCap(const NoString& sLine);
    void RespondCap(const NoString& sResponse);
    void ParsePass(const NoString& sAuthLine);
    void ParseUser(const NoString& sAuthLine);
    void ParseIdentifier(const NoString& sAuthLine);

private:
    NoClient(const NoClient&) = delete;
    NoClient& operator=(const NoClient&) = delete;
    std::unique_ptr<NoClientPrivate> d;
    friend class NoClientPrivate;
    friend class NoClientSocket;
    friend class ClientTest;
};

#endif // NOCLIENT_H
