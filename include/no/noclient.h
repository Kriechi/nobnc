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

    NoSocket* socket() const;

    void sendRequiredPasswordNotice();
    void acceptLogin(NoUser& User);
    void refuseLogin(const NoString& sReason);

    NoString nick(bool bAllowIRCNick = true) const;
    NoString nickMask() const;
    NoString identifier() const;
    bool hasNamesX() const;
    bool hasUhNames() const;
    bool isAway() const;
    bool hasServerTime() const;
    bool hasBatch() const;
    bool hasSelfMessage() const;

    static bool isValidIdentifier(const NoString& sIdentifier);

    void userCommand(NoString& sLine);
    void yserPortCommand(NoString& sLine);
    void statusCtcp(const NoString& sCommand);
    void bouncedOff();
    bool isAttached() const;

    bool isPlaybackActive() const;
    void setPlaybackActive(bool bActive);

    void putIrc(const NoString& sLine);
    void putClient(const NoString& sLine);
    uint putStatus(const NoTable& table);
    void putStatus(const NoString& sLine);
    void putStatusNotice(const NoString& sLine);
    void putModule(const NoString& sModule, const NoString& sLine);
    void putModuleNotice(const NoString& sModule, const NoString& sLine);

    bool isCapEnabled(const NoString& sCap) const;

    bool sendMotd();
    void helpUser(const NoString& sFilter = "");
    void authUser();

    void setNick(const NoString& s);
    void setAway(bool bAway);
    NoUser* user() const;
    void setNetwork(NoNetwork* pNetwork, bool bDisconnect = true, bool bReconnect = true);
    NoNetwork* network() const;
    std::vector<NoClient*> clients() const;
    NoIrcSocket* ircSocket() const;
    NoString fullName() const;

    void readLine(const NoString& sData);

private:
    void handleCap(const NoString& sLine);
    void respondCap(const NoString& sResponse);
    void parsePass(const NoString& sAuthLine);
    void parseUser(const NoString& sAuthLine);
    void parseIdentifier(const NoString& sAuthLine);

private:
    NoClient(const NoClient&) = delete;
    NoClient& operator=(const NoClient&) = delete;
    std::unique_ptr<NoClientPrivate> d;
    friend class NoClientPrivate;
    friend class NoClientSocket;
    friend class ClientTest;
};

#endif // NOCLIENT_H
