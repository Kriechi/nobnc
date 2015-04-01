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

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
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
    void refuseLogin(const NoString& reason);

    NoString nick(bool allowIRCNick = true) const;
    NoString nickMask() const;
    NoString identifier() const;
    bool hasNamesX() const;
    bool hasUhNames() const;
    bool isAway() const;
    bool hasServerTime() const;
    bool hasBatch() const;
    bool hasSelfMessage() const;

    static bool isValidIdentifier(const NoString& identifier);

    void userCommand(NoString& line);
    void yserPortCommand(NoString& line);
    void statusCtcp(const NoString& command);
    void bouncedOff();
    bool isAttached() const;

    bool isPlaybackActive() const;
    void setPlaybackActive(bool active);

    void putIrc(const NoString& line);
    void putClient(const NoString& line);
    uint putStatus(const NoTable& table);
    void putStatus(const NoString& line);
    void putStatusNotice(const NoString& line);
    void putModule(const NoString& module, const NoString& line);
    void putModuleNotice(const NoString& module, const NoString& line);

    bool isCapEnabled(const NoString& cap) const;

    bool sendMotd();
    void helpUser(const NoString& filter = "");
    void authUser();

    void setNick(const NoString& s);
    void setAway(bool away);
    NoUser* user() const;
    void setNetwork(NoNetwork* network, bool bDisconnect = true, bool bReconnect = true);
    NoNetwork* network() const;
    std::vector<NoClient*> clients() const;
    NoIrcSocket* ircSocket() const;
    NoString fullName() const;

    void readLine(const NoString& data);

private:
    void handleCap(const NoString& line);
    void respondCap(const NoString& response);
    void parsePass(const NoString& line);
    void parseUser(const NoString& line);
    void parseIdentifier(const NoString& line);

private:
    NoClient(const NoClient&) = delete;
    NoClient& operator=(const NoClient&) = delete;
    std::unique_ptr<NoClientPrivate> d;
    friend class NoClientPrivate;
    friend class NoClientSocket;
    friend class ClientTest;
};

#endif // NOCLIENT_H
