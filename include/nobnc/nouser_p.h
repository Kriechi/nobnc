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

#ifndef NOUSER_P_H
#define NOUSER_P_H

#include "nouser.h"

class NoUserTimer;

class NoUserPrivate
{
public:
    static NoUserPrivate* get(NoUser* user)
    {
        return user->d.get();
    }

    void addBytesRead(ulonglong bytes);
    void addBytesWritten(ulonglong bytes);

    void bounceAllClients();
    bool loadModule(const NoString& name, const NoString& args, const NoString& notice, NoString& error);

    NoUser* q;

    NoString userName = "";
    NoString cleanUserName = "";
    NoString nickName = "";
    NoString altNick = "";
    NoString ident = "";
    NoString realName = "";
    NoString bindHost = "";
    NoString dccBindHost = "";
    NoString password = "";
    NoString passwordSalt = "";
    NoString statusPrefix = "*";
    NoString defaultChanModes = "";
    NoString clientEncoding = "";

    NoString quitMessage = "";
    NoStringMap ctcpReplies;
    NoString timestampFormat = "[%H:%M:%S]";
    NoString timezone = "";

    NoString userPath = "";

    bool multiClients = true;
    bool denyLoadMod = false;
    bool admin = false;
    bool denysetBindHost = false;
    bool autoClearChanBuffer = true;
    bool autoClearQueryBuffer = true;
    bool beingDeleted = false;
    bool appendTimestamp = false;
    bool prependTimestamp = true;

    NoUserTimer* userTimer = nullptr;

    std::vector<NoNetwork*> networks;
    std::vector<NoClient*> clients;
    std::set<NoString> allowedHosts;
    uint bufferCount = 50;
    ulonglong bytesRead = 0;
    ulonglong bytesWritten = 0;
    uint maxJoinTries = 10;
    uint maxNetworks = 1;
    uint maxQueryBuffers = 50;
    uint maxJoins = 0;
    NoString skinName = "";

    NoModuleLoader* loader = nullptr;
};

#endif // NOUSER_P_H
