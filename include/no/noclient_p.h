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

#ifndef NOCLIENT_P_H
#define NOCLIENT_P_H

#include "noclient.h"

class NoAuthenticator;

class NoClientPrivate
{
public:
    bool receivedPass = false;
    bool receivedNick = false;
    bool receivedUser = false;
    bool inCapLs = false;
    bool inPlayback = false;
    bool away = false;
    bool hasNamesX = false;
    bool hasUhNames = false;
    bool hasServerTime = false;
    bool hasBatch = false;
    bool hasSelfMessage = false;
    NoUser* user = nullptr;
    NoSocket* socket = nullptr;
    NoNetwork* network = nullptr;
    NoString nickname = "";
    NoString password = "";
    NoString username = "";
    NoString sNetwork = "";
    NoString identifier = "";
    std::shared_ptr<NoAuthenticator> authenticator;
    NoStringSet acceptedCaps;
};

#endif // NOCLIENT_P_H
