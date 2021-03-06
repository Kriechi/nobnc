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

#ifndef NOAPP_P_H
#define NOAPP_P_H

#include "noapp.h"
#include "nosocketmanager_p.h"
#include <list>

class NoAppPrivate
{
public:
    static NoAppPrivate* get(NoApp* app)
    {
        return app->d.get();
    }

    static NoApp* instance;

    NoString expandConfigPath(const NoString& configFile, bool allowMkDir = true);
    void backupConfigOnce(const NoString& suffix);

    void enableConnectQueue();
    void disableConnectQueue();

    // Never call this unless you are NoConnectQueueTimer::~NoConnectQueueTimer()
    void leakConnectQueueTimer(NoConnectQueueTimer* timer);

    bool doRehash(NoString& error);
    // Returns true if something was done
    bool handleUserDeletion();
    NoString makeConfigHeader();
    bool addListener(const NoString& line, NoString& error);
    bool addListener(NoSettings* settings, NoString& error);

    void addBytesRead(ulonglong bytes);
    void addBytesWritten(ulonglong bytes);

    time_t startTime;

    NoApp::ConfigState configState = NoApp::ConfigNothing;
    std::vector<NoListener*> listeners;
    std::map<NoString, NoUser*> users;
    std::map<NoString, NoUser*> delUsers;
    NoSocketManager manager;

    NoString curPath;
    NoString appPath;

    NoString configFile;
    NoString skinName;
    NoString statusPrefix;
    NoString sslCertFile;
    NoString sslCiphers;
    NoString sslProtocols;
    NoStringVector bindHosts;
    NoStringVector trustedProxies;
    NoStringVector motd;
    NoFile* lockFile = nullptr;
    uint connectDelay = 5;
    uint anonIpLimit = 10;
    uint maxBufferSize = 500;
    uint disabledSslProtocols = 0;
    NoModuleLoader* loader = nullptr;
    ulonglong bytesRead = 0;
    ulonglong bytesWritten = 0;
    std::list<NoNetwork*> connectQueue;
    NoConnectQueueTimer* connectQueueTimer = nullptr;
    uint connectPaused = 0;
    NoCacheMap<NoString> connectThrottle;
    bool hideVersion = false;
};

#endif // NOAPP_P_H
