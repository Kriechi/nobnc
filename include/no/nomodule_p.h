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

#ifndef NOMODULE_P_H
#define NOMODULE_P_H

#include "nomodule.h"
#include "noapp.h"

class NoModulePrivate
{
public:
    NoModulePrivate(NoModuleHandle pDLL, NoUser* pUser, NoNetwork* pNetwork, const NoString& sModName, const NoString& sDataDir, No::ModuleType eType)
        : type(eType),
          handle(pDLL),
          manager(noApp->manager()),
          user(pUser),
          network(pNetwork),
          client(nullptr),
          name(sModName),
          dataDir(sDataDir)
    {
    }

    static NoModulePrivate* get(NoModule* module)
    {
        return module->d.get();
    }

    void addTimer(NoTimer* timer)
    {
        timers.insert(timer);
    }
    void removeTimer(NoTimer* timer)
    {
        timers.erase(timer);
    }
    void addSocket(NoModuleSocket* socket)
    {
        sockets.insert(socket);
    }
    void removeSocket(NoModuleSocket* socket)
    {
        sockets.erase(socket);
    }

    No::ModuleType type;
    NoString description;
    std::set<NoTimer*> timers;
    std::set<NoModuleSocket*> sockets;
#ifdef HAVE_PTHREAD
    std::set<NoModuleJob*> jobs;
#endif
    NoModuleHandle handle;
    NoSocketManager* manager;
    NoUser* user;
    NoNetwork* network;
    NoClient* client;
    NoString name;
    NoString dataDir;
    NoString savePath;
    NoString args;
    NoString path;

    std::vector<std::shared_ptr<NoWebPage>> subPages;
    std::map<NoString, NoModuleCommand> commands;
};

#endif // NOMODULE_H
