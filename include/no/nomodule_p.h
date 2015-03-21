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

#ifndef NOMODULE_P_H
#define NOMODULE_P_H

#include "nomodule.h"
#include "noapp.h"

class NoModulePrivate
{
public:
    NoModulePrivate(NoModuleHandle pDLL, NoUser* pUser, NoNetwork* pNetwork, const NoString& sModName, const NoString& sDataDir, No::ModuleType eType)
        : eType(eType), pDLL(pDLL), pManager(&NoApp::Get().GetManager()), pUser(pUser), pNetwork(pNetwork),
          pClient(nullptr), sModName(sModName), sDataDir(sDataDir) { }

    static NoModulePrivate* get(NoModule* module) { return module->d.get(); }

    void addTimer(NoTimer* timer) { sTimers.insert(timer); }
    void removeTimer(NoTimer* timer) { sTimers.erase(timer); }

    No::ModuleType eType;
    NoString sDescription;
    std::set<NoTimer*> sTimers;
    std::set<NoModuleSocket*> sSockets;
#ifdef HAVE_PTHREAD
    std::set<NoModuleJob*> sJobs;
#endif
    NoModuleHandle pDLL;
    NoSocketManager* pManager;
    NoUser* pUser;
    NoNetwork* pNetwork;
    NoClient* pClient;
    NoString sModName;
    NoString sDataDir;
    NoString sSavePath;
    NoString sArgs;
    NoString sModPath;

    VWebPages vSubPages;
    std::map<NoString, NoModuleCommand> mCommands;
};

#endif // NOMODULE_H
