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

extern bool ZNC_NO_NEED_TO_DO_ANYTHING_ON_MODULE_CALL_EXITER;
#define NOTHING &ZNC_NO_NEED_TO_DO_ANYTHING_ON_MODULE_CALL_EXITER

#define ALLMODULECALL(macFUNC, macEXITER)                                          \
    do {                                                                           \
        NoModuleLoader* GMods = noApp->loader();                          \
        bool bAllExit = false;                                                     \
        if (GMods->macFUNC) {                                                      \
            bAllExit = true;                                                       \
        } else {                                                                   \
            const std::map<NoString, NoUser*>& mUsers = noApp->userMap(); \
            std::map<NoString, NoUser*>::const_iterator it;                        \
            for (it = mUsers.begin(); it != mUsers.end(); ++it) {                  \
                NoModuleLoader* UMods = it->second->loader();                      \
                if (UMods->macFUNC) {                                              \
                    bAllExit = true;                                               \
                    break;                                                         \
                }                                                                  \
                const std::vector<NoNetwork*>& mNets = it->second->networks();     \
                std::vector<NoNetwork*>::const_iterator it2;                       \
                for (it2 = mNets.begin(); it2 != mNets.end(); ++it2) {             \
                    NoModuleLoader* NMods = (*it2)->loader();                      \
                    if (NMods->macFUNC) {                                          \
                        bAllExit = true;                                           \
                        break;                                                     \
                    }                                                              \
                }                                                                  \
                if (bAllExit)                                                      \
                    break;                                                         \
            }                                                                      \
        }                                                                          \
        if (bAllExit)                                                              \
            *macEXITER = true;                                                     \
    } while (false)

#define _GLOBALMODULECALL(macFUNC, macUSER, macNETWORK, macCLIENT, macEXITER) \
    do {                                                                      \
        NoModuleLoader* GMods = noApp->loader();                     \
        NoUser* pOldGUser = GMods->user();                                    \
        NoNetwork* pOldGNetwork = GMods->network();                           \
        NoClient* pOldGClient = GMods->client();                              \
        GMods->setUser(macUSER);                                              \
        GMods->setNetwork(macNETWORK);                                        \
        GMods->setClient(macCLIENT);                                          \
        if (GMods->macFUNC) {                                                 \
            GMods->setUser(pOldGUser);                                        \
            GMods->setNetwork(pOldGNetwork);                                  \
            GMods->setClient(pOldGClient);                                    \
            *macEXITER = true;                                                \
        }                                                                     \
        GMods->setUser(pOldGUser);                                            \
        GMods->setNetwork(pOldGNetwork);                                      \
        GMods->setClient(pOldGClient);                                        \
    } while (false)

#define _USERMODULECALL(macFUNC, macUSER, macNETWORK, macCLIENT, macEXITER)         \
    do {                                                                            \
        bool bGlobalExited = false;                                                 \
        _GLOBALMODULECALL(macFUNC, macUSER, macNETWORK, macCLIENT, &bGlobalExited); \
        if (bGlobalExited) {                                                        \
            *macEXITER = true;                                                      \
            break;                                                                  \
        }                                                                           \
        if (macUSER != nullptr) {                                                   \
            NoModuleLoader* UMods = macUSER->loader();                              \
            NoNetwork* pOldUNetwork = UMods->network();                             \
            NoClient* pOldUClient = UMods->client();                                \
            UMods->setNetwork(macNETWORK);                                          \
            UMods->setClient(macCLIENT);                                            \
            if (UMods->macFUNC) {                                                   \
                UMods->setNetwork(pOldUNetwork);                                    \
                UMods->setClient(pOldUClient);                                      \
                *macEXITER = true;                                                  \
            }                                                                       \
            UMods->setNetwork(pOldUNetwork);                                        \
            UMods->setClient(pOldUClient);                                          \
        }                                                                           \
    } while (false)

#define NETWORKMODULECALL(macFUNC, macUSER, macNETWORK, macCLIENT, macEXITER)   \
    do {                                                                        \
        bool bUserExited = false;                                               \
        _USERMODULECALL(macFUNC, macUSER, macNETWORK, macCLIENT, &bUserExited); \
        if (bUserExited) {                                                      \
            *macEXITER = true;                                                  \
            break;                                                              \
        }                                                                       \
        if (macNETWORK != nullptr) {                                            \
            NoModuleLoader* NMods = macNETWORK->loader();                       \
            NoClient* pOldNClient = NMods->client();                            \
            NMods->setClient(macCLIENT);                                        \
            if (NMods->macFUNC) {                                               \
                NMods->setClient(pOldNClient);                                  \
                *macEXITER = true;                                              \
            }                                                                   \
            NMods->setClient(pOldNClient);                                      \
        }                                                                       \
    } while (false)

#define GLOBALMODULECALL(macFUNC, macEXITER) _GLOBALMODULECALL(macFUNC, nullptr, nullptr, nullptr, macEXITER)

#define USERMODULECALL(macFUNC, macUSER, macCLIENT, macEXITER) \
    _USERMODULECALL(macFUNC, macUSER, nullptr, macCLIENT, macEXITER)

class NoModulePrivate
{
public:
    NoModulePrivate(NoModuleHandle pDLL, NoUser* user, NoNetwork* network, const NoString& name, const NoString& dataDir, No::ModuleType type)
        : type(type),
          handle(pDLL),
          manager(noApp->manager()),
          user(user),
          network(network),
          client(nullptr),
          name(name),
          dataDir(dataDir)
    {
    }

    static NoModulePrivate* get(NoModule* module)
    {
        return module->d.get();
    }

    static double buildVersion();

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
