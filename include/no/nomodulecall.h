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

#ifndef NOMAIN_H
#define NOMAIN_H

#include <no/noglobal.h>

extern bool ZNC_NO_NEED_TO_DO_ANYTHING_ON_MODULE_CALL_EXITER;
#define NOTHING &ZNC_NO_NEED_TO_DO_ANYTHING_ON_MODULE_CALL_EXITER

#define ALLMODULECALL(macFUNC, macEXITER)                                      \
    do {                                                                       \
        NoModuleLoader* GMods = NoApp::Get().GetLoader();                            \
        bool bAllExit = false;                                                 \
        if (GMods->macFUNC) {                                                   \
            bAllExit = true;                                                   \
        } else {                                                               \
            const std::map<NoString, NoUser*>& mUsers = NoApp::Get().GetUserMap();     \
            std::map<NoString, NoUser*>::const_iterator it;                           \
            for (it = mUsers.begin(); it != mUsers.end(); ++it) {              \
                NoModuleLoader* UMods = it->second->GetLoader();                    \
                if (UMods->macFUNC) {                                           \
                    bAllExit = true;                                           \
                    break;                                                     \
                }                                                              \
                const std::vector<NoNetwork*>& mNets = it->second->GetNetworks(); \
                std::vector<NoNetwork*>::const_iterator it2;                      \
                for (it2 = mNets.begin(); it2 != mNets.end(); ++it2) {         \
                    NoModuleLoader* NMods = (*it2)->GetLoader();                    \
                    if (NMods->macFUNC) {                                       \
                        bAllExit = true;                                       \
                        break;                                                 \
                    }                                                          \
                }                                                              \
                if (bAllExit) break;                                           \
            }                                                                  \
        }                                                                      \
        if (bAllExit) *macEXITER = true;                                       \
    } while (false)

#define _GLOBALMODULECALL(macFUNC, macUSER, macNETWORK, macCLIENT, macEXITER) \
    do {                                                                      \
        NoModuleLoader* GMods = NoApp::Get().GetLoader();                           \
        NoUser* pOldGUser = GMods->user();                                   \
        NoNetwork* pOldGNetwork = GMods->network();                       \
        NoClient* pOldGClient = GMods->client();                             \
        GMods->setUser(macUSER);                                               \
        GMods->setNetwork(macNETWORK);                                         \
        GMods->setClient(macCLIENT);                                           \
        if (GMods->macFUNC) {                                                  \
            GMods->setUser(pOldGUser);                                         \
            GMods->setNetwork(pOldGNetwork);                                   \
            GMods->setClient(pOldGClient);                                     \
            *macEXITER = true;                                                \
        }                                                                     \
        GMods->setUser(pOldGUser);                                             \
        GMods->setNetwork(pOldGNetwork);                                       \
        GMods->setClient(pOldGClient);                                         \
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
            NoModuleLoader* UMods = macUSER->GetLoader();                                \
            NoNetwork* pOldUNetwork = UMods->network();                         \
            NoClient* pOldUClient = UMods->client();                               \
            UMods->setNetwork(macNETWORK);                                           \
            UMods->setClient(macCLIENT);                                             \
            if (UMods->macFUNC) {                                                    \
                UMods->setNetwork(pOldUNetwork);                                     \
                UMods->setClient(pOldUClient);                                       \
                *macEXITER = true;                                                  \
            }                                                                       \
            UMods->setNetwork(pOldUNetwork);                                         \
            UMods->setClient(pOldUClient);                                           \
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
            NoModuleLoader* NMods = macNETWORK->GetLoader();                         \
            NoClient* pOldNClient = NMods->client();                           \
            NMods->setClient(macCLIENT);                                         \
            if (NMods->macFUNC) {                                                \
                NMods->setClient(pOldNClient);                                   \
                *macEXITER = true;                                              \
            }                                                                   \
            NMods->setClient(pOldNClient);                                       \
        }                                                                       \
    } while (false)

#define GLOBALMODULECALL(macFUNC, macEXITER) _GLOBALMODULECALL(macFUNC, nullptr, nullptr, nullptr, macEXITER)

#define USERMODULECALL(macFUNC, macUSER, macCLIENT, macEXITER) \
    _USERMODULECALL(macFUNC, macUSER, nullptr, macCLIENT, macEXITER)

/** @mainpage
 *  Welcome to the API documentation for ZNC.
 *
 *  To write your own module, you should start with writing a new class which
 *  inherits from NoModule. Use #MODCONSTRUCTOR for the module's constructor and
 *  call #MODULEDEFS at the end of your source file.
 *  Congratulations, you just wrote your first module. <br>
 *  For global modules, the procedure is similar. Instead of #MODULEDEFS call
 *  #GLOBALMODULEDEFS.
 *
 *  If you want your module to actually do something, you should override some
 *  of the hooks from NoModule. These are the functions whose names start with
 *  "On". They are called when the associated event happens.
 *
 *  Feel free to also look at existing modules.
 */

#endif // NOMAIN_H
