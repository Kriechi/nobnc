/*
 * Copyright (C) 2015 NoBNC
 * Copyright (C) 2004-2015 ZNC, see the NOTICE file for details.
 * Copyright (C) 2008 by Stefan Rado
 * based on admin.cpp by Sebastian Ramacher
 * based on admin.cpp in crox branch
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

#include <no/nomodule.h>
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/nochannel.h>
#include <no/noircsocket.h>
#include <no/noapp.h>
#include <no/nonick.h>

template <std::size_t N>
struct array_size_helper
{
    char __place_holder[N];
};

template <class T, std::size_t N>
static array_size_helper<N> array_size(T (&)[N])
{
    return array_size_helper<N>();
}

#define ARRAY_SIZE(array) sizeof(array_size((array)))

class NoAdminMod : public NoModule
{
    using NoModule::putModule;

    void PrintVarsHelp(const NoString& sFilter, const char* vars[][2], uint uSize, const NoString& sDescription)
    {
        NoTable VarTable;
        VarTable.addColumn("Type");
        VarTable.addColumn("Variables");
        std::map<const char*, NoStringVector> mvsTypedVariables;
        for (uint i = 0; i != uSize; ++i) {
            NoString sVar = NoString(vars[i][0]).toLower();
            if (sFilter.empty() || sVar.startsWith(sFilter) || No::wildCmp(sVar, sFilter)) {
                mvsTypedVariables[vars[i][1]].emplace_back(vars[i][0]);
            }
        }
        for (const auto& i : mvsTypedVariables) {
            VarTable.addRow();
            VarTable.setValue("Type", i.first);
            VarTable.setValue("Variables", NoString(", ").join(i.second.cbegin(), i.second.cend()));
        }
        if (!VarTable.isEmpty()) {
            putModule(sDescription);
            putModule(VarTable);
        }
    }

    void PrintHelp(const NoString& sLine)
    {
        handleHelpCommand(sLine);

        static const char* str = "String";
        static const char* boolean = "Boolean (true/false)";
        static const char* integer = "Integer";
        static const char* doublenum = "Double";

        const NoString sCmdFilter = No::token(sLine, 1);
        const NoString sVarFilter = No::tokens(sLine, 2).toLower();

        if (sCmdFilter.empty() || sCmdFilter.startsWith("Set") || sCmdFilter.startsWith("Get")) {
            static const char* vars[][2] = {
                { "Nick", str },
                { "Altnick", str },
                { "Ident", str },
                { "RealName", str },
                { "BindHost", str },
                { "MultiClients", boolean },
                { "DenyLoadMod", boolean },
                { "DenysetBindHost", boolean },
                { "DefaultChanModes", str },
                { "QuitMsg", str },
                { "BufferCount", integer },
                { "AutoClearChanBuffer", boolean },
                { "autoclearQueryBuffer", boolean },
                { "Password", str },
                { "JoinTries", integer },
                { "MaxJoins", integer },
                { "MaxNetworks", integer },
                { "MaxQueryBuffers", integer },
                { "Timezone", str },
                { "Admin", boolean },
                { "AppendTimestamp", boolean },
                { "PrependTimestamp", boolean },
                { "TimestampFormat", str },
                { "DCCBindHost", str },
                { "StatusPrefix", str },
#ifdef HAVE_ICU
                { "ClientEncoding", str },
#endif
            };
            PrintVarsHelp(sVarFilter,
                          vars,
                          ARRAY_SIZE(vars),
                          "The following variables are available when using the Set/Get commands:");
        }

        if (sCmdFilter.empty() || sCmdFilter.startsWith("SetNetwork") || sCmdFilter.startsWith("GetNetwork")) {
            static const char* nvars[][2] = {
                { "Nick", str },
                { "Altnick", str },
                { "Ident", str },
                { "RealName", str },
                { "BindHost", str },
                { "FloodRate", doublenum },
                { "FloodBurst", integer },
                { "JoinDelay", integer },
#ifdef HAVE_ICU
                { "Encoding", str },
#endif
                { "QuitMsg", str },
            };
            PrintVarsHelp(sVarFilter,
                          nvars,
                          ARRAY_SIZE(nvars),
                          "The following variables are available when using the SetNetwork/GetNetwork commands:");
        }

        if (sCmdFilter.empty() || sCmdFilter.startsWith("SetChan") || sCmdFilter.startsWith("GetChan")) {
            static const char* cvars[][2] = { { "DefModes", str },
                                              { "Key", str },
                                              { "Buffer", integer },
                                              { "InConfig", boolean },
                                              { "AutoClearChanBuffer", boolean },
                                              { "Detached", boolean } };
            PrintVarsHelp(sVarFilter,
                          cvars,
                          ARRAY_SIZE(cvars),
                          "The following variables are available when using the SetChan/GetChan commands:");
        }

        if (sCmdFilter.empty())
            putModule("You can use $user as the user name and $network as the network name for modifying your own "
                      "user and network.");
    }

    NoUser* FindUser(const NoString& sUsername)
    {
        if (sUsername.equals("$me") || sUsername.equals("$user"))
            return user();
        NoUser* pUser = NoApp::Get().FindUser(sUsername);
        if (!pUser) {
            putModule("Error: User [" + sUsername + "] not found.");
            return nullptr;
        }
        if (pUser != user() && !user()->isAdmin()) {
            putModule("Error: You need to have admin rights to modify other users!");
            return nullptr;
        }
        return pUser;
    }

    NoNetwork* FindNetwork(NoUser* pUser, const NoString& sNetwork)
    {
        if (sNetwork.equals("$net") || sNetwork.equals("$network")) {
            if (pUser != user()) {
                putModule("Error: You cannot use " + sNetwork + " to modify other users!");
                return nullptr;
            }
            return NoModule::network();
        }
        NoNetwork* pNetwork = pUser->findNetwork(sNetwork);
        if (!pNetwork) {
            putModule("Error: [" + pUser->userName() + "] does not have a network named [" + sNetwork + "].");
        }
        return pNetwork;
    }

    void Get(const NoString& sLine)
    {
        const NoString sVar = No::token(sLine, 1).toLower();
        NoString sUsername = No::tokens(sLine, 2);
        NoUser* pUser;

        if (sVar.empty()) {
            putModule("Usage: Get <variable> [username]");
            return;
        }

        if (sUsername.empty()) {
            pUser = user();
        } else {
            pUser = FindUser(sUsername);
        }

        if (!pUser)
            return;

        if (sVar == "nick")
            putModule("Nick = " + pUser->nick());
        else if (sVar == "altnick")
            putModule("AltNick = " + pUser->altNick());
        else if (sVar == "ident")
            putModule("Ident = " + pUser->ident());
        else if (sVar == "realname")
            putModule("RealName = " + pUser->realName());
        else if (sVar == "bindhost")
            putModule("BindHost = " + pUser->bindHost());
        else if (sVar == "multiclients")
            putModule("MultiClients = " + NoString(pUser->multiClients()));
        else if (sVar == "denyloadmod")
            putModule("DenyLoadMod = " + NoString(pUser->denyLoadMod()));
        else if (sVar == "denysetbindhost")
            putModule("DenysetBindHost = " + NoString(pUser->denysetBindHost()));
        else if (sVar == "defaultchanmodes")
            putModule("DefaultChanModes = " + pUser->defaultChanModes());
        else if (sVar == "quitmsg")
            putModule("QuitMsg = " + pUser->quitMsg());
        else if (sVar == "buffercount")
            putModule("BufferCount = " + NoString(pUser->bufferCount()));
        else if (sVar == "keepbuffer")
            putModule("KeepBuffer = " +
                      NoString(!pUser->autoClearChanBuffer())); // XXX compatibility crap, added in 0.207
        else if (sVar == "autoclearchanbuffer")
            putModule("AutoClearChanBuffer = " + NoString(pUser->autoClearChanBuffer()));
        else if (sVar == "autoclearquerybuffer")
            putModule("autoclearQueryBuffer = " + NoString(pUser->autoclearQueryBuffer()));
        else if (sVar == "maxjoins")
            putModule("MaxJoins = " + NoString(pUser->maxJoins()));
        else if (sVar == "maxnetworks")
            putModule("MaxNetworks = " + NoString(pUser->maxNetworks()));
        else if (sVar == "maxquerybuffers")
            putModule("MaxQueryBuffers = " + NoString(pUser->maxQueryBuffers()));
        else if (sVar == "jointries")
            putModule("JoinTries = " + NoString(pUser->joinTries()));
        else if (sVar == "timezone")
            putModule("Timezone = " + pUser->timezone());
        else if (sVar == "appendtimestamp")
            putModule("AppendTimestamp = " + NoString(pUser->timestampAppend()));
        else if (sVar == "prependtimestamp")
            putModule("PrependTimestamp = " + NoString(pUser->timestampPrepend()));
        else if (sVar == "timestampformat")
            putModule("TimestampFormat = " + pUser->timestampFormat());
        else if (sVar == "dccbindhost")
            putModule("DCCBindHost = " + NoString(pUser->dccBindHost()));
        else if (sVar == "admin")
            putModule("Admin = " + NoString(pUser->isAdmin()));
        else if (sVar == "statusprefix")
            putModule("StatusPrefix = " + pUser->statusPrefix());
#ifdef HAVE_ICU
        else if (sVar == "clientencoding")
            putModule("ClientEncoding = " + pUser->clientEncoding());
#endif
        else
            putModule("Error: Unknown variable");
    }

    void Set(const NoString& sLine)
    {
        const NoString sVar = No::token(sLine, 1).toLower();
        NoString sUserName = No::token(sLine, 2);
        NoString sValue = No::tokens(sLine, 3);

        if (sValue.empty()) {
            putModule("Usage: Set <variable> <username> <value>");
            return;
        }

        NoUser* pUser = FindUser(sUserName);
        if (!pUser)
            return;

        if (sVar == "nick") {
            pUser->setNick(sValue);
            putModule("Nick = " + sValue);
        } else if (sVar == "altnick") {
            pUser->setAltNick(sValue);
            putModule("AltNick = " + sValue);
        } else if (sVar == "ident") {
            pUser->setIdent(sValue);
            putModule("Ident = " + sValue);
        } else if (sVar == "realname") {
            pUser->setRealName(sValue);
            putModule("RealName = " + sValue);
        } else if (sVar == "bindhost") {
            if (!pUser->denysetBindHost() || user()->isAdmin()) {
                if (sValue.equals(user()->bindHost())) {
                    putModule("This bind host is already set!");
                    return;
                }

                const NoStringVector& vsHosts = NoApp::Get().bindHosts();
                if (!user()->isAdmin() && !vsHosts.empty()) {
                    NoStringVector::const_iterator it;
                    bool bFound = false;

                    for (it = vsHosts.begin(); it != vsHosts.end(); ++it) {
                        if (sValue.equals(*it)) {
                            bFound = true;
                            break;
                        }
                    }

                    if (!bFound) {
                        putModule("You may not use this bind host. See /msg " + user()->statusPrefix() +
                                  "status ListBindHosts for a list");
                        return;
                    }
                }

                pUser->setBindHost(sValue);
                putModule("BindHost = " + sValue);
            } else {
                putModule("Access denied!");
            }
        } else if (sVar == "multiclients") {
            bool b = sValue.toBool();
            pUser->setMultiClients(b);
            putModule("MultiClients = " + NoString(b));
        } else if (sVar == "denyloadmod") {
            if (user()->isAdmin()) {
                bool b = sValue.toBool();
                pUser->setDenyLoadMod(b);
                putModule("DenyLoadMod = " + NoString(b));
            } else {
                putModule("Access denied!");
            }
        } else if (sVar == "denysetbindhost") {
            if (user()->isAdmin()) {
                bool b = sValue.toBool();
                pUser->setDenysetBindHost(b);
                putModule("DenysetBindHost = " + NoString(b));
            } else {
                putModule("Access denied!");
            }
        } else if (sVar == "defaultchanmodes") {
            pUser->setDefaultChanModes(sValue);
            putModule("DefaultChanModes = " + sValue);
        } else if (sVar == "quitmsg") {
            pUser->setQuitMsg(sValue);
            putModule("QuitMsg = " + sValue);
        } else if (sVar == "buffercount") {
            uint i = sValue.toUInt();
            // Admins don't have to honour the buffer limit
            if (pUser->setBufferCount(i, user()->isAdmin())) {
                putModule("BufferCount = " + sValue);
            } else {
                putModule("Setting failed, limit is " + NoString(NoApp::Get().GetMaxBufferSize()));
            }
        } else if (sVar == "keepbuffer") { // XXX compatibility crap, added in 0.207
            bool b = !sValue.toBool();
            pUser->setAutoClearChanBuffer(b);
            putModule("AutoClearChanBuffer = " + NoString(b));
        } else if (sVar == "autoclearchanbuffer") {
            bool b = sValue.toBool();
            pUser->setAutoClearChanBuffer(b);
            putModule("AutoClearChanBuffer = " + NoString(b));
        } else if (sVar == "autoclearquerybuffer") {
            bool b = sValue.toBool();
            pUser->setAutoclearQueryBuffer(b);
            putModule("autoclearQueryBuffer = " + NoString(b));
        } else if (sVar == "password") {
            const NoString sSalt = No::salt();
            const NoString sHash = NoUser::saltedHash(sValue, sSalt);
            pUser->setPassword(sHash, NoUser::HashDefault, sSalt);
            putModule("Password has been changed!");
        } else if (sVar == "maxjoins") {
            uint i = sValue.toUInt();
            pUser->setMaxJoins(i);
            putModule("MaxJoins = " + NoString(pUser->maxJoins()));
        } else if (sVar == "maxnetworks") {
            if (user()->isAdmin()) {
                uint i = sValue.toUInt();
                pUser->setMaxNetworks(i);
                putModule("MaxNetworks = " + sValue);
            } else {
                putModule("Access denied!");
            }
        } else if (sVar == "maxquerybuffers") {
            uint i = sValue.toUInt();
            pUser->setMaxQueryBuffers(i);
            putModule("MaxQueryBuffers = " + sValue);
        } else if (sVar == "jointries") {
            uint i = sValue.toUInt();
            pUser->setJoinTries(i);
            putModule("JoinTries = " + NoString(pUser->joinTries()));
        } else if (sVar == "timezone") {
            pUser->setTimezone(sValue);
            putModule("Timezone = " + pUser->timezone());
        } else if (sVar == "admin") {
            if (user()->isAdmin() && pUser != user()) {
                bool b = sValue.toBool();
                pUser->setAdmin(b);
                putModule("Admin = " + NoString(pUser->isAdmin()));
            } else {
                putModule("Access denied!");
            }
        } else if (sVar == "prependtimestamp") {
            bool b = sValue.toBool();
            pUser->setTimestampPrepend(b);
            putModule("PrependTimestamp = " + NoString(b));
        } else if (sVar == "appendtimestamp") {
            bool b = sValue.toBool();
            pUser->setTimestampAppend(b);
            putModule("AppendTimestamp = " + NoString(b));
        } else if (sVar == "timestampformat") {
            pUser->setTimestampFormat(sValue);
            putModule("TimestampFormat = " + sValue);
        } else if (sVar == "dccbindhost") {
            if (!pUser->denysetBindHost() || user()->isAdmin()) {
                pUser->setDccBindHost(sValue);
                putModule("DCCBindHost = " + sValue);
            } else {
                putModule("Access denied!");
            }
        } else if (sVar == "statusprefix") {
            if (sVar.find_first_of(" \t\n") == NoString::npos) {
                pUser->setStatusPrefix(sValue);
                putModule("StatusPrefix = " + sValue);
            } else {
                putModule("That would be a bad idea!");
            }
        }
#ifdef HAVE_ICU
        else if (sVar == "clientencoding") {
            pUser->setClientEncoding(sValue);
            putModule("ClientEncoding = " + sValue);
        }
#endif
        else
            putModule("Error: Unknown variable");
    }

    void GetNetwork(const NoString& sLine)
    {
        const NoString sVar = No::token(sLine, 1).toLower();
        const NoString sUsername = No::token(sLine, 2);
        const NoString sNetwork = No::token(sLine, 3);

        NoNetwork* pNetwork = nullptr;

        if (sUsername.empty()) {
            pNetwork = NoModule::network();
        } else {
            NoUser* pUser = FindUser(sUsername);
            if (!pUser) {
                return;
            }

            pNetwork = FindNetwork(pUser, sNetwork);
            if (!pNetwork && !sNetwork.empty()) {
                return;
            }
        }

        if (!pNetwork) {
            putModule("Usage: GetNetwork <variable> <username> <network>");
            return;
        }

        if (sVar.equals("nick")) {
            putModule("Nick = " + pNetwork->nick());
        } else if (sVar.equals("altnick")) {
            putModule("AltNick = " + pNetwork->altNick());
        } else if (sVar.equals("ident")) {
            putModule("Ident = " + pNetwork->ident());
        } else if (sVar.equals("realname")) {
            putModule("RealName = " + pNetwork->realName());
        } else if (sVar.equals("bindhost")) {
            putModule("BindHost = " + pNetwork->bindHost());
        } else if (sVar.equals("floodrate")) {
            putModule("FloodRate = " + NoString(pNetwork->floodRate()));
        } else if (sVar.equals("floodburst")) {
            putModule("FloodBurst = " + NoString(pNetwork->floodBurst()));
        } else if (sVar.equals("joindelay")) {
            putModule("JoinDelay = " + NoString(pNetwork->joinDelay()));
#ifdef HAVE_ICU
        } else if (sVar.equals("encoding")) {
            putModule("Encoding = " + pNetwork->encoding());
#endif
        } else if (sVar.equals("quitmsg")) {
            putModule("QuitMsg = " + pNetwork->quitMsg());
        } else {
            putModule("Error: Unknown variable");
        }
    }

    void SetNetwork(const NoString& sLine)
    {
        const NoString sVar = No::token(sLine, 1).toLower();
        const NoString sUsername = No::token(sLine, 2);
        const NoString sNetwork = No::token(sLine, 3);
        const NoString sValue = No::tokens(sLine, 4);

        NoUser* pUser = nullptr;
        NoNetwork* pNetwork = nullptr;

        if (sUsername.empty()) {
            pUser = user();
            pNetwork = NoModule::network();
        } else {
            pUser = FindUser(sUsername);
            if (!pUser) {
                return;
            }

            pNetwork = FindNetwork(pUser, sNetwork);
            if (!pNetwork && !sNetwork.empty()) {
                return;
            }
        }

        if (!pNetwork) {
            putModule("Usage: SetNetwork <variable> <username> <network> <value>");
            return;
        }

        if (sVar.equals("nick")) {
            pNetwork->setNick(sValue);
            putModule("Nick = " + pNetwork->nick());
        } else if (sVar.equals("altnick")) {
            pNetwork->setAltNick(sValue);
            putModule("AltNick = " + pNetwork->altNick());
        } else if (sVar.equals("ident")) {
            pNetwork->setIdent(sValue);
            putModule("Ident = " + pNetwork->ident());
        } else if (sVar.equals("realname")) {
            pNetwork->setRealName(sValue);
            putModule("RealName = " + pNetwork->realName());
        } else if (sVar.equals("bindhost")) {
            if (!pUser->denysetBindHost() || user()->isAdmin()) {
                if (sValue.equals(pNetwork->bindHost())) {
                    putModule("This bind host is already set!");
                    return;
                }

                const NoStringVector& vsHosts = NoApp::Get().bindHosts();
                if (!user()->isAdmin() && !vsHosts.empty()) {
                    NoStringVector::const_iterator it;
                    bool bFound = false;

                    for (it = vsHosts.begin(); it != vsHosts.end(); ++it) {
                        if (sValue.equals(*it)) {
                            bFound = true;
                            break;
                        }
                    }

                    if (!bFound) {
                        putModule("You may not use this bind host. See /msg " + user()->statusPrefix() +
                                  "status ListBindHosts for a list");
                        return;
                    }
                }

                pNetwork->setBindHost(sValue);
                putModule("BindHost = " + sValue);
            } else {
                putModule("Access denied!");
            }
        } else if (sVar.equals("floodrate")) {
            pNetwork->setFloodRate(sValue.toDouble());
            putModule("FloodRate = " + NoString(pNetwork->floodRate()));
        } else if (sVar.equals("floodburst")) {
            pNetwork->setFloodBurst(sValue.toUShort());
            putModule("FloodBurst = " + NoString(pNetwork->floodBurst()));
        } else if (sVar.equals("joindelay")) {
            pNetwork->setJoinDelay(sValue.toUShort());
            putModule("JoinDelay = " + NoString(pNetwork->joinDelay()));
#ifdef HAVE_ICU
        } else if (sVar.equals("encoding")) {
            pNetwork->setEncoding(sValue);
            putModule("Encoding = " + pNetwork->encoding());
#endif
        } else if (sVar.equals("quitmsg")) {
            pNetwork->setQuitMsg(sValue);
            putModule("QuitMsg = " + pNetwork->quitMsg());
        } else {
            putModule("Error: Unknown variable");
        }
    }

    void addChannel(const NoString& sLine)
    {
        const NoString sUsername = No::token(sLine, 1);
        const NoString sNetwork = No::token(sLine, 2);
        const NoString sChan = No::token(sLine, 3);

        if (sChan.empty()) {
            putModule("Usage: addChannel <username> <network> <channel>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser)
            return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        if (pNetwork->findChannel(sChan)) {
            putModule("Error: [" + sUsername + "] already has a channel named [" + sChan + "].");
            return;
        }

        NoChannel* pChan = new NoChannel(sChan, pNetwork, true);
        if (pNetwork->addChannel(pChan))
            putModule("Channel [" + pChan->name() + "] for user [" + sUsername + "] added.");
        else
            putModule("Could not add channel [" + sChan + "] for user [" + sUsername + "], does it already exist?");
    }

    void removeChannel(const NoString& sLine)
    {
        const NoString sUsername = No::token(sLine, 1);
        const NoString sNetwork = No::token(sLine, 2);
        const NoString sChan = No::token(sLine, 3);

        if (sChan.empty()) {
            putModule("Usage: removeChannel <username> <network> <channel>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser)
            return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        std::vector<NoChannel*> vChans = pNetwork->findChannels(sChan);
        if (vChans.empty()) {
            putModule("Error: User [" + sUsername + "] does not have any channel matching [" + sChan + "].");
            return;
        }

        NoStringVector vsNames;
        for (const NoChannel* pChan : vChans) {
            const NoString& sName = pChan->name();
            vsNames.push_back(sName);
            pNetwork->putIrc("PART " + sName);
            pNetwork->removeChannel(sName);
        }

        putModule("Channel(s) [" + NoString(",").join(vsNames.begin(), vsNames.end()) + "] for user [" + sUsername +
                  "] deleted.");
    }

    void GetChan(const NoString& sLine)
    {
        const NoString sVar = No::token(sLine, 1).toLower();
        NoString sUsername = No::token(sLine, 2);
        NoString sNetwork = No::token(sLine, 3);
        NoString sChan = No::tokens(sLine, 4);

        if (sChan.empty()) {
            putModule("Usage: GetChan <variable> <username> <network> <chan>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser)
            return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        std::vector<NoChannel*> vChans = pNetwork->findChannels(sChan);
        if (vChans.empty()) {
            putModule("Error: No channel(s) matching [" + sChan + "] found.");
            return;
        }

        for (NoChannel* pChan : vChans) {
            if (sVar == "defmodes") {
                putModule(pChan->name() + ": DefModes = " + pChan->defaultModes());
            } else if (sVar == "buffer") {
                NoString sValue(pChan->bufferCount());
                if (!pChan->hasBufferCountSet()) {
                    sValue += " (default)";
                }
                putModule(pChan->name() + ": Buffer = " + sValue);
            } else if (sVar == "inconfig") {
                putModule(pChan->name() + ": InConfig = " + NoString(pChan->inConfig()));
            } else if (sVar == "keepbuffer") {
                putModule(pChan->name() + ": KeepBuffer = " +
                          NoString(!pChan->autoClearChanBuffer())); // XXX compatibility crap, added in 0.207
            } else if (sVar == "autoclearchanbuffer") {
                NoString sValue(pChan->autoClearChanBuffer());
                if (!pChan->hasAutoClearChanBufferSet()) {
                    sValue += " (default)";
                }
                putModule(pChan->name() + ": AutoClearChanBuffer = " + sValue);
            } else if (sVar == "detached") {
                putModule(pChan->name() + ": Detached = " + NoString(pChan->isDetached()));
            } else if (sVar == "key") {
                putModule(pChan->name() + ": Key = " + pChan->key());
            } else {
                putModule("Error: Unknown variable");
                return;
            }
        }
    }

    void SetChan(const NoString& sLine)
    {
        const NoString sVar = No::token(sLine, 1).toLower();
        NoString sUsername = No::token(sLine, 2);
        NoString sNetwork = No::token(sLine, 3);
        NoString sChan = No::token(sLine, 4);
        NoString sValue = No::tokens(sLine, 5);

        if (sValue.empty()) {
            putModule("Usage: SetChan <variable> <username> <network> <chan> <value>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser)
            return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        std::vector<NoChannel*> vChans = pNetwork->findChannels(sChan);
        if (vChans.empty()) {
            putModule("Error: No channel(s) matching [" + sChan + "] found.");
            return;
        }

        for (NoChannel* pChan : vChans) {
            if (sVar == "defmodes") {
                pChan->setDefaultModes(sValue);
                putModule(pChan->name() + ": DefModes = " + sValue);
            } else if (sVar == "buffer") {
                uint i = sValue.toUInt();
                // Admins don't have to honour the buffer limit
                if (pChan->setBufferCount(i, user()->isAdmin())) {
                    putModule(pChan->name() + ": Buffer = " + sValue);
                } else {
                    putModule("Setting failed, limit is " + NoString(NoApp::Get().GetMaxBufferSize()));
                    return;
                }
            } else if (sVar == "inconfig") {
                bool b = sValue.toBool();
                pChan->setInConfig(b);
                putModule(pChan->name() + ": InConfig = " + NoString(b));
            } else if (sVar == "keepbuffer") { // XXX compatibility crap, added in 0.207
                bool b = !sValue.toBool();
                pChan->setAutoClearChanBuffer(b);
                putModule(pChan->name() + ": AutoClearChanBuffer = " + NoString(b));
            } else if (sVar == "autoclearchanbuffer") {
                bool b = sValue.toBool();
                pChan->setAutoClearChanBuffer(b);
                putModule(pChan->name() + ": AutoClearChanBuffer = " + NoString(b));
            } else if (sVar == "detached") {
                bool b = sValue.toBool();
                if (pChan->isDetached() != b) {
                    if (b)
                        pChan->detachUser();
                    else
                        pChan->attachUser();
                }
                putModule(pChan->name() + ": Detached = " + NoString(b));
            } else if (sVar == "key") {
                pChan->setKey(sValue);
                putModule(pChan->name() + ": Key = " + sValue);
            } else {
                putModule("Error: Unknown variable");
                return;
            }
        }
    }

    void ListUsers(const NoString&)
    {
        if (!user()->isAdmin())
            return;

        const std::map<NoString, NoUser*>& msUsers = NoApp::Get().GetUserMap();
        NoTable Table;
        Table.addColumn("Username");
        Table.addColumn("Realname");
        Table.addColumn("IsAdmin");
        Table.addColumn("Nick");
        Table.addColumn("AltNick");
        Table.addColumn("Ident");
        Table.addColumn("BindHost");

        for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it) {
            Table.addRow();
            Table.setValue("Username", it->first);
            Table.setValue("Realname", it->second->realName());
            if (!it->second->isAdmin())
                Table.setValue("IsAdmin", "No");
            else
                Table.setValue("IsAdmin", "Yes");
            Table.setValue("Nick", it->second->nick());
            Table.setValue("AltNick", it->second->altNick());
            Table.setValue("Ident", it->second->ident());
            Table.setValue("BindHost", it->second->bindHost());
        }

        putModule(Table);
    }

    void AddUser(const NoString& sLine)
    {
        if (!user()->isAdmin()) {
            putModule("Error: You need to have admin rights to add new users!");
            return;
        }

        const NoString sUsername = No::token(sLine, 1), sPassword = No::token(sLine, 2);
        if (sPassword.empty()) {
            putModule("Usage: AddUser <username> <password>");
            return;
        }

        if (NoApp::Get().FindUser(sUsername)) {
            putModule("Error: User [" + sUsername + "] already exists!");
            return;
        }

        NoUser* pNewUser = new NoUser(sUsername);
        NoString sSalt = No::salt();
        pNewUser->setPassword(NoUser::saltedHash(sPassword, sSalt), NoUser::HashDefault, sSalt);

        NoString sErr;
        if (!NoApp::Get().AddUser(pNewUser, sErr)) {
            delete pNewUser;
            putModule("Error: User not added! [" + sErr + "]");
            return;
        }

        putModule("User [" + sUsername + "] added!");
        return;
    }

    void DelUser(const NoString& sLine)
    {
        if (!user()->isAdmin()) {
            putModule("Error: You need to have admin rights to delete users!");
            return;
        }

        const NoString sUsername = No::tokens(sLine, 1);
        if (sUsername.empty()) {
            putModule("Usage: DelUser <username>");
            return;
        }

        NoUser* pUser = NoApp::Get().FindUser(sUsername);

        if (!pUser) {
            putModule("Error: User [" + sUsername + "] does not exist!");
            return;
        }

        if (pUser == user()) {
            putModule("Error: You can't delete yourself!");
            return;
        }

        if (!NoApp::Get().DeleteUser(pUser->userName())) {
            // This can't happen, because we got the user from FindUser()
            putModule("Error: Internal error!");
            return;
        }

        putModule("User " + sUsername + " deleted!");
        return;
    }

    void CloneUser(const NoString& sLine)
    {
        if (!user()->isAdmin()) {
            putModule("Error: You need to have admin rights to add new users!");
            return;
        }

        const NoString sOldUsername = No::token(sLine, 1), sNewUsername = No::tokens(sLine, 2);

        if (sOldUsername.empty() || sNewUsername.empty()) {
            putModule("Usage: CloneUser <old username> <new username>");
            return;
        }

        NoUser* pOldUser = NoApp::Get().FindUser(sOldUsername);

        if (!pOldUser) {
            putModule("Error: User [" + sOldUsername + "] not found!");
            return;
        }

        NoUser* pNewUser = new NoUser(sNewUsername);
        NoString sError;
        if (!pNewUser->clone(*pOldUser, sError)) {
            delete pNewUser;
            putModule("Error: Cloning failed! [" + sError + "]");
            return;
        }

        if (!NoApp::Get().AddUser(pNewUser, sError)) {
            delete pNewUser;
            putModule("Error: User not added! [" + sError + "]");
            return;
        }

        putModule("User [" + sNewUsername + "] added!");
        return;
    }

    void AddNetwork(const NoString& sLine)
    {
        NoString sUser = No::token(sLine, 1);
        NoString sNetwork = No::token(sLine, 2);
        NoUser* pUser = user();

        if (sNetwork.empty()) {
            sNetwork = sUser;
        } else {
            pUser = FindUser(sUser);
            if (!pUser) {
                putModule("User [" + sUser + "] not found");
                return;
            }
        }

        if (sNetwork.empty()) {
            putModule("Usage: AddNetwork [user] network");
            return;
        }

        if (!user()->isAdmin() && !pUser->hasSpaceForNewNetwork()) {
            putStatus("Network number limit reached. Ask an admin to increase the limit for you, or delete unneeded "
                      "networks using /znc DelNetwork <name>");
            return;
        }

        if (pUser->findNetwork(sNetwork)) {
            putModule("[" + pUser->userName() + "] already has a network with the name [" + sNetwork + "]");
            return;
        }

        NoString sNetworkAddError;
        if (pUser->addNetwork(sNetwork, sNetworkAddError)) {
            putModule("Network [" + sNetwork + "] added for user [" + pUser->userName() + "].");
        } else {
            putModule("Network [" + sNetwork + "] could not be added for user [" + pUser->userName() + "]: " + sNetworkAddError);
        }
    }

    void DelNetwork(const NoString& sLine)
    {
        NoString sUser = No::token(sLine, 1);
        NoString sNetwork = No::token(sLine, 2);
        NoUser* pUser = user();

        if (sNetwork.empty()) {
            sNetwork = sUser;
        } else {
            pUser = FindUser(sUser);
            if (!pUser) {
                return;
            }
        }

        if (sNetwork.empty()) {
            putModule("Usage: DelNetwork [user] network");
            return;
        }

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        if (pNetwork == NoModule::network()) {
            putModule("The currently active network can be deleted via " + user()->statusPrefix() + "status");
            return;
        }

        if (pUser->deleteNetwork(sNetwork)) {
            putModule("Network [" + sNetwork + "] deleted on user [" + pUser->userName() + "].");
        } else {
            putModule("Network [" + sNetwork + "] could not be deleted for user [" + pUser->userName() + "].");
        }
    }

    void ListNetworks(const NoString& sLine)
    {
        NoString sUser = No::token(sLine, 1);
        NoUser* pUser = user();

        if (!sUser.empty()) {
            pUser = FindUser(sUser);
            if (!pUser) {
                return;
            }
        }

        const std::vector<NoNetwork*>& vNetworks = pUser->networks();

        NoTable Table;
        Table.addColumn("Network");
        Table.addColumn("OnIRC");
        Table.addColumn("IRC Server");
        Table.addColumn("IRC User");
        Table.addColumn("Channels");

        for (uint a = 0; a < vNetworks.size(); a++) {
            NoNetwork* pNetwork = vNetworks[a];
            Table.addRow();
            Table.setValue("Network", pNetwork->name());
            if (pNetwork->isIrcConnected()) {
                Table.setValue("OnIRC", "Yes");
                Table.setValue("IRC Server", pNetwork->ircServer());
                Table.setValue("IRC User", pNetwork->ircNick().nickMask());
                Table.setValue("Channels", NoString(pNetwork->channels().size()));
            } else {
                Table.setValue("OnIRC", "No");
            }
        }

        if (putModule(Table) == 0) {
            putModule("No networks");
        }
    }

    void AddServer(const NoString& sLine)
    {
        NoString sUsername = No::token(sLine, 1);
        NoString sNetwork = No::token(sLine, 2);
        NoString sServer = No::tokens(sLine, 3);

        if (sServer.empty()) {
            putModule("Usage: AddServer <username> <network> <server>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser)
            return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        if (pNetwork->addServer(sServer))
            putModule("Added IRC Server [" + sServer + "] for network [" + sNetwork + "] for user [" + pUser->userName() + "].");
        else
            putModule("Could not add IRC server [" + sServer + "] for network [" + sNetwork + "] for user [" +
                      pUser->userName() + "].");
    }

    void removeServer(const NoString& sLine)
    {
        NoString sUsername = No::token(sLine, 1);
        NoString sNetwork = No::token(sLine, 2);
        NoString sServer = No::tokens(sLine, 3);
        ushort uPort = No::token(sLine, 4).toUShort();
        NoString sPass = No::token(sLine, 5);

        if (sServer.empty()) {
            putModule("Usage: removeServer <username> <network> <server>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser)
            return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        if (pNetwork->removeServer(sServer, uPort, sPass))
            putModule("Deleted IRC Server [" + sServer + "] for network [" + sNetwork + "] for user [" + pUser->userName() + "].");
        else
            putModule("Could not delete IRC server [" + sServer + "] for network [" + sNetwork + "] for user [" +
                      pUser->userName() + "].");
    }

    void ReconnectUser(const NoString& sLine)
    {
        NoString sUserName = No::token(sLine, 1);
        NoString sNetwork = No::token(sLine, 2);

        if (sNetwork.empty()) {
            putModule("Usage: Reconnect <username> <network>");
            return;
        }

        NoUser* pUser = FindUser(sUserName);
        if (!pUser) {
            putModule("User [" + sUserName + "] not found.");
            return;
        }

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        NoIrcSocket* pIRCSock = pNetwork->ircSocket();
        // cancel connection attempt:
        if (pIRCSock && !pIRCSock->isConnected()) {
            pIRCSock->close();
        }
        // or close existing connection:
        else if (pIRCSock) {
            pIRCSock->Quit();
        }

        // then reconnect
        pNetwork->setEnabled(true);

        putModule("Queued network [" + sNetwork + "] for user [" + pUser->userName() + "] for a reconnect.");
    }

    void DisconnectUser(const NoString& sLine)
    {
        NoString sUserName = No::token(sLine, 1);
        NoString sNetwork = No::token(sLine, 2);

        if (sNetwork.empty()) {
            putModule("Usage: Disconnect <username> <network>");
            return;
        }

        NoUser* pUser = FindUser(sUserName);
        if (!pUser) {
            putModule("User [" + sUserName + "] not found.");
            return;
        }

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        pNetwork->setEnabled(false);
        putModule("Closed IRC connection for network [" + sNetwork + "] on user [" + sUserName + "].");
    }

    void ListCTCP(const NoString& sLine)
    {
        NoString sUserName = No::tokens(sLine, 1);

        if (sUserName.empty()) {
            sUserName = user()->userName();
        }
        NoUser* pUser = FindUser(sUserName);
        if (!pUser)
            return;

        const NoStringMap& msCTCPReplies = pUser->ctcpReplies();
        NoTable Table;
        Table.addColumn("Request");
        Table.addColumn("Reply");
        for (NoStringMap::const_iterator it = msCTCPReplies.begin(); it != msCTCPReplies.end(); ++it) {
            Table.addRow();
            Table.setValue("Request", it->first);
            Table.setValue("Reply", it->second);
        }

        if (Table.isEmpty()) {
            putModule("No CTCP replies for user [" + pUser->userName() + "] configured!");
        } else {
            putModule("CTCP replies for user [" + pUser->userName() + "]:");
            putModule(Table);
        }
    }

    void AddCTCP(const NoString& sLine)
    {
        NoString sUserName = No::token(sLine, 1);
        NoString sCTCPRequest = No::token(sLine, 2);
        NoString sCTCPReply = No::tokens(sLine, 3);

        if (sCTCPRequest.empty()) {
            sCTCPRequest = sUserName;
            sCTCPReply = No::tokens(sLine, 2);
            sUserName = user()->userName();
        }
        if (sCTCPRequest.empty()) {
            putModule("Usage: AddCTCP [user] [request] [reply]");
            putModule("This will cause ZNC to reply to the CTCP instead of forwarding it to clients.");
            putModule("An empty reply will cause the CTCP request to be blocked.");
            return;
        }

        NoUser* pUser = FindUser(sUserName);
        if (!pUser)
            return;

        if (pUser->addCtcpReply(sCTCPRequest, sCTCPReply))
            putModule("Added!");
        else
            putModule("Error!");
    }

    void DelCTCP(const NoString& sLine)
    {
        NoString sUserName = No::token(sLine, 1);
        NoString sCTCPRequest = No::tokens(sLine, 2);

        if (sCTCPRequest.empty()) {
            sCTCPRequest = sUserName;
            sUserName = user()->userName();
        }
        NoUser* pUser = FindUser(sUserName);
        if (!pUser)
            return;

        if (sCTCPRequest.empty()) {
            putModule("Usage: DelCTCP [user] [request]");
            return;
        }

        if (pUser->removeCtcpReply(sCTCPRequest))
            putModule("Successfully removed [" + sCTCPRequest + "] for user [" + pUser->userName() + "].");
        else
            putModule("Error: [" + sCTCPRequest + "] not found for user [" + pUser->userName() + "]!");
    }

    void LoadModuleFor(NoModuleLoader* Modules, const NoString& sModName, const NoString& sArgs, No::ModuleType eType, NoUser* pUser, NoNetwork* pNetwork)
    {
        if (pUser->denyLoadMod() && !user()->isAdmin()) {
            putModule("Loading modules has been disabled.");
            return;
        }

        NoString sModRet;
        NoModule* pMod = Modules->findModule(sModName);
        if (!pMod) {
            if (!Modules->loadModule(sModName, sArgs, eType, pUser, pNetwork, sModRet)) {
                putModule("Unable to load module [" + sModName + "] [" + sModRet + "]");
            } else {
                putModule("Loaded module [" + sModName + "]");
            }
        } else if (pMod->args() != sArgs) {
            if (!Modules->reloadModule(sModName, sArgs, pUser, pNetwork, sModRet)) {
                putModule("Unable to reload module [" + sModName + "] [" + sModRet + "]");
            } else {
                putModule("Reloaded module [" + sModName + "]");
            }
        } else {
            putModule("Unable to load module [" + sModName + "] because it is already loaded");
        }
    }

    void LoadModuleForUser(const NoString& sLine)
    {
        NoString sUsername = No::token(sLine, 1);
        NoString sModName = No::token(sLine, 2);
        NoString sArgs = No::tokens(sLine, 3);

        if (sModName.empty()) {
            putModule("Usage: LoadModule <username> <modulename> [args]");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser)
            return;

        LoadModuleFor(pUser->loader(), sModName, sArgs, No::UserModule, pUser, nullptr);
    }

    void LoadModuleForNetwork(const NoString& sLine)
    {
        NoString sUsername = No::token(sLine, 1);
        NoString sNetwork = No::token(sLine, 2);
        NoString sModName = No::token(sLine, 3);
        NoString sArgs = No::tokens(sLine, 4);

        if (sModName.empty()) {
            putModule("Usage: LoadNetModule <username> <network> <modulename> [args]");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser)
            return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        LoadModuleFor(pNetwork->loader(), sModName, sArgs, No::NetworkModule, pUser, pNetwork);
    }

    void UnLoadModuleFor(NoModuleLoader* Modules, const NoString& sModName, NoUser* pUser)
    {
        if (pUser->denyLoadMod() && !user()->isAdmin()) {
            putModule("Loading modules has been disabled.");
            return;
        }

        if (Modules->findModule(sModName) == this) {
            putModule("Please use /znc unloadmod " + sModName);
            return;
        }

        NoString sModRet;
        if (!Modules->unloadModule(sModName, sModRet)) {
            putModule("Unable to unload module [" + sModName + "] [" + sModRet + "]");
        } else {
            putModule("Unloaded module [" + sModName + "]");
        }
    }

    void UnLoadModuleForUser(const NoString& sLine)
    {
        NoString sUsername = No::token(sLine, 1);
        NoString sModName = No::token(sLine, 2);

        if (sModName.empty()) {
            putModule("Usage: UnloadModule <username> <modulename>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser)
            return;

        UnLoadModuleFor(pUser->loader(), sModName, pUser);
    }

    void UnLoadModuleForNetwork(const NoString& sLine)
    {
        NoString sUsername = No::token(sLine, 1);
        NoString sNetwork = No::token(sLine, 2);
        NoString sModName = No::token(sLine, 3);

        if (sModName.empty()) {
            putModule("Usage: UnloadNetModule <username> <network> <modulename>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser)
            return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        UnLoadModuleFor(pNetwork->loader(), sModName, pUser);
    }

    void ListModulesFor(NoModuleLoader* Modules, const NoString& sWhere)
    {
        if (Modules->isEmpty()) {
            putModule(sWhere + " has no modules loaded.");
        } else {
            putModule("Modules loaded for " + sWhere + ":");
            NoTable Table;
            Table.addColumn("Name");
            Table.addColumn("Arguments");

            for (NoModule* mod : Modules->modules()) {
                Table.addRow();
                Table.setValue("Name", mod->moduleName());
                Table.setValue("Arguments", mod->args());
            }

            putModule(Table);
        }
    }

    void ListModulesForUser(const NoString& sLine)
    {
        NoString sUsername = No::token(sLine, 1);

        if (sUsername.empty()) {
            putModule("Usage: ListMods <username>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser)
            return;

        ListModulesFor(pUser->loader(), "User [" + pUser->userName() + "]");
    }

    void ListModulesForNetwork(const NoString& sLine)
    {
        NoString sUsername = No::token(sLine, 1);
        NoString sNetwork = No::token(sLine, 2);

        if (sNetwork.empty()) {
            putModule("Usage: ListNetMods <username> <network>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser)
            return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        ListModulesFor(pNetwork->loader(), "Network [" + pNetwork->name() + "] of user [" + pUser->userName() + "]");
    }

public:
    MODCONSTRUCTOR(NoAdminMod)
    {
        addCommand("Help",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::PrintHelp),
                   "[command] [variable]",
                   "Prints help for matching commands and variables");
        addCommand("Get",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::Get),
                   "<variable> [username]",
                   "Prints the variable's value for the given or current user");
        addCommand("Set", static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::Set), "<variable> <username> <value>", "Sets the variable's value for the given user");
        addCommand("GetNetwork",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::GetNetwork),
                   "<variable> [username] [network]",
                   "Prints the variable's value for the given network");
        addCommand("SetNetwork",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::SetNetwork),
                   "<variable> <username> <network> <value>",
                   "Sets the variable's value for the given network");
        addCommand("GetChan",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::GetChan),
                   "<variable> [username] <network> <chan>",
                   "Prints the variable's value for the given channel");
        addCommand("SetChan",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::SetChan),
                   "<variable> <username> <network> <chan> <value>",
                   "Sets the variable's value for the given channel");
        addCommand("addChannel",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::addChannel),
                   "<username> <network> <chan>",
                   "Adds a new channel");
        addCommand("removeChannel",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::removeChannel),
                   "<username> <network> <chan>",
                   "Deletes a channel");
        addCommand("ListUsers", static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::ListUsers), "", "Lists users");
        addCommand("AddUser", static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::AddUser), "<username> <password>", "Adds a new user");
        addCommand("DelUser",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::DelUser),
                   "<username>",
                   "Deletes a user");
        addCommand("CloneUser",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::CloneUser),
                   "<old username> <new username>",
                   "Clones a user");
        addCommand("AddServer",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::AddServer),
                   "<username> <network> <server>",
                   "Adds a new IRC server for the given or current user");
        addCommand("removeServer",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::removeServer),
                   "<username> <network> <server>",
                   "Deletes an IRC server from the given or current user");
        addCommand("Reconnect",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::ReconnectUser),
                   "<username> <network>",
                   "Cycles the user's IRC server connection");
        addCommand("Disconnect",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::DisconnectUser),
                   "<username> <network>",
                   "Disconnects the user from their IRC server");
        addCommand("LoadModule",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::LoadModuleForUser),
                   "<username> <modulename> [args]",
                   "Loads a Module for a user");
        addCommand("UnLoadModule",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::UnLoadModuleForUser),
                   "<username> <modulename>",
                   "Removes a Module of a user");
        addCommand("ListMods", static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::ListModulesForUser), "<username>", "Get the list of modules for a user");
        addCommand("LoadNetModule",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::LoadModuleForNetwork),
                   "<username> <network> <modulename> [args]",
                   "Loads a Module for a network");
        addCommand("UnLoadNetModule",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::UnLoadModuleForNetwork),
                   "<username> <network> <modulename>",
                   "Removes a Module of a network");
        addCommand("ListNetMods",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::ListModulesForNetwork),
                   "<username> <network>",
                   "Get the list of modules for a network");
        addCommand("ListCTCPs",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::ListCTCP),
                   "<username>",
                   "List the configured CTCP replies");
        addCommand("AddCTCP",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::AddCTCP),
                   "<username> <ctcp> [reply]",
                   "Configure a new CTCP reply");
        addCommand("DelCTCP",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::DelCTCP),
                   "<username> <ctcp>",
                   "Remove a CTCP reply");

        // Network commands
        addCommand("AddNetwork",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::AddNetwork),
                   "[username] <network>",
                   "Add a network for a user");
        addCommand("DelNetwork",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::DelNetwork),
                   "[username] <network>",
                   "Delete a network for a user");
        addCommand("ListNetworks", static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminMod::ListNetworks), "[username]", "List all networks for a user");
    }
};

template <>
void no_moduleInfo<NoAdminMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("controlpanel");
}

USERMODULEDEFS(NoAdminMod, "Dynamic configuration through IRC. Allows editing only yourself if you're not ZNC admin.")
