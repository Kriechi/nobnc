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

#include <nobnc/nomodule.h>
#include <nobnc/nouser.h>
#include <nobnc/nonetwork.h>
#include <nobnc/nochannel.h>
#include <nobnc/noircsocket.h>
#include <nobnc/noapp.h>
#include <nobnc/nonick.h>
#include <nobnc/noutils.h>
#include <nobnc/notable.h>

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

    void PrintVarsHelp(const NoString& filter, const char* vars[][2], uint uSize, const NoString& description)
    {
        NoTable VarTable;
        VarTable.addColumn("Type");
        VarTable.addColumn("Variables");
        std::map<const char*, NoStringVector> mvsTypedVariables;
        for (uint i = 0; i != uSize; ++i) {
            NoString sVar = NoString(vars[i][0]).toLower();
            if (filter.empty() || sVar.startsWith(filter) || No::wildCmp(sVar, filter)) {
                mvsTypedVariables[vars[i][1]].emplace_back(vars[i][0]);
            }
        }
        for (const auto& i : mvsTypedVariables) {
            VarTable.addRow();
            VarTable.setValue("Type", i.first);
            VarTable.setValue("Variables", NoString(", ").join(i.second.cbegin(), i.second.cend()));
        }
        if (!VarTable.isEmpty()) {
            putModule(description);
            putModule(VarTable);
        }
    }

    void onHelpCommand(const NoString& line)
    {
        NoModule::onHelpCommand(line);

        static const char* str = "String";
        static const char* boolean = "Boolean (true/false)";
        static const char* integer = "Integer";
        static const char* doublenum = "Double";

        const NoString sCmdFilter = No::token(line, 1);
        const NoString sVarFilter = No::tokens(line, 2).toLower();

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

    NoUser* FindUser(const NoString& username)
    {
        if (username.equals("$me") || username.equals("$user"))
            return user();
        NoUser* user = noApp->findUser(username);
        if (!user) {
            putModule("Error: User [" + username + "] not found.");
            return nullptr;
        }
        if (user != NoModule::user() && !NoModule::user()->isAdmin()) {
            putModule("Error: You need to have admin rights to modify other users!");
            return nullptr;
        }
        return user;
    }

    NoNetwork* FindNetwork(NoUser* user, const NoString& sNetwork)
    {
        if (sNetwork.equals("$net") || sNetwork.equals("$network")) {
            if (user != NoModule::user()) {
                putModule("Error: You cannot use " + sNetwork + " to modify other users!");
                return nullptr;
            }
            return NoModule::network();
        }
        NoNetwork* network = user->findNetwork(sNetwork);
        if (!network) {
            putModule("Error: [" + user->userName() + "] does not have a network named [" + sNetwork + "].");
        }
        return network;
    }

    void Get(const NoString& line)
    {
        const NoString sVar = No::token(line, 1).toLower();
        NoString username = No::tokens(line, 2);
        NoUser* user;

        if (sVar.empty()) {
            putModule("Usage: Get <variable> [username]");
            return;
        }

        if (username.empty()) {
            user = NoModule::user();
        } else {
            user = FindUser(username);
        }

        if (!user)
            return;

        if (sVar == "nick")
            putModule("Nick = " + user->nick());
        else if (sVar == "altnick")
            putModule("AltNick = " + user->altNick());
        else if (sVar == "ident")
            putModule("Ident = " + user->ident());
        else if (sVar == "realname")
            putModule("RealName = " + user->realName());
        else if (sVar == "bindhost")
            putModule("BindHost = " + user->bindHost());
        else if (sVar == "multiclients")
            putModule("MultiClients = " + NoString(user->multiClients()));
        else if (sVar == "denyloadmod")
            putModule("DenyLoadMod = " + NoString(user->denyLoadMod()));
        else if (sVar == "denysetbindhost")
            putModule("DenysetBindHost = " + NoString(user->denysetBindHost()));
        else if (sVar == "defaultchanmodes")
            putModule("DefaultChanModes = " + user->defaultChanModes());
        else if (sVar == "quitmsg")
            putModule("QuitMsg = " + user->quitMessage());
        else if (sVar == "buffercount")
            putModule("BufferCount = " + NoString(user->bufferCount()));
        else if (sVar == "autoclearchanbuffer")
            putModule("AutoClearChanBuffer = " + NoString(user->autoClearChanBuffer()));
        else if (sVar == "autoclearquerybuffer")
            putModule("autoclearQueryBuffer = " + NoString(user->autoclearQueryBuffer()));
        else if (sVar == "maxjoins")
            putModule("MaxJoins = " + NoString(user->maxJoins()));
        else if (sVar == "maxnetworks")
            putModule("MaxNetworks = " + NoString(user->maxNetworks()));
        else if (sVar == "maxquerybuffers")
            putModule("MaxQueryBuffers = " + NoString(user->maxQueryBuffers()));
        else if (sVar == "jointries")
            putModule("JoinTries = " + NoString(user->joinTries()));
        else if (sVar == "timezone")
            putModule("Timezone = " + user->timezone());
        else if (sVar == "appendtimestamp")
            putModule("AppendTimestamp = " + NoString(user->timestampAppend()));
        else if (sVar == "prependtimestamp")
            putModule("PrependTimestamp = " + NoString(user->timestampPrepend()));
        else if (sVar == "timestampformat")
            putModule("TimestampFormat = " + user->timestampFormat());
        else if (sVar == "dccbindhost")
            putModule("DCCBindHost = " + NoString(user->dccBindHost()));
        else if (sVar == "admin")
            putModule("Admin = " + NoString(user->isAdmin()));
        else if (sVar == "statusprefix")
            putModule("StatusPrefix = " + user->statusPrefix());
#ifdef HAVE_ICU
        else if (sVar == "clientencoding")
            putModule("ClientEncoding = " + user->clientEncoding());
#endif
        else
            putModule("Error: Unknown variable");
    }

    void Set(const NoString& line)
    {
        const NoString sVar = No::token(line, 1).toLower();
        NoString userName = No::token(line, 2);
        NoString value = No::tokens(line, 3);

        if (value.empty()) {
            putModule("Usage: Set <variable> <username> <value>");
            return;
        }

        NoUser* user = FindUser(userName);
        if (!user)
            return;

        if (sVar == "nick") {
            user->setNick(value);
            putModule("Nick = " + value);
        } else if (sVar == "altnick") {
            user->setAltNick(value);
            putModule("AltNick = " + value);
        } else if (sVar == "ident") {
            user->setIdent(value);
            putModule("Ident = " + value);
        } else if (sVar == "realname") {
            user->setRealName(value);
            putModule("RealName = " + value);
        } else if (sVar == "bindhost") {
            if (!user->denysetBindHost() || NoModule::user()->isAdmin()) {
                if (value.equals(NoModule::user()->bindHost())) {
                    putModule("This bind host is already set!");
                    return;
                }

                const NoStringVector& vsHosts = noApp->bindHosts();
                if (!NoModule::user()->isAdmin() && !vsHosts.empty()) {
                    NoStringVector::const_iterator it;
                    bool bFound = false;

                    for (it = vsHosts.begin(); it != vsHosts.end(); ++it) {
                        if (value.equals(*it)) {
                            bFound = true;
                            break;
                        }
                    }

                    if (!bFound) {
                        putModule("You may not use this bind host. See /msg " + NoModule::user()->statusPrefix() +
                                  "status ListBindHosts for a list");
                        return;
                    }
                }

                user->setBindHost(value);
                putModule("BindHost = " + value);
            } else {
                putModule("Access denied!");
            }
        } else if (sVar == "multiclients") {
            bool b = value.toBool();
            user->setMultiClients(b);
            putModule("MultiClients = " + NoString(b));
        } else if (sVar == "denyloadmod") {
            if (NoModule::user()->isAdmin()) {
                bool b = value.toBool();
                user->setDenyLoadMod(b);
                putModule("DenyLoadMod = " + NoString(b));
            } else {
                putModule("Access denied!");
            }
        } else if (sVar == "denysetbindhost") {
            if (NoModule::user()->isAdmin()) {
                bool b = value.toBool();
                user->setDenysetBindHost(b);
                putModule("DenysetBindHost = " + NoString(b));
            } else {
                putModule("Access denied!");
            }
        } else if (sVar == "defaultchanmodes") {
            user->setDefaultChanModes(value);
            putModule("DefaultChanModes = " + value);
        } else if (sVar == "quitmsg") {
            user->setQuitMessage(value);
            putModule("QuitMsg = " + value);
        } else if (sVar == "buffercount") {
            uint i = value.toUInt();
            // Admins don't have to honour the buffer limit
            if (user->setBufferCount(i, NoModule::user()->isAdmin())) {
                putModule("BufferCount = " + value);
            } else {
                putModule("Setting failed, limit is " + NoString(noApp->maxBufferSize()));
            }
        } else if (sVar == "autoclearchanbuffer") {
            bool b = value.toBool();
            user->setAutoClearChanBuffer(b);
            putModule("AutoClearChanBuffer = " + NoString(b));
        } else if (sVar == "autoclearquerybuffer") {
            bool b = value.toBool();
            user->setAutoclearQueryBuffer(b);
            putModule("autoclearQueryBuffer = " + NoString(b));
        } else if (sVar == "password") {
            user->setPassword(value);
            putModule("Password has been changed!");
        } else if (sVar == "maxjoins") {
            uint i = value.toUInt();
            user->setMaxJoins(i);
            putModule("MaxJoins = " + NoString(user->maxJoins()));
        } else if (sVar == "maxnetworks") {
            if (NoModule::user()->isAdmin()) {
                uint i = value.toUInt();
                user->setMaxNetworks(i);
                putModule("MaxNetworks = " + value);
            } else {
                putModule("Access denied!");
            }
        } else if (sVar == "maxquerybuffers") {
            uint i = value.toUInt();
            user->setMaxQueryBuffers(i);
            putModule("MaxQueryBuffers = " + value);
        } else if (sVar == "jointries") {
            uint i = value.toUInt();
            user->setJoinTries(i);
            putModule("JoinTries = " + NoString(user->joinTries()));
        } else if (sVar == "timezone") {
            user->setTimezone(value);
            putModule("Timezone = " + user->timezone());
        } else if (sVar == "admin") {
            if (NoModule::user()->isAdmin() && user != NoModule::user()) {
                bool b = value.toBool();
                user->setAdmin(b);
                putModule("Admin = " + NoString(user->isAdmin()));
            } else {
                putModule("Access denied!");
            }
        } else if (sVar == "prependtimestamp") {
            bool b = value.toBool();
            user->setTimestampPrepend(b);
            putModule("PrependTimestamp = " + NoString(b));
        } else if (sVar == "appendtimestamp") {
            bool b = value.toBool();
            user->setTimestampAppend(b);
            putModule("AppendTimestamp = " + NoString(b));
        } else if (sVar == "timestampformat") {
            user->setTimestampFormat(value);
            putModule("TimestampFormat = " + value);
        } else if (sVar == "dccbindhost") {
            if (!user->denysetBindHost() || NoModule::user()->isAdmin()) {
                user->setDccBindHost(value);
                putModule("DCCBindHost = " + value);
            } else {
                putModule("Access denied!");
            }
        } else if (sVar == "statusprefix") {
            if (sVar.find_first_of(" \t\n") == NoString::npos) {
                user->setStatusPrefix(value);
                putModule("StatusPrefix = " + value);
            } else {
                putModule("That would be a bad idea!");
            }
        }
#ifdef HAVE_ICU
        else if (sVar == "clientencoding") {
            user->setClientEncoding(value);
            putModule("ClientEncoding = " + value);
        }
#endif
        else
            putModule("Error: Unknown variable");
    }

    void GetNetwork(const NoString& line)
    {
        const NoString sVar = No::token(line, 1).toLower();
        const NoString username = No::token(line, 2);
        const NoString sNetwork = No::token(line, 3);

        NoNetwork* network = nullptr;

        if (username.empty()) {
            network = NoModule::network();
        } else {
            NoUser* user = FindUser(username);
            if (!user) {
                return;
            }

            network = FindNetwork(user, sNetwork);
            if (!network && !sNetwork.empty()) {
                return;
            }
        }

        if (!network) {
            putModule("Usage: GetNetwork <variable> <username> <network>");
            return;
        }

        if (sVar.equals("nick")) {
            putModule("Nick = " + network->nick());
        } else if (sVar.equals("altnick")) {
            putModule("AltNick = " + network->altNick());
        } else if (sVar.equals("ident")) {
            putModule("Ident = " + network->ident());
        } else if (sVar.equals("realname")) {
            putModule("RealName = " + network->realName());
        } else if (sVar.equals("bindhost")) {
            putModule("BindHost = " + network->bindHost());
        } else if (sVar.equals("floodrate")) {
            putModule("FloodRate = " + NoString(network->floodRate()));
        } else if (sVar.equals("floodburst")) {
            putModule("FloodBurst = " + NoString(network->floodBurst()));
        } else if (sVar.equals("joindelay")) {
            putModule("JoinDelay = " + NoString(network->joinDelay()));
#ifdef HAVE_ICU
        } else if (sVar.equals("encoding")) {
            putModule("Encoding = " + network->encoding());
#endif
        } else if (sVar.equals("quitmsg")) {
            putModule("QuitMsg = " + network->quitMessage());
        } else {
            putModule("Error: Unknown variable");
        }
    }

    void SetNetwork(const NoString& line)
    {
        const NoString sVar = No::token(line, 1).toLower();
        const NoString username = No::token(line, 2);
        const NoString sNetwork = No::token(line, 3);
        const NoString value = No::tokens(line, 4);

        NoUser* user = nullptr;
        NoNetwork* network = nullptr;

        if (username.empty()) {
            user = NoModule::user();
            network = NoModule::network();
        } else {
            user = FindUser(username);
            if (!user) {
                return;
            }

            network = FindNetwork(user, sNetwork);
            if (!network && !sNetwork.empty()) {
                return;
            }
        }

        if (!network) {
            putModule("Usage: SetNetwork <variable> <username> <network> <value>");
            return;
        }

        if (sVar.equals("nick")) {
            network->setNick(value);
            putModule("Nick = " + network->nick());
        } else if (sVar.equals("altnick")) {
            network->setAltNick(value);
            putModule("AltNick = " + network->altNick());
        } else if (sVar.equals("ident")) {
            network->setIdent(value);
            putModule("Ident = " + network->ident());
        } else if (sVar.equals("realname")) {
            network->setRealName(value);
            putModule("RealName = " + network->realName());
        } else if (sVar.equals("bindhost")) {
            if (!user->denysetBindHost() || NoModule::user()->isAdmin()) {
                if (value.equals(network->bindHost())) {
                    putModule("This bind host is already set!");
                    return;
                }

                const NoStringVector& vsHosts = noApp->bindHosts();
                if (!NoModule::user()->isAdmin() && !vsHosts.empty()) {
                    NoStringVector::const_iterator it;
                    bool bFound = false;

                    for (it = vsHosts.begin(); it != vsHosts.end(); ++it) {
                        if (value.equals(*it)) {
                            bFound = true;
                            break;
                        }
                    }

                    if (!bFound) {
                        putModule("You may not use this bind host. See /msg " + NoModule::user()->statusPrefix() +
                                  "status ListBindHosts for a list");
                        return;
                    }
                }

                network->setBindHost(value);
                putModule("BindHost = " + value);
            } else {
                putModule("Access denied!");
            }
        } else if (sVar.equals("floodrate")) {
            network->setFloodRate(value.toDouble());
            putModule("FloodRate = " + NoString(network->floodRate()));
        } else if (sVar.equals("floodburst")) {
            network->setFloodBurst(value.toUShort());
            putModule("FloodBurst = " + NoString(network->floodBurst()));
        } else if (sVar.equals("joindelay")) {
            network->setJoinDelay(value.toUShort());
            putModule("JoinDelay = " + NoString(network->joinDelay()));
#ifdef HAVE_ICU
        } else if (sVar.equals("encoding")) {
            network->setEncoding(value);
            putModule("Encoding = " + network->encoding());
#endif
        } else if (sVar.equals("quitmsg")) {
            network->setQuitMessage(value);
            putModule("QuitMsg = " + network->quitMessage());
        } else {
            putModule("Error: Unknown variable");
        }
    }

    void addChannel(const NoString& line)
    {
        const NoString username = No::token(line, 1);
        const NoString sNetwork = No::token(line, 2);
        const NoString sChan = No::token(line, 3);

        if (sChan.empty()) {
            putModule("Usage: addChannel <username> <network> <channel>");
            return;
        }

        NoUser* user = FindUser(username);
        if (!user)
            return;

        NoNetwork* network = FindNetwork(user, sNetwork);
        if (!network) {
            return;
        }

        if (network->findChannel(sChan)) {
            putModule("Error: [" + username + "] already has a channel named [" + sChan + "].");
            return;
        }

        NoChannel* channel = new NoChannel(sChan, network, true);
        if (network->addChannel(channel))
            putModule("channel [" + channel->name() + "] for user [" + username + "] added.");
        else
            putModule("Could not add channel [" + sChan + "] for user [" + username + "], does it already exist?");
    }

    void removeChannel(const NoString& line)
    {
        const NoString username = No::token(line, 1);
        const NoString sNetwork = No::token(line, 2);
        const NoString sChan = No::token(line, 3);

        if (sChan.empty()) {
            putModule("Usage: removeChannel <username> <network> <channel>");
            return;
        }

        NoUser* user = FindUser(username);
        if (!user)
            return;

        NoNetwork* network = FindNetwork(user, sNetwork);
        if (!network) {
            return;
        }

        std::vector<NoChannel*> channels = network->findChannels(sChan);
        if (channels.empty()) {
            putModule("Error: User [" + username + "] does not have any channel matching [" + sChan + "].");
            return;
        }

        NoStringVector vsNames;
        for (const NoChannel* channel : channels) {
            const NoString& name = channel->name();
            vsNames.push_back(name);
            network->putIrc("PART " + name);
            network->removeChannel(name);
        }

        putModule("channel(s) [" + NoString(",").join(vsNames.begin(), vsNames.end()) + "] for user [" + username +
                  "] deleted.");
    }

    void GetChan(const NoString& line)
    {
        const NoString sVar = No::token(line, 1).toLower();
        NoString username = No::token(line, 2);
        NoString sNetwork = No::token(line, 3);
        NoString sChan = No::tokens(line, 4);

        if (sChan.empty()) {
            putModule("Usage: GetChan <variable> <username> <network> <chan>");
            return;
        }

        NoUser* user = FindUser(username);
        if (!user)
            return;

        NoNetwork* network = FindNetwork(user, sNetwork);
        if (!network) {
            return;
        }

        std::vector<NoChannel*> channels = network->findChannels(sChan);
        if (channels.empty()) {
            putModule("Error: No channel(s) matching [" + sChan + "] found.");
            return;
        }

        for (NoChannel* channel : channels) {
            if (sVar == "defmodes") {
                putModule(channel->name() + ": DefModes = " + channel->defaultModes());
            } else if (sVar == "buffer") {
                NoString value(channel->bufferCount());
                if (!channel->hasBufferCountSet()) {
                    value += " (default)";
                }
                putModule(channel->name() + ": Buffer = " + value);
            } else if (sVar == "inconfig") {
                putModule(channel->name() + ": InConfig = " + NoString(channel->inConfig()));
            } else if (sVar == "autoclearchanbuffer") {
                NoString value(channel->autoClearChanBuffer());
                if (!channel->hasAutoClearChanBufferSet()) {
                    value += " (default)";
                }
                putModule(channel->name() + ": AutoClearChanBuffer = " + value);
            } else if (sVar == "detached") {
                putModule(channel->name() + ": Detached = " + NoString(channel->isDetached()));
            } else if (sVar == "key") {
                putModule(channel->name() + ": Key = " + channel->key());
            } else {
                putModule("Error: Unknown variable");
                return;
            }
        }
    }

    void SetChan(const NoString& line)
    {
        const NoString sVar = No::token(line, 1).toLower();
        NoString username = No::token(line, 2);
        NoString sNetwork = No::token(line, 3);
        NoString sChan = No::token(line, 4);
        NoString value = No::tokens(line, 5);

        if (value.empty()) {
            putModule("Usage: SetChan <variable> <username> <network> <chan> <value>");
            return;
        }

        NoUser* user = FindUser(username);
        if (!user)
            return;

        NoNetwork* network = FindNetwork(user, sNetwork);
        if (!network) {
            return;
        }

        std::vector<NoChannel*> channels = network->findChannels(sChan);
        if (channels.empty()) {
            putModule("Error: No channel(s) matching [" + sChan + "] found.");
            return;
        }

        for (NoChannel* channel : channels) {
            if (sVar == "defmodes") {
                channel->setDefaultModes(value);
                putModule(channel->name() + ": DefModes = " + value);
            } else if (sVar == "buffer") {
                uint i = value.toUInt();
                // Admins don't have to honour the buffer limit
                if (channel->setBufferCount(i, NoModule::user()->isAdmin())) {
                    putModule(channel->name() + ": Buffer = " + value);
                } else {
                    putModule("Setting failed, limit is " + NoString(noApp->maxBufferSize()));
                    return;
                }
            } else if (sVar == "inconfig") {
                bool b = value.toBool();
                channel->setInConfig(b);
                putModule(channel->name() + ": InConfig = " + NoString(b));
            } else if (sVar == "autoclearchanbuffer") {
                bool b = value.toBool();
                channel->setAutoClearChanBuffer(b);
                putModule(channel->name() + ": AutoClearChanBuffer = " + NoString(b));
            } else if (sVar == "detached") {
                bool b = value.toBool();
                if (channel->isDetached() != b) {
                    if (b)
                        channel->detachUser();
                    else
                        channel->attachUser();
                }
                putModule(channel->name() + ": Detached = " + NoString(b));
            } else if (sVar == "key") {
                channel->setKey(value);
                putModule(channel->name() + ": Key = " + value);
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

        const std::map<NoString, NoUser*>& msUsers = noApp->userMap();
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

    void AddUser(const NoString& line)
    {
        if (!user()->isAdmin()) {
            putModule("Error: You need to have admin rights to add new users!");
            return;
        }

        const NoString username = No::token(line, 1), sPassword = No::token(line, 2);
        if (sPassword.empty()) {
            putModule("Usage: AddUser <username> <password>");
            return;
        }

        if (noApp->findUser(username)) {
            putModule("Error: User [" + username + "] already exists!");
            return;
        }

        NoUser* pNewUser = new NoUser(username);
        pNewUser->setPassword(sPassword);

        NoString sErr;
        if (!noApp->addUser(pNewUser, sErr)) {
            delete pNewUser;
            putModule("Error: User not added! [" + sErr + "]");
            return;
        }

        putModule("User [" + username + "] added!");
        return;
    }

    void DelUser(const NoString& line)
    {
        if (!user()->isAdmin()) {
            putModule("Error: You need to have admin rights to delete users!");
            return;
        }

        const NoString username = No::tokens(line, 1);
        if (username.empty()) {
            putModule("Usage: DelUser <username>");
            return;
        }

        NoUser* user = noApp->findUser(username);

        if (!user) {
            putModule("Error: User [" + username + "] does not exist!");
            return;
        }

        if (user == NoModule::user()) {
            putModule("Error: You can't delete yourself!");
            return;
        }

        if (!noApp->deleteUser(user->userName())) {
            // This can't happen, because we got the user from FindUser()
            putModule("Error: Internal error!");
            return;
        }

        putModule("User " + username + " deleted!");
        return;
    }

    void CloneUser(const NoString& line)
    {
        if (!user()->isAdmin()) {
            putModule("Error: You need to have admin rights to add new users!");
            return;
        }

        const NoString sOldUsername = No::token(line, 1), sNewUsername = No::tokens(line, 2);

        if (sOldUsername.empty() || sNewUsername.empty()) {
            putModule("Usage: CloneUser <old username> <new username>");
            return;
        }

        NoUser* oldUser = noApp->findUser(sOldUsername);

        if (!oldUser) {
            putModule("Error: User [" + sOldUsername + "] not found!");
            return;
        }

        NoUser* pNewUser = new NoUser(sNewUsername);
        NoString error;
        if (!pNewUser->clone(oldUser, error)) {
            delete pNewUser;
            putModule("Error: Cloning failed! [" + error + "]");
            return;
        }

        if (!noApp->addUser(pNewUser, error)) {
            delete pNewUser;
            putModule("Error: User not added! [" + error + "]");
            return;
        }

        putModule("User [" + sNewUsername + "] added!");
        return;
    }

    void AddNetwork(const NoString& line)
    {
        NoString sUser = No::token(line, 1);
        NoString sNetwork = No::token(line, 2);
        NoUser* user = NoModule::user();

        if (sNetwork.empty()) {
            sNetwork = sUser;
        } else {
            user = FindUser(sUser);
            if (!user) {
                putModule("User [" + sUser + "] not found");
                return;
            }
        }

        if (sNetwork.empty()) {
            putModule("Usage: AddNetwork [user] network");
            return;
        }

        if (!NoModule::user()->isAdmin() && !user->hasSpaceForNewNetwork()) {
            putStatus("Network number limit reached. Ask an admin to increase the limit for you, or delete unneeded "
                      "networks using /znc DelNetwork <name>");
            return;
        }

        if (user->findNetwork(sNetwork)) {
            putModule("[" + user->userName() + "] already has a network with the name [" + sNetwork + "]");
            return;
        }

        NoString sNetworkAddError;
        if (user->addNetwork(sNetwork, sNetworkAddError)) {
            putModule("Network [" + sNetwork + "] added for user [" + user->userName() + "].");
        } else {
            putModule("Network [" + sNetwork + "] could not be added for user [" + user->userName() + "]: " + sNetworkAddError);
        }
    }

    void DelNetwork(const NoString& line)
    {
        NoString sUser = No::token(line, 1);
        NoString sNetwork = No::token(line, 2);
        NoUser* user = NoModule::user();

        if (sNetwork.empty()) {
            sNetwork = sUser;
        } else {
            user = FindUser(sUser);
            if (!user) {
                return;
            }
        }

        if (sNetwork.empty()) {
            putModule("Usage: DelNetwork [user] network");
            return;
        }

        NoNetwork* network = FindNetwork(user, sNetwork);
        if (!network) {
            return;
        }

        if (network == NoModule::network()) {
            putModule("The currently active network can be deleted via " + NoModule::user()->statusPrefix() + "status");
            return;
        }

        if (user->deleteNetwork(sNetwork)) {
            putModule("Network [" + sNetwork + "] deleted on user [" + user->userName() + "].");
        } else {
            putModule("Network [" + sNetwork + "] could not be deleted for user [" + user->userName() + "].");
        }
    }

    void ListNetworks(const NoString& line)
    {
        NoString sUser = No::token(line, 1);
        NoUser* user = NoModule::user();

        if (!sUser.empty()) {
            user = FindUser(sUser);
            if (!user) {
                return;
            }
        }

        const std::vector<NoNetwork*>& vNetworks = user->networks();

        NoTable Table;
        Table.addColumn("Network");
        Table.addColumn("OnIRC");
        Table.addColumn("IRC Server");
        Table.addColumn("IRC User");
        Table.addColumn("Channels");

        for (uint a = 0; a < vNetworks.size(); a++) {
            NoNetwork* network = vNetworks[a];
            Table.addRow();
            Table.setValue("Network", network->name());
            if (network->isIrcConnected()) {
                Table.setValue("OnIRC", "Yes");
                Table.setValue("IRC Server", network->ircServer());
                Table.setValue("IRC User", network->ircNick().hostMask());
                Table.setValue("Channels", NoString(network->channels().size()));
            } else {
                Table.setValue("OnIRC", "No");
            }
        }

        if (putModule(Table) == 0) {
            putModule("No networks");
        }
    }

    void AddServer(const NoString& line)
    {
        NoString username = No::token(line, 1);
        NoString sNetwork = No::token(line, 2);
        NoString sServer = No::tokens(line, 3);

        if (sServer.empty()) {
            putModule("Usage: AddServer <username> <network> <server>");
            return;
        }

        NoUser* user = FindUser(username);
        if (!user)
            return;

        NoNetwork* network = FindNetwork(user, sNetwork);
        if (!network) {
            return;
        }

        if (network->addServer(sServer))
            putModule("Added IRC Server [" + sServer + "] for network [" + sNetwork + "] for user [" + user->userName() + "].");
        else
            putModule("Could not add IRC server [" + sServer + "] for network [" + sNetwork + "] for user [" +
                      user->userName() + "].");
    }

    void removeServer(const NoString& line)
    {
        NoString username = No::token(line, 1);
        NoString sNetwork = No::token(line, 2);
        NoString sServer = No::tokens(line, 3);
        ushort port = No::token(line, 4).toUShort();
        NoString pass = No::token(line, 5);

        if (sServer.empty()) {
            putModule("Usage: removeServer <username> <network> <server>");
            return;
        }

        NoUser* user = FindUser(username);
        if (!user)
            return;

        NoNetwork* network = FindNetwork(user, sNetwork);
        if (!network) {
            return;
        }

        if (network->removeServer(sServer, port, pass))
            putModule("Deleted IRC Server [" + sServer + "] for network [" + sNetwork + "] for user [" + user->userName() + "].");
        else
            putModule("Could not delete IRC server [" + sServer + "] for network [" + sNetwork + "] for user [" +
                      user->userName() + "].");
    }

    void ReconnectUser(const NoString& line)
    {
        NoString userName = No::token(line, 1);
        NoString sNetwork = No::token(line, 2);

        if (sNetwork.empty()) {
            putModule("Usage: Reconnect <username> <network>");
            return;
        }

        NoUser* user = FindUser(userName);
        if (!user) {
            putModule("User [" + userName + "] not found.");
            return;
        }

        NoNetwork* network = FindNetwork(user, sNetwork);
        if (!network) {
            return;
        }

        NoIrcSocket* socket = network->ircSocket();
        // cancel connection attempt:
        if (socket && !socket->isConnected()) {
            socket->close();
        }
        // or close existing connection:
        else if (socket) {
            socket->quit();
        }

        // then reconnect
        network->setEnabled(true);

        putModule("Queued network [" + sNetwork + "] for user [" + user->userName() + "] for a reconnect.");
    }

    void DisconnectUser(const NoString& line)
    {
        NoString userName = No::token(line, 1);
        NoString sNetwork = No::token(line, 2);

        if (sNetwork.empty()) {
            putModule("Usage: Disconnect <username> <network>");
            return;
        }

        NoUser* user = FindUser(userName);
        if (!user) {
            putModule("User [" + userName + "] not found.");
            return;
        }

        NoNetwork* network = FindNetwork(user, sNetwork);
        if (!network) {
            return;
        }

        network->setEnabled(false);
        putModule("Closed IRC connection for network [" + sNetwork + "] on user [" + userName + "].");
    }

    void ListCTCP(const NoString& line)
    {
        NoString userName = No::tokens(line, 1);

        if (userName.empty()) {
            userName = NoModule::user()->userName();
        }
        NoUser* user = FindUser(userName);
        if (!user)
            return;

        const NoStringMap& msCTCPReplies = user->ctcpReplies();
        NoTable Table;
        Table.addColumn("Request");
        Table.addColumn("Reply");
        for (NoStringMap::const_iterator it = msCTCPReplies.begin(); it != msCTCPReplies.end(); ++it) {
            Table.addRow();
            Table.setValue("Request", it->first);
            Table.setValue("Reply", it->second);
        }

        if (Table.isEmpty()) {
            putModule("No CTCP replies for user [" + user->userName() + "] configured!");
        } else {
            putModule("CTCP replies for user [" + user->userName() + "]:");
            putModule(Table);
        }
    }

    void AddCTCP(const NoString& line)
    {
        NoString userName = No::token(line, 1);
        NoString sCTCPRequest = No::token(line, 2);
        NoString sCTCPReply = No::tokens(line, 3);

        if (sCTCPRequest.empty()) {
            sCTCPRequest = userName;
            sCTCPReply = No::tokens(line, 2);
            userName = user()->userName();
        }
        if (sCTCPRequest.empty()) {
            putModule("Usage: AddCTCP [user] [request] [reply]");
            putModule("This will cause ZNC to reply to the CTCP instead of forwarding it to clients.");
            putModule("An empty reply will cause the CTCP request to be blocked.");
            return;
        }

        NoUser* user = FindUser(userName);
        if (!user)
            return;

        if (user->addCtcpReply(sCTCPRequest, sCTCPReply))
            putModule("Added!");
        else
            putModule("Error!");
    }

    void DelCTCP(const NoString& line)
    {
        NoString userName = No::token(line, 1);
        NoString sCTCPRequest = No::tokens(line, 2);

        if (sCTCPRequest.empty()) {
            sCTCPRequest = userName;
            userName = user()->userName();
        }
        NoUser* user = FindUser(userName);
        if (!user)
            return;

        if (sCTCPRequest.empty()) {
            putModule("Usage: DelCTCP [user] [request]");
            return;
        }

        if (user->removeCtcpReply(sCTCPRequest))
            putModule("Successfully removed [" + sCTCPRequest + "] for user [" + user->userName() + "].");
        else
            putModule("Error: [" + sCTCPRequest + "] not found for user [" + user->userName() + "]!");
    }

    void LoadModuleFor(NoModuleLoader* Modules, const NoString& name, const NoString& args, No::ModuleType type, NoUser* user, NoNetwork* network)
    {
        if (user->denyLoadMod() && !NoModule::user()->isAdmin()) {
            putModule("Loading modules has been disabled.");
            return;
        }

        NoString sModRet;
        NoModule* mod = Modules->findModule(name);
        if (!mod) {
            if (!Modules->loadModule(name, args, type, user, network, sModRet)) {
                putModule("Unable to load module [" + name + "] [" + sModRet + "]");
            } else {
                putModule("Loaded module [" + name + "]");
            }
        } else if (mod->args() != args) {
            if (!Modules->reloadModule(name, args, user, network, sModRet)) {
                putModule("Unable to reload module [" + name + "] [" + sModRet + "]");
            } else {
                putModule("Reloaded module [" + name + "]");
            }
        } else {
            putModule("Unable to load module [" + name + "] because it is already loaded");
        }
    }

    void LoadModuleForUser(const NoString& line)
    {
        NoString username = No::token(line, 1);
        NoString name = No::token(line, 2);
        NoString args = No::tokens(line, 3);

        if (name.empty()) {
            putModule("Usage: LoadModule <username> <modulename> [args]");
            return;
        }

        NoUser* user = FindUser(username);
        if (!user)
            return;

        LoadModuleFor(user->loader(), name, args, No::UserModule, user, nullptr);
    }

    void LoadModuleForNetwork(const NoString& line)
    {
        NoString username = No::token(line, 1);
        NoString sNetwork = No::token(line, 2);
        NoString name = No::token(line, 3);
        NoString args = No::tokens(line, 4);

        if (name.empty()) {
            putModule("Usage: LoadNetModule <username> <network> <modulename> [args]");
            return;
        }

        NoUser* user = FindUser(username);
        if (!user)
            return;

        NoNetwork* network = FindNetwork(user, sNetwork);
        if (!network) {
            return;
        }

        LoadModuleFor(network->loader(), name, args, No::NetworkModule, user, network);
    }

    void UnLoadModuleFor(NoModuleLoader* Modules, const NoString& name, NoUser* user)
    {
        if (user->denyLoadMod() && !NoModule::user()->isAdmin()) {
            putModule("Loading modules has been disabled.");
            return;
        }

        if (Modules->findModule(name) == this) {
            putModule("Please use /znc unloadmod " + name);
            return;
        }

        NoString sModRet;
        if (!Modules->unloadModule(name, sModRet)) {
            putModule("Unable to unload module [" + name + "] [" + sModRet + "]");
        } else {
            putModule("Unloaded module [" + name + "]");
        }
    }

    void UnLoadModuleForUser(const NoString& line)
    {
        NoString username = No::token(line, 1);
        NoString name = No::token(line, 2);

        if (name.empty()) {
            putModule("Usage: UnloadModule <username> <modulename>");
            return;
        }

        NoUser* user = FindUser(username);
        if (!user)
            return;

        UnLoadModuleFor(user->loader(), name, user);
    }

    void UnLoadModuleForNetwork(const NoString& line)
    {
        NoString username = No::token(line, 1);
        NoString sNetwork = No::token(line, 2);
        NoString name = No::token(line, 3);

        if (name.empty()) {
            putModule("Usage: UnloadNetModule <username> <network> <modulename>");
            return;
        }

        NoUser* user = FindUser(username);
        if (!user)
            return;

        NoNetwork* network = FindNetwork(user, sNetwork);
        if (!network) {
            return;
        }

        UnLoadModuleFor(network->loader(), name, user);
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
                Table.setValue("Name", mod->name());
                Table.setValue("Arguments", mod->args());
            }

            putModule(Table);
        }
    }

    void ListModulesForUser(const NoString& line)
    {
        NoString username = No::token(line, 1);

        if (username.empty()) {
            putModule("Usage: ListMods <username>");
            return;
        }

        NoUser* user = FindUser(username);
        if (!user)
            return;

        ListModulesFor(user->loader(), "User [" + user->userName() + "]");
    }

    void ListModulesForNetwork(const NoString& line)
    {
        NoString username = No::token(line, 1);
        NoString sNetwork = No::token(line, 2);

        if (sNetwork.empty()) {
            putModule("Usage: ListNetMods <username> <network>");
            return;
        }

        NoUser* user = FindUser(username);
        if (!user)
            return;

        NoNetwork* network = FindNetwork(user, sNetwork);
        if (!network) {
            return;
        }

        ListModulesFor(network->loader(), "Network [" + network->name() + "] of user [" + user->userName() + "]");
    }

public:
    MODCONSTRUCTOR(NoAdminMod)
    {
        addCommand("Help",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::onHelpCommand),
                   "[command] [variable]",
                   "Prints help for matching commands and variables");
        addCommand("Get",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::Get),
                   "<variable> [username]",
                   "Prints the variable's value for the given or current user");
        addCommand("Set", static_cast<NoModule::CommandFunction>(&NoAdminMod::Set), "<variable> <username> <value>", "Sets the variable's value for the given user");
        addCommand("GetNetwork",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::GetNetwork),
                   "<variable> [username] [network]",
                   "Prints the variable's value for the given network");
        addCommand("SetNetwork",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::SetNetwork),
                   "<variable> <username> <network> <value>",
                   "Sets the variable's value for the given network");
        addCommand("GetChan",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::GetChan),
                   "<variable> [username] <network> <chan>",
                   "Prints the variable's value for the given channel");
        addCommand("SetChan",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::SetChan),
                   "<variable> <username> <network> <chan> <value>",
                   "Sets the variable's value for the given channel");
        addCommand("addChannel",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::addChannel),
                   "<username> <network> <chan>",
                   "Adds a new channel");
        addCommand("removeChannel",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::removeChannel),
                   "<username> <network> <chan>",
                   "Deletes a channel");
        addCommand("ListUsers", static_cast<NoModule::CommandFunction>(&NoAdminMod::ListUsers), "", "Lists users");
        addCommand("AddUser", static_cast<NoModule::CommandFunction>(&NoAdminMod::AddUser), "<username> <password>", "Adds a new user");
        addCommand("DelUser",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::DelUser),
                   "<username>",
                   "Deletes a user");
        addCommand("CloneUser",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::CloneUser),
                   "<old username> <new username>",
                   "Clones a user");
        addCommand("AddServer",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::AddServer),
                   "<username> <network> <server>",
                   "Adds a new IRC server for the given or current user");
        addCommand("removeServer",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::removeServer),
                   "<username> <network> <server>",
                   "Deletes an IRC server from the given or current user");
        addCommand("Reconnect",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::ReconnectUser),
                   "<username> <network>",
                   "Cycles the user's IRC server connection");
        addCommand("Disconnect",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::DisconnectUser),
                   "<username> <network>",
                   "Disconnects the user from their IRC server");
        addCommand("LoadModule",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::LoadModuleForUser),
                   "<username> <modulename> [args]",
                   "Loads a Module for a user");
        addCommand("UnLoadModule",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::UnLoadModuleForUser),
                   "<username> <modulename>",
                   "Removes a Module of a user");
        addCommand("ListMods", static_cast<NoModule::CommandFunction>(&NoAdminMod::ListModulesForUser), "<username>", "Get the list of modules for a user");
        addCommand("LoadNetModule",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::LoadModuleForNetwork),
                   "<username> <network> <modulename> [args]",
                   "Loads a Module for a network");
        addCommand("UnLoadNetModule",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::UnLoadModuleForNetwork),
                   "<username> <network> <modulename>",
                   "Removes a Module of a network");
        addCommand("ListNetMods",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::ListModulesForNetwork),
                   "<username> <network>",
                   "Get the list of modules for a network");
        addCommand("ListCTCPs",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::ListCTCP),
                   "<username>",
                   "List the configured CTCP replies");
        addCommand("AddCTCP",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::AddCTCP),
                   "<username> <ctcp> [reply]",
                   "Configure a new CTCP reply");
        addCommand("DelCTCP",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::DelCTCP),
                   "<username> <ctcp>",
                   "Remove a CTCP reply");

        // network commands
        addCommand("AddNetwork",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::AddNetwork),
                   "[username] <network>",
                   "Add a network for a user");
        addCommand("DelNetwork",
                   static_cast<NoModule::CommandFunction>(&NoAdminMod::DelNetwork),
                   "[username] <network>",
                   "Delete a network for a user");
        addCommand("ListNetworks", static_cast<NoModule::CommandFunction>(&NoAdminMod::ListNetworks), "[username]", "List all networks for a user");
    }
};

template <>
void no_moduleInfo<NoAdminMod>(NoModuleInfo& info)
{
    info.setWikiPage("controlpanel");
}

USERMODULEDEFS(NoAdminMod, "Dynamic configuration through IRC. Allows editing only yourself if you're not ZNC admin.")
