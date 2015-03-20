/*
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
#include <no/noircconnection.h>
#include <no/noapp.h>

template <std::size_t N> struct array_size_helper
{
    char __place_holder[N];
};

template <class T, std::size_t N> static array_size_helper<N> array_size(T (&)[N]) { return array_size_helper<N>(); }

#define ARRAY_SIZE(array) sizeof(array_size((array)))

class NoAdminMod : public NoModule
{
    using NoModule::PutModule;

    void PrintVarsHelp(const NoString& sFilter, const char* vars[][2], uint uSize, const NoString& sDescription)
    {
        NoTable VarTable;
        VarTable.AddColumn("Type");
        VarTable.AddColumn("Variables");
        std::map<const char*, NoStringVector> mvsTypedVariables;
        for (uint i = 0; i != uSize; ++i) {
            NoString sVar = NoString(vars[i][0]).toLower();
            if (sFilter.empty() || sVar.startsWith(sFilter) || sVar.wildCmp(sFilter)) {
                mvsTypedVariables[vars[i][1]].emplace_back(vars[i][0]);
            }
        }
        for (const auto& i : mvsTypedVariables) {
            VarTable.AddRow();
            VarTable.SetCell("Type", i.first);
            VarTable.SetCell("Variables", NoString(", ").join(i.second.cbegin(), i.second.cend()));
        }
        if (!VarTable.empty()) {
            PutModule(sDescription);
            PutModule(VarTable);
        }
    }

    void PrintHelp(const NoString& sLine)
    {
        HandleHelpCommand(sLine);

        static const char* str = "String";
        static const char* boolean = "Boolean (true/false)";
        static const char* integer = "Integer";
        static const char* doublenum = "Double";

        const NoString sCmdFilter = sLine.token(1);
        const NoString sVarFilter = sLine.tokens(2).toLower();

        if (sCmdFilter.empty() || sCmdFilter.startsWith("Set") || sCmdFilter.startsWith("Get")) {
            static const char* vars[][2] = {
                { "Nick", str },
                { "Altnick", str },
                { "Ident", str },
                { "RealName", str },
                { "BindHost", str },
                { "MultiClients", boolean },
                { "DenyLoadMod", boolean },
                { "DenySetBindHost", boolean },
                { "DefaultChanModes", str },
                { "QuitMsg", str },
                { "BufferCount", integer },
                { "AutoClearChanBuffer", boolean },
                { "AutoClearQueryBuffer", boolean },
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
            PutModule("You can use $user as the user name and $network as the network name for modifying your own "
                      "user and network.");
    }

    NoUser* FindUser(const NoString& sUsername)
    {
        if (sUsername.equals("$me") || sUsername.equals("$user")) return GetUser();
        NoUser* pUser = NoApp::Get().FindUser(sUsername);
        if (!pUser) {
            PutModule("Error: User [" + sUsername + "] not found.");
            return nullptr;
        }
        if (pUser != GetUser() && !GetUser()->IsAdmin()) {
            PutModule("Error: You need to have admin rights to modify other users!");
            return nullptr;
        }
        return pUser;
    }

    NoNetwork* FindNetwork(NoUser* pUser, const NoString& sNetwork)
    {
        if (sNetwork.equals("$net") || sNetwork.equals("$network")) {
            if (pUser != GetUser()) {
                PutModule("Error: You cannot use " + sNetwork + " to modify other users!");
                return nullptr;
            }
            return NoModule::GetNetwork();
        }
        NoNetwork* pNetwork = pUser->FindNetwork(sNetwork);
        if (!pNetwork) {
            PutModule("Error: [" + pUser->GetUserName() + "] does not have a network named [" + sNetwork + "].");
        }
        return pNetwork;
    }

    void Get(const NoString& sLine)
    {
        const NoString sVar = sLine.token(1).toLower();
        NoString sUsername = sLine.tokens(2);
        NoUser* pUser;

        if (sVar.empty()) {
            PutModule("Usage: Get <variable> [username]");
            return;
        }

        if (sUsername.empty()) {
            pUser = GetUser();
        } else {
            pUser = FindUser(sUsername);
        }

        if (!pUser) return;

        if (sVar == "nick")
            PutModule("Nick = " + pUser->GetNick());
        else if (sVar == "altnick")
            PutModule("AltNick = " + pUser->GetAltNick());
        else if (sVar == "ident")
            PutModule("Ident = " + pUser->GetIdent());
        else if (sVar == "realname")
            PutModule("RealName = " + pUser->GetRealName());
        else if (sVar == "bindhost")
            PutModule("BindHost = " + pUser->GetBindHost());
        else if (sVar == "multiclients")
            PutModule("MultiClients = " + NoString(pUser->MultiClients()));
        else if (sVar == "denyloadmod")
            PutModule("DenyLoadMod = " + NoString(pUser->DenyLoadMod()));
        else if (sVar == "denysetbindhost")
            PutModule("DenySetBindHost = " + NoString(pUser->DenySetBindHost()));
        else if (sVar == "defaultchanmodes")
            PutModule("DefaultChanModes = " + pUser->GetDefaultChanModes());
        else if (sVar == "quitmsg")
            PutModule("QuitMsg = " + pUser->GetQuitMsg());
        else if (sVar == "buffercount")
            PutModule("BufferCount = " + NoString(pUser->GetBufferCount()));
        else if (sVar == "keepbuffer")
            PutModule("KeepBuffer = " +
                      NoString(!pUser->AutoClearChanBuffer())); // XXX compatibility crap, added in 0.207
        else if (sVar == "autoclearchanbuffer")
            PutModule("AutoClearChanBuffer = " + NoString(pUser->AutoClearChanBuffer()));
        else if (sVar == "autoclearquerybuffer")
            PutModule("AutoClearQueryBuffer = " + NoString(pUser->AutoClearQueryBuffer()));
        else if (sVar == "maxjoins")
            PutModule("MaxJoins = " + NoString(pUser->MaxJoins()));
        else if (sVar == "maxnetworks")
            PutModule("MaxNetworks = " + NoString(pUser->MaxNetworks()));
        else if (sVar == "maxquerybuffers")
            PutModule("MaxQueryBuffers = " + NoString(pUser->MaxQueryBuffers()));
        else if (sVar == "jointries")
            PutModule("JoinTries = " + NoString(pUser->JoinTries()));
        else if (sVar == "timezone")
            PutModule("Timezone = " + pUser->GetTimezone());
        else if (sVar == "appendtimestamp")
            PutModule("AppendTimestamp = " + NoString(pUser->GetTimestampAppend()));
        else if (sVar == "prependtimestamp")
            PutModule("PrependTimestamp = " + NoString(pUser->GetTimestampPrepend()));
        else if (sVar == "timestampformat")
            PutModule("TimestampFormat = " + pUser->GetTimestampFormat());
        else if (sVar == "dccbindhost")
            PutModule("DCCBindHost = " + NoString(pUser->GetDCCBindHost()));
        else if (sVar == "admin")
            PutModule("Admin = " + NoString(pUser->IsAdmin()));
        else if (sVar == "statusprefix")
            PutModule("StatusPrefix = " + pUser->GetStatusPrefix());
#ifdef HAVE_ICU
        else if (sVar == "clientencoding")
            PutModule("ClientEncoding = " + pUser->GetClientEncoding());
#endif
        else
            PutModule("Error: Unknown variable");
    }

    void Set(const NoString& sLine)
    {
        const NoString sVar = sLine.token(1).toLower();
        NoString sUserName = sLine.token(2);
        NoString sValue = sLine.tokens(3);

        if (sValue.empty()) {
            PutModule("Usage: Set <variable> <username> <value>");
            return;
        }

        NoUser* pUser = FindUser(sUserName);
        if (!pUser) return;

        if (sVar == "nick") {
            pUser->SetNick(sValue);
            PutModule("Nick = " + sValue);
        } else if (sVar == "altnick") {
            pUser->SetAltNick(sValue);
            PutModule("AltNick = " + sValue);
        } else if (sVar == "ident") {
            pUser->SetIdent(sValue);
            PutModule("Ident = " + sValue);
        } else if (sVar == "realname") {
            pUser->SetRealName(sValue);
            PutModule("RealName = " + sValue);
        } else if (sVar == "bindhost") {
            if (!pUser->DenySetBindHost() || GetUser()->IsAdmin()) {
                if (sValue.equals(GetUser()->GetBindHost())) {
                    PutModule("This bind host is already set!");
                    return;
                }

                const NoStringVector& vsHosts = NoApp::Get().GetBindHosts();
                if (!GetUser()->IsAdmin() && !vsHosts.empty()) {
                    NoStringVector::const_iterator it;
                    bool bFound = false;

                    for (it = vsHosts.begin(); it != vsHosts.end(); ++it) {
                        if (sValue.equals(*it)) {
                            bFound = true;
                            break;
                        }
                    }

                    if (!bFound) {
                        PutModule("You may not use this bind host. See /msg " + GetUser()->GetStatusPrefix() +
                                  "status ListBindHosts for a list");
                        return;
                    }
                }

                pUser->SetBindHost(sValue);
                PutModule("BindHost = " + sValue);
            } else {
                PutModule("Access denied!");
            }
        } else if (sVar == "multiclients") {
            bool b = sValue.toBool();
            pUser->SetMultiClients(b);
            PutModule("MultiClients = " + NoString(b));
        } else if (sVar == "denyloadmod") {
            if (GetUser()->IsAdmin()) {
                bool b = sValue.toBool();
                pUser->SetDenyLoadMod(b);
                PutModule("DenyLoadMod = " + NoString(b));
            } else {
                PutModule("Access denied!");
            }
        } else if (sVar == "denysetbindhost") {
            if (GetUser()->IsAdmin()) {
                bool b = sValue.toBool();
                pUser->SetDenySetBindHost(b);
                PutModule("DenySetBindHost = " + NoString(b));
            } else {
                PutModule("Access denied!");
            }
        } else if (sVar == "defaultchanmodes") {
            pUser->SetDefaultChanModes(sValue);
            PutModule("DefaultChanModes = " + sValue);
        } else if (sVar == "quitmsg") {
            pUser->SetQuitMsg(sValue);
            PutModule("QuitMsg = " + sValue);
        } else if (sVar == "buffercount") {
            uint i = sValue.toUInt();
            // Admins don't have to honour the buffer limit
            if (pUser->SetBufferCount(i, GetUser()->IsAdmin())) {
                PutModule("BufferCount = " + sValue);
            } else {
                PutModule("Setting failed, limit is " + NoString(NoApp::Get().GetMaxBufferSize()));
            }
        } else if (sVar == "keepbuffer") { // XXX compatibility crap, added in 0.207
            bool b = !sValue.toBool();
            pUser->SetAutoClearChanBuffer(b);
            PutModule("AutoClearChanBuffer = " + NoString(b));
        } else if (sVar == "autoclearchanbuffer") {
            bool b = sValue.toBool();
            pUser->SetAutoClearChanBuffer(b);
            PutModule("AutoClearChanBuffer = " + NoString(b));
        } else if (sVar == "autoclearquerybuffer") {
            bool b = sValue.toBool();
            pUser->SetAutoClearQueryBuffer(b);
            PutModule("AutoClearQueryBuffer = " + NoString(b));
        } else if (sVar == "password") {
            const NoString sSalt = NoUtils::GetSalt();
            const NoString sHash = NoUser::SaltedHash(sValue, sSalt);
            pUser->SetPass(sHash, NoUser::HASH_DEFAULT, sSalt);
            PutModule("Password has been changed!");
        } else if (sVar == "maxjoins") {
            uint i = sValue.toUInt();
            pUser->SetMaxJoins(i);
            PutModule("MaxJoins = " + NoString(pUser->MaxJoins()));
        } else if (sVar == "maxnetworks") {
            if (GetUser()->IsAdmin()) {
                uint i = sValue.toUInt();
                pUser->SetMaxNetworks(i);
                PutModule("MaxNetworks = " + sValue);
            } else {
                PutModule("Access denied!");
            }
        } else if (sVar == "maxquerybuffers") {
            uint i = sValue.toUInt();
            pUser->SetMaxQueryBuffers(i);
            PutModule("MaxQueryBuffers = " + sValue);
        } else if (sVar == "jointries") {
            uint i = sValue.toUInt();
            pUser->SetJoinTries(i);
            PutModule("JoinTries = " + NoString(pUser->JoinTries()));
        } else if (sVar == "timezone") {
            pUser->SetTimezone(sValue);
            PutModule("Timezone = " + pUser->GetTimezone());
        } else if (sVar == "admin") {
            if (GetUser()->IsAdmin() && pUser != GetUser()) {
                bool b = sValue.toBool();
                pUser->SetAdmin(b);
                PutModule("Admin = " + NoString(pUser->IsAdmin()));
            } else {
                PutModule("Access denied!");
            }
        } else if (sVar == "prependtimestamp") {
            bool b = sValue.toBool();
            pUser->SetTimestampPrepend(b);
            PutModule("PrependTimestamp = " + NoString(b));
        } else if (sVar == "appendtimestamp") {
            bool b = sValue.toBool();
            pUser->SetTimestampAppend(b);
            PutModule("AppendTimestamp = " + NoString(b));
        } else if (sVar == "timestampformat") {
            pUser->SetTimestampFormat(sValue);
            PutModule("TimestampFormat = " + sValue);
        } else if (sVar == "dccbindhost") {
            if (!pUser->DenySetBindHost() || GetUser()->IsAdmin()) {
                pUser->SetDCCBindHost(sValue);
                PutModule("DCCBindHost = " + sValue);
            } else {
                PutModule("Access denied!");
            }
        } else if (sVar == "statusprefix") {
            if (sVar.find_first_of(" \t\n") == NoString::npos) {
                pUser->SetStatusPrefix(sValue);
                PutModule("StatusPrefix = " + sValue);
            } else {
                PutModule("That would be a bad idea!");
            }
        }
#ifdef HAVE_ICU
        else if (sVar == "clientencoding") {
            pUser->SetClientEncoding(sValue);
            PutModule("ClientEncoding = " + sValue);
        }
#endif
        else
            PutModule("Error: Unknown variable");
    }

    void GetNetwork(const NoString& sLine)
    {
        const NoString sVar = sLine.token(1).toLower();
        const NoString sUsername = sLine.token(2);
        const NoString sNetwork = sLine.token(3);

        NoNetwork* pNetwork = nullptr;

        if (sUsername.empty()) {
            pNetwork = NoModule::GetNetwork();
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
            PutModule("Usage: GetNetwork <variable> <username> <network>");
            return;
        }

        if (sVar.equals("nick")) {
            PutModule("Nick = " + pNetwork->GetNick());
        } else if (sVar.equals("altnick")) {
            PutModule("AltNick = " + pNetwork->GetAltNick());
        } else if (sVar.equals("ident")) {
            PutModule("Ident = " + pNetwork->GetIdent());
        } else if (sVar.equals("realname")) {
            PutModule("RealName = " + pNetwork->GetRealName());
        } else if (sVar.equals("bindhost")) {
            PutModule("BindHost = " + pNetwork->GetBindHost());
        } else if (sVar.equals("floodrate")) {
            PutModule("FloodRate = " + NoString(pNetwork->GetFloodRate()));
        } else if (sVar.equals("floodburst")) {
            PutModule("FloodBurst = " + NoString(pNetwork->GetFloodBurst()));
        } else if (sVar.equals("joindelay")) {
            PutModule("JoinDelay = " + NoString(pNetwork->GetJoinDelay()));
#ifdef HAVE_ICU
        } else if (sVar.equals("encoding")) {
            PutModule("Encoding = " + pNetwork->GetEncoding());
#endif
        } else if (sVar.equals("quitmsg")) {
            PutModule("QuitMsg = " + pNetwork->GetQuitMsg());
        } else {
            PutModule("Error: Unknown variable");
        }
    }

    void SetNetwork(const NoString& sLine)
    {
        const NoString sVar = sLine.token(1).toLower();
        const NoString sUsername = sLine.token(2);
        const NoString sNetwork = sLine.token(3);
        const NoString sValue = sLine.tokens(4);

        NoUser* pUser = nullptr;
        NoNetwork* pNetwork = nullptr;

        if (sUsername.empty()) {
            pUser = GetUser();
            pNetwork = NoModule::GetNetwork();
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
            PutModule("Usage: SetNetwork <variable> <username> <network> <value>");
            return;
        }

        if (sVar.equals("nick")) {
            pNetwork->SetNick(sValue);
            PutModule("Nick = " + pNetwork->GetNick());
        } else if (sVar.equals("altnick")) {
            pNetwork->SetAltNick(sValue);
            PutModule("AltNick = " + pNetwork->GetAltNick());
        } else if (sVar.equals("ident")) {
            pNetwork->SetIdent(sValue);
            PutModule("Ident = " + pNetwork->GetIdent());
        } else if (sVar.equals("realname")) {
            pNetwork->SetRealName(sValue);
            PutModule("RealName = " + pNetwork->GetRealName());
        } else if (sVar.equals("bindhost")) {
            if (!pUser->DenySetBindHost() || GetUser()->IsAdmin()) {
                if (sValue.equals(pNetwork->GetBindHost())) {
                    PutModule("This bind host is already set!");
                    return;
                }

                const NoStringVector& vsHosts = NoApp::Get().GetBindHosts();
                if (!GetUser()->IsAdmin() && !vsHosts.empty()) {
                    NoStringVector::const_iterator it;
                    bool bFound = false;

                    for (it = vsHosts.begin(); it != vsHosts.end(); ++it) {
                        if (sValue.equals(*it)) {
                            bFound = true;
                            break;
                        }
                    }

                    if (!bFound) {
                        PutModule("You may not use this bind host. See /msg " + GetUser()->GetStatusPrefix() +
                                  "status ListBindHosts for a list");
                        return;
                    }
                }

                pNetwork->SetBindHost(sValue);
                PutModule("BindHost = " + sValue);
            } else {
                PutModule("Access denied!");
            }
        } else if (sVar.equals("floodrate")) {
            pNetwork->SetFloodRate(sValue.toDouble());
            PutModule("FloodRate = " + NoString(pNetwork->GetFloodRate()));
        } else if (sVar.equals("floodburst")) {
            pNetwork->SetFloodBurst(sValue.toUShort());
            PutModule("FloodBurst = " + NoString(pNetwork->GetFloodBurst()));
        } else if (sVar.equals("joindelay")) {
            pNetwork->SetJoinDelay(sValue.toUShort());
            PutModule("JoinDelay = " + NoString(pNetwork->GetJoinDelay()));
#ifdef HAVE_ICU
        } else if (sVar.equals("encoding")) {
            pNetwork->SetEncoding(sValue);
            PutModule("Encoding = " + pNetwork->GetEncoding());
#endif
        } else if (sVar.equals("quitmsg")) {
            pNetwork->SetQuitMsg(sValue);
            PutModule("QuitMsg = " + pNetwork->GetQuitMsg());
        } else {
            PutModule("Error: Unknown variable");
        }
    }

    void AddChan(const NoString& sLine)
    {
        const NoString sUsername = sLine.token(1);
        const NoString sNetwork = sLine.token(2);
        const NoString sChan = sLine.token(3);

        if (sChan.empty()) {
            PutModule("Usage: AddChan <username> <network> <channel>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser) return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        if (pNetwork->FindChan(sChan)) {
            PutModule("Error: [" + sUsername + "] already has a channel named [" + sChan + "].");
            return;
        }

        NoChannel* pChan = new NoChannel(sChan, pNetwork, true);
        if (pNetwork->AddChan(pChan))
            PutModule("Channel [" + pChan->getName() + "] for user [" + sUsername + "] added.");
        else
            PutModule("Could not add channel [" + sChan + "] for user [" + sUsername + "], does it already exist?");
    }

    void DelChan(const NoString& sLine)
    {
        const NoString sUsername = sLine.token(1);
        const NoString sNetwork = sLine.token(2);
        const NoString sChan = sLine.token(3);

        if (sChan.empty()) {
            PutModule("Usage: DelChan <username> <network> <channel>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser) return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        std::vector<NoChannel*> vChans = pNetwork->FindChans(sChan);
        if (vChans.empty()) {
            PutModule("Error: User [" + sUsername + "] does not have any channel matching [" + sChan + "].");
            return;
        }

        NoStringVector vsNames;
        for (const NoChannel* pChan : vChans) {
            const NoString& sName = pChan->getName();
            vsNames.push_back(sName);
            pNetwork->PutIRC("PART " + sName);
            pNetwork->DelChan(sName);
        }

        PutModule("Channel(s) [" + NoString(",").join(vsNames.begin(), vsNames.end()) + "] for user [" + sUsername +
                  "] deleted.");
    }

    void GetChan(const NoString& sLine)
    {
        const NoString sVar = sLine.token(1).toLower();
        NoString sUsername = sLine.token(2);
        NoString sNetwork = sLine.token(3);
        NoString sChan = sLine.tokens(4);

        if (sChan.empty()) {
            PutModule("Usage: GetChan <variable> <username> <network> <chan>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser) return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        std::vector<NoChannel*> vChans = pNetwork->FindChans(sChan);
        if (vChans.empty()) {
            PutModule("Error: No channel(s) matching [" + sChan + "] found.");
            return;
        }

        for (NoChannel* pChan : vChans) {
            if (sVar == "defmodes") {
                PutModule(pChan->getName() + ": DefModes = " + pChan->getDefaultModes());
            } else if (sVar == "buffer") {
                NoString sValue(pChan->getBufferCount());
                if (!pChan->hasBufferCountSet()) {
                    sValue += " (default)";
                }
                PutModule(pChan->getName() + ": Buffer = " + sValue);
            } else if (sVar == "inconfig") {
                PutModule(pChan->getName() + ": InConfig = " + NoString(pChan->inConfig()));
            } else if (sVar == "keepbuffer") {
                PutModule(pChan->getName() + ": KeepBuffer = " +
                          NoString(!pChan->autoClearChanBuffer())); // XXX compatibility crap, added in 0.207
            } else if (sVar == "autoclearchanbuffer") {
                NoString sValue(pChan->autoClearChanBuffer());
                if (!pChan->hasAutoClearChanBufferSet()) {
                    sValue += " (default)";
                }
                PutModule(pChan->getName() + ": AutoClearChanBuffer = " + sValue);
            } else if (sVar == "detached") {
                PutModule(pChan->getName() + ": Detached = " + NoString(pChan->isDetached()));
            } else if (sVar == "key") {
                PutModule(pChan->getName() + ": Key = " + pChan->getKey());
            } else {
                PutModule("Error: Unknown variable");
                return;
            }
        }
    }

    void SetChan(const NoString& sLine)
    {
        const NoString sVar = sLine.token(1).toLower();
        NoString sUsername = sLine.token(2);
        NoString sNetwork = sLine.token(3);
        NoString sChan = sLine.token(4);
        NoString sValue = sLine.tokens(5);

        if (sValue.empty()) {
            PutModule("Usage: SetChan <variable> <username> <network> <chan> <value>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser) return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        std::vector<NoChannel*> vChans = pNetwork->FindChans(sChan);
        if (vChans.empty()) {
            PutModule("Error: No channel(s) matching [" + sChan + "] found.");
            return;
        }

        for (NoChannel* pChan : vChans) {
            if (sVar == "defmodes") {
                pChan->setDefaultModes(sValue);
                PutModule(pChan->getName() + ": DefModes = " + sValue);
            } else if (sVar == "buffer") {
                uint i = sValue.toUInt();
                // Admins don't have to honour the buffer limit
                if (pChan->setBufferCount(i, GetUser()->IsAdmin())) {
                    PutModule(pChan->getName() + ": Buffer = " + sValue);
                } else {
                    PutModule("Setting failed, limit is " + NoString(NoApp::Get().GetMaxBufferSize()));
                    return;
                }
            } else if (sVar == "inconfig") {
                bool b = sValue.toBool();
                pChan->setInConfig(b);
                PutModule(pChan->getName() + ": InConfig = " + NoString(b));
            } else if (sVar == "keepbuffer") { // XXX compatibility crap, added in 0.207
                bool b = !sValue.toBool();
                pChan->setAutoClearChanBuffer(b);
                PutModule(pChan->getName() + ": AutoClearChanBuffer = " + NoString(b));
            } else if (sVar == "autoclearchanbuffer") {
                bool b = sValue.toBool();
                pChan->setAutoClearChanBuffer(b);
                PutModule(pChan->getName() + ": AutoClearChanBuffer = " + NoString(b));
            } else if (sVar == "detached") {
                bool b = sValue.toBool();
                if (pChan->isDetached() != b) {
                    if (b)
                        pChan->detachUser();
                    else
                        pChan->attachUser();
                }
                PutModule(pChan->getName() + ": Detached = " + NoString(b));
            } else if (sVar == "key") {
                pChan->setKey(sValue);
                PutModule(pChan->getName() + ": Key = " + sValue);
            } else {
                PutModule("Error: Unknown variable");
                return;
            }
        }
    }

    void ListUsers(const NoString&)
    {
        if (!GetUser()->IsAdmin()) return;

        const std::map<NoString, NoUser*>& msUsers = NoApp::Get().GetUserMap();
        NoTable Table;
        Table.AddColumn("Username");
        Table.AddColumn("Realname");
        Table.AddColumn("IsAdmin");
        Table.AddColumn("Nick");
        Table.AddColumn("AltNick");
        Table.AddColumn("Ident");
        Table.AddColumn("BindHost");

        for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it) {
            Table.AddRow();
            Table.SetCell("Username", it->first);
            Table.SetCell("Realname", it->second->GetRealName());
            if (!it->second->IsAdmin())
                Table.SetCell("IsAdmin", "No");
            else
                Table.SetCell("IsAdmin", "Yes");
            Table.SetCell("Nick", it->second->GetNick());
            Table.SetCell("AltNick", it->second->GetAltNick());
            Table.SetCell("Ident", it->second->GetIdent());
            Table.SetCell("BindHost", it->second->GetBindHost());
        }

        PutModule(Table);
    }

    void AddUser(const NoString& sLine)
    {
        if (!GetUser()->IsAdmin()) {
            PutModule("Error: You need to have admin rights to add new users!");
            return;
        }

        const NoString sUsername = sLine.token(1), sPassword = sLine.token(2);
        if (sPassword.empty()) {
            PutModule("Usage: AddUser <username> <password>");
            return;
        }

        if (NoApp::Get().FindUser(sUsername)) {
            PutModule("Error: User [" + sUsername + "] already exists!");
            return;
        }

        NoUser* pNewUser = new NoUser(sUsername);
        NoString sSalt = NoUtils::GetSalt();
        pNewUser->SetPass(NoUser::SaltedHash(sPassword, sSalt), NoUser::HASH_DEFAULT, sSalt);

        NoString sErr;
        if (!NoApp::Get().AddUser(pNewUser, sErr)) {
            delete pNewUser;
            PutModule("Error: User not added! [" + sErr + "]");
            return;
        }

        PutModule("User [" + sUsername + "] added!");
        return;
    }

    void DelUser(const NoString& sLine)
    {
        if (!GetUser()->IsAdmin()) {
            PutModule("Error: You need to have admin rights to delete users!");
            return;
        }

        const NoString sUsername = sLine.tokens(1);
        if (sUsername.empty()) {
            PutModule("Usage: DelUser <username>");
            return;
        }

        NoUser* pUser = NoApp::Get().FindUser(sUsername);

        if (!pUser) {
            PutModule("Error: User [" + sUsername + "] does not exist!");
            return;
        }

        if (pUser == GetUser()) {
            PutModule("Error: You can't delete yourself!");
            return;
        }

        if (!NoApp::Get().DeleteUser(pUser->GetUserName())) {
            // This can't happen, because we got the user from FindUser()
            PutModule("Error: Internal error!");
            return;
        }

        PutModule("User " + sUsername + " deleted!");
        return;
    }

    void CloneUser(const NoString& sLine)
    {
        if (!GetUser()->IsAdmin()) {
            PutModule("Error: You need to have admin rights to add new users!");
            return;
        }

        const NoString sOldUsername = sLine.token(1), sNewUsername = sLine.tokens(2);

        if (sOldUsername.empty() || sNewUsername.empty()) {
            PutModule("Usage: CloneUser <old username> <new username>");
            return;
        }

        NoUser* pOldUser = NoApp::Get().FindUser(sOldUsername);

        if (!pOldUser) {
            PutModule("Error: User [" + sOldUsername + "] not found!");
            return;
        }

        NoUser* pNewUser = new NoUser(sNewUsername);
        NoString sError;
        if (!pNewUser->Clone(*pOldUser, sError)) {
            delete pNewUser;
            PutModule("Error: Cloning failed! [" + sError + "]");
            return;
        }

        if (!NoApp::Get().AddUser(pNewUser, sError)) {
            delete pNewUser;
            PutModule("Error: User not added! [" + sError + "]");
            return;
        }

        PutModule("User [" + sNewUsername + "] added!");
        return;
    }

    void AddNetwork(const NoString& sLine)
    {
        NoString sUser = sLine.token(1);
        NoString sNetwork = sLine.token(2);
        NoUser* pUser = GetUser();

        if (sNetwork.empty()) {
            sNetwork = sUser;
        } else {
            pUser = FindUser(sUser);
            if (!pUser) {
                PutModule("User [" + sUser + "] not found");
                return;
            }
        }

        if (sNetwork.empty()) {
            PutModule("Usage: AddNetwork [user] network");
            return;
        }

        if (!GetUser()->IsAdmin() && !pUser->HasSpaceForNewNetwork()) {
            PutStatus("Network number limit reached. Ask an admin to increase the limit for you, or delete unneeded "
                      "networks using /znc DelNetwork <name>");
            return;
        }

        if (pUser->FindNetwork(sNetwork)) {
            PutModule("[" + pUser->GetUserName() + "] already has a network with the name [" + sNetwork + "]");
            return;
        }

        NoString sNetworkAddError;
        if (pUser->AddNetwork(sNetwork, sNetworkAddError)) {
            PutModule("Network [" + sNetwork + "] added for user [" + pUser->GetUserName() + "].");
        } else {
            PutModule("Network [" + sNetwork + "] could not be added for user [" + pUser->GetUserName() + "]: " + sNetworkAddError);
        }
    }

    void DelNetwork(const NoString& sLine)
    {
        NoString sUser = sLine.token(1);
        NoString sNetwork = sLine.token(2);
        NoUser* pUser = GetUser();

        if (sNetwork.empty()) {
            sNetwork = sUser;
        } else {
            pUser = FindUser(sUser);
            if (!pUser) {
                return;
            }
        }

        if (sNetwork.empty()) {
            PutModule("Usage: DelNetwork [user] network");
            return;
        }

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        if (pNetwork == NoModule::GetNetwork()) {
            PutModule("The currently active network can be deleted via " + GetUser()->GetStatusPrefix() + "status");
            return;
        }

        if (pUser->DeleteNetwork(sNetwork)) {
            PutModule("Network [" + sNetwork + "] deleted on user [" + pUser->GetUserName() + "].");
        } else {
            PutModule("Network [" + sNetwork + "] could not be deleted for user [" + pUser->GetUserName() + "].");
        }
    }

    void ListNetworks(const NoString& sLine)
    {
        NoString sUser = sLine.token(1);
        NoUser* pUser = GetUser();

        if (!sUser.empty()) {
            pUser = FindUser(sUser);
            if (!pUser) {
                return;
            }
        }

        const std::vector<NoNetwork*>& vNetworks = pUser->GetNetworks();

        NoTable Table;
        Table.AddColumn("Network");
        Table.AddColumn("OnIRC");
        Table.AddColumn("IRC Server");
        Table.AddColumn("IRC User");
        Table.AddColumn("Channels");

        for (uint a = 0; a < vNetworks.size(); a++) {
            NoNetwork* pNetwork = vNetworks[a];
            Table.AddRow();
            Table.SetCell("Network", pNetwork->GetName());
            if (pNetwork->IsIRCConnected()) {
                Table.SetCell("OnIRC", "Yes");
                Table.SetCell("IRC Server", pNetwork->GetIRCServer());
                Table.SetCell("IRC User", pNetwork->GetIRCNick().nickMask());
                Table.SetCell("Channels", NoString(pNetwork->GetChans().size()));
            } else {
                Table.SetCell("OnIRC", "No");
            }
        }

        if (PutModule(Table) == 0) {
            PutModule("No networks");
        }
    }

    void AddServer(const NoString& sLine)
    {
        NoString sUsername = sLine.token(1);
        NoString sNetwork = sLine.token(2);
        NoString sServer = sLine.tokens(3);

        if (sServer.empty()) {
            PutModule("Usage: AddServer <username> <network> <server>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser) return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        if (pNetwork->AddServer(sServer))
            PutModule("Added IRC Server [" + sServer + "] for network [" + sNetwork + "] for user [" + pUser->GetUserName() + "].");
        else
            PutModule("Could not add IRC server [" + sServer + "] for network [" + sNetwork + "] for user [" +
                      pUser->GetUserName() + "].");
    }

    void DelServer(const NoString& sLine)
    {
        NoString sUsername = sLine.token(1);
        NoString sNetwork = sLine.token(2);
        NoString sServer = sLine.tokens(3);
        ushort uPort = sLine.token(4).toUShort();
        NoString sPass = sLine.token(5);

        if (sServer.empty()) {
            PutModule("Usage: DelServer <username> <network> <server>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser) return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        if (pNetwork->DelServer(sServer, uPort, sPass))
            PutModule("Deleted IRC Server [" + sServer + "] for network [" + sNetwork + "] for user [" + pUser->GetUserName() + "].");
        else
            PutModule("Could not delete IRC server [" + sServer + "] for network [" + sNetwork + "] for user [" +
                      pUser->GetUserName() + "].");
    }

    void ReconnectUser(const NoString& sLine)
    {
        NoString sUserName = sLine.token(1);
        NoString sNetwork = sLine.token(2);

        if (sNetwork.empty()) {
            PutModule("Usage: Reconnect <username> <network>");
            return;
        }

        NoUser* pUser = FindUser(sUserName);
        if (!pUser) {
            PutModule("User [" + sUserName + "] not found.");
            return;
        }

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        NoIrcConnection* pIRCSock = pNetwork->GetIRCSock();
        // cancel connection attempt:
        if (pIRCSock && !pIRCSock->IsConnected()) {
            pIRCSock->Close();
        }
        // or close existing connection:
        else if (pIRCSock) {
            pIRCSock->Quit();
        }

        // then reconnect
        pNetwork->SetIRCConnectEnabled(true);

        PutModule("Queued network [" + sNetwork + "] for user [" + pUser->GetUserName() + "] for a reconnect.");
    }

    void DisconnectUser(const NoString& sLine)
    {
        NoString sUserName = sLine.token(1);
        NoString sNetwork = sLine.token(2);

        if (sNetwork.empty()) {
            PutModule("Usage: Disconnect <username> <network>");
            return;
        }

        NoUser* pUser = FindUser(sUserName);
        if (!pUser) {
            PutModule("User [" + sUserName + "] not found.");
            return;
        }

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        pNetwork->SetIRCConnectEnabled(false);
        PutModule("Closed IRC connection for network [" + sNetwork + "] on user [" + sUserName + "].");
    }

    void ListCTCP(const NoString& sLine)
    {
        NoString sUserName = sLine.tokens(1);

        if (sUserName.empty()) {
            sUserName = GetUser()->GetUserName();
        }
        NoUser* pUser = FindUser(sUserName);
        if (!pUser) return;

        const NoStringMap& msCTCPReplies = pUser->GetCTCPReplies();
        NoTable Table;
        Table.AddColumn("Request");
        Table.AddColumn("Reply");
        for (NoStringMap::const_iterator it = msCTCPReplies.begin(); it != msCTCPReplies.end(); ++it) {
            Table.AddRow();
            Table.SetCell("Request", it->first);
            Table.SetCell("Reply", it->second);
        }

        if (Table.empty()) {
            PutModule("No CTCP replies for user [" + pUser->GetUserName() + "] configured!");
        } else {
            PutModule("CTCP replies for user [" + pUser->GetUserName() + "]:");
            PutModule(Table);
        }
    }

    void AddCTCP(const NoString& sLine)
    {
        NoString sUserName = sLine.token(1);
        NoString sCTCPRequest = sLine.token(2);
        NoString sCTCPReply = sLine.tokens(3);

        if (sCTCPRequest.empty()) {
            sCTCPRequest = sUserName;
            sCTCPReply = sLine.tokens(2);
            sUserName = GetUser()->GetUserName();
        }
        if (sCTCPRequest.empty()) {
            PutModule("Usage: AddCTCP [user] [request] [reply]");
            PutModule("This will cause ZNC to reply to the CTCP instead of forwarding it to clients.");
            PutModule("An empty reply will cause the CTCP request to be blocked.");
            return;
        }

        NoUser* pUser = FindUser(sUserName);
        if (!pUser) return;

        if (pUser->AddCTCPReply(sCTCPRequest, sCTCPReply))
            PutModule("Added!");
        else
            PutModule("Error!");
    }

    void DelCTCP(const NoString& sLine)
    {
        NoString sUserName = sLine.token(1);
        NoString sCTCPRequest = sLine.tokens(2);

        if (sCTCPRequest.empty()) {
            sCTCPRequest = sUserName;
            sUserName = GetUser()->GetUserName();
        }
        NoUser* pUser = FindUser(sUserName);
        if (!pUser) return;

        if (sCTCPRequest.empty()) {
            PutModule("Usage: DelCTCP [user] [request]");
            return;
        }

        if (pUser->DelCTCPReply(sCTCPRequest))
            PutModule("Successfully removed [" + sCTCPRequest + "] for user [" + pUser->GetUserName() + "].");
        else
            PutModule("Error: [" + sCTCPRequest + "] not found for user [" + pUser->GetUserName() + "]!");
    }

    void LoadModuleFor(NoModules& Modules, const NoString& sModName, const NoString& sArgs, NoModInfo::ModuleType eType, NoUser* pUser, NoNetwork* pNetwork)
    {
        if (pUser->DenyLoadMod() && !GetUser()->IsAdmin()) {
            PutModule("Loading modules has been disabled.");
            return;
        }

        NoString sModRet;
        NoModule* pMod = Modules.FindModule(sModName);
        if (!pMod) {
            if (!Modules.LoadModule(sModName, sArgs, eType, pUser, pNetwork, sModRet)) {
                PutModule("Unable to load module [" + sModName + "] [" + sModRet + "]");
            } else {
                PutModule("Loaded module [" + sModName + "]");
            }
        } else if (pMod->GetArgs() != sArgs) {
            if (!Modules.ReloadModule(sModName, sArgs, pUser, pNetwork, sModRet)) {
                PutModule("Unable to reload module [" + sModName + "] [" + sModRet + "]");
            } else {
                PutModule("Reloaded module [" + sModName + "]");
            }
        } else {
            PutModule("Unable to load module [" + sModName + "] because it is already loaded");
        }
    }

    void LoadModuleForUser(const NoString& sLine)
    {
        NoString sUsername = sLine.token(1);
        NoString sModName = sLine.token(2);
        NoString sArgs = sLine.tokens(3);

        if (sModName.empty()) {
            PutModule("Usage: LoadModule <username> <modulename> [args]");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser) return;

        LoadModuleFor(pUser->GetModules(), sModName, sArgs, NoModInfo::UserModule, pUser, nullptr);
    }

    void LoadModuleForNetwork(const NoString& sLine)
    {
        NoString sUsername = sLine.token(1);
        NoString sNetwork = sLine.token(2);
        NoString sModName = sLine.token(3);
        NoString sArgs = sLine.tokens(4);

        if (sModName.empty()) {
            PutModule("Usage: LoadNetModule <username> <network> <modulename> [args]");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser) return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        LoadModuleFor(pNetwork->GetModules(), sModName, sArgs, NoModInfo::NetworkModule, pUser, pNetwork);
    }

    void UnLoadModuleFor(NoModules& Modules, const NoString& sModName, NoUser* pUser)
    {
        if (pUser->DenyLoadMod() && !GetUser()->IsAdmin()) {
            PutModule("Loading modules has been disabled.");
            return;
        }

        if (Modules.FindModule(sModName) == this) {
            PutModule("Please use /znc unloadmod " + sModName);
            return;
        }

        NoString sModRet;
        if (!Modules.UnloadModule(sModName, sModRet)) {
            PutModule("Unable to unload module [" + sModName + "] [" + sModRet + "]");
        } else {
            PutModule("Unloaded module [" + sModName + "]");
        }
    }

    void UnLoadModuleForUser(const NoString& sLine)
    {
        NoString sUsername = sLine.token(1);
        NoString sModName = sLine.token(2);

        if (sModName.empty()) {
            PutModule("Usage: UnloadModule <username> <modulename>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser) return;

        UnLoadModuleFor(pUser->GetModules(), sModName, pUser);
    }

    void UnLoadModuleForNetwork(const NoString& sLine)
    {
        NoString sUsername = sLine.token(1);
        NoString sNetwork = sLine.token(2);
        NoString sModName = sLine.token(3);

        if (sModName.empty()) {
            PutModule("Usage: UnloadNetModule <username> <network> <modulename>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser) return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        UnLoadModuleFor(pNetwork->GetModules(), sModName, pUser);
    }

    void ListModulesFor(NoModules& Modules, const NoString& sWhere)
    {
        if (!Modules.size()) {
            PutModule(sWhere + " has no modules loaded.");
        } else {
            PutModule("Modules loaded for " + sWhere + ":");
            NoTable Table;
            Table.AddColumn("Name");
            Table.AddColumn("Arguments");

            for (uint b = 0; b < Modules.size(); b++) {
                Table.AddRow();
                Table.SetCell("Name", Modules[b]->GetModName());
                Table.SetCell("Arguments", Modules[b]->GetArgs());
            }

            PutModule(Table);
        }
    }

    void ListModulesForUser(const NoString& sLine)
    {
        NoString sUsername = sLine.token(1);

        if (sUsername.empty()) {
            PutModule("Usage: ListMods <username>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser) return;

        ListModulesFor(pUser->GetModules(), "User [" + pUser->GetUserName() + "]");
    }

    void ListModulesForNetwork(const NoString& sLine)
    {
        NoString sUsername = sLine.token(1);
        NoString sNetwork = sLine.token(2);

        if (sNetwork.empty()) {
            PutModule("Usage: ListNetMods <username> <network>");
            return;
        }

        NoUser* pUser = FindUser(sUsername);
        if (!pUser) return;

        NoNetwork* pNetwork = FindNetwork(pUser, sNetwork);
        if (!pNetwork) {
            return;
        }

        ListModulesFor(pNetwork->GetModules(), "Network [" + pNetwork->GetName() + "] of user [" + pUser->GetUserName() + "]");
    }

public:
    MODCONSTRUCTOR(NoAdminMod)
    {
        AddCommand("Help",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::PrintHelp),
                   "[command] [variable]",
                   "Prints help for matching commands and variables");
        AddCommand("Get",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::Get),
                   "<variable> [username]",
                   "Prints the variable's value for the given or current user");
        AddCommand("Set",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::Set),
                   "<variable> <username> <value>",
                   "Sets the variable's value for the given user");
        AddCommand("GetNetwork",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::GetNetwork),
                   "<variable> [username] [network]",
                   "Prints the variable's value for the given network");
        AddCommand("SetNetwork",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::SetNetwork),
                   "<variable> <username> <network> <value>",
                   "Sets the variable's value for the given network");
        AddCommand("GetChan",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::GetChan),
                   "<variable> [username] <network> <chan>",
                   "Prints the variable's value for the given channel");
        AddCommand("SetChan",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::SetChan),
                   "<variable> <username> <network> <chan> <value>",
                   "Sets the variable's value for the given channel");
        AddCommand("AddChan", static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::AddChan), "<username> <network> <chan>", "Adds a new channel");
        AddCommand("DelChan", static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::DelChan), "<username> <network> <chan>", "Deletes a channel");
        AddCommand("ListUsers", static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::ListUsers), "", "Lists users");
        AddCommand("AddUser",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::AddUser),
                   "<username> <password>",
                   "Adds a new user");
        AddCommand("DelUser",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::DelUser),
                   "<username>",
                   "Deletes a user");
        AddCommand("CloneUser",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::CloneUser),
                   "<old username> <new username>",
                   "Clones a user");
        AddCommand("AddServer",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::AddServer),
                   "<username> <network> <server>",
                   "Adds a new IRC server for the given or current user");
        AddCommand("DelServer",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::DelServer),
                   "<username> <network> <server>",
                   "Deletes an IRC server from the given or current user");
        AddCommand("Reconnect", static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::ReconnectUser), "<username> <network>", "Cycles the user's IRC server connection");
        AddCommand("Disconnect",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::DisconnectUser),
                   "<username> <network>",
                   "Disconnects the user from their IRC server");
        AddCommand("LoadModule",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::LoadModuleForUser),
                   "<username> <modulename> [args]",
                   "Loads a Module for a user");
        AddCommand("UnLoadModule",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::UnLoadModuleForUser),
                   "<username> <modulename>",
                   "Removes a Module of a user");
        AddCommand("ListMods",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::ListModulesForUser),
                   "<username>",
                   "Get the list of modules for a user");
        AddCommand("LoadNetModule",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::LoadModuleForNetwork),
                   "<username> <network> <modulename> [args]",
                   "Loads a Module for a network");
        AddCommand("UnLoadNetModule",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::UnLoadModuleForNetwork),
                   "<username> <network> <modulename>",
                   "Removes a Module of a network");
        AddCommand("ListNetMods",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::ListModulesForNetwork),
                   "<username> <network>",
                   "Get the list of modules for a network");
        AddCommand("ListCTCPs",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::ListCTCP),
                   "<username>",
                   "List the configured CTCP replies");
        AddCommand("AddCTCP", static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::AddCTCP), "<username> <ctcp> [reply]", "Configure a new CTCP reply");
        AddCommand("DelCTCP",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::DelCTCP),
                   "<username> <ctcp>",
                   "Remove a CTCP reply");

        // Network commands
        AddCommand("AddNetwork", static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::AddNetwork), "[username] <network>", "Add a network for a user");
        AddCommand("DelNetwork", static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::DelNetwork), "[username] <network>", "Delete a network for a user");
        AddCommand("ListNetworks",
                   static_cast<NoModCommand::ModCmdFunc>(&NoAdminMod::ListNetworks),
                   "[username]",
                   "List all networks for a user");
    }
};

template <> void TModInfo<NoAdminMod>(NoModInfo& Info) { Info.SetWikiPage("controlpanel"); }

USERMODULEDEFS(NoAdminMod, "Dynamic configuration through IRC. Allows editing only yourself if you're not ZNC admin.")
