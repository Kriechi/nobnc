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

#include "noclient.h"
#include "noclient_p.h"
#include "nochannel.h"
#include "nodir.h"
#include "nonetwork.h"
#include "noircsocket.h"
#include "noserverinfo.h"
#include "nouser.h"
#include "noquery.h"
#include "noexception.h"
#include "nomodulecall.h"
#include "noapp.h"
#include "nolistener.h"
#include "noregistry.h"
#include "nonick.h"
#include "nobuffer.h"

void NoClient::UserCommand(NoString& sLine)
{
    if (!d->user) {
        return;
    }

    if (sLine.empty()) {
        return;
    }

    bool bReturn = false;
    NETWORKMODULECALL(OnStatusCommand(sLine), d->user, d->network, this, &bReturn);
    if (bReturn) return;

    const NoString sCommand = No::token(sLine, 0);

    if (sCommand.equals("HELP")) {
        HelpUser(No::token(sLine, 1));
    } else if (sCommand.equals("LISTNICKS")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sChan = No::token(sLine, 1);

        if (sChan.empty()) {
            PutStatus("Usage: ListNicks <#chan>");
            return;
        }

        NoChannel* pChan = d->network->FindChan(sChan);

        if (!pChan) {
            PutStatus("You are not on [" + sChan + "]");
            return;
        }

        if (!pChan->isOn()) {
            PutStatus("You are not on [" + sChan + "] [trying]");
            return;
        }

        const std::map<NoString, NoNick>& msNicks = pChan->getNicks();
        NoIrcSocket* pIRCSock = d->network->GetIRCSock();
        const NoString& sPerms = (pIRCSock) ? pIRCSock->GetPerms() : "";

        if (msNicks.empty()) {
            PutStatus("No nicks on [" + sChan + "]");
            return;
        }

        NoTable Table;

        for (uint p = 0; p < sPerms.size(); p++) {
            NoString sPerm;
            sPerm += sPerms[p];
            Table.addColumn(sPerm);
        }

        Table.addColumn("Nick");
        Table.addColumn("Ident");
        Table.addColumn("Host");

        for (const auto& it : msNicks) {
            Table.addRow();

            for (uint b = 0; b < sPerms.size(); b++) {
                if (it.second.hasPerm(sPerms[b])) {
                    NoString sPerm;
                    sPerm += sPerms[b];
                    Table.setValue(sPerm, sPerm);
                }
            }

            Table.setValue("Nick", it.second.nick());
            Table.setValue("Ident", it.second.ident());
            Table.setValue("Host", it.second.host());
        }

        PutStatus(Table);
    } else if (sCommand.equals("DETACH")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sPatterns = No::tokens(sLine, 1);

        if (sPatterns.empty()) {
            PutStatus("Usage: Detach <#chans>");
            return;
        }

        sPatterns.replace(",", " ");
        NoStringVector vsChans = sPatterns.split(" ", No::SkipEmptyParts);

        std::set<NoChannel*> sChans;
        for (const NoString& sChan : vsChans) {
            std::vector<NoChannel*> vChans = d->network->FindChans(sChan);
            sChans.insert(vChans.begin(), vChans.end());
        }

        uint uDetached = 0;
        for (NoChannel* pChan : sChans) {
            if (pChan->isDetached()) continue;
            uDetached++;
            pChan->detachUser();
        }

        PutStatus("There were [" + NoString(sChans.size()) + "] channels matching [" + sPatterns + "]");
        PutStatus("Detached [" + NoString(uDetached) + "] channels");
    } else if (sCommand.equals("VERSION")) {
        PutStatus(NoApp::GetTag());
        PutStatus(NoApp::GetCompileOptionsString());
    } else if (sCommand.equals("MOTD") || sCommand.equals("ShowMOTD")) {
        if (!SendMotd()) {
            PutStatus("There is no MOTD set.");
        }
    } else if (d->user->IsAdmin() && sCommand.equals("Rehash")) {
        NoString sRet;

        if (NoApp::Get().RehashConfig(sRet)) {
            PutStatus("Rehashing succeeded!");
        } else {
            PutStatus("Rehashing failed: " + sRet);
        }
    } else if (d->user->IsAdmin() && sCommand.equals("SaveConfig")) {
        if (NoApp::Get().WriteConfig()) {
            PutStatus("Wrote config to [" + NoApp::Get().GetConfigFile() + "]");
        } else {
            PutStatus("Error while trying to write config.");
        }
    } else if (sCommand.equals("LISTCLIENTS")) {
        NoUser* pUser = d->user;
        NoString sNick = No::token(sLine, 1);

        if (!sNick.empty()) {
            if (!d->user->IsAdmin()) {
                PutStatus("Usage: ListClients");
                return;
            }

            pUser = NoApp::Get().FindUser(sNick);

            if (!pUser) {
                PutStatus("No such user [" + sNick + "]");
                return;
            }
        }

        std::vector<NoClient*> vClients = pUser->GetAllClients();

        if (vClients.empty()) {
            PutStatus("No clients are connected");
            return;
        }

        NoTable Table;
        Table.addColumn("Host");
        Table.addColumn("Network");
        Table.addColumn("Identifier");

        for (const NoClient* pClient : vClients) {
            Table.addRow();
            Table.setValue("Host", pClient->GetSocket()->GetRemoteIP());
            if (pClient->GetNetwork()) {
                Table.setValue("Network", pClient->GetNetwork()->GetName());
            }
            Table.setValue("Identifier", pClient->GetIdentifier());
        }

        PutStatus(Table);
    } else if (d->user->IsAdmin() && sCommand.equals("LISTUSERS")) {
        const std::map<NoString, NoUser*>& msUsers = NoApp::Get().GetUserMap();
        NoTable Table;
        Table.addColumn("Username");
        Table.addColumn("Networks");
        Table.addColumn("Clients");

        for (const auto& it : msUsers) {
            Table.addRow();
            Table.setValue("Username", it.first);
            Table.setValue("Networks", NoString(it.second->GetNetworks().size()));
            Table.setValue("Clients", NoString(it.second->GetAllClients().size()));
        }

        PutStatus(Table);
    } else if (d->user->IsAdmin() && sCommand.equals("LISTALLUSERNETWORKS")) {
        const std::map<NoString, NoUser*>& msUsers = NoApp::Get().GetUserMap();
        NoTable Table;
        Table.addColumn("Username");
        Table.addColumn("Network");
        Table.addColumn("Clients");
        Table.addColumn("OnIRC");
        Table.addColumn("IRC Server");
        Table.addColumn("IRC User");
        Table.addColumn("Channels");

        for (const auto& it : msUsers) {
            Table.addRow();
            Table.setValue("Username", it.first);
            Table.setValue("Network", "N/A");
            Table.setValue("Clients", NoString(it.second->GetUserClients().size()));

            const std::vector<NoNetwork*>& vNetworks = it.second->GetNetworks();

            for (const NoNetwork* pNetwork : vNetworks) {
                Table.addRow();
                if (pNetwork == vNetworks.back()) {
                    Table.setValue("Username", "`-");
                } else {
                    Table.setValue("Username", "|-");
                }
                Table.setValue("Network", pNetwork->GetName());
                Table.setValue("Clients", NoString(pNetwork->GetClients().size()));
                if (pNetwork->IsIRCConnected()) {
                    Table.setValue("OnIRC", "Yes");
                    Table.setValue("IRC Server", pNetwork->GetIRCServer());
                    Table.setValue("IRC User", pNetwork->GetIRCNick().nickMask());
                    Table.setValue("Channels", NoString(pNetwork->GetChans().size()));
                } else {
                    Table.setValue("OnIRC", "No");
                }
            }
        }

        PutStatus(Table);
    } else if (d->user->IsAdmin() && sCommand.equals("SetMOTD")) {
        NoString sMessage = No::tokens(sLine, 1);

        if (sMessage.empty()) {
            PutStatus("Usage: SetMOTD <message>");
        } else {
            NoApp::Get().SetMotd(sMessage);
            PutStatus("MOTD set to [" + sMessage + "]");
        }
    } else if (d->user->IsAdmin() && sCommand.equals("AddMOTD")) {
        NoString sMessage = No::tokens(sLine, 1);

        if (sMessage.empty()) {
            PutStatus("Usage: AddMOTD <message>");
        } else {
            NoApp::Get().AddMotd(sMessage);
            PutStatus("Added [" + sMessage + "] to MOTD");
        }
    } else if (d->user->IsAdmin() && sCommand.equals("ClearMOTD")) {
        NoApp::Get().ClearMotd();
        PutStatus("Cleared MOTD");
    } else if (d->user->IsAdmin() && sCommand.equals("BROADCAST")) {
        NoApp::Get().Broadcast(No::tokens(sLine, 1));
    } else if (d->user->IsAdmin() && (sCommand.equals("SHUTDOWN") || sCommand.equals("RESTART"))) {
        bool bRestart = sCommand.equals("RESTART");
        NoString sMessage = No::tokens(sLine, 1);
        bool bForce = false;

        if (No::token(sMessage, 0).equals("FORCE")) {
            bForce = true;
            sMessage = No::tokens(sMessage, 1);
        }

        if (sMessage.empty()) {
            sMessage = (bRestart ? "ZNC is being restarted NOW!" : "ZNC is being shut down NOW!");
        }

        if (!NoApp::Get().WriteConfig() && !bForce) {
            PutStatus("ERROR: Writing config file to disk failed! Aborting. Use " + sCommand.toUpper() +
                      " FORCE to ignore.");
        } else {
            NoApp::Get().Broadcast(sMessage);
            throw NoException(bRestart ? NoException::Restart : NoException::Shutdown);
        }
    } else if (sCommand.equals("JUMP") || sCommand.equals("CONNECT")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        if (!d->network->HasServers()) {
            PutStatus("You don't have any servers added.");
            return;
        }

        NoString sArgs = No::tokens(sLine, 1);
        sArgs.trim();
        NoServerInfo* pServer = nullptr;

        if (!sArgs.empty()) {
            pServer = d->network->FindServer(sArgs);
            if (!pServer) {
                PutStatus("Server [" + sArgs + "] not found");
                return;
            }
            d->network->SetNextServer(pServer);

            // If we are already connecting to some server,
            // we have to abort that attempt
            NoSocket* pIRCSock = GetIRCSock();
            if (pIRCSock && !pIRCSock->IsConnected()) {
                pIRCSock->Close();
            }
        }

        if (GetIRCSock()) {
            GetIRCSock()->Quit();
            if (pServer)
                PutStatus("Connecting to [" + pServer->host() + "]...");
            else
                PutStatus("Jumping to the next server in the list...");
        } else {
            if (pServer)
                PutStatus("Connecting to [" + pServer->host() + "]...");
            else
                PutStatus("Connecting...");
        }

        d->network->SetIRCConnectEnabled(true);
        return;
    } else if (sCommand.equals("DISCONNECT")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        if (GetIRCSock()) {
            NoString sQuitMsg = No::tokens(sLine, 1);
            GetIRCSock()->Quit(sQuitMsg);
        }

        d->network->SetIRCConnectEnabled(false);
        PutStatus("Disconnected from IRC. Use 'connect' to reconnect.");
        return;
    } else if (sCommand.equals("ENABLECHAN")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sPatterns = No::tokens(sLine, 1);

        if (sPatterns.empty()) {
            PutStatus("Usage: EnableChan <#chans>");
        } else {
            sPatterns.replace(",", " ");
            NoStringVector vsChans = sPatterns.split(" ", No::SkipEmptyParts);

            std::set<NoChannel*> sChans;
            for (const NoString& sChan : vsChans) {
                std::vector<NoChannel*> vChans = d->network->FindChans(sChan);
                sChans.insert(vChans.begin(), vChans.end());
            }

            uint uEnabled = 0;
            for (NoChannel* pChan : sChans) {
                if (!pChan->isDisabled()) continue;
                uEnabled++;
                pChan->enable();
            }

            PutStatus("There were [" + NoString(sChans.size()) + "] channels matching [" + sPatterns + "]");
            PutStatus("Enabled [" + NoString(uEnabled) + "] channels");
        }
    } else if (sCommand.equals("DISABLECHAN")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sPatterns = No::tokens(sLine, 1);

        if (sPatterns.empty()) {
            PutStatus("Usage: DisableChan <#chans>");
        } else {
            sPatterns.replace(",", " ");
            NoStringVector vsChans = sPatterns.split(" ", No::SkipEmptyParts);

            std::set<NoChannel*> sChans;
            for (const NoString& sChan : vsChans) {
                std::vector<NoChannel*> vChans = d->network->FindChans(sChan);
                sChans.insert(vChans.begin(), vChans.end());
            }

            uint uDisabled = 0;
            for (NoChannel* pChan : sChans) {
                if (pChan->isDisabled()) continue;
                uDisabled++;
                pChan->disable();
            }

            PutStatus("There were [" + NoString(sChans.size()) + "] channels matching [" + sPatterns + "]");
            PutStatus("Disabled [" + NoString(uDisabled) + "] channels");
        }
    } else if (sCommand.equals("SHOWCHAN")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sChan = No::tokens(sLine, 1);
        if (sChan.empty()) {
            PutStatus("Usage: ShowChan <#chan>");
            return;
        }

        NoChannel* pChan = d->network->FindChan(sChan);
        if (!pChan) {
            PutStatus("No such channel [" + sChan + "]");
            return;
        }
        sChan = pChan->getPermStr() + pChan->getName();
        NoString sStatus =
        pChan->isOn() ? (pChan->isDetached() ? "Detached" : "Joined") : (pChan->isDisabled() ? "Disabled" : "Trying");

        NoTable Table;
        Table.addColumn(sChan, false);
        Table.addColumn(sStatus);

        Table.addRow();
        Table.setValue(sChan, "InConfig");
        Table.setValue(sStatus, NoString(pChan->inConfig() ? "yes" : "no"));

        Table.addRow();
        Table.setValue(sChan, "Buffer");
        Table.setValue(sStatus,
                      NoString(pChan->getBuffer().size()) + "/" + NoString(pChan->getBufferCount()) +
                      NoString(pChan->hasBufferCountSet() ? "" : " (default)"));

        Table.addRow();
        Table.setValue(sChan, "AutoClearChanBuffer");
        Table.setValue(sStatus,
                      NoString(pChan->autoClearChanBuffer() ? "yes" : "no") +
                      NoString(pChan->hasAutoClearChanBufferSet() ? "" : " (default)"));

        if (pChan->isOn()) {
            Table.addRow();
            Table.setValue(sChan, "Topic");
            Table.setValue(sStatus, pChan->getTopic());

            Table.addRow();
            Table.setValue(sChan, "Modes");
            Table.setValue(sStatus, pChan->getModeString());

            Table.addRow();
            Table.setValue(sChan, "Users");

            NoStringVector vsUsers;
            vsUsers.push_back("All: " + NoString(pChan->getNickCount()));

            NoIrcSocket* pIRCSock = d->network->GetIRCSock();
            const NoString& sPerms = pIRCSock ? pIRCSock->GetPerms() : "";
            std::map<char, uint> mPerms = pChan->getPermCounts();
            for (char cPerm : sPerms) {
                vsUsers.push_back(NoString(cPerm) + ": " + NoString(mPerms[cPerm]));
            }
            Table.setValue(sStatus, NoString(", ").join(vsUsers.begin(), vsUsers.end()));
        }

        PutStatus(Table);
    } else if (sCommand.equals("LISTCHANS")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoNetwork* pNetwork = d->network;

        const NoString sNick = No::token(sLine, 1);
        const NoString sNetwork = No::token(sLine, 2);

        if (!sNick.empty()) {
            if (!d->user->IsAdmin()) {
                PutStatus("Usage: ListChans");
                return;
            }

            NoUser* pUser = NoApp::Get().FindUser(sNick);

            if (!pUser) {
                PutStatus("No such user [" + sNick + "]");
                return;
            }

            pNetwork = pUser->FindNetwork(sNetwork);
            if (!pNetwork) {
                PutStatus("No such network for user [" + sNetwork + "]");
                return;
            }
        }

        const std::vector<NoChannel*>& vChans = pNetwork->GetChans();

        if (vChans.empty()) {
            PutStatus("There are no channels defined.");
            return;
        }

        NoTable Table;
        Table.addColumn("Name");
        Table.addColumn("Status");

        uint uNumDetached = 0, uNumDisabled = 0, uNumJoined = 0;

        for (const NoChannel* pChan : vChans) {
            Table.addRow();
            Table.setValue("Name", pChan->getPermStr() + pChan->getName());
            Table.setValue("Status",
                          ((pChan->isOn()) ? ((pChan->isDetached()) ? "Detached" : "Joined") :
                                             ((pChan->isDisabled()) ? "Disabled" : "Trying")));

            if (pChan->isDetached()) uNumDetached++;
            if (pChan->isOn()) uNumJoined++;
            if (pChan->isDisabled()) uNumDisabled++;
        }

        PutStatus(Table);
        PutStatus("Total: " + NoString(vChans.size()) + " - Joined: " + NoString(uNumJoined) + " - Detached: " +
                  NoString(uNumDetached) + " - Disabled: " + NoString(uNumDisabled));
    } else if (sCommand.equals("ADDNETWORK")) {
        if (!d->user->IsAdmin() && !d->user->HasSpaceForNewNetwork()) {
            PutStatus("Network number limit reached. Ask an admin to increase the limit for you, or delete unneeded "
                      "networks using /znc DelNetwork <name>");
            return;
        }

        NoString sNetwork = No::token(sLine, 1);

        if (sNetwork.empty()) {
            PutStatus("Usage: AddNetwork <name>");
            return;
        }
        if (!NoNetwork::IsValidNetwork(sNetwork)) {
            PutStatus("Network name should be alphanumeric");
            return;
        }

        NoString sNetworkAddError;
        if (d->user->AddNetwork(sNetwork, sNetworkAddError)) {
            PutStatus("Network added. Use /znc JumpNetwork " + sNetwork + ", or connect to ZNC with username " +
                      d->user->GetUserName() + "/" + sNetwork + " (instead of just " + d->user->GetUserName() +
                      ") to connect to it.");
        } else {
            PutStatus("Unable to add that network");
            PutStatus(sNetworkAddError);
        }
    } else if (sCommand.equals("DELNETWORK")) {
        NoString sNetwork = No::token(sLine, 1);

        if (sNetwork.empty()) {
            PutStatus("Usage: DelNetwork <name>");
            return;
        }

        if (d->network && d->network->GetName().equals(sNetwork)) {
            SetNetwork(nullptr);
        }

        if (d->user->DeleteNetwork(sNetwork)) {
            PutStatus("Network deleted");
        } else {
            PutStatus("Failed to delete network");
            PutStatus("Perhaps this network doesn't exist");
        }
    } else if (sCommand.equals("LISTNETWORKS")) {
        NoUser* pUser = d->user;

        if (d->user->IsAdmin() && !No::token(sLine, 1).empty()) {
            pUser = NoApp::Get().FindUser(No::token(sLine, 1));

            if (!pUser) {
                PutStatus("User not found " + No::token(sLine, 1));
                return;
            }
        }

        const std::vector<NoNetwork*>& vNetworks = pUser->GetNetworks();

        NoTable Table;
        Table.addColumn("Network");
        Table.addColumn("OnIRC");
        Table.addColumn("IRC Server");
        Table.addColumn("IRC User");
        Table.addColumn("Channels");

        for (const NoNetwork* pNetwork : vNetworks) {
            Table.addRow();
            Table.setValue("Network", pNetwork->GetName());
            if (pNetwork->IsIRCConnected()) {
                Table.setValue("OnIRC", "Yes");
                Table.setValue("IRC Server", pNetwork->GetIRCServer());
                Table.setValue("IRC User", pNetwork->GetIRCNick().nickMask());
                Table.setValue("Channels", NoString(pNetwork->GetChans().size()));
            } else {
                Table.setValue("OnIRC", "No");
            }
        }

        if (PutStatus(Table) == 0) {
            PutStatus("No networks");
        }
    } else if (sCommand.equals("MOVENETWORK")) {
        if (!d->user->IsAdmin()) {
            PutStatus("Access Denied.");
            return;
        }

        NoString sOldUser = No::token(sLine, 1);
        NoString sOldNetwork = No::token(sLine, 2);
        NoString sNewUser = No::token(sLine, 3);
        NoString sNewNetwork = No::token(sLine, 4);

        if (sOldUser.empty() || sOldNetwork.empty() || sNewUser.empty()) {
            PutStatus("Usage: MoveNetwork <old user> <old network> <new user> [new network]");
            return;
        }
        if (sNewNetwork.empty()) {
            sNewNetwork = sOldNetwork;
        }

        NoUser* pOldUser = NoApp::Get().FindUser(sOldUser);
        if (!pOldUser) {
            PutStatus("Old user [" + sOldUser + "] not found.");
            return;
        }

        NoNetwork* pOldNetwork = pOldUser->FindNetwork(sOldNetwork);
        if (!pOldNetwork) {
            PutStatus("Old network [" + sOldNetwork + "] not found.");
            return;
        }

        NoUser* pNewUser = NoApp::Get().FindUser(sNewUser);
        if (!pNewUser) {
            PutStatus("New user [" + sOldUser + "] not found.");
            return;
        }

        if (pNewUser->FindNetwork(sNewNetwork)) {
            PutStatus("User [" + sNewUser + "] already has network [" + sNewNetwork + "].");
            return;
        }

        if (!NoNetwork::IsValidNetwork(sNewNetwork)) {
            PutStatus("Invalid network name [" + sNewNetwork + "]");
            return;
        }

        std::vector<NoModule*> vMods = pOldNetwork->GetLoader()->GetModules();
        for (NoModule* pMod : vMods) {
            NoString sOldModPath = pOldNetwork->GetNetworkPath() + "/moddata/" + pMod->GetModName();
            NoString sNewModPath = pNewUser->GetUserPath() + "/networks/" + sNewNetwork + "/moddata/" + pMod->GetModName();

            NoDir oldDir(sOldModPath);
            for (NoFile* pFile : oldDir) {
                if (pFile->GetShortName() != ".registry") {
                    PutStatus("Some files seem to be in [" + sOldModPath + "]. You might want to move them to [" + sNewModPath + "]");
                    break;
                }
            }

            NoRegistry registry(pMod);
            registry.copy(sNewModPath);
        }

        NoString sNetworkAddError;
        NoNetwork* pNewNetwork = pNewUser->AddNetwork(sNewNetwork, sNetworkAddError);

        if (!pNewNetwork) {
            PutStatus("Error adding network:" + sNetworkAddError);
            return;
        }

        pNewNetwork->Clone(*pOldNetwork, false);

        if (d->network && d->network->GetName().equals(sOldNetwork) && d->user == pOldUser) {
            SetNetwork(nullptr);
        }

        if (pOldUser->DeleteNetwork(sOldNetwork)) {
            PutStatus("Success.");
        } else {
            PutStatus("Copied the network to new user, but failed to delete old network");
        }
    } else if (sCommand.equals("JUMPNETWORK")) {
        NoString sNetwork = No::token(sLine, 1);

        if (sNetwork.empty()) {
            PutStatus("No network supplied.");
            return;
        }

        if (d->network && (d->network->GetName() == sNetwork)) {
            PutStatus("You are already connected with this network.");
            return;
        }

        NoNetwork* pNetwork = d->user->FindNetwork(sNetwork);
        if (pNetwork) {
            PutStatus("Switched to " + sNetwork);
            SetNetwork(pNetwork);
        } else {
            PutStatus("You don't have a network named " + sNetwork);
        }
    } else if (sCommand.equals("ADDSERVER")) {
        NoString sServer = No::token(sLine, 1);

        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        if (sServer.empty()) {
            PutStatus("Usage: AddServer <host> [[+]port] [pass]");
            return;
        }

        if (d->network->AddServer(No::tokens(sLine, 1))) {
            PutStatus("Server added");
        } else {
            PutStatus("Unable to add that server");
            PutStatus("Perhaps the server is already added or openssl is disabled?");
        }
    } else if (sCommand.equals("REMSERVER") || sCommand.equals("DELSERVER")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sServer = No::token(sLine, 1);
        ushort uPort = No::token(sLine, 2).toUShort();
        NoString sPass = No::token(sLine, 3);

        if (sServer.empty()) {
            PutStatus("Usage: DelServer <host> [port] [pass]");
            return;
        }

        if (!d->network->HasServers()) {
            PutStatus("You don't have any servers added.");
            return;
        }

        if (d->network->DelServer(sServer, uPort, sPass)) {
            PutStatus("Server removed");
        } else {
            PutStatus("No such server");
        }
    } else if (sCommand.equals("LISTSERVERS")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        if (d->network->HasServers()) {
            const std::vector<NoServerInfo*>& vServers = d->network->GetServers();
            NoServerInfo* pCurServ = d->network->GetCurrentServer();
            NoTable Table;
            Table.addColumn("Host");
            Table.addColumn("Port");
            Table.addColumn("SSL");
            Table.addColumn("Pass");

            for (const NoServerInfo* pServer : vServers) {
                Table.addRow();
                Table.setValue("Host", pServer->host() + (pServer == pCurServ ? "*" : ""));
                Table.setValue("Port", NoString(pServer->port()));
                Table.setValue("SSL", (pServer->isSsl()) ? "SSL" : "");
                Table.setValue("Pass", pServer->password());
            }

            PutStatus(Table);
        } else {
            PutStatus("You don't have any servers added.");
        }
    } else if (sCommand.equals("AddTrustedServerFingerprint")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }
        NoString sFP = No::token(sLine, 1);
        if (sFP.empty()) {
            PutStatus("Usage: AddTrustedServerFingerprint <fi:ng:er>");
            return;
        }
        d->network->AddTrustedFingerprint(sFP);
        PutStatus("Done.");
    } else if (sCommand.equals("DelTrustedServerFingerprint")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }
        NoString sFP = No::token(sLine, 1);
        if (sFP.empty()) {
            PutStatus("Usage: DelTrustedServerFingerprint <fi:ng:er>");
            return;
        }
        d->network->DelTrustedFingerprint(sFP);
        PutStatus("Done.");
    } else if (sCommand.equals("ListTrustedServerFingerprints")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }
        const NoStringSet& ssFPs = d->network->GetTrustedFingerprints();
        if (ssFPs.empty()) {
            PutStatus("No fingerprints added.");
        } else {
            int k = 0;
            for (const NoString& sFP : ssFPs) {
                PutStatus(NoString(++k) + ". " + sFP);
            }
        }
    } else if (sCommand.equals("TOPICS")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        const std::vector<NoChannel*>& vChans = d->network->GetChans();
        NoTable Table;
        Table.addColumn("Name");
        Table.addColumn("Set By");
        Table.addColumn("Topic");

        for (const NoChannel* pChan : vChans) {
            Table.addRow();
            Table.setValue("Name", pChan->getName());
            Table.setValue("Set By", pChan->getTopicOwner());
            Table.setValue("Topic", pChan->getTopic());
        }

        PutStatus(Table);
    } else if (sCommand.equals("LISTMODS") || sCommand.equals("LISTMODULES")) {
        if (d->user->IsAdmin()) {
            NoModuleLoader* GModules = NoApp::Get().GetLoader();

            if (GModules->isEmpty()) {
                PutStatus("No global modules loaded.");
            } else {
                PutStatus("Global modules:");
                NoTable GTable;
                GTable.addColumn("Name");
                GTable.addColumn("Arguments");

                for (const NoModule* pMod : GModules->GetModules()) {
                    GTable.addRow();
                    GTable.setValue("Name", pMod->GetModName());
                    GTable.setValue("Arguments", pMod->GetArgs());
                }

                PutStatus(GTable);
            }
        }

        NoModuleLoader* Modules = d->user->GetLoader();

        if (Modules->isEmpty()) {
            PutStatus("Your user has no modules loaded.");
        } else {
            PutStatus("User modules:");
            NoTable Table;
            Table.addColumn("Name");
            Table.addColumn("Arguments");

            for (const NoModule* pMod : Modules->GetModules()) {
                Table.addRow();
                Table.setValue("Name", pMod->GetModName());
                Table.setValue("Arguments", pMod->GetArgs());
            }

            PutStatus(Table);
        }

        if (d->network) {
            NoModuleLoader* NetworkModules = d->network->GetLoader();
            if (NetworkModules->isEmpty()) {
                PutStatus("This network has no modules loaded.");
            } else {
                PutStatus("Network modules:");
                NoTable Table;
                Table.addColumn("Name");
                Table.addColumn("Arguments");

                for (const NoModule* pMod : NetworkModules->GetModules()) {
                    Table.addRow();
                    Table.setValue("Name", pMod->GetModName());
                    Table.setValue("Arguments", pMod->GetArgs());
                }

                PutStatus(Table);
            }
        }

        return;
    } else if (sCommand.equals("LISTAVAILMODS") || sCommand.equals("LISTAVAILABLEMODULES")) {
        if (d->user->DenyLoadMod()) {
            PutStatus("Access Denied.");
            return;
        }

        if (d->user->IsAdmin()) {
            std::set<NoModuleInfo> ssGlobalMods;
            NoApp::Get().GetLoader()->GetAvailableMods(ssGlobalMods, No::GlobalModule);

            if (ssGlobalMods.empty()) {
                PutStatus("No global modules available.");
            } else {
                PutStatus("Global modules:");
                NoTable GTable;
                GTable.addColumn("Name");
                GTable.addColumn("Description");

                for (const NoModuleInfo& Info : ssGlobalMods) {
                    GTable.addRow();
                    GTable.setValue("Name", (NoApp::Get().GetLoader()->FindModule(Info.GetName()) ? "*" : " ") + Info.GetName());
                    GTable.setValue("Description", No::ellipsize(Info.GetDescription(), 128));
                }

                PutStatus(GTable);
            }
        }

        std::set<NoModuleInfo> ssUserMods;
        NoApp::Get().GetLoader()->GetAvailableMods(ssUserMods);

        if (ssUserMods.empty()) {
            PutStatus("No user modules available.");
        } else {
            PutStatus("User modules:");
            NoTable Table;
            Table.addColumn("Name");
            Table.addColumn("Description");

            for (const NoModuleInfo& Info : ssUserMods) {
                Table.addRow();
                Table.setValue("Name", (d->user->GetLoader()->FindModule(Info.GetName()) ? "*" : " ") + Info.GetName());
                Table.setValue("Description", No::ellipsize(Info.GetDescription(), 128));
            }

            PutStatus(Table);
        }

        std::set<NoModuleInfo> ssNetworkMods;
        NoApp::Get().GetLoader()->GetAvailableMods(ssNetworkMods, No::NetworkModule);

        if (ssNetworkMods.empty()) {
            PutStatus("No network modules available.");
        } else {
            PutStatus("Network modules:");
            NoTable Table;
            Table.addColumn("Name");
            Table.addColumn("Description");

            for (const NoModuleInfo& Info : ssNetworkMods) {
                Table.addRow();
                Table.setValue("Name", ((d->network && d->network->GetLoader()->FindModule(Info.GetName())) ? "*" : " ") + Info.GetName());
                Table.setValue("Description", No::ellipsize(Info.GetDescription(), 128));
            }

            PutStatus(Table);
        }
        return;
    } else if (sCommand.equals("LOADMOD") || sCommand.equals("LOADMODULE")) {
        No::ModuleType eType;
        NoString sType = No::token(sLine, 1);
        NoString sMod = No::token(sLine, 2);
        NoString sArgs = No::tokens(sLine, 3);

        // TODO use proper library for parsing arguments
        if (sType.equals("--type=global")) {
            eType = No::GlobalModule;
        } else if (sType.equals("--type=user")) {
            eType = No::UserModule;
        } else if (sType.equals("--type=network")) {
            eType = No::NetworkModule;
        } else {
            sMod = sType;
            sArgs = No::tokens(sLine, 2);
            sType = "default";
            // Will be set correctly later
            eType = No::UserModule;
        }

        if (d->user->DenyLoadMod()) {
            PutStatus("Unable to load [" + sMod + "]: Access Denied.");
            return;
        }

        if (sMod.empty()) {
            PutStatus("Usage: LoadMod [--type=global|user|network] <module> [args]");
            return;
        }

        NoModuleInfo ModInfo;
        NoString sRetMsg;
        if (!NoApp::Get().GetLoader()->GetModInfo(ModInfo, sMod, sRetMsg)) {
            PutStatus("Unable to find modinfo [" + sMod + "] [" + sRetMsg + "]");
            return;
        }

        if (sType.equals("default")) {
            eType = ModInfo.GetDefaultType();
        }

        if (eType == No::GlobalModule && !d->user->IsAdmin()) {
            PutStatus("Unable to load global module [" + sMod + "]: Access Denied.");
            return;
        }

        if (eType == No::NetworkModule && !d->network) {
            PutStatus("Unable to load network module [" + sMod + "] Not connected with a network.");
            return;
        }

        NoString sModRet;
        bool b = false;

        switch (eType) {
        case No::GlobalModule:
            b = NoApp::Get().GetLoader()->LoadModule(sMod, sArgs, eType, nullptr, nullptr, sModRet);
            break;
        case No::UserModule:
            b = d->user->GetLoader()->LoadModule(sMod, sArgs, eType, d->user, nullptr, sModRet);
            break;
        case No::NetworkModule:
            b = d->network->GetLoader()->LoadModule(sMod, sArgs, eType, d->user, d->network, sModRet);
            break;
        default:
            sModRet = "Unable to load module [" + sMod + "]: Unknown module type";
        }

        if (b) sModRet = "Loaded module [" + sMod + "] " + sModRet;

        PutStatus(sModRet);
        return;
    } else if (sCommand.equals("UNLOADMOD") || sCommand.equals("UNLOADMODULE")) {
        No::ModuleType eType = No::UserModule;
        NoString sType = No::token(sLine, 1);
        NoString sMod = No::token(sLine, 2);

        // TODO use proper library for parsing arguments
        if (sType.equals("--type=global")) {
            eType = No::GlobalModule;
        } else if (sType.equals("--type=user")) {
            eType = No::UserModule;
        } else if (sType.equals("--type=network")) {
            eType = No::NetworkModule;
        } else {
            sMod = sType;
            sType = "default";
        }

        if (d->user->DenyLoadMod()) {
            PutStatus("Unable to unload [" + sMod + "] Access Denied.");
            return;
        }

        if (sMod.empty()) {
            PutStatus("Usage: UnloadMod [--type=global|user|network] <module>");
            return;
        }

        if (sType.equals("default")) {
            NoModuleInfo ModInfo;
            NoString sRetMsg;
            if (!NoApp::Get().GetLoader()->GetModInfo(ModInfo, sMod, sRetMsg)) {
                PutStatus("Unable to find modinfo [" + sMod + "] [" + sRetMsg + "]");
                return;
            }

            eType = ModInfo.GetDefaultType();
        }

        if (eType == No::GlobalModule && !d->user->IsAdmin()) {
            PutStatus("Unable to unload global module [" + sMod + "]: Access Denied.");
            return;
        }

        if (eType == No::NetworkModule && !d->network) {
            PutStatus("Unable to unload network module [" + sMod + "] Not connected with a network.");
            return;
        }

        NoString sModRet;

        switch (eType) {
        case No::GlobalModule:
            NoApp::Get().GetLoader()->UnloadModule(sMod, sModRet);
            break;
        case No::UserModule:
            d->user->GetLoader()->UnloadModule(sMod, sModRet);
            break;
        case No::NetworkModule:
            d->network->GetLoader()->UnloadModule(sMod, sModRet);
            break;
        default:
            sModRet = "Unable to unload module [" + sMod + "]: Unknown module type";
        }

        PutStatus(sModRet);
        return;
    } else if (sCommand.equals("RELOADMOD") || sCommand.equals("RELOADMODULE")) {
        No::ModuleType eType;
        NoString sType = No::token(sLine, 1);
        NoString sMod = No::token(sLine, 2);
        NoString sArgs = No::tokens(sLine, 3);

        if (d->user->DenyLoadMod()) {
            PutStatus("Unable to reload modules. Access Denied.");
            return;
        }

        // TODO use proper library for parsing arguments
        if (sType.equals("--type=global")) {
            eType = No::GlobalModule;
        } else if (sType.equals("--type=user")) {
            eType = No::UserModule;
        } else if (sType.equals("--type=network")) {
            eType = No::NetworkModule;
        } else {
            sMod = sType;
            sArgs = No::tokens(sLine, 2);
            sType = "default";
            // Will be set correctly later
            eType = No::UserModule;
        }

        if (sMod.empty()) {
            PutStatus("Usage: ReloadMod [--type=global|user|network] <module> [args]");
            return;
        }

        if (sType.equals("default")) {
            NoModuleInfo ModInfo;
            NoString sRetMsg;
            if (!NoApp::Get().GetLoader()->GetModInfo(ModInfo, sMod, sRetMsg)) {
                PutStatus("Unable to find modinfo for [" + sMod + "] [" + sRetMsg + "]");
                return;
            }

            eType = ModInfo.GetDefaultType();
        }

        if (eType == No::GlobalModule && !d->user->IsAdmin()) {
            PutStatus("Unable to reload global module [" + sMod + "]: Access Denied.");
            return;
        }

        if (eType == No::NetworkModule && !d->network) {
            PutStatus("Unable to load network module [" + sMod + "] Not connected with a network.");
            return;
        }

        NoString sModRet;

        switch (eType) {
        case No::GlobalModule:
            NoApp::Get().GetLoader()->ReloadModule(sMod, sArgs, nullptr, nullptr, sModRet);
            break;
        case No::UserModule:
            d->user->GetLoader()->ReloadModule(sMod, sArgs, d->user, nullptr, sModRet);
            break;
        case No::NetworkModule:
            d->network->GetLoader()->ReloadModule(sMod, sArgs, d->user, d->network, sModRet);
            break;
        default:
            sModRet = "Unable to reload module [" + sMod + "]: Unknown module type";
        }

        PutStatus(sModRet);
        return;
    } else if ((sCommand.equals("UPDATEMOD") || sCommand.equals("UPDATEMODULE")) && d->user->IsAdmin()) {
        NoString sMod = No::token(sLine, 1);

        if (sMod.empty()) {
            PutStatus("Usage: UpdateMod <module>");
            return;
        }

        PutStatus("Reloading [" + sMod + "] everywhere");
        if (NoApp::Get().UpdateModule(sMod)) {
            PutStatus("Done");
        } else {
            PutStatus("Done, but there were errors, [" + sMod + "] could not be loaded everywhere.");
        }
    } else if ((sCommand.equals("ADDBINDHOST") || sCommand.equals("ADDVHOST")) && d->user->IsAdmin()) {
        NoString sHost = No::token(sLine, 1);

        if (sHost.empty()) {
            PutStatus("Usage: AddBindHost <host>");
            return;
        }

        if (NoApp::Get().AddBindHost(sHost)) {
            PutStatus("Done");
        } else {
            PutStatus("The host [" + sHost + "] is already in the list");
        }
    } else if ((sCommand.equals("REMBINDHOST") || sCommand.equals("DELBINDHOST") || sCommand.equals("REMVHOST") ||
                sCommand.equals("DELVHOST")) &&
               d->user->IsAdmin()) {
        NoString sHost = No::token(sLine, 1);

        if (sHost.empty()) {
            PutStatus("Usage: DelBindHost <host>");
            return;
        }

        if (NoApp::Get().RemBindHost(sHost)) {
            PutStatus("Done");
        } else {
            PutStatus("The host [" + sHost + "] is not in the list");
        }
    } else if ((sCommand.equals("LISTBINDHOSTS") || sCommand.equals("LISTVHOSTS")) &&
               (d->user->IsAdmin() || !d->user->DenySetBindHost())) {
        const NoStringVector& vsHosts = NoApp::Get().GetBindHosts();

        if (vsHosts.empty()) {
            PutStatus("No bind hosts configured");
            return;
        }

        NoTable Table;
        Table.addColumn("Host");

        for (const NoString& sHost : vsHosts) {
            Table.addRow();
            Table.setValue("Host", sHost);
        }
        PutStatus(Table);
    } else if ((sCommand.equals("SETBINDHOST") || sCommand.equals("SETVHOST")) &&
               (d->user->IsAdmin() || !d->user->DenySetBindHost())) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command. Try SetUserBindHost instead");
            return;
        }
        NoString sArg = No::token(sLine, 1);

        if (sArg.empty()) {
            PutStatus("Usage: SetBindHost <host>");
            return;
        }

        if (sArg.equals(d->network->GetBindHost())) {
            PutStatus("You already have this bind host!");
            return;
        }

        const NoStringVector& vsHosts = NoApp::Get().GetBindHosts();
        if (!d->user->IsAdmin() && !vsHosts.empty()) {
            bool bFound = false;

            for (const NoString& sHost : vsHosts) {
                if (sArg.equals(sHost)) {
                    bFound = true;
                    break;
                }
            }

            if (!bFound) {
                PutStatus("You may not use this bind host. See [ListBindHosts] for a list");
                return;
            }
        }

        d->network->SetBindHost(sArg);
        PutStatus("Set bind host for network [" + d->network->GetName() + "] to [" + d->network->GetBindHost() + "]");
    } else if (sCommand.equals("SETUSERBINDHOST") && (d->user->IsAdmin() || !d->user->DenySetBindHost())) {
        NoString sArg = No::token(sLine, 1);

        if (sArg.empty()) {
            PutStatus("Usage: SetUserBindHost <host>");
            return;
        }

        if (sArg.equals(d->user->GetBindHost())) {
            PutStatus("You already have this bind host!");
            return;
        }

        const NoStringVector& vsHosts = NoApp::Get().GetBindHosts();
        if (!d->user->IsAdmin() && !vsHosts.empty()) {
            bool bFound = false;

            for (const NoString& sHost : vsHosts) {
                if (sArg.equals(sHost)) {
                    bFound = true;
                    break;
                }
            }

            if (!bFound) {
                PutStatus("You may not use this bind host. See [ListBindHosts] for a list");
                return;
            }
        }

        d->user->SetBindHost(sArg);
        PutStatus("Set bind host to [" + d->user->GetBindHost() + "]");
    } else if ((sCommand.equals("CLEARBINDHOST") || sCommand.equals("CLEARVHOST")) &&
               (d->user->IsAdmin() || !d->user->DenySetBindHost())) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command. Try ClearUserBindHost instead");
            return;
        }
        d->network->SetBindHost("");
        PutStatus("Bind host cleared for this network.");
    } else if (sCommand.equals("CLEARUSERBINDHOST") && (d->user->IsAdmin() || !d->user->DenySetBindHost())) {
        d->user->SetBindHost("");
        PutStatus("Bind host cleared for your user.");
    } else if (sCommand.equals("SHOWBINDHOST")) {
        PutStatus("This user's default bind host " +
                  (d->user->GetBindHost().empty() ? "not set" : "is [" + d->user->GetBindHost() + "]"));
        if (d->network) {
            PutStatus("This network's bind host " +
                      (d->network->GetBindHost().empty() ? "not set" : "is [" + d->network->GetBindHost() + "]"));
        }
    } else if (sCommand.equals("PLAYBUFFER")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sBuffer = No::token(sLine, 1);

        if (sBuffer.empty()) {
            PutStatus("Usage: PlayBuffer <#chan|query>");
            return;
        }

        if (d->network->IsChan(sBuffer)) {
            NoChannel* pChan = d->network->FindChan(sBuffer);

            if (!pChan) {
                PutStatus("You are not on [" + sBuffer + "]");
                return;
            }

            if (!pChan->isOn()) {
                PutStatus("You are not on [" + sBuffer + "] [trying]");
                return;
            }

            if (pChan->getBuffer().isEmpty()) {
                PutStatus("The buffer for [" + sBuffer + "] is empty");
                return;
            }

            pChan->sendBuffer(this);
        } else {
            NoQuery* pQuery = d->network->FindQuery(sBuffer);

            if (!pQuery) {
                PutStatus("No active query with [" + sBuffer + "]");
                return;
            }

            if (pQuery->getBuffer().isEmpty()) {
                PutStatus("The buffer for [" + sBuffer + "] is empty");
                return;
            }

            pQuery->sendBuffer(this);
        }
    } else if (sCommand.equals("CLEARBUFFER")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sBuffer = No::token(sLine, 1);

        if (sBuffer.empty()) {
            PutStatus("Usage: ClearBuffer <#chan|query>");
            return;
        }

        uint uMatches = 0;
        std::vector<NoChannel*> vChans = d->network->FindChans(sBuffer);
        for (NoChannel* pChan : vChans) {
            uMatches++;

            pChan->clearBuffer();
        }

        std::vector<NoQuery*> vQueries = d->network->FindQueries(sBuffer);
        for (NoQuery* pQuery : vQueries) {
            uMatches++;

            d->network->DelQuery(pQuery->getName());
        }

        PutStatus("[" + NoString(uMatches) + "] buffers matching [" + sBuffer + "] have been cleared");
    } else if (sCommand.equals("CLEARALLCHANNELBUFFERS")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        for (NoChannel* pChan : d->network->GetChans()) {
            pChan->clearBuffer();
        }
        PutStatus("All channel buffers have been cleared");
    } else if (sCommand.equals("CLEARALLQUERYBUFFERS")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        d->network->ClearQueryBuffer();
        PutStatus("All query buffers have been cleared");
    } else if (sCommand.equals("CLEARALLBUFFERS")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        for (NoChannel* pChan : d->network->GetChans()) {
            pChan->clearBuffer();
        }
        d->network->ClearQueryBuffer();
        PutStatus("All buffers have been cleared");
    } else if (sCommand.equals("SETBUFFER")) {
        if (!d->network) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sBuffer = No::token(sLine, 1);

        if (sBuffer.empty()) {
            PutStatus("Usage: SetBuffer <#chan|query> [linecount]");
            return;
        }

        uint uLineCount = No::token(sLine, 2).toUInt();
        uint uMatches = 0, uFail = 0;
        std::vector<NoChannel*> vChans = d->network->FindChans(sBuffer);
        for (NoChannel* pChan : vChans) {
            uMatches++;

            if (!pChan->setBufferCount(uLineCount)) uFail++;
        }

        std::vector<NoQuery*> vQueries = d->network->FindQueries(sBuffer);
        for (NoQuery* pQuery : vQueries) {
            uMatches++;

            if (!pQuery->setBufferCount(uLineCount)) uFail++;
        }

        PutStatus("BufferCount for [" + NoString(uMatches - uFail) + "] buffer was set to [" + NoString(uLineCount) + "]");
        if (uFail > 0) {
            PutStatus("Setting BufferCount failed for [" + NoString(uFail) + "] buffers, "
                                                                            "max buffer count is " +
                      NoString(NoApp::Get().GetMaxBufferSize()));
        }
    } else if (d->user->IsAdmin() && sCommand.equals("TRAFFIC")) {
        NoApp::TrafficStatsPair Users, ZNC, Total;
        NoApp::TrafficStatsMap traffic = NoApp::Get().GetTrafficStats(Users, ZNC, Total);

        NoTable Table;
        Table.addColumn("Username");
        Table.addColumn("In");
        Table.addColumn("Out");
        Table.addColumn("Total");

        for (const auto& it : traffic) {
            Table.addRow();
            Table.setValue("Username", it.first);
            Table.setValue("In", No::toByteStr(it.second.first));
            Table.setValue("Out", No::toByteStr(it.second.second));
            Table.setValue("Total", No::toByteStr(it.second.first + it.second.second));
        }

        Table.addRow();
        Table.setValue("Username", "<Users>");
        Table.setValue("In", No::toByteStr(Users.first));
        Table.setValue("Out", No::toByteStr(Users.second));
        Table.setValue("Total", No::toByteStr(Users.first + Users.second));

        Table.addRow();
        Table.setValue("Username", "<ZNC>");
        Table.setValue("In", No::toByteStr(ZNC.first));
        Table.setValue("Out", No::toByteStr(ZNC.second));
        Table.setValue("Total", No::toByteStr(ZNC.first + ZNC.second));

        Table.addRow();
        Table.setValue("Username", "<Total>");
        Table.setValue("In", No::toByteStr(Total.first));
        Table.setValue("Out", No::toByteStr(Total.second));
        Table.setValue("Total", No::toByteStr(Total.first + Total.second));

        PutStatus(Table);
    } else if (sCommand.equals("UPTIME")) {
        PutStatus("Running for " + NoApp::Get().GetUptime());
    } else if (d->user->IsAdmin() &&
               (sCommand.equals("LISTPORTS") || sCommand.equals("ADDPORT") || sCommand.equals("DELPORT"))) {
        UserPortCommand(sLine);
    } else {
        PutStatus("Unknown command [" + sCommand + "] try 'Help'");
    }
}

void NoClient::UserPortCommand(NoString& sLine)
{
    const NoString sCommand = No::token(sLine, 0);

    if (sCommand.equals("LISTPORTS")) {
        NoTable Table;
        Table.addColumn("Port");
        Table.addColumn("BindHost");
        Table.addColumn("SSL");
        Table.addColumn("Proto");
        Table.addColumn("IRC/Web");
        Table.addColumn("URIPrefix");

        std::vector<NoListener*>::const_iterator it;
        const std::vector<NoListener*>& vpListeners = NoApp::Get().GetListeners();

        for (const NoListener* pListener : vpListeners) {
            Table.addRow();
            Table.setValue("Port", NoString(pListener->port()));
            Table.setValue("BindHost", (pListener->host().empty() ? NoString("*") : pListener->host()));
            Table.setValue("SSL", NoString(pListener->isSsl()));

            No::AddressType eAddr = pListener->addressType();
            Table.setValue("Proto", (eAddr == No::Ipv4AndIpv6Address ? "All" : (eAddr == No::Ipv4Address ? "IPv4" : "IPv6")));

            No::AcceptType eAccept = pListener->acceptType();
            Table.setValue("IRC/Web",
                          (eAccept == No::AcceptAll ? "All" :
                                                              (eAccept == No::AcceptIrc ? "IRC" : "Web")));
            Table.setValue("URIPrefix", pListener->uriPrefix() + "/");
        }

        PutStatus(Table);

        return;
    }

    NoString sPort = No::token(sLine, 1);
    NoString sAddr = No::token(sLine, 2);
    No::AddressType eAddr = No::Ipv4AndIpv6Address;

    if (sAddr.equals("IPV4")) {
        eAddr = No::Ipv4Address;
    } else if (sAddr.equals("IPV6")) {
        eAddr = No::Ipv6Address;
    } else if (sAddr.equals("ALL")) {
        eAddr = No::Ipv4AndIpv6Address;
    } else {
        sAddr.clear();
    }

    ushort uPort = sPort.toUShort();

    if (sCommand.equals("ADDPORT")) {
        No::AcceptType eAccept = No::AcceptAll;
        NoString sAccept = No::token(sLine, 3);

        if (sAccept.equals("WEB")) {
            eAccept = No::AcceptHttp;
        } else if (sAccept.equals("IRC")) {
            eAccept = No::AcceptIrc;
        } else if (sAccept.equals("ALL")) {
            eAccept = No::AcceptAll;
        } else {
            sAccept.clear();
        }

        if (sPort.empty() || sAddr.empty() || sAccept.empty()) {
            PutStatus("Usage: AddPort <[+]port> <ipv4|ipv6|all> <web|irc|all> [bindhost [uriprefix]]");
        } else {
            bool bSSL = (sPort.left(1).equals("+"));
            const NoString sHost = No::token(sLine, 4);
            const NoString sURIPrefix = No::token(sLine, 5);

            NoListener* pListener = new NoListener(sHost, uPort);
            pListener->setUriPrefix(sURIPrefix);
            pListener->setSsl(bSSL);
            pListener->setAddressType(eAddr);
            pListener->setAcceptType(eAccept);

            if (!pListener->listen()) {
                delete pListener;
                PutStatus("Unable to bind [" + NoString(strerror(errno)) + "]");
            } else {
                if (NoApp::Get().AddListener(pListener))
                    PutStatus("Port Added");
                else
                    PutStatus("Error?!");
            }
        }
    } else if (sCommand.equals("DELPORT")) {
        if (sPort.empty() || sAddr.empty()) {
            PutStatus("Usage: DelPort <port> <ipv4|ipv6|all> [bindhost]");
        } else {
            const NoString sBindHost = No::token(sLine, 3);

            NoListener* pListener = NoApp::Get().FindListener(uPort, sBindHost, eAddr);

            if (pListener) {
                NoApp::Get().DelListener(pListener);
                PutStatus("Deleted Port");
            } else {
                PutStatus("Unable to find a matching port");
            }
        }
    }
}

static void AddCommandHelp(NoTable& Table, const NoString& sCmd, const NoString& sArgs, const NoString& sDesc, const NoString& sFilter = "")
{
    if (sFilter.empty() || sCmd.startsWith(sFilter) || wildCmp(sCmd, sFilter, No::CaseInsensitive)) {
        Table.addRow();
        Table.setValue("Command", sCmd);
        Table.setValue("Arguments", sArgs);
        Table.setValue("Description", sDesc);
    }
}

void NoClient::HelpUser(const NoString& sFilter)
{
    NoTable Table;
    Table.addColumn("Command");
    Table.addColumn("Arguments");
    Table.addColumn("Description");

    if (sFilter.empty()) {
        PutStatus("In the following list all occurrences of <#chan> support wildcards (* and ?)");
        PutStatus("(Except ListNicks)");
    }

    AddCommandHelp(Table, "Version", "", "Print which version of ZNC this is", sFilter);

    AddCommandHelp(Table, "ListMods", "", "List all loaded modules", sFilter);
    AddCommandHelp(Table, "ListAvailMods", "", "List all available modules", sFilter);
    if (!d->user->IsAdmin()) { // If they are an admin we will add this command below with an argument
        AddCommandHelp(Table, "ListChans", "", "List all channels", sFilter);
    }
    AddCommandHelp(Table, "ListNicks", "<#chan>", "List all nicks on a channel", sFilter);
    if (!d->user->IsAdmin()) {
        AddCommandHelp(Table, "ListClients", "", "List all clients connected to your ZNC user", sFilter);
    }
    AddCommandHelp(Table, "ListServers", "", "List all servers of current IRC network", sFilter);

    AddCommandHelp(Table, "AddNetwork", "<name>", "Add a network to your user", sFilter);
    AddCommandHelp(Table, "DelNetwork", "<name>", "Delete a network from your user", sFilter);
    AddCommandHelp(Table, "ListNetworks", "", "List all networks", sFilter);
    if (d->user->IsAdmin()) {
        AddCommandHelp(Table,
                       "MoveNetwork",
                       "<old user> <old network> <new user> [new network]",
                       "Move an IRC network from one user to another",
                       sFilter);
    }
    AddCommandHelp(Table,
                   "JumpNetwork",
                   "<network>",
                   "Jump to another network (Alternatively, you can connect to ZNC several times, using "
                   "`user/network` as username)",
                   sFilter);

    AddCommandHelp(Table,
                   "AddServer",
                   "<host> [[+]port] [pass]",
                   "Add a server to the list of alternate/backup servers of current IRC network.",
                   sFilter);
    AddCommandHelp(Table,
                   "DelServer",
                   "<host> [port] [pass]",
                   "Remove a server from the list of alternate/backup servers of current IRC network",
                   sFilter);

    AddCommandHelp(Table,
                   "AddTrustedServerFingerprint",
                   "<fi:ng:er>",
                   "Add a trusted server SSL certificate fingerprint (SHA-256) to current IRC network.",
                   sFilter);
    AddCommandHelp(Table,
                   "DelTrustedServerFingerprint",
                   "<fi:ng:er>",
                   "Delete a trusted server SSL certificate from current IRC network.",
                   sFilter);
    AddCommandHelp(
    Table, "ListTrustedServerFingerprints", "", "List all trusted server SSL certificates of current IRC network.", sFilter);

    AddCommandHelp(Table, "ShowChan", "<#chan>", "Show channel details", sFilter);
    AddCommandHelp(Table, "EnableChan", "<#chans>", "Enable channels", sFilter);
    AddCommandHelp(Table, "DisableChan", "<#chans>", "Disable channels", sFilter);
    AddCommandHelp(Table, "Detach", "<#chans>", "Detach from channels", sFilter);
    AddCommandHelp(Table, "Topics", "", "Show topics in all your channels", sFilter);

    AddCommandHelp(Table, "PlayBuffer", "<#chan|query>", "Play back the specified buffer", sFilter);
    AddCommandHelp(Table, "ClearBuffer", "<#chan|query>", "Clear the specified buffer", sFilter);
    AddCommandHelp(Table, "ClearAllBuffers", "", "Clear all channel and query buffers", sFilter);
    AddCommandHelp(Table, "ClearAllChannelBuffers", "", "Clear the channel buffers", sFilter);
    AddCommandHelp(Table, "ClearAllQueryBuffers", "", "Clear the query buffers", sFilter);
    AddCommandHelp(Table, "SetBuffer", "<#chan|query> [linecount]", "Set the buffer count", sFilter);

    if (d->user->IsAdmin()) {
        AddCommandHelp(Table, "AddBindHost", "<host (IP preferred)>", "Adds a bind host for normal users to use", sFilter);
        AddCommandHelp(Table, "DelBindHost", "<host>", "Removes a bind host from the list", sFilter);
    }

    if (d->user->IsAdmin() || !d->user->DenySetBindHost()) {
        AddCommandHelp(Table, "ListBindHosts", "", "Shows the configured list of bind hosts", sFilter);
        AddCommandHelp(Table, "SetBindHost", "<host (IP preferred)>", "Set the bind host for this connection", sFilter);
        AddCommandHelp(Table, "SetUserBindHost", "<host (IP preferred)>", "Set the default bind host for this user", sFilter);
        AddCommandHelp(Table, "ClearBindHost", "", "Clear the bind host for this connection", sFilter);
        AddCommandHelp(Table, "ClearUserBindHost", "", "Clear the default bind host for this user", sFilter);
    }

    AddCommandHelp(Table, "ShowBindHost", "", "Show currently selected bind host", sFilter);
    AddCommandHelp(Table, "Jump", "[server]", "Jump to the next or the specified server", sFilter);
    AddCommandHelp(Table, "Disconnect", "[message]", "Disconnect from IRC", sFilter);
    AddCommandHelp(Table, "Connect", "", "Reconnect to IRC", sFilter);
    AddCommandHelp(Table, "Uptime", "", "Show for how long ZNC has been running", sFilter);

    if (!d->user->DenyLoadMod()) {
        AddCommandHelp(Table, "LoadMod", "[--type=global|user|network] <module>", "Load a module", sFilter);
        AddCommandHelp(Table, "UnloadMod", "[--type=global|user|network] <module>", "Unload a module", sFilter);
        AddCommandHelp(Table, "ReloadMod", "[--type=global|user|network] <module>", "Reload a module", sFilter);
        if (d->user->IsAdmin()) {
            AddCommandHelp(Table, "UpdateMod", "<module>", "Reload a module everywhere", sFilter);
        }
    }

    AddCommandHelp(Table, "ShowMOTD", "", "Show ZNC's message of the day", sFilter);

    if (d->user->IsAdmin()) {
        AddCommandHelp(Table, "SetMOTD", "<message>", "Set ZNC's message of the day", sFilter);
        AddCommandHelp(Table, "AddMOTD", "<message>", "Append <message> to ZNC's MOTD", sFilter);
        AddCommandHelp(Table, "ClearMOTD", "", "Clear ZNC's MOTD", sFilter);
        AddCommandHelp(Table, "ListPorts", "", "Show all active listeners", sFilter);
        AddCommandHelp(Table,
                       "AddPort",
                       "<[+]port> <ipv4|ipv6|all> <web|irc|all> [bindhost [uriprefix]]",
                       "Add another port for ZNC to listen on",
                       sFilter);
        AddCommandHelp(Table, "DelPort", "<port> <ipv4|ipv6|all> [bindhost]", "Remove a port from ZNC", sFilter);
        AddCommandHelp(Table, "Rehash", "", "Reload znc.conf from disk", sFilter);
        AddCommandHelp(Table, "SaveConfig", "", "Save the current settings to disk", sFilter);
        AddCommandHelp(Table, "ListUsers", "", "List all ZNC users and their connection status", sFilter);
        AddCommandHelp(Table, "ListAllUserNetworks", "", "List all ZNC users and their networks", sFilter);
        AddCommandHelp(Table, "ListChans", "[user <network>]", "List all channels", sFilter);
        AddCommandHelp(Table, "ListClients", "[user]", "List all connected clients", sFilter);
        AddCommandHelp(Table, "Traffic", "", "Show basic traffic stats for all ZNC users", sFilter);
        AddCommandHelp(Table, "Broadcast", "[message]", "Broadcast a message to all ZNC users", sFilter);
        AddCommandHelp(Table, "Shutdown", "[message]", "Shut down ZNC completely", sFilter);
        AddCommandHelp(Table, "Restart", "[message]", "Restart ZNC", sFilter);
    }

    if (Table.isEmpty()) {
        PutStatus("No matches for '" + sFilter + "'");
    } else {
        PutStatus(Table);
    }
}
