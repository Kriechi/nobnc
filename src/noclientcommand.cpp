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

#include "noclient.h"
#include "nochannel.h"
#include "nodir.h"
#include "nonetwork.h"
#include "noircconnection.h"
#include "noserver.h"
#include "nouser.h"
#include "noquery.h"
#include "noexception.h"
#include "nomodulecall.h"
#include "noapp.h"

void NoClient::UserCommand(NoString& sLine)
{
    if (!m_pUser) {
        return;
    }

    if (sLine.empty()) {
        return;
    }

    bool bReturn = false;
    NETWORKMODULECALL(OnStatusCommand(sLine), m_pUser, m_pNetwork, this, &bReturn);
    if (bReturn) return;

    const NoString sCommand = sLine.Token(0);

    if (sCommand.Equals("HELP")) {
        HelpUser(sLine.Token(1));
    } else if (sCommand.Equals("LISTNICKS")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sChan = sLine.Token(1);

        if (sChan.empty()) {
            PutStatus("Usage: ListNicks <#chan>");
            return;
        }

        NoChannel* pChan = m_pNetwork->FindChan(sChan);

        if (!pChan) {
            PutStatus("You are not on [" + sChan + "]");
            return;
        }

        if (!pChan->isOn()) {
            PutStatus("You are not on [" + sChan + "] [trying]");
            return;
        }

        const std::map<NoString, NoNick>& msNicks = pChan->getNicks();
        NoIrcConnection* pIRCSock = m_pNetwork->GetIRCSock();
        const NoString& sPerms = (pIRCSock) ? pIRCSock->GetPerms() : "";

        if (msNicks.empty()) {
            PutStatus("No nicks on [" + sChan + "]");
            return;
        }

        NoTable Table;

        for (uint p = 0; p < sPerms.size(); p++) {
            NoString sPerm;
            sPerm += sPerms[p];
            Table.AddColumn(sPerm);
        }

        Table.AddColumn("Nick");
        Table.AddColumn("Ident");
        Table.AddColumn("Host");

        for (const auto& it : msNicks) {
            Table.AddRow();

            for (uint b = 0; b < sPerms.size(); b++) {
                if (it.second.hasPerm(sPerms[b])) {
                    NoString sPerm;
                    sPerm += sPerms[b];
                    Table.SetCell(sPerm, sPerm);
                }
            }

            Table.SetCell("Nick", it.second.nick());
            Table.SetCell("Ident", it.second.ident());
            Table.SetCell("Host", it.second.host());
        }

        PutStatus(Table);
    } else if (sCommand.Equals("DETACH")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sPatterns = sLine.Tokens(1);

        if (sPatterns.empty()) {
            PutStatus("Usage: Detach <#chans>");
            return;
        }

        sPatterns.Replace(",", " ");
        NoStringVector vsChans = sPatterns.Split(" ", No::SkipEmptyParts);

        std::set<NoChannel*> sChans;
        for (const NoString& sChan : vsChans) {
            std::vector<NoChannel*> vChans = m_pNetwork->FindChans(sChan);
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
    } else if (sCommand.Equals("VERSION")) {
        PutStatus(NoApp::GetTag());
        PutStatus(NoApp::GetCompileOptionsString());
    } else if (sCommand.Equals("MOTD") || sCommand.Equals("ShowMOTD")) {
        if (!SendMotd()) {
            PutStatus("There is no MOTD set.");
        }
    } else if (m_pUser->IsAdmin() && sCommand.Equals("Rehash")) {
        NoString sRet;

        if (NoApp::Get().RehashConfig(sRet)) {
            PutStatus("Rehashing succeeded!");
        } else {
            PutStatus("Rehashing failed: " + sRet);
        }
    } else if (m_pUser->IsAdmin() && sCommand.Equals("SaveConfig")) {
        if (NoApp::Get().WriteConfig()) {
            PutStatus("Wrote config to [" + NoApp::Get().GetConfigFile() + "]");
        } else {
            PutStatus("Error while trying to write config.");
        }
    } else if (sCommand.Equals("LISTCLIENTS")) {
        NoUser* pUser = m_pUser;
        NoString sNick = sLine.Token(1);

        if (!sNick.empty()) {
            if (!m_pUser->IsAdmin()) {
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
        Table.AddColumn("Host");
        Table.AddColumn("Network");
        Table.AddColumn("Identifier");

        for (const NoClient* pClient : vClients) {
            Table.AddRow();
            Table.SetCell("Host", pClient->GetRemoteIP());
            if (pClient->GetNetwork()) {
                Table.SetCell("Network", pClient->GetNetwork()->GetName());
            }
            Table.SetCell("Identifier", pClient->GetIdentifier());
        }

        PutStatus(Table);
    } else if (m_pUser->IsAdmin() && sCommand.Equals("LISTUSERS")) {
        const std::map<NoString, NoUser*>& msUsers = NoApp::Get().GetUserMap();
        NoTable Table;
        Table.AddColumn("Username");
        Table.AddColumn("Networks");
        Table.AddColumn("Clients");

        for (const auto& it : msUsers) {
            Table.AddRow();
            Table.SetCell("Username", it.first);
            Table.SetCell("Networks", NoString(it.second->GetNetworks().size()));
            Table.SetCell("Clients", NoString(it.second->GetAllClients().size()));
        }

        PutStatus(Table);
    } else if (m_pUser->IsAdmin() && sCommand.Equals("LISTALLUSERNETWORKS")) {
        const std::map<NoString, NoUser*>& msUsers = NoApp::Get().GetUserMap();
        NoTable Table;
        Table.AddColumn("Username");
        Table.AddColumn("Network");
        Table.AddColumn("Clients");
        Table.AddColumn("OnIRC");
        Table.AddColumn("IRC Server");
        Table.AddColumn("IRC User");
        Table.AddColumn("Channels");

        for (const auto& it : msUsers) {
            Table.AddRow();
            Table.SetCell("Username", it.first);
            Table.SetCell("Network", "N/A");
            Table.SetCell("Clients", NoString(it.second->GetUserClients().size()));

            const std::vector<NoNetwork*>& vNetworks = it.second->GetNetworks();

            for (const NoNetwork* pNetwork : vNetworks) {
                Table.AddRow();
                if (pNetwork == vNetworks.back()) {
                    Table.SetCell("Username", "`-");
                } else {
                    Table.SetCell("Username", "|-");
                }
                Table.SetCell("Network", pNetwork->GetName());
                Table.SetCell("Clients", NoString(pNetwork->GetClients().size()));
                if (pNetwork->IsIRCConnected()) {
                    Table.SetCell("OnIRC", "Yes");
                    Table.SetCell("IRC Server", pNetwork->GetIRCServer());
                    Table.SetCell("IRC User", pNetwork->GetIRCNick().nickMask());
                    Table.SetCell("Channels", NoString(pNetwork->GetChans().size()));
                } else {
                    Table.SetCell("OnIRC", "No");
                }
            }
        }

        PutStatus(Table);
    } else if (m_pUser->IsAdmin() && sCommand.Equals("SetMOTD")) {
        NoString sMessage = sLine.Tokens(1);

        if (sMessage.empty()) {
            PutStatus("Usage: SetMOTD <message>");
        } else {
            NoApp::Get().SetMotd(sMessage);
            PutStatus("MOTD set to [" + sMessage + "]");
        }
    } else if (m_pUser->IsAdmin() && sCommand.Equals("AddMOTD")) {
        NoString sMessage = sLine.Tokens(1);

        if (sMessage.empty()) {
            PutStatus("Usage: AddMOTD <message>");
        } else {
            NoApp::Get().AddMotd(sMessage);
            PutStatus("Added [" + sMessage + "] to MOTD");
        }
    } else if (m_pUser->IsAdmin() && sCommand.Equals("ClearMOTD")) {
        NoApp::Get().ClearMotd();
        PutStatus("Cleared MOTD");
    } else if (m_pUser->IsAdmin() && sCommand.Equals("BROADCAST")) {
        NoApp::Get().Broadcast(sLine.Tokens(1));
    } else if (m_pUser->IsAdmin() && (sCommand.Equals("SHUTDOWN") || sCommand.Equals("RESTART"))) {
        bool bRestart = sCommand.Equals("RESTART");
        NoString sMessage = sLine.Tokens(1);
        bool bForce = false;

        if (sMessage.Token(0).Equals("FORCE")) {
            bForce = true;
            sMessage = sMessage.Tokens(1);
        }

        if (sMessage.empty()) {
            sMessage = (bRestart ? "ZNC is being restarted NOW!" : "ZNC is being shut down NOW!");
        }

        if (!NoApp::Get().WriteConfig() && !bForce) {
            PutStatus("ERROR: Writing config file to disk failed! Aborting. Use " + sCommand.AsUpper() +
                      " FORCE to ignore.");
        } else {
            NoApp::Get().Broadcast(sMessage);
            throw NoException(bRestart ? NoException::Restart : NoException::Shutdown);
        }
    } else if (sCommand.Equals("JUMP") || sCommand.Equals("CONNECT")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        if (!m_pNetwork->HasServers()) {
            PutStatus("You don't have any servers added.");
            return;
        }

        NoString sArgs = sLine.Tokens(1);
        sArgs.Trim();
        NoServer* pServer = nullptr;

        if (!sArgs.empty()) {
            pServer = m_pNetwork->FindServer(sArgs);
            if (!pServer) {
                PutStatus("Server [" + sArgs + "] not found");
                return;
            }
            m_pNetwork->SetNextServer(pServer);

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
                PutStatus("Connecting to [" + pServer->GetName() + "]...");
            else
                PutStatus("Jumping to the next server in the list...");
        } else {
            if (pServer)
                PutStatus("Connecting to [" + pServer->GetName() + "]...");
            else
                PutStatus("Connecting...");
        }

        m_pNetwork->SetIRCConnectEnabled(true);
        return;
    } else if (sCommand.Equals("DISCONNECT")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        if (GetIRCSock()) {
            NoString sQuitMsg = sLine.Tokens(1);
            GetIRCSock()->Quit(sQuitMsg);
        }

        m_pNetwork->SetIRCConnectEnabled(false);
        PutStatus("Disconnected from IRC. Use 'connect' to reconnect.");
        return;
    } else if (sCommand.Equals("ENABLECHAN")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sPatterns = sLine.Tokens(1);

        if (sPatterns.empty()) {
            PutStatus("Usage: EnableChan <#chans>");
        } else {
            sPatterns.Replace(",", " ");
            NoStringVector vsChans = sPatterns.Split(" ", No::SkipEmptyParts);

            std::set<NoChannel*> sChans;
            for (const NoString& sChan : vsChans) {
                std::vector<NoChannel*> vChans = m_pNetwork->FindChans(sChan);
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
    } else if (sCommand.Equals("DISABLECHAN")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sPatterns = sLine.Tokens(1);

        if (sPatterns.empty()) {
            PutStatus("Usage: DisableChan <#chans>");
        } else {
            sPatterns.Replace(",", " ");
            NoStringVector vsChans = sPatterns.Split(" ", No::SkipEmptyParts);

            std::set<NoChannel*> sChans;
            for (const NoString& sChan : vsChans) {
                std::vector<NoChannel*> vChans = m_pNetwork->FindChans(sChan);
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
    } else if (sCommand.Equals("SHOWCHAN")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sChan = sLine.Tokens(1);
        if (sChan.empty()) {
            PutStatus("Usage: ShowChan <#chan>");
            return;
        }

        NoChannel* pChan = m_pNetwork->FindChan(sChan);
        if (!pChan) {
            PutStatus("No such channel [" + sChan + "]");
            return;
        }
        sChan = pChan->getPermStr() + pChan->getName();
        NoString sStatus =
        pChan->isOn() ? (pChan->isDetached() ? "Detached" : "Joined") : (pChan->isDisabled() ? "Disabled" : "Trying");

        NoTable Table;
        Table.AddColumn(sChan, false);
        Table.AddColumn(sStatus);

        Table.AddRow();
        Table.SetCell(sChan, "InConfig");
        Table.SetCell(sStatus, NoString(pChan->inConfig() ? "yes" : "no"));

        Table.AddRow();
        Table.SetCell(sChan, "Buffer");
        Table.SetCell(sStatus,
                      NoString(pChan->getBuffer().size()) + "/" + NoString(pChan->getBufferCount()) +
                      NoString(pChan->hasBufferCountSet() ? "" : " (default)"));

        Table.AddRow();
        Table.SetCell(sChan, "AutoClearChanBuffer");
        Table.SetCell(sStatus,
                      NoString(pChan->autoClearChanBuffer() ? "yes" : "no") +
                      NoString(pChan->hasAutoClearChanBufferSet() ? "" : " (default)"));

        if (pChan->isOn()) {
            Table.AddRow();
            Table.SetCell(sChan, "Topic");
            Table.SetCell(sStatus, pChan->getTopic());

            Table.AddRow();
            Table.SetCell(sChan, "Modes");
            Table.SetCell(sStatus, pChan->getModeString());

            Table.AddRow();
            Table.SetCell(sChan, "Users");

            NoStringVector vsUsers;
            vsUsers.push_back("All: " + NoString(pChan->getNickCount()));

            NoIrcConnection* pIRCSock = m_pNetwork->GetIRCSock();
            const NoString& sPerms = pIRCSock ? pIRCSock->GetPerms() : "";
            std::map<char, uint> mPerms = pChan->getPermCounts();
            for (char cPerm : sPerms) {
                vsUsers.push_back(NoString(cPerm) + ": " + NoString(mPerms[cPerm]));
            }
            Table.SetCell(sStatus, NoString(", ").Join(vsUsers.begin(), vsUsers.end()));
        }

        PutStatus(Table);
    } else if (sCommand.Equals("LISTCHANS")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoNetwork* pNetwork = m_pNetwork;

        const NoString sNick = sLine.Token(1);
        const NoString sNetwork = sLine.Token(2);

        if (!sNick.empty()) {
            if (!m_pUser->IsAdmin()) {
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
        Table.AddColumn("Name");
        Table.AddColumn("Status");

        uint uNumDetached = 0, uNumDisabled = 0, uNumJoined = 0;

        for (const NoChannel* pChan : vChans) {
            Table.AddRow();
            Table.SetCell("Name", pChan->getPermStr() + pChan->getName());
            Table.SetCell("Status",
                          ((pChan->isOn()) ? ((pChan->isDetached()) ? "Detached" : "Joined") :
                                             ((pChan->isDisabled()) ? "Disabled" : "Trying")));

            if (pChan->isDetached()) uNumDetached++;
            if (pChan->isOn()) uNumJoined++;
            if (pChan->isDisabled()) uNumDisabled++;
        }

        PutStatus(Table);
        PutStatus("Total: " + NoString(vChans.size()) + " - Joined: " + NoString(uNumJoined) + " - Detached: " +
                  NoString(uNumDetached) + " - Disabled: " + NoString(uNumDisabled));
    } else if (sCommand.Equals("ADDNETWORK")) {
        if (!m_pUser->IsAdmin() && !m_pUser->HasSpaceForNewNetwork()) {
            PutStatus("Network number limit reached. Ask an admin to increase the limit for you, or delete unneeded "
                      "networks using /znc DelNetwork <name>");
            return;
        }

        NoString sNetwork = sLine.Token(1);

        if (sNetwork.empty()) {
            PutStatus("Usage: AddNetwork <name>");
            return;
        }
        if (!NoNetwork::IsValidNetwork(sNetwork)) {
            PutStatus("Network name should be alphanumeric");
            return;
        }

        NoString sNetworkAddError;
        if (m_pUser->AddNetwork(sNetwork, sNetworkAddError)) {
            PutStatus("Network added. Use /znc JumpNetwork " + sNetwork + ", or connect to ZNC with username " +
                      m_pUser->GetUserName() + "/" + sNetwork + " (instead of just " + m_pUser->GetUserName() +
                      ") to connect to it.");
        } else {
            PutStatus("Unable to add that network");
            PutStatus(sNetworkAddError);
        }
    } else if (sCommand.Equals("DELNETWORK")) {
        NoString sNetwork = sLine.Token(1);

        if (sNetwork.empty()) {
            PutStatus("Usage: DelNetwork <name>");
            return;
        }

        if (m_pNetwork && m_pNetwork->GetName().Equals(sNetwork)) {
            SetNetwork(nullptr);
        }

        if (m_pUser->DeleteNetwork(sNetwork)) {
            PutStatus("Network deleted");
        } else {
            PutStatus("Failed to delete network");
            PutStatus("Perhaps this network doesn't exist");
        }
    } else if (sCommand.Equals("LISTNETWORKS")) {
        NoUser* pUser = m_pUser;

        if (m_pUser->IsAdmin() && !sLine.Token(1).empty()) {
            pUser = NoApp::Get().FindUser(sLine.Token(1));

            if (!pUser) {
                PutStatus("User not found " + sLine.Token(1));
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

        for (const NoNetwork* pNetwork : vNetworks) {
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

        if (PutStatus(Table) == 0) {
            PutStatus("No networks");
        }
    } else if (sCommand.Equals("MOVENETWORK")) {
        if (!m_pUser->IsAdmin()) {
            PutStatus("Access Denied.");
            return;
        }

        NoString sOldUser = sLine.Token(1);
        NoString sOldNetwork = sLine.Token(2);
        NoString sNewUser = sLine.Token(3);
        NoString sNewNetwork = sLine.Token(4);

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

        const NoModules& vMods = pOldNetwork->GetModules();
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

            pMod->MoveRegistry(sNewModPath);
        }

        NoString sNetworkAddError;
        NoNetwork* pNewNetwork = pNewUser->AddNetwork(sNewNetwork, sNetworkAddError);

        if (!pNewNetwork) {
            PutStatus("Error adding network:" + sNetworkAddError);
            return;
        }

        pNewNetwork->Clone(*pOldNetwork, false);

        if (m_pNetwork && m_pNetwork->GetName().Equals(sOldNetwork) && m_pUser == pOldUser) {
            SetNetwork(nullptr);
        }

        if (pOldUser->DeleteNetwork(sOldNetwork)) {
            PutStatus("Success.");
        } else {
            PutStatus("Copied the network to new user, but failed to delete old network");
        }
    } else if (sCommand.Equals("JUMPNETWORK")) {
        NoString sNetwork = sLine.Token(1);

        if (sNetwork.empty()) {
            PutStatus("No network supplied.");
            return;
        }

        if (m_pNetwork && (m_pNetwork->GetName() == sNetwork)) {
            PutStatus("You are already connected with this network.");
            return;
        }

        NoNetwork* pNetwork = m_pUser->FindNetwork(sNetwork);
        if (pNetwork) {
            PutStatus("Switched to " + sNetwork);
            SetNetwork(pNetwork);
        } else {
            PutStatus("You don't have a network named " + sNetwork);
        }
    } else if (sCommand.Equals("ADDSERVER")) {
        NoString sServer = sLine.Token(1);

        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        if (sServer.empty()) {
            PutStatus("Usage: AddServer <host> [[+]port] [pass]");
            return;
        }

        if (m_pNetwork->AddServer(sLine.Tokens(1))) {
            PutStatus("Server added");
        } else {
            PutStatus("Unable to add that server");
            PutStatus("Perhaps the server is already added or openssl is disabled?");
        }
    } else if (sCommand.Equals("REMSERVER") || sCommand.Equals("DELSERVER")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sServer = sLine.Token(1);
        ushort uPort = sLine.Token(2).ToUShort();
        NoString sPass = sLine.Token(3);

        if (sServer.empty()) {
            PutStatus("Usage: DelServer <host> [port] [pass]");
            return;
        }

        if (!m_pNetwork->HasServers()) {
            PutStatus("You don't have any servers added.");
            return;
        }

        if (m_pNetwork->DelServer(sServer, uPort, sPass)) {
            PutStatus("Server removed");
        } else {
            PutStatus("No such server");
        }
    } else if (sCommand.Equals("LISTSERVERS")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        if (m_pNetwork->HasServers()) {
            const std::vector<NoServer*>& vServers = m_pNetwork->GetServers();
            NoServer* pCurServ = m_pNetwork->GetCurrentServer();
            NoTable Table;
            Table.AddColumn("Host");
            Table.AddColumn("Port");
            Table.AddColumn("SSL");
            Table.AddColumn("Pass");

            for (const NoServer* pServer : vServers) {
                Table.AddRow();
                Table.SetCell("Host", pServer->GetName() + (pServer == pCurServ ? "*" : ""));
                Table.SetCell("Port", NoString(pServer->GetPort()));
                Table.SetCell("SSL", (pServer->IsSSL()) ? "SSL" : "");
                Table.SetCell("Pass", pServer->GetPass());
            }

            PutStatus(Table);
        } else {
            PutStatus("You don't have any servers added.");
        }
    } else if (sCommand.Equals("AddTrustedServerFingerprint")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }
        NoString sFP = sLine.Token(1);
        if (sFP.empty()) {
            PutStatus("Usage: AddTrustedServerFingerprint <fi:ng:er>");
            return;
        }
        m_pNetwork->AddTrustedFingerprint(sFP);
        PutStatus("Done.");
    } else if (sCommand.Equals("DelTrustedServerFingerprint")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }
        NoString sFP = sLine.Token(1);
        if (sFP.empty()) {
            PutStatus("Usage: DelTrustedServerFingerprint <fi:ng:er>");
            return;
        }
        m_pNetwork->DelTrustedFingerprint(sFP);
        PutStatus("Done.");
    } else if (sCommand.Equals("ListTrustedServerFingerprints")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }
        const NoStringSet& ssFPs = m_pNetwork->GetTrustedFingerprints();
        if (ssFPs.empty()) {
            PutStatus("No fingerprints added.");
        } else {
            int k = 0;
            for (const NoString& sFP : ssFPs) {
                PutStatus(NoString(++k) + ". " + sFP);
            }
        }
    } else if (sCommand.Equals("TOPICS")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        const std::vector<NoChannel*>& vChans = m_pNetwork->GetChans();
        NoTable Table;
        Table.AddColumn("Name");
        Table.AddColumn("Set By");
        Table.AddColumn("Topic");

        for (const NoChannel* pChan : vChans) {
            Table.AddRow();
            Table.SetCell("Name", pChan->getName());
            Table.SetCell("Set By", pChan->getTopicOwner());
            Table.SetCell("Topic", pChan->getTopic());
        }

        PutStatus(Table);
    } else if (sCommand.Equals("LISTMODS") || sCommand.Equals("LISTMODULES")) {
        if (m_pUser->IsAdmin()) {
            NoModules& GModules = NoApp::Get().GetModules();

            if (!GModules.size()) {
                PutStatus("No global modules loaded.");
            } else {
                PutStatus("Global modules:");
                NoTable GTable;
                GTable.AddColumn("Name");
                GTable.AddColumn("Arguments");

                for (const NoModule* pMod : GModules) {
                    GTable.AddRow();
                    GTable.SetCell("Name", pMod->GetModName());
                    GTable.SetCell("Arguments", pMod->GetArgs());
                }

                PutStatus(GTable);
            }
        }

        NoModules& Modules = m_pUser->GetModules();

        if (!Modules.size()) {
            PutStatus("Your user has no modules loaded.");
        } else {
            PutStatus("User modules:");
            NoTable Table;
            Table.AddColumn("Name");
            Table.AddColumn("Arguments");

            for (const NoModule* pMod : Modules) {
                Table.AddRow();
                Table.SetCell("Name", pMod->GetModName());
                Table.SetCell("Arguments", pMod->GetArgs());
            }

            PutStatus(Table);
        }

        if (m_pNetwork) {
            NoModules& NetworkModules = m_pNetwork->GetModules();
            if (NetworkModules.empty()) {
                PutStatus("This network has no modules loaded.");
            } else {
                PutStatus("Network modules:");
                NoTable Table;
                Table.AddColumn("Name");
                Table.AddColumn("Arguments");

                for (const NoModule* pMod : NetworkModules) {
                    Table.AddRow();
                    Table.SetCell("Name", pMod->GetModName());
                    Table.SetCell("Arguments", pMod->GetArgs());
                }

                PutStatus(Table);
            }
        }

        return;
    } else if (sCommand.Equals("LISTAVAILMODS") || sCommand.Equals("LISTAVAILABLEMODULES")) {
        if (m_pUser->DenyLoadMod()) {
            PutStatus("Access Denied.");
            return;
        }

        if (m_pUser->IsAdmin()) {
            std::set<NoModInfo> ssGlobalMods;
            NoApp::Get().GetModules().GetAvailableMods(ssGlobalMods, NoModInfo::GlobalModule);

            if (ssGlobalMods.empty()) {
                PutStatus("No global modules available.");
            } else {
                PutStatus("Global modules:");
                NoTable GTable;
                GTable.AddColumn("Name");
                GTable.AddColumn("Description");

                for (const NoModInfo& Info : ssGlobalMods) {
                    GTable.AddRow();
                    GTable.SetCell("Name", (NoApp::Get().GetModules().FindModule(Info.GetName()) ? "*" : " ") + Info.GetName());
                    GTable.SetCell("Description", NoUtils::Ellipsize(Info.GetDescription(), 128));
                }

                PutStatus(GTable);
            }
        }

        std::set<NoModInfo> ssUserMods;
        NoApp::Get().GetModules().GetAvailableMods(ssUserMods);

        if (ssUserMods.empty()) {
            PutStatus("No user modules available.");
        } else {
            PutStatus("User modules:");
            NoTable Table;
            Table.AddColumn("Name");
            Table.AddColumn("Description");

            for (const NoModInfo& Info : ssUserMods) {
                Table.AddRow();
                Table.SetCell("Name", (m_pUser->GetModules().FindModule(Info.GetName()) ? "*" : " ") + Info.GetName());
                Table.SetCell("Description", NoUtils::Ellipsize(Info.GetDescription(), 128));
            }

            PutStatus(Table);
        }

        std::set<NoModInfo> ssNetworkMods;
        NoApp::Get().GetModules().GetAvailableMods(ssNetworkMods, NoModInfo::NetworkModule);

        if (ssNetworkMods.empty()) {
            PutStatus("No network modules available.");
        } else {
            PutStatus("Network modules:");
            NoTable Table;
            Table.AddColumn("Name");
            Table.AddColumn("Description");

            for (const NoModInfo& Info : ssNetworkMods) {
                Table.AddRow();
                Table.SetCell("Name", ((m_pNetwork && m_pNetwork->GetModules().FindModule(Info.GetName())) ? "*" : " ") + Info.GetName());
                Table.SetCell("Description", NoUtils::Ellipsize(Info.GetDescription(), 128));
            }

            PutStatus(Table);
        }
        return;
    } else if (sCommand.Equals("LOADMOD") || sCommand.Equals("LOADMODULE")) {
        NoModInfo::EModuleType eType;
        NoString sType = sLine.Token(1);
        NoString sMod = sLine.Token(2);
        NoString sArgs = sLine.Tokens(3);

        // TODO use proper library for parsing arguments
        if (sType.Equals("--type=global")) {
            eType = NoModInfo::GlobalModule;
        } else if (sType.Equals("--type=user")) {
            eType = NoModInfo::UserModule;
        } else if (sType.Equals("--type=network")) {
            eType = NoModInfo::NetworkModule;
        } else {
            sMod = sType;
            sArgs = sLine.Tokens(2);
            sType = "default";
            // Will be set correctly later
            eType = NoModInfo::UserModule;
        }

        if (m_pUser->DenyLoadMod()) {
            PutStatus("Unable to load [" + sMod + "]: Access Denied.");
            return;
        }

        if (sMod.empty()) {
            PutStatus("Usage: LoadMod [--type=global|user|network] <module> [args]");
            return;
        }

        NoModInfo ModInfo;
        NoString sRetMsg;
        if (!NoApp::Get().GetModules().GetModInfo(ModInfo, sMod, sRetMsg)) {
            PutStatus("Unable to find modinfo [" + sMod + "] [" + sRetMsg + "]");
            return;
        }

        if (sType.Equals("default")) {
            eType = ModInfo.GetDefaultType();
        }

        if (eType == NoModInfo::GlobalModule && !m_pUser->IsAdmin()) {
            PutStatus("Unable to load global module [" + sMod + "]: Access Denied.");
            return;
        }

        if (eType == NoModInfo::NetworkModule && !m_pNetwork) {
            PutStatus("Unable to load network module [" + sMod + "] Not connected with a network.");
            return;
        }

        NoString sModRet;
        bool b = false;

        switch (eType) {
        case NoModInfo::GlobalModule:
            b = NoApp::Get().GetModules().LoadModule(sMod, sArgs, eType, nullptr, nullptr, sModRet);
            break;
        case NoModInfo::UserModule:
            b = m_pUser->GetModules().LoadModule(sMod, sArgs, eType, m_pUser, nullptr, sModRet);
            break;
        case NoModInfo::NetworkModule:
            b = m_pNetwork->GetModules().LoadModule(sMod, sArgs, eType, m_pUser, m_pNetwork, sModRet);
            break;
        default:
            sModRet = "Unable to load module [" + sMod + "]: Unknown module type";
        }

        if (b) sModRet = "Loaded module [" + sMod + "] " + sModRet;

        PutStatus(sModRet);
        return;
    } else if (sCommand.Equals("UNLOADMOD") || sCommand.Equals("UNLOADMODULE")) {
        NoModInfo::EModuleType eType = NoModInfo::UserModule;
        NoString sType = sLine.Token(1);
        NoString sMod = sLine.Token(2);

        // TODO use proper library for parsing arguments
        if (sType.Equals("--type=global")) {
            eType = NoModInfo::GlobalModule;
        } else if (sType.Equals("--type=user")) {
            eType = NoModInfo::UserModule;
        } else if (sType.Equals("--type=network")) {
            eType = NoModInfo::NetworkModule;
        } else {
            sMod = sType;
            sType = "default";
        }

        if (m_pUser->DenyLoadMod()) {
            PutStatus("Unable to unload [" + sMod + "] Access Denied.");
            return;
        }

        if (sMod.empty()) {
            PutStatus("Usage: UnloadMod [--type=global|user|network] <module>");
            return;
        }

        if (sType.Equals("default")) {
            NoModInfo ModInfo;
            NoString sRetMsg;
            if (!NoApp::Get().GetModules().GetModInfo(ModInfo, sMod, sRetMsg)) {
                PutStatus("Unable to find modinfo [" + sMod + "] [" + sRetMsg + "]");
                return;
            }

            eType = ModInfo.GetDefaultType();
        }

        if (eType == NoModInfo::GlobalModule && !m_pUser->IsAdmin()) {
            PutStatus("Unable to unload global module [" + sMod + "]: Access Denied.");
            return;
        }

        if (eType == NoModInfo::NetworkModule && !m_pNetwork) {
            PutStatus("Unable to unload network module [" + sMod + "] Not connected with a network.");
            return;
        }

        NoString sModRet;

        switch (eType) {
        case NoModInfo::GlobalModule:
            NoApp::Get().GetModules().UnloadModule(sMod, sModRet);
            break;
        case NoModInfo::UserModule:
            m_pUser->GetModules().UnloadModule(sMod, sModRet);
            break;
        case NoModInfo::NetworkModule:
            m_pNetwork->GetModules().UnloadModule(sMod, sModRet);
            break;
        default:
            sModRet = "Unable to unload module [" + sMod + "]: Unknown module type";
        }

        PutStatus(sModRet);
        return;
    } else if (sCommand.Equals("RELOADMOD") || sCommand.Equals("RELOADMODULE")) {
        NoModInfo::EModuleType eType;
        NoString sType = sLine.Token(1);
        NoString sMod = sLine.Token(2);
        NoString sArgs = sLine.Tokens(3);

        if (m_pUser->DenyLoadMod()) {
            PutStatus("Unable to reload modules. Access Denied.");
            return;
        }

        // TODO use proper library for parsing arguments
        if (sType.Equals("--type=global")) {
            eType = NoModInfo::GlobalModule;
        } else if (sType.Equals("--type=user")) {
            eType = NoModInfo::UserModule;
        } else if (sType.Equals("--type=network")) {
            eType = NoModInfo::NetworkModule;
        } else {
            sMod = sType;
            sArgs = sLine.Tokens(2);
            sType = "default";
            // Will be set correctly later
            eType = NoModInfo::UserModule;
        }

        if (sMod.empty()) {
            PutStatus("Usage: ReloadMod [--type=global|user|network] <module> [args]");
            return;
        }

        if (sType.Equals("default")) {
            NoModInfo ModInfo;
            NoString sRetMsg;
            if (!NoApp::Get().GetModules().GetModInfo(ModInfo, sMod, sRetMsg)) {
                PutStatus("Unable to find modinfo for [" + sMod + "] [" + sRetMsg + "]");
                return;
            }

            eType = ModInfo.GetDefaultType();
        }

        if (eType == NoModInfo::GlobalModule && !m_pUser->IsAdmin()) {
            PutStatus("Unable to reload global module [" + sMod + "]: Access Denied.");
            return;
        }

        if (eType == NoModInfo::NetworkModule && !m_pNetwork) {
            PutStatus("Unable to load network module [" + sMod + "] Not connected with a network.");
            return;
        }

        NoString sModRet;

        switch (eType) {
        case NoModInfo::GlobalModule:
            NoApp::Get().GetModules().ReloadModule(sMod, sArgs, nullptr, nullptr, sModRet);
            break;
        case NoModInfo::UserModule:
            m_pUser->GetModules().ReloadModule(sMod, sArgs, m_pUser, nullptr, sModRet);
            break;
        case NoModInfo::NetworkModule:
            m_pNetwork->GetModules().ReloadModule(sMod, sArgs, m_pUser, m_pNetwork, sModRet);
            break;
        default:
            sModRet = "Unable to reload module [" + sMod + "]: Unknown module type";
        }

        PutStatus(sModRet);
        return;
    } else if ((sCommand.Equals("UPDATEMOD") || sCommand.Equals("UPDATEMODULE")) && m_pUser->IsAdmin()) {
        NoString sMod = sLine.Token(1);

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
    } else if ((sCommand.Equals("ADDBINDHOST") || sCommand.Equals("ADDVHOST")) && m_pUser->IsAdmin()) {
        NoString sHost = sLine.Token(1);

        if (sHost.empty()) {
            PutStatus("Usage: AddBindHost <host>");
            return;
        }

        if (NoApp::Get().AddBindHost(sHost)) {
            PutStatus("Done");
        } else {
            PutStatus("The host [" + sHost + "] is already in the list");
        }
    } else if ((sCommand.Equals("REMBINDHOST") || sCommand.Equals("DELBINDHOST") || sCommand.Equals("REMVHOST") ||
                sCommand.Equals("DELVHOST")) &&
               m_pUser->IsAdmin()) {
        NoString sHost = sLine.Token(1);

        if (sHost.empty()) {
            PutStatus("Usage: DelBindHost <host>");
            return;
        }

        if (NoApp::Get().RemBindHost(sHost)) {
            PutStatus("Done");
        } else {
            PutStatus("The host [" + sHost + "] is not in the list");
        }
    } else if ((sCommand.Equals("LISTBINDHOSTS") || sCommand.Equals("LISTVHOSTS")) &&
               (m_pUser->IsAdmin() || !m_pUser->DenySetBindHost())) {
        const NoStringVector& vsHosts = NoApp::Get().GetBindHosts();

        if (vsHosts.empty()) {
            PutStatus("No bind hosts configured");
            return;
        }

        NoTable Table;
        Table.AddColumn("Host");

        for (const NoString& sHost : vsHosts) {
            Table.AddRow();
            Table.SetCell("Host", sHost);
        }
        PutStatus(Table);
    } else if ((sCommand.Equals("SETBINDHOST") || sCommand.Equals("SETVHOST")) &&
               (m_pUser->IsAdmin() || !m_pUser->DenySetBindHost())) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command. Try SetUserBindHost instead");
            return;
        }
        NoString sArg = sLine.Token(1);

        if (sArg.empty()) {
            PutStatus("Usage: SetBindHost <host>");
            return;
        }

        if (sArg.Equals(m_pNetwork->GetBindHost())) {
            PutStatus("You already have this bind host!");
            return;
        }

        const NoStringVector& vsHosts = NoApp::Get().GetBindHosts();
        if (!m_pUser->IsAdmin() && !vsHosts.empty()) {
            bool bFound = false;

            for (const NoString& sHost : vsHosts) {
                if (sArg.Equals(sHost)) {
                    bFound = true;
                    break;
                }
            }

            if (!bFound) {
                PutStatus("You may not use this bind host. See [ListBindHosts] for a list");
                return;
            }
        }

        m_pNetwork->SetBindHost(sArg);
        PutStatus("Set bind host for network [" + m_pNetwork->GetName() + "] to [" + m_pNetwork->GetBindHost() + "]");
    } else if (sCommand.Equals("SETUSERBINDHOST") && (m_pUser->IsAdmin() || !m_pUser->DenySetBindHost())) {
        NoString sArg = sLine.Token(1);

        if (sArg.empty()) {
            PutStatus("Usage: SetUserBindHost <host>");
            return;
        }

        if (sArg.Equals(m_pUser->GetBindHost())) {
            PutStatus("You already have this bind host!");
            return;
        }

        const NoStringVector& vsHosts = NoApp::Get().GetBindHosts();
        if (!m_pUser->IsAdmin() && !vsHosts.empty()) {
            bool bFound = false;

            for (const NoString& sHost : vsHosts) {
                if (sArg.Equals(sHost)) {
                    bFound = true;
                    break;
                }
            }

            if (!bFound) {
                PutStatus("You may not use this bind host. See [ListBindHosts] for a list");
                return;
            }
        }

        m_pUser->SetBindHost(sArg);
        PutStatus("Set bind host to [" + m_pUser->GetBindHost() + "]");
    } else if ((sCommand.Equals("CLEARBINDHOST") || sCommand.Equals("CLEARVHOST")) &&
               (m_pUser->IsAdmin() || !m_pUser->DenySetBindHost())) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command. Try ClearUserBindHost instead");
            return;
        }
        m_pNetwork->SetBindHost("");
        PutStatus("Bind host cleared for this network.");
    } else if (sCommand.Equals("CLEARUSERBINDHOST") && (m_pUser->IsAdmin() || !m_pUser->DenySetBindHost())) {
        m_pUser->SetBindHost("");
        PutStatus("Bind host cleared for your user.");
    } else if (sCommand.Equals("SHOWBINDHOST")) {
        PutStatus("This user's default bind host " +
                  (m_pUser->GetBindHost().empty() ? "not set" : "is [" + m_pUser->GetBindHost() + "]"));
        if (m_pNetwork) {
            PutStatus("This network's bind host " +
                      (m_pNetwork->GetBindHost().empty() ? "not set" : "is [" + m_pNetwork->GetBindHost() + "]"));
        }
    } else if (sCommand.Equals("PLAYBUFFER")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sBuffer = sLine.Token(1);

        if (sBuffer.empty()) {
            PutStatus("Usage: PlayBuffer <#chan|query>");
            return;
        }

        if (m_pNetwork->IsChan(sBuffer)) {
            NoChannel* pChan = m_pNetwork->FindChan(sBuffer);

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
            NoQuery* pQuery = m_pNetwork->FindQuery(sBuffer);

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
    } else if (sCommand.Equals("CLEARBUFFER")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sBuffer = sLine.Token(1);

        if (sBuffer.empty()) {
            PutStatus("Usage: ClearBuffer <#chan|query>");
            return;
        }

        uint uMatches = 0;
        std::vector<NoChannel*> vChans = m_pNetwork->FindChans(sBuffer);
        for (NoChannel* pChan : vChans) {
            uMatches++;

            pChan->clearBuffer();
        }

        std::vector<NoQuery*> vQueries = m_pNetwork->FindQueries(sBuffer);
        for (NoQuery* pQuery : vQueries) {
            uMatches++;

            m_pNetwork->DelQuery(pQuery->getName());
        }

        PutStatus("[" + NoString(uMatches) + "] buffers matching [" + sBuffer + "] have been cleared");
    } else if (sCommand.Equals("CLEARALLCHANNELBUFFERS")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        for (NoChannel* pChan : m_pNetwork->GetChans()) {
            pChan->clearBuffer();
        }
        PutStatus("All channel buffers have been cleared");
    } else if (sCommand.Equals("CLEARALLQUERYBUFFERS")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        m_pNetwork->ClearQueryBuffer();
        PutStatus("All query buffers have been cleared");
    } else if (sCommand.Equals("CLEARALLBUFFERS")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        for (NoChannel* pChan : m_pNetwork->GetChans()) {
            pChan->clearBuffer();
        }
        m_pNetwork->ClearQueryBuffer();
        PutStatus("All buffers have been cleared");
    } else if (sCommand.Equals("SETBUFFER")) {
        if (!m_pNetwork) {
            PutStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sBuffer = sLine.Token(1);

        if (sBuffer.empty()) {
            PutStatus("Usage: SetBuffer <#chan|query> [linecount]");
            return;
        }

        uint uLineCount = sLine.Token(2).ToUInt();
        uint uMatches = 0, uFail = 0;
        std::vector<NoChannel*> vChans = m_pNetwork->FindChans(sBuffer);
        for (NoChannel* pChan : vChans) {
            uMatches++;

            if (!pChan->setBufferCount(uLineCount)) uFail++;
        }

        std::vector<NoQuery*> vQueries = m_pNetwork->FindQueries(sBuffer);
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
    } else if (m_pUser->IsAdmin() && sCommand.Equals("TRAFFIC")) {
        NoApp::TrafficStatsPair Users, ZNC, Total;
        NoApp::TrafficStatsMap traffic = NoApp::Get().GetTrafficStats(Users, ZNC, Total);

        NoTable Table;
        Table.AddColumn("Username");
        Table.AddColumn("In");
        Table.AddColumn("Out");
        Table.AddColumn("Total");

        for (const auto& it : traffic) {
            Table.AddRow();
            Table.SetCell("Username", it.first);
            Table.SetCell("In", NoUtils::ToByteStr(it.second.first));
            Table.SetCell("Out", NoUtils::ToByteStr(it.second.second));
            Table.SetCell("Total", NoUtils::ToByteStr(it.second.first + it.second.second));
        }

        Table.AddRow();
        Table.SetCell("Username", "<Users>");
        Table.SetCell("In", NoUtils::ToByteStr(Users.first));
        Table.SetCell("Out", NoUtils::ToByteStr(Users.second));
        Table.SetCell("Total", NoUtils::ToByteStr(Users.first + Users.second));

        Table.AddRow();
        Table.SetCell("Username", "<ZNC>");
        Table.SetCell("In", NoUtils::ToByteStr(ZNC.first));
        Table.SetCell("Out", NoUtils::ToByteStr(ZNC.second));
        Table.SetCell("Total", NoUtils::ToByteStr(ZNC.first + ZNC.second));

        Table.AddRow();
        Table.SetCell("Username", "<Total>");
        Table.SetCell("In", NoUtils::ToByteStr(Total.first));
        Table.SetCell("Out", NoUtils::ToByteStr(Total.second));
        Table.SetCell("Total", NoUtils::ToByteStr(Total.first + Total.second));

        PutStatus(Table);
    } else if (sCommand.Equals("UPTIME")) {
        PutStatus("Running for " + NoApp::Get().GetUptime());
    } else if (m_pUser->IsAdmin() &&
               (sCommand.Equals("LISTPORTS") || sCommand.Equals("ADDPORT") || sCommand.Equals("DELPORT"))) {
        UserPortCommand(sLine);
    } else {
        PutStatus("Unknown command [" + sCommand + "] try 'Help'");
    }
}

void NoClient::UserPortCommand(NoString& sLine)
{
    const NoString sCommand = sLine.Token(0);

    if (sCommand.Equals("LISTPORTS")) {
        NoTable Table;
        Table.AddColumn("Port");
        Table.AddColumn("BindHost");
        Table.AddColumn("SSL");
        Table.AddColumn("Proto");
        Table.AddColumn("IRC/Web");
        Table.AddColumn("URIPrefix");

        std::vector<NoListener*>::const_iterator it;
        const std::vector<NoListener*>& vpListeners = NoApp::Get().GetListeners();

        for (const NoListener* pListener : vpListeners) {
            Table.AddRow();
            Table.SetCell("Port", NoString(pListener->GetPort()));
            Table.SetCell("BindHost", (pListener->GetBindHost().empty() ? NoString("*") : pListener->GetBindHost()));
            Table.SetCell("SSL", NoString(pListener->IsSSL()));

            EAddrType eAddr = pListener->GetAddrType();
            Table.SetCell("Proto", (eAddr == ADDR_ALL ? "All" : (eAddr == ADDR_IPV4ONLY ? "IPv4" : "IPv6")));

            NoListener::EAcceptType eAccept = pListener->GetAcceptType();
            Table.SetCell("IRC/Web",
                          (eAccept == NoListener::ACCEPT_ALL ? "All" :
                                                              (eAccept == NoListener::ACCEPT_IRC ? "IRC" : "Web")));
            Table.SetCell("URIPrefix", pListener->GetURIPrefix() + "/");
        }

        PutStatus(Table);

        return;
    }

    NoString sPort = sLine.Token(1);
    NoString sAddr = sLine.Token(2);
    EAddrType eAddr = ADDR_ALL;

    if (sAddr.Equals("IPV4")) {
        eAddr = ADDR_IPV4ONLY;
    } else if (sAddr.Equals("IPV6")) {
        eAddr = ADDR_IPV6ONLY;
    } else if (sAddr.Equals("ALL")) {
        eAddr = ADDR_ALL;
    } else {
        sAddr.clear();
    }

    ushort uPort = sPort.ToUShort();

    if (sCommand.Equals("ADDPORT")) {
        NoListener::EAcceptType eAccept = NoListener::ACCEPT_ALL;
        NoString sAccept = sLine.Token(3);

        if (sAccept.Equals("WEB")) {
            eAccept = NoListener::ACCEPT_HTTP;
        } else if (sAccept.Equals("IRC")) {
            eAccept = NoListener::ACCEPT_IRC;
        } else if (sAccept.Equals("ALL")) {
            eAccept = NoListener::ACCEPT_ALL;
        } else {
            sAccept.clear();
        }

        if (sPort.empty() || sAddr.empty() || sAccept.empty()) {
            PutStatus("Usage: AddPort <[+]port> <ipv4|ipv6|all> <web|irc|all> [bindhost [uriprefix]]");
        } else {
            bool bSSL = (sPort.Left(1).Equals("+"));
            const NoString sBindHost = sLine.Token(4);
            const NoString sURIPrefix = sLine.Token(5);

            NoListener* pListener = new NoListener(uPort, sBindHost, sURIPrefix, bSSL, eAddr, eAccept);

            if (!pListener->Listen()) {
                delete pListener;
                PutStatus("Unable to bind [" + NoString(strerror(errno)) + "]");
            } else {
                if (NoApp::Get().AddListener(pListener))
                    PutStatus("Port Added");
                else
                    PutStatus("Error?!");
            }
        }
    } else if (sCommand.Equals("DELPORT")) {
        if (sPort.empty() || sAddr.empty()) {
            PutStatus("Usage: DelPort <port> <ipv4|ipv6|all> [bindhost]");
        } else {
            const NoString sBindHost = sLine.Token(3);

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
    if (sFilter.empty() || sCmd.StartsWith(sFilter) || sCmd.AsLower().WildCmp(sFilter.AsLower())) {
        Table.AddRow();
        Table.SetCell("Command", sCmd);
        Table.SetCell("Arguments", sArgs);
        Table.SetCell("Description", sDesc);
    }
}

void NoClient::HelpUser(const NoString& sFilter)
{
    NoTable Table;
    Table.AddColumn("Command");
    Table.AddColumn("Arguments");
    Table.AddColumn("Description");

    if (sFilter.empty()) {
        PutStatus("In the following list all occurrences of <#chan> support wildcards (* and ?)");
        PutStatus("(Except ListNicks)");
    }

    AddCommandHelp(Table, "Version", "", "Print which version of ZNC this is", sFilter);

    AddCommandHelp(Table, "ListMods", "", "List all loaded modules", sFilter);
    AddCommandHelp(Table, "ListAvailMods", "", "List all available modules", sFilter);
    if (!m_pUser->IsAdmin()) { // If they are an admin we will add this command below with an argument
        AddCommandHelp(Table, "ListChans", "", "List all channels", sFilter);
    }
    AddCommandHelp(Table, "ListNicks", "<#chan>", "List all nicks on a channel", sFilter);
    if (!m_pUser->IsAdmin()) {
        AddCommandHelp(Table, "ListClients", "", "List all clients connected to your ZNC user", sFilter);
    }
    AddCommandHelp(Table, "ListServers", "", "List all servers of current IRC network", sFilter);

    AddCommandHelp(Table, "AddNetwork", "<name>", "Add a network to your user", sFilter);
    AddCommandHelp(Table, "DelNetwork", "<name>", "Delete a network from your user", sFilter);
    AddCommandHelp(Table, "ListNetworks", "", "List all networks", sFilter);
    if (m_pUser->IsAdmin()) {
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

    if (m_pUser->IsAdmin()) {
        AddCommandHelp(Table, "AddBindHost", "<host (IP preferred)>", "Adds a bind host for normal users to use", sFilter);
        AddCommandHelp(Table, "DelBindHost", "<host>", "Removes a bind host from the list", sFilter);
    }

    if (m_pUser->IsAdmin() || !m_pUser->DenySetBindHost()) {
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

    if (!m_pUser->DenyLoadMod()) {
        AddCommandHelp(Table, "LoadMod", "[--type=global|user|network] <module>", "Load a module", sFilter);
        AddCommandHelp(Table, "UnloadMod", "[--type=global|user|network] <module>", "Unload a module", sFilter);
        AddCommandHelp(Table, "ReloadMod", "[--type=global|user|network] <module>", "Reload a module", sFilter);
        if (m_pUser->IsAdmin()) {
            AddCommandHelp(Table, "UpdateMod", "<module>", "Reload a module everywhere", sFilter);
        }
    }

    AddCommandHelp(Table, "ShowMOTD", "", "Show ZNC's message of the day", sFilter);

    if (m_pUser->IsAdmin()) {
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

    if (Table.empty()) {
        PutStatus("No matches for '" + sFilter + "'");
    } else {
        PutStatus(Table);
    }
}
