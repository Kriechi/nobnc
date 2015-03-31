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
#include "nofile.h"
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

void NoClient::userCommand(NoString& sLine)
{
    if (!d->user) {
        return;
    }

    if (sLine.empty()) {
        return;
    }

    bool bReturn = false;
    NETWORKMODULECALL(onStatusCommand(sLine), d->user, d->network, this, &bReturn);
    if (bReturn)
        return;

    const NoString sCommand = No::token(sLine, 0);

    if (sCommand.equals("HELP")) {
        helpUser(No::token(sLine, 1));
    } else if (sCommand.equals("LISTNICKS")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sChan = No::token(sLine, 1);

        if (sChan.empty()) {
            putStatus("Usage: ListNicks <#chan>");
            return;
        }

        NoChannel* pChan = d->network->findChannel(sChan);

        if (!pChan) {
            putStatus("You are not on [" + sChan + "]");
            return;
        }

        if (!pChan->isOn()) {
            putStatus("You are not on [" + sChan + "] [trying]");
            return;
        }

        const std::map<NoString, NoNick>& msNicks = pChan->nicks();
        NoIrcSocket* pIRCSock = d->network->ircSocket();
        const NoString& sPerms = (pIRCSock) ? pIRCSock->perms() : "";

        if (msNicks.empty()) {
            putStatus("No nicks on [" + sChan + "]");
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

        putStatus(Table);
    } else if (sCommand.equals("DETACH")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sPatterns = No::tokens(sLine, 1);

        if (sPatterns.empty()) {
            putStatus("Usage: Detach <#chans>");
            return;
        }

        sPatterns.replace(",", " ");
        NoStringVector vsChans = sPatterns.split(" ", No::SkipEmptyParts);

        std::set<NoChannel*> sChans;
        for (const NoString& sChan : vsChans) {
            std::vector<NoChannel*> vChans = d->network->findChannels(sChan);
            sChans.insert(vChans.begin(), vChans.end());
        }

        uint uDetached = 0;
        for (NoChannel* pChan : sChans) {
            if (pChan->isDetached())
                continue;
            uDetached++;
            pChan->detachUser();
        }

        putStatus("There were [" + NoString(sChans.size()) + "] channels matching [" + sPatterns + "]");
        putStatus("Detached [" + NoString(uDetached) + "] channels");
    } else if (sCommand.equals("VERSION")) {
        putStatus(NoApp::tag());
        putStatus(NoApp::compileOptionsString());
    } else if (sCommand.equals("MOTD") || sCommand.equals("ShowMOTD")) {
        if (!sendMotd()) {
            putStatus("There is no MOTD set.");
        }
    } else if (d->user->isAdmin() && sCommand.equals("Rehash")) {
        NoString sRet;

        if (noApp->rehashConfig(sRet)) {
            putStatus("Rehashing succeeded!");
        } else {
            putStatus("Rehashing failed: " + sRet);
        }
    } else if (d->user->isAdmin() && sCommand.equals("SaveConfig")) {
        if (noApp->writeConfig()) {
            putStatus("Wrote config to [" + noApp->configFile() + "]");
        } else {
            putStatus("Error while trying to write config.");
        }
    } else if (sCommand.equals("LISTCLIENTS")) {
        NoUser* pUser = d->user;
        NoString sNick = No::token(sLine, 1);

        if (!sNick.empty()) {
            if (!d->user->isAdmin()) {
                putStatus("Usage: ListClients");
                return;
            }

            pUser = noApp->findUser(sNick);

            if (!pUser) {
                putStatus("No such user [" + sNick + "]");
                return;
            }
        }

        std::vector<NoClient*> vClients = pUser->allClients();

        if (vClients.empty()) {
            putStatus("No clients are connected");
            return;
        }

        NoTable Table;
        Table.addColumn("Host");
        Table.addColumn("Network");
        Table.addColumn("Identifier");

        for (const NoClient* pClient : vClients) {
            Table.addRow();
            Table.setValue("Host", pClient->socket()->remoteAddress());
            if (pClient->network()) {
                Table.setValue("Network", pClient->network()->name());
            }
            Table.setValue("Identifier", pClient->identifier());
        }

        putStatus(Table);
    } else if (d->user->isAdmin() && sCommand.equals("LISTUSERS")) {
        const std::map<NoString, NoUser*>& msUsers = noApp->userMap();
        NoTable Table;
        Table.addColumn("Username");
        Table.addColumn("Networks");
        Table.addColumn("Clients");

        for (const auto& it : msUsers) {
            Table.addRow();
            Table.setValue("Username", it.first);
            Table.setValue("Networks", NoString(it.second->networks().size()));
            Table.setValue("Clients", NoString(it.second->allClients().size()));
        }

        putStatus(Table);
    } else if (d->user->isAdmin() && sCommand.equals("LISTALLUSERNETWORKS")) {
        const std::map<NoString, NoUser*>& msUsers = noApp->userMap();
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
            Table.setValue("Clients", NoString(it.second->userClients().size()));

            const std::vector<NoNetwork*>& vNetworks = it.second->networks();

            for (const NoNetwork* pNetwork : vNetworks) {
                Table.addRow();
                if (pNetwork == vNetworks.back()) {
                    Table.setValue("Username", "`-");
                } else {
                    Table.setValue("Username", "|-");
                }
                Table.setValue("Network", pNetwork->name());
                Table.setValue("Clients", NoString(pNetwork->clients().size()));
                if (pNetwork->isIrcConnected()) {
                    Table.setValue("OnIRC", "Yes");
                    Table.setValue("IRC Server", pNetwork->ircServer());
                    Table.setValue("IRC User", pNetwork->ircNick().nickMask());
                    Table.setValue("Channels", NoString(pNetwork->channels().size()));
                } else {
                    Table.setValue("OnIRC", "No");
                }
            }
        }

        putStatus(Table);
    } else if (d->user->isAdmin() && sCommand.equals("SetMOTD")) {
        NoString sMessage = No::tokens(sLine, 1);

        if (sMessage.empty()) {
            putStatus("Usage: SetMOTD <message>");
        } else {
            noApp->setMotd(sMessage);
            putStatus("MOTD set to [" + sMessage + "]");
        }
    } else if (d->user->isAdmin() && sCommand.equals("AddMOTD")) {
        NoString sMessage = No::tokens(sLine, 1);

        if (sMessage.empty()) {
            putStatus("Usage: AddMOTD <message>");
        } else {
            noApp->addMotd(sMessage);
            putStatus("Added [" + sMessage + "] to MOTD");
        }
    } else if (d->user->isAdmin() && sCommand.equals("ClearMOTD")) {
        noApp->clearMotd();
        putStatus("Cleared MOTD");
    } else if (d->user->isAdmin() && sCommand.equals("BROADCAST")) {
        noApp->broadcast(No::tokens(sLine, 1));
    } else if (d->user->isAdmin() && (sCommand.equals("SHUTDOWN") || sCommand.equals("RESTART"))) {
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

        if (!noApp->writeConfig() && !bForce) {
            putStatus("ERROR: Writing config file to disk failed! Aborting. Use " + sCommand.toUpper() +
                      " FORCE to ignore.");
        } else {
            noApp->broadcast(sMessage);
            throw NoException(bRestart ? NoException::Restart : NoException::Shutdown);
        }
    } else if (sCommand.equals("JUMP") || sCommand.equals("CONNECT")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        if (!d->network->hasServers()) {
            putStatus("You don't have any servers added.");
            return;
        }

        NoString sArgs = No::tokens(sLine, 1);
        sArgs.trim();
        NoServerInfo* pServer = nullptr;

        if (!sArgs.empty()) {
            pServer = d->network->findServer(sArgs);
            if (!pServer) {
                putStatus("Server [" + sArgs + "] not found");
                return;
            }
            d->network->setNextServer(pServer);

            // If we are already connecting to some server,
            // we have to abort that attempt
            NoSocket* pIRCSock = ircSocket();
            if (pIRCSock && !pIRCSock->isConnected()) {
                pIRCSock->close();
            }
        }

        if (ircSocket()) {
            ircSocket()->quit();
            if (pServer)
                putStatus("Connecting to [" + pServer->host() + "]...");
            else
                putStatus("Jumping to the next server in the list...");
        } else {
            if (pServer)
                putStatus("Connecting to [" + pServer->host() + "]...");
            else
                putStatus("Connecting...");
        }

        d->network->setEnabled(true);
        return;
    } else if (sCommand.equals("DISCONNECT")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        if (ircSocket()) {
            NoString sQuitMsg = No::tokens(sLine, 1);
            ircSocket()->quit(sQuitMsg);
        }

        d->network->setEnabled(false);
        putStatus("Disconnected from IRC. Use 'connect' to reconnect.");
        return;
    } else if (sCommand.equals("ENABLECHAN")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sPatterns = No::tokens(sLine, 1);

        if (sPatterns.empty()) {
            putStatus("Usage: EnableChan <#chans>");
        } else {
            sPatterns.replace(",", " ");
            NoStringVector vsChans = sPatterns.split(" ", No::SkipEmptyParts);

            std::set<NoChannel*> sChans;
            for (const NoString& sChan : vsChans) {
                std::vector<NoChannel*> vChans = d->network->findChannels(sChan);
                sChans.insert(vChans.begin(), vChans.end());
            }

            uint uEnabled = 0;
            for (NoChannel* pChan : sChans) {
                if (!pChan->isDisabled())
                    continue;
                uEnabled++;
                pChan->enable();
            }

            putStatus("There were [" + NoString(sChans.size()) + "] channels matching [" + sPatterns + "]");
            putStatus("Enabled [" + NoString(uEnabled) + "] channels");
        }
    } else if (sCommand.equals("DISABLECHAN")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sPatterns = No::tokens(sLine, 1);

        if (sPatterns.empty()) {
            putStatus("Usage: DisableChan <#chans>");
        } else {
            sPatterns.replace(",", " ");
            NoStringVector vsChans = sPatterns.split(" ", No::SkipEmptyParts);

            std::set<NoChannel*> sChans;
            for (const NoString& sChan : vsChans) {
                std::vector<NoChannel*> vChans = d->network->findChannels(sChan);
                sChans.insert(vChans.begin(), vChans.end());
            }

            uint uDisabled = 0;
            for (NoChannel* pChan : sChans) {
                if (pChan->isDisabled())
                    continue;
                uDisabled++;
                pChan->disable();
            }

            putStatus("There were [" + NoString(sChans.size()) + "] channels matching [" + sPatterns + "]");
            putStatus("Disabled [" + NoString(uDisabled) + "] channels");
        }
    } else if (sCommand.equals("SHOWCHAN")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sChan = No::tokens(sLine, 1);
        if (sChan.empty()) {
            putStatus("Usage: ShowChan <#chan>");
            return;
        }

        NoChannel* pChan = d->network->findChannel(sChan);
        if (!pChan) {
            putStatus("No such channel [" + sChan + "]");
            return;
        }
        sChan = pChan->permStr() + pChan->name();
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
                       NoString(pChan->buffer().size()) + "/" + NoString(pChan->bufferCount()) +
                       NoString(pChan->hasBufferCountSet() ? "" : " (default)"));

        Table.addRow();
        Table.setValue(sChan, "AutoClearChanBuffer");
        Table.setValue(sStatus,
                       NoString(pChan->autoClearChanBuffer() ? "yes" : "no") +
                       NoString(pChan->hasAutoClearChanBufferSet() ? "" : " (default)"));

        if (pChan->isOn()) {
            Table.addRow();
            Table.setValue(sChan, "Topic");
            Table.setValue(sStatus, pChan->topic());

            Table.addRow();
            Table.setValue(sChan, "Modes");
            Table.setValue(sStatus, pChan->modeString());

            Table.addRow();
            Table.setValue(sChan, "Users");

            NoStringVector vsUsers;
            vsUsers.push_back("All: " + NoString(pChan->nickCount()));

            NoIrcSocket* pIRCSock = d->network->ircSocket();
            const NoString& sPerms = pIRCSock ? pIRCSock->perms() : "";
            std::map<char, uint> mPerms = pChan->permCounts();
            for (char cPerm : sPerms) {
                vsUsers.push_back(NoString(cPerm) + ": " + NoString(mPerms[cPerm]));
            }
            Table.setValue(sStatus, NoString(", ").join(vsUsers.begin(), vsUsers.end()));
        }

        putStatus(Table);
    } else if (sCommand.equals("LISTCHANS")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoNetwork* pNetwork = d->network;

        const NoString sNick = No::token(sLine, 1);
        const NoString sNetwork = No::token(sLine, 2);

        if (!sNick.empty()) {
            if (!d->user->isAdmin()) {
                putStatus("Usage: ListChans");
                return;
            }

            NoUser* pUser = noApp->findUser(sNick);

            if (!pUser) {
                putStatus("No such user [" + sNick + "]");
                return;
            }

            pNetwork = pUser->findNetwork(sNetwork);
            if (!pNetwork) {
                putStatus("No such network for user [" + sNetwork + "]");
                return;
            }
        }

        const std::vector<NoChannel*>& vChans = pNetwork->channels();

        if (vChans.empty()) {
            putStatus("There are no channels defined.");
            return;
        }

        NoTable Table;
        Table.addColumn("Name");
        Table.addColumn("Status");

        uint uNumDetached = 0, uNumDisabled = 0, uNumJoined = 0;

        for (const NoChannel* pChan : vChans) {
            Table.addRow();
            Table.setValue("Name", pChan->permStr() + pChan->name());
            Table.setValue("Status",
                           ((pChan->isOn()) ? ((pChan->isDetached()) ? "Detached" : "Joined") :
                                              ((pChan->isDisabled()) ? "Disabled" : "Trying")));

            if (pChan->isDetached())
                uNumDetached++;
            if (pChan->isOn())
                uNumJoined++;
            if (pChan->isDisabled())
                uNumDisabled++;
        }

        putStatus(Table);
        putStatus("Total: " + NoString(vChans.size()) + " - Joined: " + NoString(uNumJoined) + " - Detached: " +
                  NoString(uNumDetached) + " - Disabled: " + NoString(uNumDisabled));
    } else if (sCommand.equals("ADDNETWORK")) {
        if (!d->user->isAdmin() && !d->user->hasSpaceForNewNetwork()) {
            putStatus("Network number limit reached. Ask an admin to increase the limit for you, or delete unneeded "
                      "networks using /znc DelNetwork <name>");
            return;
        }

        NoString sNetwork = No::token(sLine, 1);

        if (sNetwork.empty()) {
            putStatus("Usage: AddNetwork <name>");
            return;
        }
        if (!NoNetwork::isValidNetwork(sNetwork)) {
            putStatus("Network name should be alphanumeric");
            return;
        }

        NoString sNetworkAddError;
        if (d->user->addNetwork(sNetwork, sNetworkAddError)) {
            putStatus("Network added. Use /znc JumpNetwork " + sNetwork + ", or connect to ZNC with username " + d->user->userName() +
                      "/" + sNetwork + " (instead of just " + d->user->userName() + ") to connect to it.");
        } else {
            putStatus("Unable to add that network");
            putStatus(sNetworkAddError);
        }
    } else if (sCommand.equals("DELNETWORK")) {
        NoString sNetwork = No::token(sLine, 1);

        if (sNetwork.empty()) {
            putStatus("Usage: DelNetwork <name>");
            return;
        }

        if (d->network && d->network->name().equals(sNetwork)) {
            setNetwork(nullptr);
        }

        if (d->user->deleteNetwork(sNetwork)) {
            putStatus("Network deleted");
        } else {
            putStatus("Failed to delete network");
            putStatus("Perhaps this network doesn't exist");
        }
    } else if (sCommand.equals("LISTNETWORKS")) {
        NoUser* pUser = d->user;

        if (d->user->isAdmin() && !No::token(sLine, 1).empty()) {
            pUser = noApp->findUser(No::token(sLine, 1));

            if (!pUser) {
                putStatus("User not found " + No::token(sLine, 1));
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

        for (const NoNetwork* pNetwork : vNetworks) {
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

        if (putStatus(Table) == 0) {
            putStatus("No networks");
        }
    } else if (sCommand.equals("MOVENETWORK")) {
        if (!d->user->isAdmin()) {
            putStatus("Access Denied.");
            return;
        }

        NoString sOldUser = No::token(sLine, 1);
        NoString sOldNetwork = No::token(sLine, 2);
        NoString sNewUser = No::token(sLine, 3);
        NoString sNewNetwork = No::token(sLine, 4);

        if (sOldUser.empty() || sOldNetwork.empty() || sNewUser.empty()) {
            putStatus("Usage: MoveNetwork <old user> <old network> <new user> [new network]");
            return;
        }
        if (sNewNetwork.empty()) {
            sNewNetwork = sOldNetwork;
        }

        NoUser* pOldUser = noApp->findUser(sOldUser);
        if (!pOldUser) {
            putStatus("Old user [" + sOldUser + "] not found.");
            return;
        }

        NoNetwork* pOldNetwork = pOldUser->findNetwork(sOldNetwork);
        if (!pOldNetwork) {
            putStatus("Old network [" + sOldNetwork + "] not found.");
            return;
        }

        NoUser* pNewUser = noApp->findUser(sNewUser);
        if (!pNewUser) {
            putStatus("New user [" + sOldUser + "] not found.");
            return;
        }

        if (pNewUser->findNetwork(sNewNetwork)) {
            putStatus("User [" + sNewUser + "] already has network [" + sNewNetwork + "].");
            return;
        }

        if (!NoNetwork::isValidNetwork(sNewNetwork)) {
            putStatus("Invalid network name [" + sNewNetwork + "]");
            return;
        }

        std::vector<NoModule*> vMods = pOldNetwork->loader()->modules();
        for (NoModule* pMod : vMods) {
            NoString sOldModPath = pOldNetwork->networkPath() + "/moddata/" + pMod->moduleName();
            NoString sNewModPath = pNewUser->userPath() + "/networks/" + sNewNetwork + "/moddata/" + pMod->moduleName();

            NoDir oldDir(sOldModPath);
            for (NoFile* pFile : oldDir.files()) {
                if (pFile->GetShortName() != ".registry") {
                    putStatus("Some files seem to be in [" + sOldModPath + "]. You might want to move them to [" + sNewModPath + "]");
                    break;
                }
            }

            NoRegistry registry(pMod);
            registry.copy(sNewModPath);
        }

        NoString sNetworkAddError;
        NoNetwork* pNewNetwork = pNewUser->addNetwork(sNewNetwork, sNetworkAddError);

        if (!pNewNetwork) {
            putStatus("Error adding network:" + sNetworkAddError);
            return;
        }

        pNewNetwork->clone(*pOldNetwork, false);

        if (d->network && d->network->name().equals(sOldNetwork) && d->user == pOldUser) {
            setNetwork(nullptr);
        }

        if (pOldUser->deleteNetwork(sOldNetwork)) {
            putStatus("Success.");
        } else {
            putStatus("Copied the network to new user, but failed to delete old network");
        }
    } else if (sCommand.equals("JUMPNETWORK")) {
        NoString sNetwork = No::token(sLine, 1);

        if (sNetwork.empty()) {
            putStatus("No network supplied.");
            return;
        }

        if (d->network && (d->network->name() == sNetwork)) {
            putStatus("You are already connected with this network.");
            return;
        }

        NoNetwork* pNetwork = d->user->findNetwork(sNetwork);
        if (pNetwork) {
            putStatus("Switched to " + sNetwork);
            setNetwork(pNetwork);
        } else {
            putStatus("You don't have a network named " + sNetwork);
        }
    } else if (sCommand.equals("ADDSERVER")) {
        NoString sServer = No::token(sLine, 1);

        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        if (sServer.empty()) {
            putStatus("Usage: AddServer <host> [[+]port] [pass]");
            return;
        }

        if (d->network->addServer(No::tokens(sLine, 1))) {
            putStatus("Server added");
        } else {
            putStatus("Unable to add that server");
            putStatus("Perhaps the server is already added or openssl is disabled?");
        }
    } else if (sCommand.equals("REMSERVER") || sCommand.equals("DELSERVER")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sServer = No::token(sLine, 1);
        ushort uPort = No::token(sLine, 2).toUShort();
        NoString sPass = No::token(sLine, 3);

        if (sServer.empty()) {
            putStatus("Usage: removeServer <host> [port] [pass]");
            return;
        }

        if (!d->network->hasServers()) {
            putStatus("You don't have any servers added.");
            return;
        }

        if (d->network->removeServer(sServer, uPort, sPass)) {
            putStatus("Server removed");
        } else {
            putStatus("No such server");
        }
    } else if (sCommand.equals("LISTSERVERS")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        if (d->network->hasServers()) {
            const std::vector<NoServerInfo*>& vServers = d->network->servers();
            NoServerInfo* pCurServ = d->network->currentServer();
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

            putStatus(Table);
        } else {
            putStatus("You don't have any servers added.");
        }
    } else if (sCommand.equals("AddTrustedServerFingerprint")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }
        NoString sFP = No::token(sLine, 1);
        if (sFP.empty()) {
            putStatus("Usage: AddTrustedServerFingerprint <fi:ng:er>");
            return;
        }
        d->network->addTrustedFingerprint(sFP);
        putStatus("Done.");
    } else if (sCommand.equals("DelTrustedServerFingerprint")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }
        NoString sFP = No::token(sLine, 1);
        if (sFP.empty()) {
            putStatus("Usage: DelTrustedServerFingerprint <fi:ng:er>");
            return;
        }
        d->network->removeTrustedFingerprint(sFP);
        putStatus("Done.");
    } else if (sCommand.equals("ListTrustedServerFingerprints")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }
        const NoStringSet& ssFPs = d->network->trustedFingerprints();
        if (ssFPs.empty()) {
            putStatus("No fingerprints added.");
        } else {
            int k = 0;
            for (const NoString& sFP : ssFPs) {
                putStatus(NoString(++k) + ". " + sFP);
            }
        }
    } else if (sCommand.equals("TOPICS")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        const std::vector<NoChannel*>& vChans = d->network->channels();
        NoTable Table;
        Table.addColumn("Name");
        Table.addColumn("Set By");
        Table.addColumn("Topic");

        for (const NoChannel* pChan : vChans) {
            Table.addRow();
            Table.setValue("Name", pChan->name());
            Table.setValue("Set By", pChan->topicOwner());
            Table.setValue("Topic", pChan->topic());
        }

        putStatus(Table);
    } else if (sCommand.equals("LISTMODS") || sCommand.equals("LISTMODULES")) {
        if (d->user->isAdmin()) {
            NoModuleLoader* GModules = noApp->loader();

            if (GModules->isEmpty()) {
                putStatus("No global modules loaded.");
            } else {
                putStatus("Global modules:");
                NoTable GTable;
                GTable.addColumn("Name");
                GTable.addColumn("Arguments");

                for (const NoModule* pMod : GModules->modules()) {
                    GTable.addRow();
                    GTable.setValue("Name", pMod->moduleName());
                    GTable.setValue("Arguments", pMod->args());
                }

                putStatus(GTable);
            }
        }

        NoModuleLoader* Modules = d->user->loader();

        if (Modules->isEmpty()) {
            putStatus("Your user has no modules loaded.");
        } else {
            putStatus("User modules:");
            NoTable Table;
            Table.addColumn("Name");
            Table.addColumn("Arguments");

            for (const NoModule* pMod : Modules->modules()) {
                Table.addRow();
                Table.setValue("Name", pMod->moduleName());
                Table.setValue("Arguments", pMod->args());
            }

            putStatus(Table);
        }

        if (d->network) {
            NoModuleLoader* NetworkModules = d->network->loader();
            if (NetworkModules->isEmpty()) {
                putStatus("This network has no modules loaded.");
            } else {
                putStatus("Network modules:");
                NoTable Table;
                Table.addColumn("Name");
                Table.addColumn("Arguments");

                for (const NoModule* pMod : NetworkModules->modules()) {
                    Table.addRow();
                    Table.setValue("Name", pMod->moduleName());
                    Table.setValue("Arguments", pMod->args());
                }

                putStatus(Table);
            }
        }

        return;
    } else if (sCommand.equals("LISTAVAILMODS") || sCommand.equals("LISTAVAILABLEMODULES")) {
        if (d->user->denyLoadMod()) {
            putStatus("Access Denied.");
            return;
        }

        if (d->user->isAdmin()) {
            std::set<NoModuleInfo> ssGlobalMods;
            noApp->loader()->availableModules(ssGlobalMods, No::GlobalModule);

            if (ssGlobalMods.empty()) {
                putStatus("No global modules available.");
            } else {
                putStatus("Global modules:");
                NoTable GTable;
                GTable.addColumn("Name");
                GTable.addColumn("Description");

                for (const NoModuleInfo& Info : ssGlobalMods) {
                    GTable.addRow();
                    GTable.setValue("Name", (noApp->loader()->findModule(Info.name()) ? "*" : " ") + Info.name());
                    GTable.setValue("Description", No::ellipsize(Info.description(), 128));
                }

                putStatus(GTable);
            }
        }

        std::set<NoModuleInfo> ssUserMods;
        noApp->loader()->availableModules(ssUserMods);

        if (ssUserMods.empty()) {
            putStatus("No user modules available.");
        } else {
            putStatus("User modules:");
            NoTable Table;
            Table.addColumn("Name");
            Table.addColumn("Description");

            for (const NoModuleInfo& Info : ssUserMods) {
                Table.addRow();
                Table.setValue("Name", (d->user->loader()->findModule(Info.name()) ? "*" : " ") + Info.name());
                Table.setValue("Description", No::ellipsize(Info.description(), 128));
            }

            putStatus(Table);
        }

        std::set<NoModuleInfo> ssNetworkMods;
        noApp->loader()->availableModules(ssNetworkMods, No::NetworkModule);

        if (ssNetworkMods.empty()) {
            putStatus("No network modules available.");
        } else {
            putStatus("Network modules:");
            NoTable Table;
            Table.addColumn("Name");
            Table.addColumn("Description");

            for (const NoModuleInfo& Info : ssNetworkMods) {
                Table.addRow();
                Table.setValue("Name", ((d->network && d->network->loader()->findModule(Info.name())) ? "*" : " ") + Info.name());
                Table.setValue("Description", No::ellipsize(Info.description(), 128));
            }

            putStatus(Table);
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

        if (d->user->denyLoadMod()) {
            putStatus("Unable to load [" + sMod + "]: Access Denied.");
            return;
        }

        if (sMod.empty()) {
            putStatus("Usage: LoadMod [--type=global|user|network] <module> [args]");
            return;
        }

        NoModuleInfo ModInfo;
        NoString sRetMsg;
        if (!noApp->loader()->moduleInfo(ModInfo, sMod, sRetMsg)) {
            putStatus("Unable to find modinfo [" + sMod + "] [" + sRetMsg + "]");
            return;
        }

        if (sType.equals("default")) {
            eType = ModInfo.defaultType();
        }

        if (eType == No::GlobalModule && !d->user->isAdmin()) {
            putStatus("Unable to load global module [" + sMod + "]: Access Denied.");
            return;
        }

        if (eType == No::NetworkModule && !d->network) {
            putStatus("Unable to load network module [" + sMod + "] Not connected with a network.");
            return;
        }

        NoString sModRet;
        bool b = false;

        switch (eType) {
        case No::GlobalModule:
            b = noApp->loader()->loadModule(sMod, sArgs, eType, nullptr, nullptr, sModRet);
            break;
        case No::UserModule:
            b = d->user->loader()->loadModule(sMod, sArgs, eType, d->user, nullptr, sModRet);
            break;
        case No::NetworkModule:
            b = d->network->loader()->loadModule(sMod, sArgs, eType, d->user, d->network, sModRet);
            break;
        default:
            sModRet = "Unable to load module [" + sMod + "]: Unknown module type";
        }

        if (b)
            sModRet = "Loaded module [" + sMod + "] " + sModRet;

        putStatus(sModRet);
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

        if (d->user->denyLoadMod()) {
            putStatus("Unable to unload [" + sMod + "] Access Denied.");
            return;
        }

        if (sMod.empty()) {
            putStatus("Usage: UnloadMod [--type=global|user|network] <module>");
            return;
        }

        if (sType.equals("default")) {
            NoModuleInfo ModInfo;
            NoString sRetMsg;
            if (!noApp->loader()->moduleInfo(ModInfo, sMod, sRetMsg)) {
                putStatus("Unable to find modinfo [" + sMod + "] [" + sRetMsg + "]");
                return;
            }

            eType = ModInfo.defaultType();
        }

        if (eType == No::GlobalModule && !d->user->isAdmin()) {
            putStatus("Unable to unload global module [" + sMod + "]: Access Denied.");
            return;
        }

        if (eType == No::NetworkModule && !d->network) {
            putStatus("Unable to unload network module [" + sMod + "] Not connected with a network.");
            return;
        }

        NoString sModRet;

        switch (eType) {
        case No::GlobalModule:
            noApp->loader()->unloadModule(sMod, sModRet);
            break;
        case No::UserModule:
            d->user->loader()->unloadModule(sMod, sModRet);
            break;
        case No::NetworkModule:
            d->network->loader()->unloadModule(sMod, sModRet);
            break;
        default:
            sModRet = "Unable to unload module [" + sMod + "]: Unknown module type";
        }

        putStatus(sModRet);
        return;
    } else if (sCommand.equals("RELOADMOD") || sCommand.equals("RELOADMODULE")) {
        No::ModuleType eType;
        NoString sType = No::token(sLine, 1);
        NoString sMod = No::token(sLine, 2);
        NoString sArgs = No::tokens(sLine, 3);

        if (d->user->denyLoadMod()) {
            putStatus("Unable to reload modules. Access Denied.");
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
            putStatus("Usage: ReloadMod [--type=global|user|network] <module> [args]");
            return;
        }

        if (sType.equals("default")) {
            NoModuleInfo ModInfo;
            NoString sRetMsg;
            if (!noApp->loader()->moduleInfo(ModInfo, sMod, sRetMsg)) {
                putStatus("Unable to find modinfo for [" + sMod + "] [" + sRetMsg + "]");
                return;
            }

            eType = ModInfo.defaultType();
        }

        if (eType == No::GlobalModule && !d->user->isAdmin()) {
            putStatus("Unable to reload global module [" + sMod + "]: Access Denied.");
            return;
        }

        if (eType == No::NetworkModule && !d->network) {
            putStatus("Unable to load network module [" + sMod + "] Not connected with a network.");
            return;
        }

        NoString sModRet;

        switch (eType) {
        case No::GlobalModule:
            noApp->loader()->reloadModule(sMod, sArgs, nullptr, nullptr, sModRet);
            break;
        case No::UserModule:
            d->user->loader()->reloadModule(sMod, sArgs, d->user, nullptr, sModRet);
            break;
        case No::NetworkModule:
            d->network->loader()->reloadModule(sMod, sArgs, d->user, d->network, sModRet);
            break;
        default:
            sModRet = "Unable to reload module [" + sMod + "]: Unknown module type";
        }

        putStatus(sModRet);
        return;
    } else if ((sCommand.equals("UPDATEMOD") || sCommand.equals("UPDATEMODULE")) && d->user->isAdmin()) {
        NoString sMod = No::token(sLine, 1);

        if (sMod.empty()) {
            putStatus("Usage: UpdateMod <module>");
            return;
        }

        putStatus("Reloading [" + sMod + "] everywhere");
        if (noApp->updateModule(sMod)) {
            putStatus("Done");
        } else {
            putStatus("Done, but there were errors, [" + sMod + "] could not be loaded everywhere.");
        }
    } else if ((sCommand.equals("ADDBINDHOST") || sCommand.equals("ADDVHOST")) && d->user->isAdmin()) {
        NoString sHost = No::token(sLine, 1);

        if (sHost.empty()) {
            putStatus("Usage: AddBindHost <host>");
            return;
        }

        if (noApp->addBindHost(sHost)) {
            putStatus("Done");
        } else {
            putStatus("The host [" + sHost + "] is already in the list");
        }
    } else if ((sCommand.equals("REMBINDHOST") || sCommand.equals("DELBINDHOST") || sCommand.equals("REMVHOST") ||
                sCommand.equals("DELVHOST")) &&
               d->user->isAdmin()) {
        NoString sHost = No::token(sLine, 1);

        if (sHost.empty()) {
            putStatus("Usage: DelBindHost <host>");
            return;
        }

        if (noApp->removeBindHost(sHost)) {
            putStatus("Done");
        } else {
            putStatus("The host [" + sHost + "] is not in the list");
        }
    } else if ((sCommand.equals("LISTBINDHOSTS") || sCommand.equals("LISTVHOSTS")) &&
               (d->user->isAdmin() || !d->user->denysetBindHost())) {
        const NoStringVector& vsHosts = noApp->bindHosts();

        if (vsHosts.empty()) {
            putStatus("No bind hosts configured");
            return;
        }

        NoTable Table;
        Table.addColumn("Host");

        for (const NoString& sHost : vsHosts) {
            Table.addRow();
            Table.setValue("Host", sHost);
        }
        putStatus(Table);
    } else if ((sCommand.equals("SETBINDHOST") || sCommand.equals("SETVHOST")) &&
               (d->user->isAdmin() || !d->user->denysetBindHost())) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command. Try SetUserBindHost instead");
            return;
        }
        NoString sArg = No::token(sLine, 1);

        if (sArg.empty()) {
            putStatus("Usage: setBindHost <host>");
            return;
        }

        if (sArg.equals(d->network->bindHost())) {
            putStatus("You already have this bind host!");
            return;
        }

        const NoStringVector& vsHosts = noApp->bindHosts();
        if (!d->user->isAdmin() && !vsHosts.empty()) {
            bool bFound = false;

            for (const NoString& sHost : vsHosts) {
                if (sArg.equals(sHost)) {
                    bFound = true;
                    break;
                }
            }

            if (!bFound) {
                putStatus("You may not use this bind host. See [ListBindHosts] for a list");
                return;
            }
        }

        d->network->setBindHost(sArg);
        putStatus("Set bind host for network [" + d->network->name() + "] to [" + d->network->bindHost() + "]");
    } else if (sCommand.equals("SETUSERBINDHOST") && (d->user->isAdmin() || !d->user->denysetBindHost())) {
        NoString sArg = No::token(sLine, 1);

        if (sArg.empty()) {
            putStatus("Usage: SetUserBindHost <host>");
            return;
        }

        if (sArg.equals(d->user->bindHost())) {
            putStatus("You already have this bind host!");
            return;
        }

        const NoStringVector& vsHosts = noApp->bindHosts();
        if (!d->user->isAdmin() && !vsHosts.empty()) {
            bool bFound = false;

            for (const NoString& sHost : vsHosts) {
                if (sArg.equals(sHost)) {
                    bFound = true;
                    break;
                }
            }

            if (!bFound) {
                putStatus("You may not use this bind host. See [ListBindHosts] for a list");
                return;
            }
        }

        d->user->setBindHost(sArg);
        putStatus("Set bind host to [" + d->user->bindHost() + "]");
    } else if ((sCommand.equals("CLEARBINDHOST") || sCommand.equals("CLEARVHOST")) &&
               (d->user->isAdmin() || !d->user->denysetBindHost())) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command. Try ClearUserBindHost instead");
            return;
        }
        d->network->setBindHost("");
        putStatus("Bind host cleared for this network.");
    } else if (sCommand.equals("CLEARUSERBINDHOST") && (d->user->isAdmin() || !d->user->denysetBindHost())) {
        d->user->setBindHost("");
        putStatus("Bind host cleared for your user.");
    } else if (sCommand.equals("SHOWBINDHOST")) {
        putStatus("This user's default bind host " + (d->user->bindHost().empty() ? "not set" : "is [" + d->user->bindHost() + "]"));
        if (d->network) {
            putStatus("This network's bind host " +
                      (d->network->bindHost().empty() ? "not set" : "is [" + d->network->bindHost() + "]"));
        }
    } else if (sCommand.equals("PLAYBUFFER")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sBuffer = No::token(sLine, 1);

        if (sBuffer.empty()) {
            putStatus("Usage: PlayBuffer <#chan|query>");
            return;
        }

        if (d->network->isChannel(sBuffer)) {
            NoChannel* pChan = d->network->findChannel(sBuffer);

            if (!pChan) {
                putStatus("You are not on [" + sBuffer + "]");
                return;
            }

            if (!pChan->isOn()) {
                putStatus("You are not on [" + sBuffer + "] [trying]");
                return;
            }

            if (pChan->buffer().isEmpty()) {
                putStatus("The buffer for [" + sBuffer + "] is empty");
                return;
            }

            pChan->sendBuffer(this);
        } else {
            NoQuery* pQuery = d->network->findQuery(sBuffer);

            if (!pQuery) {
                putStatus("No active query with [" + sBuffer + "]");
                return;
            }

            if (pQuery->buffer().isEmpty()) {
                putStatus("The buffer for [" + sBuffer + "] is empty");
                return;
            }

            pQuery->sendBuffer(this);
        }
    } else if (sCommand.equals("CLEARBUFFER")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sBuffer = No::token(sLine, 1);

        if (sBuffer.empty()) {
            putStatus("Usage: ClearBuffer <#chan|query>");
            return;
        }

        uint uMatches = 0;
        std::vector<NoChannel*> vChans = d->network->findChannels(sBuffer);
        for (NoChannel* pChan : vChans) {
            uMatches++;

            pChan->clearBuffer();
        }

        std::vector<NoQuery*> vQueries = d->network->findQueries(sBuffer);
        for (NoQuery* pQuery : vQueries) {
            uMatches++;

            d->network->removeQuery(pQuery->name());
        }

        putStatus("[" + NoString(uMatches) + "] buffers matching [" + sBuffer + "] have been cleared");
    } else if (sCommand.equals("CLEARALLCHANNELBUFFERS")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        for (NoChannel* pChan : d->network->channels()) {
            pChan->clearBuffer();
        }
        putStatus("All channel buffers have been cleared");
    } else if (sCommand.equals("CLEARALLQUERYBUFFERS")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        d->network->clearQueryBuffer();
        putStatus("All query buffers have been cleared");
    } else if (sCommand.equals("CLEARALLBUFFERS")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        for (NoChannel* pChan : d->network->channels()) {
            pChan->clearBuffer();
        }
        d->network->clearQueryBuffer();
        putStatus("All buffers have been cleared");
    } else if (sCommand.equals("SETBUFFER")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sBuffer = No::token(sLine, 1);

        if (sBuffer.empty()) {
            putStatus("Usage: SetBuffer <#chan|query> [linecount]");
            return;
        }

        uint uLineCount = No::token(sLine, 2).toUInt();
        uint uMatches = 0, uFail = 0;
        std::vector<NoChannel*> vChans = d->network->findChannels(sBuffer);
        for (NoChannel* pChan : vChans) {
            uMatches++;

            if (!pChan->setBufferCount(uLineCount))
                uFail++;
        }

        std::vector<NoQuery*> vQueries = d->network->findQueries(sBuffer);
        for (NoQuery* pQuery : vQueries) {
            uMatches++;

            if (!pQuery->setBufferCount(uLineCount))
                uFail++;
        }

        putStatus("BufferCount for [" + NoString(uMatches - uFail) + "] buffer was set to [" + NoString(uLineCount) + "]");
        if (uFail > 0) {
            putStatus("Setting BufferCount failed for [" + NoString(uFail) + "] buffers, "
                                                                             "max buffer count is " +
                      NoString(noApp->maxBufferSize()));
        }
    } else if (d->user->isAdmin() && sCommand.equals("TRAFFIC")) {
        NoApp::TrafficStatsPair Users, ZNC, Total;
        NoApp::TrafficStatsMap traffic = noApp->trafficStats(Users, ZNC, Total);

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

        putStatus(Table);
    } else if (sCommand.equals("UPTIME")) {
        putStatus("Running for " + noApp->uptime());
    } else if (d->user->isAdmin() &&
               (sCommand.equals("LISTPORTS") || sCommand.equals("ADDPORT") || sCommand.equals("DELPORT"))) {
        yserPortCommand(sLine);
    } else {
        putStatus("Unknown command [" + sCommand + "] try 'Help'");
    }
}

void NoClient::yserPortCommand(NoString& sLine)
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
        const std::vector<NoListener*>& vpListeners = noApp->listeners();

        for (const NoListener* pListener : vpListeners) {
            Table.addRow();
            Table.setValue("Port", NoString(pListener->port()));
            Table.setValue("BindHost", (pListener->host().empty() ? NoString("*") : pListener->host()));
            Table.setValue("SSL", NoString(pListener->isSsl()));

            No::AddressType eAddr = pListener->addressType();
            Table.setValue("Proto",
                           (eAddr == No::Ipv4AndIpv6Address ? "All" : (eAddr == No::Ipv4Address ? "IPv4" : "IPv6")));

            No::AcceptType eAccept = pListener->acceptType();
            Table.setValue("IRC/Web", (eAccept == No::AcceptAll ? "All" : (eAccept == No::AcceptIrc ? "IRC" : "Web")));
            Table.setValue("URIPrefix", pListener->uriPrefix() + "/");
        }

        putStatus(Table);

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
            putStatus("Usage: AddPort <[+]port> <ipv4|ipv6|all> <web|irc|all> [bindhost [uriprefix]]");
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
                putStatus("Unable to bind [" + NoString(strerror(errno)) + "]");
            } else {
                if (noApp->addListener(pListener))
                    putStatus("Port Added");
                else
                    putStatus("Error?!");
            }
        }
    } else if (sCommand.equals("DELPORT")) {
        if (sPort.empty() || sAddr.empty()) {
            putStatus("Usage: DelPort <port> <ipv4|ipv6|all> [bindhost]");
        } else {
            const NoString sBindHost = No::token(sLine, 3);

            NoListener* pListener = noApp->findListener(uPort, sBindHost, eAddr);

            if (pListener) {
                noApp->removeListener(pListener);
                putStatus("Deleted Port");
            } else {
                putStatus("Unable to find a matching port");
            }
        }
    }
}

static void
addCommandHelp(NoTable& Table, const NoString& sCmd, const NoString& sArgs, const NoString& sDesc, const NoString& sFilter = "")
{
    if (sFilter.empty() || sCmd.startsWith(sFilter) || wildCmp(sCmd, sFilter, No::CaseInsensitive)) {
        Table.addRow();
        Table.setValue("Command", sCmd);
        Table.setValue("Arguments", sArgs);
        Table.setValue("Description", sDesc);
    }
}

void NoClient::helpUser(const NoString& sFilter)
{
    NoTable Table;
    Table.addColumn("Command");
    Table.addColumn("Arguments");
    Table.addColumn("Description");

    if (sFilter.empty()) {
        putStatus("In the following list all occurrences of <#chan> support wildcards (* and ?)");
        putStatus("(Except ListNicks)");
    }

    addCommandHelp(Table, "Version", "", "Print which version of ZNC this is", sFilter);

    addCommandHelp(Table, "ListMods", "", "List all loaded modules", sFilter);
    addCommandHelp(Table, "ListAvailMods", "", "List all available modules", sFilter);
    if (!d->user->isAdmin()) { // If they are an admin we will add this command below with an argument
        addCommandHelp(Table, "ListChans", "", "List all channels", sFilter);
    }
    addCommandHelp(Table, "ListNicks", "<#chan>", "List all nicks on a channel", sFilter);
    if (!d->user->isAdmin()) {
        addCommandHelp(Table, "ListClients", "", "List all clients connected to your ZNC user", sFilter);
    }
    addCommandHelp(Table, "ListServers", "", "List all servers of current IRC network", sFilter);

    addCommandHelp(Table, "AddNetwork", "<name>", "Add a network to your user", sFilter);
    addCommandHelp(Table, "DelNetwork", "<name>", "Delete a network from your user", sFilter);
    addCommandHelp(Table, "ListNetworks", "", "List all networks", sFilter);
    if (d->user->isAdmin()) {
        addCommandHelp(Table,
                       "MoveNetwork",
                       "<old user> <old network> <new user> [new network]",
                       "Move an IRC network from one user to another",
                       sFilter);
    }
    addCommandHelp(Table,
                   "JumpNetwork",
                   "<network>",
                   "Jump to another network (Alternatively, you can connect to ZNC several times, using "
                   "`user/network` as username)",
                   sFilter);

    addCommandHelp(Table,
                   "AddServer",
                   "<host> [[+]port] [pass]",
                   "Add a server to the list of alternate/backup servers of current IRC network.",
                   sFilter);
    addCommandHelp(Table,
                   "removeServer",
                   "<host> [port] [pass]",
                   "Remove a server from the list of alternate/backup servers of current IRC network",
                   sFilter);

    addCommandHelp(Table,
                   "AddTrustedServerFingerprint",
                   "<fi:ng:er>",
                   "Add a trusted server SSL certificate fingerprint (SHA-256) to current IRC network.",
                   sFilter);
    addCommandHelp(Table,
                   "DelTrustedServerFingerprint",
                   "<fi:ng:er>",
                   "Delete a trusted server SSL certificate from current IRC network.",
                   sFilter);
    addCommandHelp(
    Table, "ListTrustedServerFingerprints", "", "List all trusted server SSL certificates of current IRC network.", sFilter);

    addCommandHelp(Table, "ShowChan", "<#chan>", "Show channel details", sFilter);
    addCommandHelp(Table, "EnableChan", "<#chans>", "Enable channels", sFilter);
    addCommandHelp(Table, "DisableChan", "<#chans>", "Disable channels", sFilter);
    addCommandHelp(Table, "Detach", "<#chans>", "Detach from channels", sFilter);
    addCommandHelp(Table, "Topics", "", "Show topics in all your channels", sFilter);

    addCommandHelp(Table, "PlayBuffer", "<#chan|query>", "Play back the specified buffer", sFilter);
    addCommandHelp(Table, "ClearBuffer", "<#chan|query>", "Clear the specified buffer", sFilter);
    addCommandHelp(Table, "ClearAllBuffers", "", "Clear all channel and query buffers", sFilter);
    addCommandHelp(Table, "ClearAllChannelBuffers", "", "Clear the channel buffers", sFilter);
    addCommandHelp(Table, "ClearAllQueryBuffers", "", "Clear the query buffers", sFilter);
    addCommandHelp(Table, "SetBuffer", "<#chan|query> [linecount]", "Set the buffer count", sFilter);

    if (d->user->isAdmin()) {
        addCommandHelp(Table, "AddBindHost", "<host (IP preferred)>", "Adds a bind host for normal users to use", sFilter);
        addCommandHelp(Table, "DelBindHost", "<host>", "Removes a bind host from the list", sFilter);
    }

    if (d->user->isAdmin() || !d->user->denysetBindHost()) {
        addCommandHelp(Table, "ListBindHosts", "", "Shows the configured list of bind hosts", sFilter);
        addCommandHelp(Table, "setBindHost", "<host (IP preferred)>", "Set the bind host for this connection", sFilter);
        addCommandHelp(Table, "SetUserBindHost", "<host (IP preferred)>", "Set the default bind host for this user", sFilter);
        addCommandHelp(Table, "ClearBindHost", "", "Clear the bind host for this connection", sFilter);
        addCommandHelp(Table, "ClearUserBindHost", "", "Clear the default bind host for this user", sFilter);
    }

    addCommandHelp(Table, "ShowBindHost", "", "Show currently selected bind host", sFilter);
    addCommandHelp(Table, "Jump", "[server]", "Jump to the next or the specified server", sFilter);
    addCommandHelp(Table, "Disconnect", "[message]", "Disconnect from IRC", sFilter);
    addCommandHelp(Table, "Connect", "", "Reconnect to IRC", sFilter);
    addCommandHelp(Table, "Uptime", "", "Show for how long ZNC has been running", sFilter);

    if (!d->user->denyLoadMod()) {
        addCommandHelp(Table, "LoadMod", "[--type=global|user|network] <module>", "Load a module", sFilter);
        addCommandHelp(Table, "UnloadMod", "[--type=global|user|network] <module>", "Unload a module", sFilter);
        addCommandHelp(Table, "ReloadMod", "[--type=global|user|network] <module>", "Reload a module", sFilter);
        if (d->user->isAdmin()) {
            addCommandHelp(Table, "UpdateMod", "<module>", "Reload a module everywhere", sFilter);
        }
    }

    addCommandHelp(Table, "ShowMOTD", "", "Show ZNC's message of the day", sFilter);

    if (d->user->isAdmin()) {
        addCommandHelp(Table, "SetMOTD", "<message>", "Set ZNC's message of the day", sFilter);
        addCommandHelp(Table, "AddMOTD", "<message>", "Append <message> to ZNC's MOTD", sFilter);
        addCommandHelp(Table, "ClearMOTD", "", "Clear ZNC's MOTD", sFilter);
        addCommandHelp(Table, "ListPorts", "", "Show all active listeners", sFilter);
        addCommandHelp(Table,
                       "AddPort",
                       "<[+]port> <ipv4|ipv6|all> <web|irc|all> [bindhost [uriprefix]]",
                       "Add another port for ZNC to listen on",
                       sFilter);
        addCommandHelp(Table, "DelPort", "<port> <ipv4|ipv6|all> [bindhost]", "Remove a port from ZNC", sFilter);
        addCommandHelp(Table, "Rehash", "", "Reload znc.conf from disk", sFilter);
        addCommandHelp(Table, "SaveConfig", "", "Save the current settings to disk", sFilter);
        addCommandHelp(Table, "ListUsers", "", "List all ZNC users and their connection status", sFilter);
        addCommandHelp(Table, "ListAllUserNetworks", "", "List all ZNC users and their networks", sFilter);
        addCommandHelp(Table, "ListChans", "[user <network>]", "List all channels", sFilter);
        addCommandHelp(Table, "ListClients", "[user]", "List all connected clients", sFilter);
        addCommandHelp(Table, "Traffic", "", "Show basic traffic stats for all ZNC users", sFilter);
        addCommandHelp(Table, "Broadcast", "[message]", "Broadcast a message to all ZNC users", sFilter);
        addCommandHelp(Table, "Shutdown", "[message]", "Shut down ZNC completely", sFilter);
        addCommandHelp(Table, "Restart", "[message]", "Restart ZNC", sFilter);
    }

    if (Table.isEmpty()) {
        putStatus("No matches for '" + sFilter + "'");
    } else {
        putStatus(Table);
    }
}
