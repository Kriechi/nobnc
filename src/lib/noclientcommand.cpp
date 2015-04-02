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

void NoClient::userCommand(NoString& line)
{
    if (!d->user) {
        return;
    }

    if (line.empty()) {
        return;
    }

    bool bReturn = false;
    NETWORKMODULECALL(onStatusCommand(line), d->user, d->network, this, &bReturn);
    if (bReturn)
        return;

    const NoString command = No::token(line, 0);

    if (command.equals("HELP")) {
        helpUser(No::token(line, 1));
    } else if (command.equals("LISTNICKS")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sChan = No::token(line, 1);

        if (sChan.empty()) {
            putStatus("Usage: ListNicks <#chan>");
            return;
        }

        NoChannel* channel = d->network->findChannel(sChan);

        if (!channel) {
            putStatus("You are not on [" + sChan + "]");
            return;
        }

        if (!channel->isOn()) {
            putStatus("You are not on [" + sChan + "] [trying]");
            return;
        }

        const std::map<NoString, NoNick>& msNicks = channel->nicks();
        NoIrcSocket* socket = d->network->ircSocket();
        const NoString& sPerms = (socket) ? socket->perms() : "";

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
    } else if (command.equals("DETACH")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sPatterns = No::tokens(line, 1);

        if (sPatterns.empty()) {
            putStatus("Usage: Detach <#chans>");
            return;
        }

        sPatterns.replace(",", " ");
        NoStringVector vsChans = sPatterns.split(" ", No::SkipEmptyParts);

        std::set<NoChannel*> sChans;
        for (const NoString& sChan : vsChans) {
            std::vector<NoChannel*> channels = d->network->findChannels(sChan);
            sChans.insert(channels.begin(), channels.end());
        }

        uint uDetached = 0;
        for (NoChannel* channel : sChans) {
            if (channel->isDetached())
                continue;
            uDetached++;
            channel->detachUser();
        }

        putStatus("There were [" + NoString(sChans.size()) + "] channels matching [" + sPatterns + "]");
        putStatus("Detached [" + NoString(uDetached) + "] channels");
    } else if (command.equals("VERSION")) {
        putStatus(NoApp::tag());
        putStatus(NoApp::compileOptionsString());
    } else if (command.equals("MOTD") || command.equals("ShowMOTD")) {
        if (!sendMotd()) {
            putStatus("There is no MOTD set.");
        }
    } else if (d->user->isAdmin() && command.equals("Rehash")) {
        NoString ret;

        if (noApp->rehashConfig(ret)) {
            putStatus("Rehashing succeeded!");
        } else {
            putStatus("Rehashing failed: " + ret);
        }
    } else if (d->user->isAdmin() && command.equals("SaveConfig")) {
        if (noApp->writeConfig()) {
            putStatus("Wrote config to [" + noApp->configFile() + "]");
        } else {
            putStatus("Error while trying to write config.");
        }
    } else if (command.equals("LISTCLIENTS")) {
        NoUser* user = d->user;
        NoString nick = No::token(line, 1);

        if (!nick.empty()) {
            if (!d->user->isAdmin()) {
                putStatus("Usage: ListClients");
                return;
            }

            user = noApp->findUser(nick);

            if (!user) {
                putStatus("No such user [" + nick + "]");
                return;
            }
        }

        std::vector<NoClient*> vClients = user->allClients();

        if (vClients.empty()) {
            putStatus("No clients are connected");
            return;
        }

        NoTable Table;
        Table.addColumn("Host");
        Table.addColumn("Network");
        Table.addColumn("Identifier");

        for (const NoClient* client : vClients) {
            Table.addRow();
            Table.setValue("Host", client->socket()->remoteAddress());
            if (client->network()) {
                Table.setValue("Network", client->network()->name());
            }
            Table.setValue("Identifier", client->identifier());
        }

        putStatus(Table);
    } else if (d->user->isAdmin() && command.equals("LISTUSERS")) {
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
    } else if (d->user->isAdmin() && command.equals("LISTALLUSERNETWORKS")) {
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

            for (const NoNetwork* network : vNetworks) {
                Table.addRow();
                if (network == vNetworks.back()) {
                    Table.setValue("Username", "`-");
                } else {
                    Table.setValue("Username", "|-");
                }
                Table.setValue("Network", network->name());
                Table.setValue("Clients", NoString(network->clients().size()));
                if (network->isIrcConnected()) {
                    Table.setValue("OnIRC", "Yes");
                    Table.setValue("IRC Server", network->ircServer());
                    Table.setValue("IRC User", network->ircNick().nickMask());
                    Table.setValue("Channels", NoString(network->channels().size()));
                } else {
                    Table.setValue("OnIRC", "No");
                }
            }
        }

        putStatus(Table);
    } else if (d->user->isAdmin() && command.equals("SetMOTD")) {
        NoString message = No::tokens(line, 1);

        if (message.empty()) {
            putStatus("Usage: SetMOTD <message>");
        } else {
            noApp->setMotd(message);
            putStatus("MOTD set to [" + message + "]");
        }
    } else if (d->user->isAdmin() && command.equals("AddMOTD")) {
        NoString message = No::tokens(line, 1);

        if (message.empty()) {
            putStatus("Usage: AddMOTD <message>");
        } else {
            noApp->addMotd(message);
            putStatus("Added [" + message + "] to MOTD");
        }
    } else if (d->user->isAdmin() && command.equals("ClearMOTD")) {
        noApp->clearMotd();
        putStatus("Cleared MOTD");
    } else if (d->user->isAdmin() && command.equals("BROADCAST")) {
        noApp->broadcast(No::tokens(line, 1));
    } else if (d->user->isAdmin() && (command.equals("SHUTDOWN") || command.equals("RESTART"))) {
        bool bRestart = command.equals("RESTART");
        NoString message = No::tokens(line, 1);
        bool force = false;

        if (No::token(message, 0).equals("FORCE")) {
            force = true;
            message = No::tokens(message, 1);
        }

        if (message.empty()) {
            message = (bRestart ? "ZNC is being restarted NOW!" : "ZNC is being shut down NOW!");
        }

        if (!noApp->writeConfig() && !force) {
            putStatus("ERROR: Writing config file to disk failed! Aborting. Use " + command.toUpper() +
                      " FORCE to ignore.");
        } else {
            noApp->broadcast(message);
            throw NoException(bRestart ? NoException::Restart : NoException::Shutdown);
        }
    } else if (command.equals("JUMP") || command.equals("CONNECT")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        if (!d->network->hasServers()) {
            putStatus("You don't have any servers added.");
            return;
        }

        NoString args = No::tokens(line, 1);
        args.trim();
        NoServerInfo* server = nullptr;

        if (!args.empty()) {
            server = d->network->findServer(args);
            if (!server) {
                putStatus("Server [" + args + "] not found");
                return;
            }
            d->network->setNextServer(server);

            // If we are already connecting to some server,
            // we have to abort that attempt
            NoSocket* socket = ircSocket();
            if (socket && !socket->isConnected()) {
                socket->close();
            }
        }

        if (ircSocket()) {
            ircSocket()->quit();
            if (server)
                putStatus("Connecting to [" + server->host() + "]...");
            else
                putStatus("Jumping to the next server in the list...");
        } else {
            if (server)
                putStatus("Connecting to [" + server->host() + "]...");
            else
                putStatus("Connecting...");
        }

        d->network->setEnabled(true);
        return;
    } else if (command.equals("DISCONNECT")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        if (ircSocket()) {
            NoString sQuitMsg = No::tokens(line, 1);
            ircSocket()->quit(sQuitMsg);
        }

        d->network->setEnabled(false);
        putStatus("Disconnected from IRC. Use 'connect' to reconnect.");
        return;
    } else if (command.equals("ENABLECHAN")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sPatterns = No::tokens(line, 1);

        if (sPatterns.empty()) {
            putStatus("Usage: EnableChan <#chans>");
        } else {
            sPatterns.replace(",", " ");
            NoStringVector vsChans = sPatterns.split(" ", No::SkipEmptyParts);

            std::set<NoChannel*> sChans;
            for (const NoString& sChan : vsChans) {
                std::vector<NoChannel*> channels = d->network->findChannels(sChan);
                sChans.insert(channels.begin(), channels.end());
            }

            uint uEnabled = 0;
            for (NoChannel* channel : sChans) {
                if (!channel->isDisabled())
                    continue;
                uEnabled++;
                channel->enable();
            }

            putStatus("There were [" + NoString(sChans.size()) + "] channels matching [" + sPatterns + "]");
            putStatus("Enabled [" + NoString(uEnabled) + "] channels");
        }
    } else if (command.equals("DISABLECHAN")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sPatterns = No::tokens(line, 1);

        if (sPatterns.empty()) {
            putStatus("Usage: DisableChan <#chans>");
        } else {
            sPatterns.replace(",", " ");
            NoStringVector vsChans = sPatterns.split(" ", No::SkipEmptyParts);

            std::set<NoChannel*> sChans;
            for (const NoString& sChan : vsChans) {
                std::vector<NoChannel*> channels = d->network->findChannels(sChan);
                sChans.insert(channels.begin(), channels.end());
            }

            uint uDisabled = 0;
            for (NoChannel* channel : sChans) {
                if (channel->isDisabled())
                    continue;
                uDisabled++;
                channel->disable();
            }

            putStatus("There were [" + NoString(sChans.size()) + "] channels matching [" + sPatterns + "]");
            putStatus("Disabled [" + NoString(uDisabled) + "] channels");
        }
    } else if (command.equals("SHOWCHAN")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sChan = No::tokens(line, 1);
        if (sChan.empty()) {
            putStatus("Usage: ShowChan <#chan>");
            return;
        }

        NoChannel* channel = d->network->findChannel(sChan);
        if (!channel) {
            putStatus("No such channel [" + sChan + "]");
            return;
        }
        sChan = channel->permStr() + channel->name();
        NoString sStatus =
        channel->isOn() ? (channel->isDetached() ? "Detached" : "Joined") : (channel->isDisabled() ? "Disabled" : "Trying");

        NoTable Table;
        Table.addColumn(sChan, false);
        Table.addColumn(sStatus);

        Table.addRow();
        Table.setValue(sChan, "InConfig");
        Table.setValue(sStatus, NoString(channel->inConfig() ? "yes" : "no"));

        Table.addRow();
        Table.setValue(sChan, "Buffer");
        Table.setValue(sStatus,
                       NoString(channel->buffer().size()) + "/" + NoString(channel->bufferCount()) +
                       NoString(channel->hasBufferCountSet() ? "" : " (default)"));

        Table.addRow();
        Table.setValue(sChan, "AutoClearChanBuffer");
        Table.setValue(sStatus,
                       NoString(channel->autoClearChanBuffer() ? "yes" : "no") +
                       NoString(channel->hasAutoClearChanBufferSet() ? "" : " (default)"));

        if (channel->isOn()) {
            Table.addRow();
            Table.setValue(sChan, "Topic");
            Table.setValue(sStatus, channel->topic());

            Table.addRow();
            Table.setValue(sChan, "Modes");
            Table.setValue(sStatus, channel->modeString());

            Table.addRow();
            Table.setValue(sChan, "Users");

            NoStringVector vsUsers;
            vsUsers.push_back("All: " + NoString(channel->nickCount()));

            NoIrcSocket* socket = d->network->ircSocket();
            const NoString& sPerms = socket ? socket->perms() : "";
            std::map<char, uint> mPerms = channel->permCounts();
            for (char cPerm : sPerms) {
                vsUsers.push_back(NoString(cPerm) + ": " + NoString(mPerms[cPerm]));
            }
            Table.setValue(sStatus, NoString(", ").join(vsUsers.begin(), vsUsers.end()));
        }

        putStatus(Table);
    } else if (command.equals("LISTCHANS")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoNetwork* network = d->network;

        const NoString nick = No::token(line, 1);
        const NoString sNetwork = No::token(line, 2);

        if (!nick.empty()) {
            if (!d->user->isAdmin()) {
                putStatus("Usage: ListChans");
                return;
            }

            NoUser* user = noApp->findUser(nick);

            if (!user) {
                putStatus("No such user [" + nick + "]");
                return;
            }

            network = user->findNetwork(sNetwork);
            if (!network) {
                putStatus("No such network for user [" + sNetwork + "]");
                return;
            }
        }

        const std::vector<NoChannel*>& channels = network->channels();

        if (channels.empty()) {
            putStatus("There are no channels defined.");
            return;
        }

        NoTable Table;
        Table.addColumn("Name");
        Table.addColumn("Status");

        uint uNumDetached = 0, uNumDisabled = 0, uNumJoined = 0;

        for (const NoChannel* channel : channels) {
            Table.addRow();
            Table.setValue("Name", channel->permStr() + channel->name());
            Table.setValue("Status",
                           ((channel->isOn()) ? ((channel->isDetached()) ? "Detached" : "Joined") :
                                              ((channel->isDisabled()) ? "Disabled" : "Trying")));

            if (channel->isDetached())
                uNumDetached++;
            if (channel->isOn())
                uNumJoined++;
            if (channel->isDisabled())
                uNumDisabled++;
        }

        putStatus(Table);
        putStatus("Total: " + NoString(channels.size()) + " - Joined: " + NoString(uNumJoined) + " - Detached: " +
                  NoString(uNumDetached) + " - Disabled: " + NoString(uNumDisabled));
    } else if (command.equals("ADDNETWORK")) {
        if (!d->user->isAdmin() && !d->user->hasSpaceForNewNetwork()) {
            putStatus("Network number limit reached. Ask an admin to increase the limit for you, or delete unneeded "
                      "networks using /znc DelNetwork <name>");
            return;
        }

        NoString sNetwork = No::token(line, 1);

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
    } else if (command.equals("DELNETWORK")) {
        NoString sNetwork = No::token(line, 1);

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
    } else if (command.equals("LISTNETWORKS")) {
        NoUser* user = d->user;

        if (d->user->isAdmin() && !No::token(line, 1).empty()) {
            user = noApp->findUser(No::token(line, 1));

            if (!user) {
                putStatus("User not found " + No::token(line, 1));
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

        for (const NoNetwork* network : vNetworks) {
            Table.addRow();
            Table.setValue("Network", network->name());
            if (network->isIrcConnected()) {
                Table.setValue("OnIRC", "Yes");
                Table.setValue("IRC Server", network->ircServer());
                Table.setValue("IRC User", network->ircNick().nickMask());
                Table.setValue("Channels", NoString(network->channels().size()));
            } else {
                Table.setValue("OnIRC", "No");
            }
        }

        if (putStatus(Table) == 0) {
            putStatus("No networks");
        }
    } else if (command.equals("MOVENETWORK")) {
        if (!d->user->isAdmin()) {
            putStatus("Access Denied.");
            return;
        }

        NoString sOldUser = No::token(line, 1);
        NoString sOldNetwork = No::token(line, 2);
        NoString sNewUser = No::token(line, 3);
        NoString sNewNetwork = No::token(line, 4);

        if (sOldUser.empty() || sOldNetwork.empty() || sNewUser.empty()) {
            putStatus("Usage: MoveNetwork <old user> <old network> <new user> [new network]");
            return;
        }
        if (sNewNetwork.empty()) {
            sNewNetwork = sOldNetwork;
        }

        NoUser* oldUser = noApp->findUser(sOldUser);
        if (!oldUser) {
            putStatus("Old user [" + sOldUser + "] not found.");
            return;
        }

        NoNetwork* pOldNetwork = oldUser->findNetwork(sOldNetwork);
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
        for (NoModule* mod : vMods) {
            NoString sOldModPath = pOldNetwork->networkPath() + "/moddata/" + mod->moduleName();
            NoString sNewModPath = pNewUser->userPath() + "/networks/" + sNewNetwork + "/moddata/" + mod->moduleName();

            NoDir oldDir(sOldModPath);
            for (NoFile* pFile : oldDir.files()) {
                if (pFile->GetShortName() != ".registry") {
                    putStatus("Some files seem to be in [" + sOldModPath + "]. You might want to move them to [" + sNewModPath + "]");
                    break;
                }
            }

            NoRegistry registry(mod);
            registry.copy(sNewModPath);
        }

        NoString sNetworkAddError;
        NoNetwork* pNewNetwork = pNewUser->addNetwork(sNewNetwork, sNetworkAddError);

        if (!pNewNetwork) {
            putStatus("Error adding network:" + sNetworkAddError);
            return;
        }

        pNewNetwork->clone(*pOldNetwork, false);

        if (d->network && d->network->name().equals(sOldNetwork) && d->user == oldUser) {
            setNetwork(nullptr);
        }

        if (oldUser->deleteNetwork(sOldNetwork)) {
            putStatus("Success.");
        } else {
            putStatus("Copied the network to new user, but failed to delete old network");
        }
    } else if (command.equals("JUMPNETWORK")) {
        NoString sNetwork = No::token(line, 1);

        if (sNetwork.empty()) {
            putStatus("No network supplied.");
            return;
        }

        if (d->network && (d->network->name() == sNetwork)) {
            putStatus("You are already connected with this network.");
            return;
        }

        NoNetwork* network = d->user->findNetwork(sNetwork);
        if (network) {
            putStatus("Switched to " + sNetwork);
            setNetwork(network);
        } else {
            putStatus("You don't have a network named " + sNetwork);
        }
    } else if (command.equals("ADDSERVER")) {
        NoString sServer = No::token(line, 1);

        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        if (sServer.empty()) {
            putStatus("Usage: AddServer <host> [[+]port] [pass]");
            return;
        }

        if (d->network->addServer(No::tokens(line, 1))) {
            putStatus("Server added");
        } else {
            putStatus("Unable to add that server");
            putStatus("Perhaps the server is already added or openssl is disabled?");
        }
    } else if (command.equals("REMSERVER") || command.equals("DELSERVER")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sServer = No::token(line, 1);
        ushort port = No::token(line, 2).toUShort();
        NoString pass = No::token(line, 3);

        if (sServer.empty()) {
            putStatus("Usage: removeServer <host> [port] [pass]");
            return;
        }

        if (!d->network->hasServers()) {
            putStatus("You don't have any servers added.");
            return;
        }

        if (d->network->removeServer(sServer, port, pass)) {
            putStatus("Server removed");
        } else {
            putStatus("No such server");
        }
    } else if (command.equals("LISTSERVERS")) {
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

            for (const NoServerInfo* server : vServers) {
                Table.addRow();
                Table.setValue("Host", server->host() + (server == pCurServ ? "*" : ""));
                Table.setValue("Port", NoString(server->port()));
                Table.setValue("SSL", (server->isSsl()) ? "SSL" : "");
                Table.setValue("Pass", server->password());
            }

            putStatus(Table);
        } else {
            putStatus("You don't have any servers added.");
        }
    } else if (command.equals("AddTrustedServerFingerprint")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }
        NoString fingerprint = No::token(line, 1);
        if (fingerprint.empty()) {
            putStatus("Usage: AddTrustedServerFingerprint <fi:ng:er>");
            return;
        }
        d->network->addTrustedFingerprint(fingerprint);
        putStatus("Done.");
    } else if (command.equals("DelTrustedServerFingerprint")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }
        NoString fingerprint = No::token(line, 1);
        if (fingerprint.empty()) {
            putStatus("Usage: DelTrustedServerFingerprint <fi:ng:er>");
            return;
        }
        d->network->removeTrustedFingerprint(fingerprint);
        putStatus("Done.");
    } else if (command.equals("ListTrustedServerFingerprints")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }
        const NoStringSet& ssFPs = d->network->trustedFingerprints();
        if (ssFPs.empty()) {
            putStatus("No fingerprints added.");
        } else {
            int k = 0;
            for (const NoString& fingerprint : ssFPs) {
                putStatus(NoString(++k) + ". " + fingerprint);
            }
        }
    } else if (command.equals("TOPICS")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        const std::vector<NoChannel*>& channels = d->network->channels();
        NoTable Table;
        Table.addColumn("Name");
        Table.addColumn("Set By");
        Table.addColumn("Topic");

        for (const NoChannel* channel : channels) {
            Table.addRow();
            Table.setValue("Name", channel->name());
            Table.setValue("Set By", channel->topicOwner());
            Table.setValue("Topic", channel->topic());
        }

        putStatus(Table);
    } else if (command.equals("LISTMODS") || command.equals("LISTMODULES")) {
        if (d->user->isAdmin()) {
            NoModuleLoader* GModules = noApp->loader();

            if (GModules->isEmpty()) {
                putStatus("No global modules loaded.");
            } else {
                putStatus("Global modules:");
                NoTable GTable;
                GTable.addColumn("Name");
                GTable.addColumn("Arguments");

                for (const NoModule* mod : GModules->modules()) {
                    GTable.addRow();
                    GTable.setValue("Name", mod->moduleName());
                    GTable.setValue("Arguments", mod->args());
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

            for (const NoModule* mod : Modules->modules()) {
                Table.addRow();
                Table.setValue("Name", mod->moduleName());
                Table.setValue("Arguments", mod->args());
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

                for (const NoModule* mod : NetworkModules->modules()) {
                    Table.addRow();
                    Table.setValue("Name", mod->moduleName());
                    Table.setValue("Arguments", mod->args());
                }

                putStatus(Table);
            }
        }

        return;
    } else if (command.equals("LISTAVAILMODS") || command.equals("LISTAVAILABLEMODULES")) {
        if (d->user->denyLoadMod()) {
            putStatus("Access Denied.");
            return;
        }

        if (d->user->isAdmin()) {
            std::set<NoModuleInfo> ssGlobalMods = noApp->loader()->availableModules(No::GlobalModule);

            if (ssGlobalMods.empty()) {
                putStatus("No global modules available.");
            } else {
                putStatus("Global modules:");
                NoTable GTable;
                GTable.addColumn("Name");
                GTable.addColumn("Description");

                for (const NoModuleInfo& info : ssGlobalMods) {
                    GTable.addRow();
                    GTable.setValue("Name", (noApp->loader()->findModule(info.name()) ? "*" : " ") + info.name());
                    GTable.setValue("Description", No::ellipsize(info.description(), 128));
                }

                putStatus(GTable);
            }
        }

        std::set<NoModuleInfo> ssUserMods = noApp->loader()->availableModules(No::UserModule);

        if (ssUserMods.empty()) {
            putStatus("No user modules available.");
        } else {
            putStatus("User modules:");
            NoTable Table;
            Table.addColumn("Name");
            Table.addColumn("Description");

            for (const NoModuleInfo& info : ssUserMods) {
                Table.addRow();
                Table.setValue("Name", (d->user->loader()->findModule(info.name()) ? "*" : " ") + info.name());
                Table.setValue("Description", No::ellipsize(info.description(), 128));
            }

            putStatus(Table);
        }

        std::set<NoModuleInfo> ssNetworkMods = noApp->loader()->availableModules(No::NetworkModule);

        if (ssNetworkMods.empty()) {
            putStatus("No network modules available.");
        } else {
            putStatus("Network modules:");
            NoTable Table;
            Table.addColumn("Name");
            Table.addColumn("Description");

            for (const NoModuleInfo& info : ssNetworkMods) {
                Table.addRow();
                Table.setValue("Name", ((d->network && d->network->loader()->findModule(info.name())) ? "*" : " ") + info.name());
                Table.setValue("Description", No::ellipsize(info.description(), 128));
            }

            putStatus(Table);
        }
        return;
    } else if (command.equals("LOADMOD") || command.equals("LOADMODULE")) {
        No::ModuleType type;
        NoString sType = No::token(line, 1);
        NoString sMod = No::token(line, 2);
        NoString args = No::tokens(line, 3);

        // TODO use proper library for parsing arguments
        if (sType.equals("--type=global")) {
            type = No::GlobalModule;
        } else if (sType.equals("--type=user")) {
            type = No::UserModule;
        } else if (sType.equals("--type=network")) {
            type = No::NetworkModule;
        } else {
            sMod = sType;
            args = No::tokens(line, 2);
            sType = "default";
            // Will be set correctly later
            type = No::UserModule;
        }

        if (d->user->denyLoadMod()) {
            putStatus("Unable to load [" + sMod + "]: Access Denied.");
            return;
        }

        if (sMod.empty()) {
            putStatus("Usage: LoadMod [--type=global|user|network] <module> [args]");
            return;
        }

        NoModuleInfo info;
        NoString message;
        if (!noApp->loader()->moduleInfo(info, sMod, message)) {
            putStatus("Unable to find modinfo [" + sMod + "] [" + message + "]");
            return;
        }

        if (sType.equals("default")) {
            type = info.defaultType();
        }

        if (type == No::GlobalModule && !d->user->isAdmin()) {
            putStatus("Unable to load global module [" + sMod + "]: Access Denied.");
            return;
        }

        if (type == No::NetworkModule && !d->network) {
            putStatus("Unable to load network module [" + sMod + "] Not connected with a network.");
            return;
        }

        NoString sModRet;
        bool b = false;

        switch (type) {
        case No::GlobalModule:
            b = noApp->loader()->loadModule(sMod, args, type, nullptr, nullptr, sModRet);
            break;
        case No::UserModule:
            b = d->user->loader()->loadModule(sMod, args, type, d->user, nullptr, sModRet);
            break;
        case No::NetworkModule:
            b = d->network->loader()->loadModule(sMod, args, type, d->user, d->network, sModRet);
            break;
        default:
            sModRet = "Unable to load module [" + sMod + "]: Unknown module type";
        }

        if (b)
            sModRet = "Loaded module [" + sMod + "] " + sModRet;

        putStatus(sModRet);
        return;
    } else if (command.equals("UNLOADMOD") || command.equals("UNLOADMODULE")) {
        No::ModuleType type = No::UserModule;
        NoString sType = No::token(line, 1);
        NoString sMod = No::token(line, 2);

        // TODO use proper library for parsing arguments
        if (sType.equals("--type=global")) {
            type = No::GlobalModule;
        } else if (sType.equals("--type=user")) {
            type = No::UserModule;
        } else if (sType.equals("--type=network")) {
            type = No::NetworkModule;
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
            NoModuleInfo info;
            NoString message;
            if (!noApp->loader()->moduleInfo(info, sMod, message)) {
                putStatus("Unable to find modinfo [" + sMod + "] [" + message + "]");
                return;
            }

            type = info.defaultType();
        }

        if (type == No::GlobalModule && !d->user->isAdmin()) {
            putStatus("Unable to unload global module [" + sMod + "]: Access Denied.");
            return;
        }

        if (type == No::NetworkModule && !d->network) {
            putStatus("Unable to unload network module [" + sMod + "] Not connected with a network.");
            return;
        }

        NoString sModRet;

        switch (type) {
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
    } else if (command.equals("RELOADMOD") || command.equals("RELOADMODULE")) {
        No::ModuleType type;
        NoString sType = No::token(line, 1);
        NoString sMod = No::token(line, 2);
        NoString args = No::tokens(line, 3);

        if (d->user->denyLoadMod()) {
            putStatus("Unable to reload modules. Access Denied.");
            return;
        }

        // TODO use proper library for parsing arguments
        if (sType.equals("--type=global")) {
            type = No::GlobalModule;
        } else if (sType.equals("--type=user")) {
            type = No::UserModule;
        } else if (sType.equals("--type=network")) {
            type = No::NetworkModule;
        } else {
            sMod = sType;
            args = No::tokens(line, 2);
            sType = "default";
            // Will be set correctly later
            type = No::UserModule;
        }

        if (sMod.empty()) {
            putStatus("Usage: ReloadMod [--type=global|user|network] <module> [args]");
            return;
        }

        if (sType.equals("default")) {
            NoModuleInfo info;
            NoString message;
            if (!noApp->loader()->moduleInfo(info, sMod, message)) {
                putStatus("Unable to find modinfo for [" + sMod + "] [" + message + "]");
                return;
            }

            type = info.defaultType();
        }

        if (type == No::GlobalModule && !d->user->isAdmin()) {
            putStatus("Unable to reload global module [" + sMod + "]: Access Denied.");
            return;
        }

        if (type == No::NetworkModule && !d->network) {
            putStatus("Unable to load network module [" + sMod + "] Not connected with a network.");
            return;
        }

        NoString sModRet;

        switch (type) {
        case No::GlobalModule:
            noApp->loader()->reloadModule(sMod, args, nullptr, nullptr, sModRet);
            break;
        case No::UserModule:
            d->user->loader()->reloadModule(sMod, args, d->user, nullptr, sModRet);
            break;
        case No::NetworkModule:
            d->network->loader()->reloadModule(sMod, args, d->user, d->network, sModRet);
            break;
        default:
            sModRet = "Unable to reload module [" + sMod + "]: Unknown module type";
        }

        putStatus(sModRet);
        return;
    } else if ((command.equals("UPDATEMOD") || command.equals("UPDATEMODULE")) && d->user->isAdmin()) {
        NoString sMod = No::token(line, 1);

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
    } else if ((command.equals("ADDBINDHOST") || command.equals("ADDVHOST")) && d->user->isAdmin()) {
        NoString host = No::token(line, 1);

        if (host.empty()) {
            putStatus("Usage: AddBindHost <host>");
            return;
        }

        if (noApp->addBindHost(host)) {
            putStatus("Done");
        } else {
            putStatus("The host [" + host + "] is already in the list");
        }
    } else if ((command.equals("REMBINDHOST") || command.equals("DELBINDHOST") || command.equals("REMVHOST") ||
                command.equals("DELVHOST")) &&
               d->user->isAdmin()) {
        NoString host = No::token(line, 1);

        if (host.empty()) {
            putStatus("Usage: DelBindHost <host>");
            return;
        }

        if (noApp->removeBindHost(host)) {
            putStatus("Done");
        } else {
            putStatus("The host [" + host + "] is not in the list");
        }
    } else if ((command.equals("LISTBINDHOSTS") || command.equals("LISTVHOSTS")) &&
               (d->user->isAdmin() || !d->user->denysetBindHost())) {
        const NoStringVector& vsHosts = noApp->bindHosts();

        if (vsHosts.empty()) {
            putStatus("No bind hosts configured");
            return;
        }

        NoTable Table;
        Table.addColumn("Host");

        for (const NoString& host : vsHosts) {
            Table.addRow();
            Table.setValue("Host", host);
        }
        putStatus(Table);
    } else if ((command.equals("SETBINDHOST") || command.equals("SETVHOST")) &&
               (d->user->isAdmin() || !d->user->denysetBindHost())) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command. Try SetUserBindHost instead");
            return;
        }
        NoString arg = No::token(line, 1);

        if (arg.empty()) {
            putStatus("Usage: setBindHost <host>");
            return;
        }

        if (arg.equals(d->network->bindHost())) {
            putStatus("You already have this bind host!");
            return;
        }

        const NoStringVector& vsHosts = noApp->bindHosts();
        if (!d->user->isAdmin() && !vsHosts.empty()) {
            bool bFound = false;

            for (const NoString& host : vsHosts) {
                if (arg.equals(host)) {
                    bFound = true;
                    break;
                }
            }

            if (!bFound) {
                putStatus("You may not use this bind host. See [ListBindHosts] for a list");
                return;
            }
        }

        d->network->setBindHost(arg);
        putStatus("Set bind host for network [" + d->network->name() + "] to [" + d->network->bindHost() + "]");
    } else if (command.equals("SETUSERBINDHOST") && (d->user->isAdmin() || !d->user->denysetBindHost())) {
        NoString arg = No::token(line, 1);

        if (arg.empty()) {
            putStatus("Usage: SetUserBindHost <host>");
            return;
        }

        if (arg.equals(d->user->bindHost())) {
            putStatus("You already have this bind host!");
            return;
        }

        const NoStringVector& vsHosts = noApp->bindHosts();
        if (!d->user->isAdmin() && !vsHosts.empty()) {
            bool bFound = false;

            for (const NoString& host : vsHosts) {
                if (arg.equals(host)) {
                    bFound = true;
                    break;
                }
            }

            if (!bFound) {
                putStatus("You may not use this bind host. See [ListBindHosts] for a list");
                return;
            }
        }

        d->user->setBindHost(arg);
        putStatus("Set bind host to [" + d->user->bindHost() + "]");
    } else if ((command.equals("CLEARBINDHOST") || command.equals("CLEARVHOST")) &&
               (d->user->isAdmin() || !d->user->denysetBindHost())) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command. Try ClearUserBindHost instead");
            return;
        }
        d->network->setBindHost("");
        putStatus("Bind host cleared for this network.");
    } else if (command.equals("CLEARUSERBINDHOST") && (d->user->isAdmin() || !d->user->denysetBindHost())) {
        d->user->setBindHost("");
        putStatus("Bind host cleared for your user.");
    } else if (command.equals("SHOWBINDHOST")) {
        putStatus("This user's default bind host " + (d->user->bindHost().empty() ? "not set" : "is [" + d->user->bindHost() + "]"));
        if (d->network) {
            putStatus("This network's bind host " +
                      (d->network->bindHost().empty() ? "not set" : "is [" + d->network->bindHost() + "]"));
        }
    } else if (command.equals("PLAYBUFFER")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sBuffer = No::token(line, 1);

        if (sBuffer.empty()) {
            putStatus("Usage: PlayBuffer <#chan|query>");
            return;
        }

        if (d->network->isChannel(sBuffer)) {
            NoChannel* channel = d->network->findChannel(sBuffer);

            if (!channel) {
                putStatus("You are not on [" + sBuffer + "]");
                return;
            }

            if (!channel->isOn()) {
                putStatus("You are not on [" + sBuffer + "] [trying]");
                return;
            }

            if (channel->buffer().isEmpty()) {
                putStatus("The buffer for [" + sBuffer + "] is empty");
                return;
            }

            channel->sendBuffer(this);
        } else {
            NoQuery* query = d->network->findQuery(sBuffer);

            if (!query) {
                putStatus("No active query with [" + sBuffer + "]");
                return;
            }

            if (query->buffer().isEmpty()) {
                putStatus("The buffer for [" + sBuffer + "] is empty");
                return;
            }

            query->sendBuffer(this);
        }
    } else if (command.equals("CLEARBUFFER")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sBuffer = No::token(line, 1);

        if (sBuffer.empty()) {
            putStatus("Usage: ClearBuffer <#chan|query>");
            return;
        }

        uint uMatches = 0;
        std::vector<NoChannel*> channels = d->network->findChannels(sBuffer);
        for (NoChannel* channel : channels) {
            uMatches++;

            channel->clearBuffer();
        }

        std::vector<NoQuery*> vQueries = d->network->findQueries(sBuffer);
        for (NoQuery* query : vQueries) {
            uMatches++;

            d->network->removeQuery(query->name());
        }

        putStatus("[" + NoString(uMatches) + "] buffers matching [" + sBuffer + "] have been cleared");
    } else if (command.equals("CLEARALLCHANNELBUFFERS")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        for (NoChannel* channel : d->network->channels()) {
            channel->clearBuffer();
        }
        putStatus("All channel buffers have been cleared");
    } else if (command.equals("CLEARALLQUERYBUFFERS")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        d->network->clearQueryBuffer();
        putStatus("All query buffers have been cleared");
    } else if (command.equals("CLEARALLBUFFERS")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        for (NoChannel* channel : d->network->channels()) {
            channel->clearBuffer();
        }
        d->network->clearQueryBuffer();
        putStatus("All buffers have been cleared");
    } else if (command.equals("SETBUFFER")) {
        if (!d->network) {
            putStatus("You must be connected with a network to use this command");
            return;
        }

        NoString sBuffer = No::token(line, 1);

        if (sBuffer.empty()) {
            putStatus("Usage: SetBuffer <#chan|query> [linecount]");
            return;
        }

        uint uLineCount = No::token(line, 2).toUInt();
        uint uMatches = 0, uFail = 0;
        std::vector<NoChannel*> channels = d->network->findChannels(sBuffer);
        for (NoChannel* channel : channels) {
            uMatches++;

            if (!channel->setBufferCount(uLineCount))
                uFail++;
        }

        std::vector<NoQuery*> vQueries = d->network->findQueries(sBuffer);
        for (NoQuery* query : vQueries) {
            uMatches++;

            if (!query->setBufferCount(uLineCount))
                uFail++;
        }

        putStatus("BufferCount for [" + NoString(uMatches - uFail) + "] buffer was set to [" + NoString(uLineCount) + "]");
        if (uFail > 0) {
            putStatus("Setting BufferCount failed for [" + NoString(uFail) + "] buffers, "
                                                                             "max buffer count is " +
                      NoString(noApp->maxBufferSize()));
        }
    } else if (d->user->isAdmin() && command.equals("TRAFFIC")) {
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
    } else if (command.equals("UPTIME")) {
        putStatus("Running for " + noApp->uptime());
    } else if (d->user->isAdmin() &&
               (command.equals("LISTPORTS") || command.equals("ADDPORT") || command.equals("DELPORT"))) {
        yserPortCommand(line);
    } else {
        putStatus("Unknown command [" + command + "] try 'Help'");
    }
}

void NoClient::yserPortCommand(NoString& line)
{
    const NoString command = No::token(line, 0);

    if (command.equals("LISTPORTS")) {
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

            No::AddressType addressType = pListener->addressType();
            Table.setValue("Proto",
                           (addressType == No::Ipv4AndIpv6Address ? "All" : (addressType == No::Ipv4Address ? "IPv4" : "IPv6")));

            No::AcceptType acceptType = pListener->acceptType();
            Table.setValue("IRC/Web", (acceptType == No::AcceptAll ? "All" : (acceptType == No::AcceptIrc ? "IRC" : "Web")));
            Table.setValue("URIPrefix", pListener->uriPrefix() + "/");
        }

        putStatus(Table);

        return;
    }

    NoString sPort = No::token(line, 1);
    NoString sAddr = No::token(line, 2);
    No::AddressType addressType = No::Ipv4AndIpv6Address;

    if (sAddr.equals("IPV4")) {
        addressType = No::Ipv4Address;
    } else if (sAddr.equals("IPV6")) {
        addressType = No::Ipv6Address;
    } else if (sAddr.equals("ALL")) {
        addressType = No::Ipv4AndIpv6Address;
    } else {
        sAddr.clear();
    }

    ushort port = sPort.toUShort();

    if (command.equals("ADDPORT")) {
        No::AcceptType acceptType = No::AcceptAll;
        NoString sAccept = No::token(line, 3);

        if (sAccept.equals("WEB")) {
            acceptType = No::AcceptHttp;
        } else if (sAccept.equals("IRC")) {
            acceptType = No::AcceptIrc;
        } else if (sAccept.equals("ALL")) {
            acceptType = No::AcceptAll;
        } else {
            sAccept.clear();
        }

        if (sPort.empty() || sAddr.empty() || sAccept.empty()) {
            putStatus("Usage: AddPort <[+]port> <ipv4|ipv6|all> <web|irc|all> [bindhost [uriprefix]]");
        } else {
            bool ssl = (sPort.left(1).equals("+"));
            const NoString host = No::token(line, 4);
            const NoString uriPrefix = No::token(line, 5);

            NoListener* pListener = new NoListener(host, port);
            pListener->setUriPrefix(uriPrefix);
            pListener->setSsl(ssl);
            pListener->setAddressType(addressType);
            pListener->setAcceptType(acceptType);

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
    } else if (command.equals("DELPORT")) {
        if (sPort.empty() || sAddr.empty()) {
            putStatus("Usage: DelPort <port> <ipv4|ipv6|all> [bindhost]");
        } else {
            const NoString bindHost = No::token(line, 3);

            NoListener* pListener = noApp->findListener(port, bindHost, addressType);

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
addCommandHelp(NoTable& Table, const NoString& cmd, const NoString& args, const NoString& desc, const NoString& filter = "")
{
    if (filter.empty() || cmd.startsWith(filter) || wildCmp(cmd, filter, No::CaseInsensitive)) {
        Table.addRow();
        Table.setValue("Command", cmd);
        Table.setValue("Arguments", args);
        Table.setValue("Description", desc);
    }
}

void NoClient::helpUser(const NoString& filter)
{
    NoTable Table;
    Table.addColumn("Command");
    Table.addColumn("Arguments");
    Table.addColumn("Description");

    if (filter.empty()) {
        putStatus("In the following list all occurrences of <#chan> support wildcards (* and ?)");
        putStatus("(Except ListNicks)");
    }

    addCommandHelp(Table, "Version", "", "Print which version of ZNC this is", filter);

    addCommandHelp(Table, "ListMods", "", "List all loaded modules", filter);
    addCommandHelp(Table, "ListAvailMods", "", "List all available modules", filter);
    if (!d->user->isAdmin()) { // If they are an admin we will add this command below with an argument
        addCommandHelp(Table, "ListChans", "", "List all channels", filter);
    }
    addCommandHelp(Table, "ListNicks", "<#chan>", "List all nicks on a channel", filter);
    if (!d->user->isAdmin()) {
        addCommandHelp(Table, "ListClients", "", "List all clients connected to your ZNC user", filter);
    }
    addCommandHelp(Table, "ListServers", "", "List all servers of current IRC network", filter);

    addCommandHelp(Table, "AddNetwork", "<name>", "Add a network to your user", filter);
    addCommandHelp(Table, "DelNetwork", "<name>", "Delete a network from your user", filter);
    addCommandHelp(Table, "ListNetworks", "", "List all networks", filter);
    if (d->user->isAdmin()) {
        addCommandHelp(Table,
                       "MoveNetwork",
                       "<old user> <old network> <new user> [new network]",
                       "Move an IRC network from one user to another",
                       filter);
    }
    addCommandHelp(Table,
                   "JumpNetwork",
                   "<network>",
                   "Jump to another network (Alternatively, you can connect to ZNC several times, using "
                   "`user/network` as username)",
                   filter);

    addCommandHelp(Table,
                   "AddServer",
                   "<host> [[+]port] [pass]",
                   "Add a server to the list of alternate/backup servers of current IRC network.",
                   filter);
    addCommandHelp(Table,
                   "removeServer",
                   "<host> [port] [pass]",
                   "Remove a server from the list of alternate/backup servers of current IRC network",
                   filter);

    addCommandHelp(Table,
                   "AddTrustedServerFingerprint",
                   "<fi:ng:er>",
                   "Add a trusted server SSL certificate fingerprint (SHA-256) to current IRC network.",
                   filter);
    addCommandHelp(Table,
                   "DelTrustedServerFingerprint",
                   "<fi:ng:er>",
                   "Delete a trusted server SSL certificate from current IRC network.",
                   filter);
    addCommandHelp(
    Table, "ListTrustedServerFingerprints", "", "List all trusted server SSL certificates of current IRC network.", filter);

    addCommandHelp(Table, "ShowChan", "<#chan>", "Show channel details", filter);
    addCommandHelp(Table, "EnableChan", "<#chans>", "Enable channels", filter);
    addCommandHelp(Table, "DisableChan", "<#chans>", "Disable channels", filter);
    addCommandHelp(Table, "Detach", "<#chans>", "Detach from channels", filter);
    addCommandHelp(Table, "Topics", "", "Show topics in all your channels", filter);

    addCommandHelp(Table, "PlayBuffer", "<#chan|query>", "Play back the specified buffer", filter);
    addCommandHelp(Table, "ClearBuffer", "<#chan|query>", "Clear the specified buffer", filter);
    addCommandHelp(Table, "ClearAllBuffers", "", "Clear all channel and query buffers", filter);
    addCommandHelp(Table, "ClearAllChannelBuffers", "", "Clear the channel buffers", filter);
    addCommandHelp(Table, "ClearAllQueryBuffers", "", "Clear the query buffers", filter);
    addCommandHelp(Table, "SetBuffer", "<#chan|query> [linecount]", "Set the buffer count", filter);

    if (d->user->isAdmin()) {
        addCommandHelp(Table, "AddBindHost", "<host (IP preferred)>", "Adds a bind host for normal users to use", filter);
        addCommandHelp(Table, "DelBindHost", "<host>", "Removes a bind host from the list", filter);
    }

    if (d->user->isAdmin() || !d->user->denysetBindHost()) {
        addCommandHelp(Table, "ListBindHosts", "", "Shows the configured list of bind hosts", filter);
        addCommandHelp(Table, "setBindHost", "<host (IP preferred)>", "Set the bind host for this connection", filter);
        addCommandHelp(Table, "SetUserBindHost", "<host (IP preferred)>", "Set the default bind host for this user", filter);
        addCommandHelp(Table, "ClearBindHost", "", "Clear the bind host for this connection", filter);
        addCommandHelp(Table, "ClearUserBindHost", "", "Clear the default bind host for this user", filter);
    }

    addCommandHelp(Table, "ShowBindHost", "", "Show currently selected bind host", filter);
    addCommandHelp(Table, "Jump", "[server]", "Jump to the next or the specified server", filter);
    addCommandHelp(Table, "Disconnect", "[message]", "Disconnect from IRC", filter);
    addCommandHelp(Table, "Connect", "", "Reconnect to IRC", filter);
    addCommandHelp(Table, "Uptime", "", "Show for how long ZNC has been running", filter);

    if (!d->user->denyLoadMod()) {
        addCommandHelp(Table, "LoadMod", "[--type=global|user|network] <module>", "Load a module", filter);
        addCommandHelp(Table, "UnloadMod", "[--type=global|user|network] <module>", "Unload a module", filter);
        addCommandHelp(Table, "ReloadMod", "[--type=global|user|network] <module>", "Reload a module", filter);
        if (d->user->isAdmin()) {
            addCommandHelp(Table, "UpdateMod", "<module>", "Reload a module everywhere", filter);
        }
    }

    addCommandHelp(Table, "ShowMOTD", "", "Show ZNC's message of the day", filter);

    if (d->user->isAdmin()) {
        addCommandHelp(Table, "SetMOTD", "<message>", "Set ZNC's message of the day", filter);
        addCommandHelp(Table, "AddMOTD", "<message>", "Append <message> to ZNC's MOTD", filter);
        addCommandHelp(Table, "ClearMOTD", "", "Clear ZNC's MOTD", filter);
        addCommandHelp(Table, "ListPorts", "", "Show all active listeners", filter);
        addCommandHelp(Table,
                       "AddPort",
                       "<[+]port> <ipv4|ipv6|all> <web|irc|all> [bindhost [uriprefix]]",
                       "Add another port for ZNC to listen on",
                       filter);
        addCommandHelp(Table, "DelPort", "<port> <ipv4|ipv6|all> [bindhost]", "Remove a port from ZNC", filter);
        addCommandHelp(Table, "Rehash", "", "Reload znc.conf from disk", filter);
        addCommandHelp(Table, "SaveConfig", "", "Save the current settings to disk", filter);
        addCommandHelp(Table, "ListUsers", "", "List all ZNC users and their connection status", filter);
        addCommandHelp(Table, "ListAllUserNetworks", "", "List all ZNC users and their networks", filter);
        addCommandHelp(Table, "ListChans", "[user <network>]", "List all channels", filter);
        addCommandHelp(Table, "ListClients", "[user]", "List all connected clients", filter);
        addCommandHelp(Table, "Traffic", "", "Show basic traffic stats for all ZNC users", filter);
        addCommandHelp(Table, "Broadcast", "[message]", "Broadcast a message to all ZNC users", filter);
        addCommandHelp(Table, "Shutdown", "[message]", "Shut down ZNC completely", filter);
        addCommandHelp(Table, "Restart", "[message]", "Restart ZNC", filter);
    }

    if (Table.isEmpty()) {
        putStatus("No matches for '" + filter + "'");
    } else {
        putStatus(Table);
    }
}
