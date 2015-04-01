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

#include "nonetwork.h"
#include "nouser.h"
#include "nofile.h"
#include "nodir.h"
#include "nosettings.h"
#include "noircsocket.h"
#include "nomessage.h"
#include "noserverinfo.h"
#include "nochannel.h"
#include "noquery.h"
#include "noescape.h"
#include "noclient.h"
#include "noapp.h"
#include "noapp_p.h"
#include "nonick.h"
#include "nobuffer.h"
#include "Csocket/Csocket.h"
#include <algorithm>
#include <memory>

class NoNetworkPingTimer : public CCron
{
public:
    NoNetworkPingTimer(NoNetwork* network) : CCron(), m_pNetwork(network)
    {
        SetName("NoNetworkPingTimer::" + m_pNetwork->user()->userName() + "::" + m_pNetwork->name());
        Start(NoNetwork::PingSlack);
    }

    NoNetworkPingTimer(const NoNetworkPingTimer&) = delete;
    NoNetworkPingTimer& operator=(const NoNetworkPingTimer&) = delete;

protected:
    void RunJob() override
    {
        NoIrcSocket* socket = m_pNetwork->ircSocket();

        if (socket && socket->timeSinceLastDataTransaction() >= NoNetwork::PingFrequency) {
            socket->putIrc("PING :ZNC");
        }

        const std::vector<NoClient*>& vClients = m_pNetwork->clients();
        for (NoClient* client : vClients) {
            if (client->socket()->timeSinceLastDataTransaction() >= NoNetwork::PingFrequency) {
                client->putClient("PING :ZNC");
            }
        }
    }

private:
    NoNetwork* m_pNetwork;
};

class NoNetworkJoinTimer : public CCron
{
public:
    NoNetworkJoinTimer(NoNetwork* network) : CCron(), m_bDelayed(false), m_pNetwork(network)
    {
        SetName("NoNetworkJoinTimer::" + m_pNetwork->user()->userName() + "::" + m_pNetwork->name());
        Start(NoNetwork::JoinFrequence);
    }

    NoNetworkJoinTimer(const NoNetworkJoinTimer&) = delete;
    NoNetworkJoinTimer& operator=(const NoNetworkJoinTimer&) = delete;

    void Delay(ushort uDelay)
    {
        m_bDelayed = true;
        Start(uDelay);
    }

protected:
    void RunJob() override
    {
        if (m_bDelayed) {
            m_bDelayed = false;
            Start(NoNetwork::JoinFrequence);
        }
        if (m_pNetwork->isIrcConnected()) {
            m_pNetwork->joinChannels();
        }
    }

private:
    bool m_bDelayed;
    NoNetwork* m_pNetwork;
};

class NoNetworkPrivate
{
public:
    NoString name = "";
    NoUser* user = nullptr;

    NoString nickName = "";
    NoString altNick = "";
    NoString ident = "";
    NoString realName = "";
    NoString bindHost = "";
    NoString encoding = "";
    NoString quitMsg = "";
    NoStringSet trustedFingerprints;

    NoModuleLoader* modules = nullptr;

    std::vector<NoClient*> clients;

    NoIrcSocket* socket = nullptr;

    std::vector<NoChannel*> channels;
    std::vector<NoQuery*> queries;

    NoString chanPrefixes = "";

    bool enabled = true;
    NoString server = "";
    std::vector<NoServerInfo*> servers;
    size_t serverIndex = 0; ///< Index in servers of our current server + 1

    NoNick ircNick;
    bool away = false;

    double floodRate = 1; ///< Set to -1 to disable protection.
    ushort floodBurst = 4;

    NoBuffer rawBuffer;
    NoBuffer motdBuffer;
    NoBuffer noticeBuffer;

    NoNetworkPingTimer* pingTimer = nullptr;
    NoNetworkJoinTimer* joinTimer = nullptr;

    ushort joinDelay = 0;
};

bool NoNetwork::isValidNetwork(const NoString& sNetwork)
{
    // ^[-\w]+$

    if (sNetwork.empty()) {
        return false;
    }

    const char* p = sNetwork.c_str();
    while (*p) {
        if (*p != '_' && *p != '-' && !isalnum(*p)) {
            return false;
        }

        p++;
    }

    return true;
}

NoNetwork::NoNetwork(NoUser* user, const NoString& name) : d(new NoNetworkPrivate)
{
    d->name = name;
    d->modules = new NoModuleLoader;

    setUser(user);

    d->rawBuffer.setLimit(100, true); // This should be more than enough raws, especially since we are buffering the
    // MOTD separately
    d->motdBuffer.setLimit(200, true); // This should be more than enough motd lines
    d->noticeBuffer.setLimit(250, true);

    d->pingTimer = new NoNetworkPingTimer(this);
    noApp->manager()->addCron(d->pingTimer);

    d->joinTimer = new NoNetworkJoinTimer(this);
    noApp->manager()->addCron(d->joinTimer);

    setEnabled(true);
}

NoNetwork::NoNetwork(NoUser* user, const NoNetwork& network) : NoNetwork(user, "")
{
    clone(network);
}

void NoNetwork::clone(const NoNetwork& network, bool cloneName)
{
    if (cloneName) {
        d->name = network.name();
    }

    d->floodRate = network.floodRate();
    d->floodBurst = network.floodBurst();
    d->joinDelay = network.joinDelay();

    setNick(network.nick());
    setAltNick(network.altNick());
    setIdent(network.ident());
    setRealName(network.realName());
    setBindHost(network.bindHost());
    setEncoding(network.encoding());
    setQuitMsg(network.quitMsg());
    d->trustedFingerprints = network.d->trustedFingerprints;

    // Servers
    const std::vector<NoServerInfo*>& vServers = network.servers();
    NoString sServer;
    NoServerInfo* pCurServ = currentServer();

    if (pCurServ) {
        sServer = pCurServ->host();
    }

    delServers();

    for (NoServerInfo* server : vServers) {
        addServer(server->host(), server->port(), server->password(), server->isSsl());
    }

    d->serverIndex = 0;
    for (size_t a = 0; a < d->servers.size(); a++) {
        if (sServer.equals(d->servers[a]->host())) {
            d->serverIndex = a + 1;
            break;
        }
    }
    if (d->serverIndex == 0) {
        d->serverIndex = d->servers.size();
        NoIrcSocket* socket = ircSocket();

        if (socket) {
            putStatus("Jumping servers because this server is no longer in the list");
            socket->quit();
        }
    }
    // !Servers

    // Chans
    const std::vector<NoChannel*>& channels = network.channels();
    for (NoChannel* pNewChan : channels) {
        NoChannel* channel = findChannel(pNewChan->name());

        if (channel) {
            channel->setInConfig(pNewChan->inConfig());
        } else {
            addChannel(pNewChan->name(), pNewChan->inConfig());
        }
    }

    for (NoChannel* channel : d->channels) {
        NoChannel* pNewChan = network.findChannel(channel->name());

        if (!pNewChan) {
            channel->setInConfig(false);
        } else {
            channel->clone(*pNewChan);
        }
    }
    // !Chans

    // Modules
    std::set<NoString> ssUnloadMods;
    NoModuleLoader* vCurMods = loader();
    const NoModuleLoader* vNewMods = network.loader();

    for (NoModule* pNewMod : vNewMods->modules()) {
        NoString sModRet;
        NoModule* pCurMod = vCurMods->findModule(pNewMod->moduleName());

        if (!pCurMod) {
            vCurMods->loadModule(pNewMod->moduleName(), pNewMod->args(), No::NetworkModule, d->user, this, sModRet);
        } else if (pNewMod->args() != pCurMod->args()) {
            vCurMods->reloadModule(pNewMod->moduleName(), pNewMod->args(), d->user, this, sModRet);
        }
    }

    for (NoModule* pCurMod : vCurMods->modules()) {
        NoModule* pNewMod = vNewMods->findModule(pCurMod->moduleName());

        if (!pNewMod) {
            ssUnloadMods.insert(pCurMod->moduleName());
        }
    }

    for (const NoString& sMod : ssUnloadMods) {
        vCurMods->unloadModule(sMod);
    }
    // !Modules

    setEnabled(network.isEnabled());
}

NoNetwork::~NoNetwork()
{
    if (d->socket) {
        noApp->manager()->removeSocket(d->socket);
        d->socket = nullptr;
    }

    // Delete clients
    while (!d->clients.empty()) {
        noApp->manager()->removeSocket(d->clients[0]->socket());
    }
    d->clients.clear();

    // Delete servers
    delServers();

    // Delete modules (this unloads all modules)
    delete d->modules;
    d->modules = nullptr;

    // Delete Channels
    for (NoChannel* channel : d->channels) {
        delete channel;
    }
    d->channels.clear();

    // Delete Queries
    for (NoQuery* query : d->queries) {
        delete query;
    }
    d->queries.clear();

    setUser(nullptr);

    // Make sure we are not in the connection queue
    NoAppPrivate::get(NoApp::instance())->connectQueue.remove(this);

    noApp->manager()->removeCron(d->pingTimer);
    noApp->manager()->removeCron(d->joinTimer);
}

void NoNetwork::delServers()
{
    for (NoServerInfo* server : d->servers) {
        delete server;
    }
    d->servers.clear();
}

NoString NoNetwork::networkPath() const
{
    NoString sNetworkPath = d->user->userPath() + "/networks/" + d->name;

    if (!NoFile::Exists(sNetworkPath)) {
        NoDir::mkpath(sNetworkPath);
    }

    return sNetworkPath;
}

template <class T>
struct TOption
{
    const char* name;
    void (NoNetwork::*pSetter)(T);
};

bool NoNetwork::parseConfig(NoSettings* settings, NoString& error, bool bUpgrade)
{
    NoStringVector vsList;

    if (!bUpgrade) {
        TOption<const NoString&> StringOptions[] = {
            { "nick", &NoNetwork::setNick },
            { "altnick", &NoNetwork::setAltNick },
            { "ident", &NoNetwork::setIdent },
            { "realname", &NoNetwork::setRealName },
            { "bindhost", &NoNetwork::setBindHost },
            { "encoding", &NoNetwork::setEncoding },
            { "quitmsg", &NoNetwork::setQuitMsg },
        };
        TOption<bool> BoolOptions[] = {
            { "ircconnectenabled", &NoNetwork::setEnabled },
        };
        TOption<double> DoubleOptions[] = {
            { "floodrate", &NoNetwork::setFloodRate },
        };
        TOption<ushort> SUIntOptions[] = {
            { "floodburst", &NoNetwork::setFloodBurst }, { "joindelay", &NoNetwork::setJoinDelay },
        };

        for (const auto& Option : StringOptions) {
            NoString value;
            if (settings->FindStringEntry(Option.name, value))
                (this->*Option.pSetter)(value);
        }

        for (const auto& Option : BoolOptions) {
            NoString value;
            if (settings->FindStringEntry(Option.name, value))
                (this->*Option.pSetter)(value.toBool());
        }

        for (const auto& Option : DoubleOptions) {
            double fValue;
            if (settings->FindDoubleEntry(Option.name, fValue))
                (this->*Option.pSetter)(fValue);
        }

        for (const auto& Option : SUIntOptions) {
            ushort value;
            if (settings->FindUShortEntry(Option.name, value))
                (this->*Option.pSetter)(value);
        }

        settings->FindStringVector("loadmodule", vsList);
        for (const NoString& value : vsList) {
            NoString name = No::token(value, 0);
            NoString notice = "Loading network module [" + name + "]";

            // XXX Legacy crap, added in ZNC 0.203, modified in 0.207
            // Note that 0.203 == 0.207
            if (name == "away") {
                notice = "NOTICE: [away] was renamed, loading [awaystore] instead";
                name = "awaystore";
            }

            // XXX Legacy crap, added in ZNC 0.207
            if (name == "autoaway") {
                notice = "NOTICE: [autoaway] was renamed, loading [awaystore] instead";
                name = "awaystore";
            }

            // XXX Legacy crap, added in 1.1; fakeonline module was dropped in 1.0 and returned in 1.1
            if (name == "fakeonline") {
                notice = "NOTICE: [fakeonline] was renamed, loading [modules_online] instead";
                name = "modules_online";
            }

            NoString sModRet;
            NoString args = No::tokens(value, 1);

            bool bModRet = loadModule(name, args, notice, sModRet);

            if (!bModRet) {
                // XXX The awaynick module was retired in 1.6 (still available as external module)
                if (name == "awaynick") {
                    // load simple_away instead, unless it's already on the list
                    if (std::find(vsList.begin(), vsList.end(), "simple_away") == vsList.end()) {
                        notice = "Loading network module [simple_away] instead";
                        name = "simple_away";
                        // not a fatal error if simple_away is not available
                        loadModule(name, args, notice, sModRet);
                    }
                } else {
                    error = sModRet;
                    return false;
                }
            }
        }
    }

    settings->FindStringVector("server", vsList);
    for (const NoString& sServer : vsList) {
        No::printAction("Adding server [" + sServer + "]");
        No::printStatus(addServer(sServer));
    }

    settings->FindStringVector("trustedserverfingerprint", vsList);
    for (const NoString& fingerprint : vsList) {
        addTrustedFingerprint(fingerprint);
    }

    settings->FindStringVector("chan", vsList);
    for (const NoString& sChan : vsList) {
        addChannel(sChan, true);
    }

    NoSettings::SubConfig subConf;
    NoSettings::SubConfig::const_iterator subIt;

    settings->FindSubConfig("chan", subConf);
    for (subIt = subConf.begin(); subIt != subConf.end(); ++subIt) {
        const NoString& sChanName = subIt->first;
        NoSettings* pSubConf = subIt->second.m_subConfig;
        NoChannel* channel = new NoChannel(sChanName, this, true, pSubConf);

        if (!pSubConf->empty()) {
            error = "Unhandled lines in config for User [" + d->user->userName() + "], network [" + name() +
                     "], channel [" + sChanName + "]!";
            No::printError(error);

            NoApp::dumpConfig(pSubConf);
            return false;
        }

        // Save the channel name, because addChannel
        // deletes the NoChannelnel*, if adding fails
        error = channel->name();
        if (!addChannel(channel)) {
            error = "channel [" + error + "] defined more than once";
            No::printError(error);
            return false;
        }
        error.clear();
    }

    return true;
}

NoSettings NoNetwork::toConfig() const
{
    NoSettings config;

    if (!d->nickName.empty()) {
        config.AddKeyValuePair("Nick", d->nickName);
    }

    if (!d->altNick.empty()) {
        config.AddKeyValuePair("AltNick", d->altNick);
    }

    if (!d->ident.empty()) {
        config.AddKeyValuePair("Ident", d->ident);
    }

    if (!d->realName.empty()) {
        config.AddKeyValuePair("RealName", d->realName);
    }
    if (!d->bindHost.empty()) {
        config.AddKeyValuePair("BindHost", d->bindHost);
    }

    config.AddKeyValuePair("IRCConnectEnabled", NoString(isEnabled()));
    config.AddKeyValuePair("FloodRate", NoString(floodRate()));
    config.AddKeyValuePair("FloodBurst", NoString(floodBurst()));
    config.AddKeyValuePair("JoinDelay", NoString(joinDelay()));
    config.AddKeyValuePair("Encoding", d->encoding);

    if (!d->quitMsg.empty()) {
        config.AddKeyValuePair("QuitMsg", d->quitMsg);
    }

    // Modules
    const NoModuleLoader* Mods = loader();

    for (NoModule* mod : Mods->modules()) {
        NoString args = mod->args();

        if (!args.empty()) {
            args = " " + args;
        }

        config.AddKeyValuePair("LoadModule", mod->moduleName() + args);
    }

    // Servers
    for (NoServerInfo* server : d->servers) {
        config.AddKeyValuePair("Server", server->toString());
    }

    for (const NoString& fingerprint : d->trustedFingerprints) {
        config.AddKeyValuePair("TrustedServerFingerprint", fingerprint);
    }

    // Chans
    for (NoChannel* channel : d->channels) {
        if (channel->inConfig()) {
            config.AddSubConfig("Channel", channel->name(), channel->toConfig());
        }
    }

    return config;
}

void NoNetwork::bounceAllClients()
{
    for (NoClient* client : d->clients) {
        client->bouncedOff();
    }

    d->clients.clear();
}

bool NoNetwork::isUserAttached() const
{
    return !d->clients.empty();
}

bool NoNetwork::isUserOnline() const
{
    for (NoClient* client : d->clients) {
        if (!client->isAway()) {
            return true;
        }
    }

    return false;
}

void NoNetwork::clientConnected(NoClient* client)
{
    if (!d->user->multiClients()) {
        bounceAllClients();
    }

    d->clients.push_back(client);

    size_t uIdx, uSize;

    client->setPlaybackActive(true);

    if (d->rawBuffer.isEmpty()) {
        client->putClient(":irc.znc.in 001 " + client->nick() + " :- Welcome to ZNC -");
    } else {
        const NoString& sClientNick = client->nick(false);
        NoStringMap msParams;
        msParams["target"] = sClientNick;

        uSize = d->rawBuffer.size();
        for (uIdx = 0; uIdx < uSize; uIdx++) {
            client->putClient(d->rawBuffer.message(uIdx, *client, msParams));
        }

        const NoNick& nick = ircNick();
        if (sClientNick != nick.nick()) { // case-sensitive match
            client->putClient(":" + sClientNick + "!" + nick.ident() + "@" + nick.host() + " NICK :" + nick.nick());
            client->setNick(nick.nick());
        }
    }

    NoStringMap msParams;
    msParams["target"] = ircNick().nick();

    // Send the cached MOTD
    uSize = d->motdBuffer.size();
    if (uSize > 0) {
        for (uIdx = 0; uIdx < uSize; uIdx++) {
            client->putClient(d->motdBuffer.message(uIdx, *client, msParams));
        }
    }

    if (ircSocket() != nullptr) {
        NoString sUserMode("");
        const std::set<uchar>& scUserModes = ircSocket()->userModes();
        for (uchar cMode : scUserModes) {
            sUserMode += cMode;
        }
        if (!sUserMode.empty()) {
            client->putClient(":" + ircNick().nickMask() + " MODE " + ircNick().nick() + " :+" + sUserMode);
        }
    }

    if (d->away) {
        // If they want to know their away reason they'll have to whois
        // themselves. At least we can tell them their away status...
        client->putClient(":irc.znc.in 306 " + ircNick().nick() + " :You have been marked as being away");
    }

    for (NoChannel* channel : d->channels) {
        if ((channel->isOn()) && (!channel->isDetached())) {
            channel->attachUser(client);
        }
    }

    bool bClearQuery = d->user->autoclearQueryBuffer();
    for (NoQuery* query : d->queries) {
        query->sendBuffer(client);
        if (bClearQuery) {
            delete query;
        }
    }
    if (bClearQuery) {
        d->queries.clear();
    }

    uSize = d->noticeBuffer.size();
    for (uIdx = 0; uIdx < uSize; uIdx++) {
        const NoMessage& BufLine = d->noticeBuffer.message(uIdx);
        NoString line = BufLine.formatted(*client, msParams);
        bool bContinue = false;
        NETWORKMODULECALL(onPrivBufferPlayLine2(*client, line, BufLine.timestamp()), d->user, this, nullptr, &bContinue);
        if (bContinue)
            continue;
        client->putClient(line);
    }
    d->noticeBuffer.clear();

    client->setPlaybackActive(false);

    // Tell them why they won't connect
    if (!isEnabled())
        client->putStatus("You are currently disconnected from IRC. "
                           "Use 'connect' to reconnect.");
}

void NoNetwork::clientDisconnected(NoClient* client)
{
    auto it = std::find(d->clients.begin(), d->clients.end(), client);
    if (it != d->clients.end()) {
        d->clients.erase(it);
    }
}

NoUser* NoNetwork::user() const
{
    return d->user;
}

NoString NoNetwork::name() const
{
    return d->name;
}

bool NoNetwork::isNetworkAttached() const
{
    return !d->clients.empty();
}
std::vector<NoClient*> NoNetwork::clients() const
{
    return d->clients;
}

std::vector<NoClient*> NoNetwork::findClients(const NoString& identifier) const
{
    std::vector<NoClient*> vClients;
    for (NoClient* client : d->clients) {
        if (client->identifier().equals(identifier)) {
            vClients.push_back(client);
        }
    }

    return vClients;
}

void NoNetwork::setUser(NoUser* user)
{
    for (NoClient* client : d->clients) {
        client->putStatus("This network is being deleted or moved to another user.");
        client->setNetwork(nullptr);
    }

    d->clients.clear();

    if (d->user) {
        d->user->removeNetwork(this);
    }

    d->user = user;
    if (d->user) {
        d->user->addNetwork(this);
    }
}

bool NoNetwork::setName(const NoString& name)
{
    if (isValidNetwork(name)) {
        d->name = name;
        return true;
    }

    return false;
}

NoModuleLoader* NoNetwork::loader() const
{
    return d->modules;
}

bool NoNetwork::putUser(const NoString& line, NoClient* client, NoClient* skipClient)
{
    for (NoClient* pEachClient : d->clients) {
        if ((!client || client == pEachClient) && skipClient != pEachClient) {
            pEachClient->putClient(line);

            if (client) {
                return true;
            }
        }
    }

    return (client == nullptr);
}

bool NoNetwork::putStatus(const NoString& line, NoClient* client, NoClient* skipClient)
{
    for (NoClient* pEachClient : d->clients) {
        if ((!client || client == pEachClient) && skipClient != pEachClient) {
            pEachClient->putStatus(line);

            if (client) {
                return true;
            }
        }
    }

    return (client == nullptr);
}

bool NoNetwork::putModule(const NoString& module, const NoString& line, NoClient* client, NoClient* skipClient)
{
    for (NoClient* pEachClient : d->clients) {
        if ((!client || client == pEachClient) && skipClient != pEachClient) {
            pEachClient->putModule(module, line);

            if (client) {
                return true;
            }
        }
    }

    return (client == nullptr);
}

// Channels

std::vector<NoChannel*> NoNetwork::channels() const
{
    return d->channels;
}

NoChannel* NoNetwork::findChannel(NoString name) const
{
    if (ircSocket()) {
        // See https://tools.ietf.org/html/draft-brocklesby-irc-isupport-03#section-3.16
        name.trimLeft(ircSocket()->isupport("STATUSMSG", ""));
    }

    for (NoChannel* channel : d->channels) {
        if (name.equals(channel->name())) {
            return channel;
        }
    }

    return nullptr;
}

std::vector<NoChannel*> NoNetwork::findChannels(const NoString& wild) const
{
    std::vector<NoChannel*> channels;
    channels.reserve(d->channels.size());
    for (NoChannel* channel : d->channels) {
        if (No::wildCmp(channel->name(), wild, No::CaseInsensitive))
            channels.push_back(channel);
    }
    return channels;
}

bool NoNetwork::addChannel(NoChannel* channel)
{
    if (!channel) {
        return false;
    }

    for (NoChannel* pEachChan : d->channels) {
        if (pEachChan->name().equals(channel->name())) {
            delete channel;
            return false;
        }
    }

    d->channels.push_back(channel);
    return true;
}

bool NoNetwork::addChannel(const NoString& name, bool bInConfig)
{
    if (name.empty() || findChannel(name)) {
        return false;
    }

    NoChannel* channel = new NoChannel(name, this, bInConfig);
    d->channels.push_back(channel);
    return true;
}

bool NoNetwork::removeChannel(const NoString& name)
{
    for (std::vector<NoChannel*>::iterator a = d->channels.begin(); a != d->channels.end(); ++a) {
        if (name.equals((*a)->name())) {
            delete *a;
            d->channels.erase(a);
            return true;
        }
    }

    return false;
}

void NoNetwork::joinChannels()
{
    // Avoid divsion by zero, it's bad!
    if (d->channels.empty())
        return;

    // We start at a random offset into the channel list so that if your
    // first 3 channels are invite-only and you got MaxJoins == 3, ZNC will
    // still be able to join the rest of your channels.
    uint start = rand() % d->channels.size();
    uint uJoins = d->user->maxJoins();
    std::set<NoChannel*> sChans;
    for (uint a = 0; a < d->channels.size(); a++) {
        uint idx = (start + a) % d->channels.size();
        NoChannel* channel = d->channels[idx];
        if (!channel->isOn() && !channel->isDisabled()) {
            if (!joinChan(channel))
                continue;

            sChans.insert(channel);

            // Limit the number of joins
            if (uJoins != 0 && --uJoins == 0) {
                // Reset the timer.
                d->joinTimer->Reset();
                break;
            }
        }
    }

    while (!sChans.empty())
        joinChannels(sChans);
}

void NoNetwork::joinChannels(std::set<NoChannel*>& sChans)
{
    NoString sKeys, sJoin;
    bool bHaveKey = false;
    size_t uiJoinLength = strlen("JOIN ");

    while (!sChans.empty()) {
        std::set<NoChannel*>::iterator it = sChans.begin();
        const NoString& name = (*it)->name();
        const NoString& key = (*it)->key();
        size_t len = name.length() + key.length();
        len += 2; // two comma

        if (!sKeys.empty() && uiJoinLength + len >= 512)
            break;

        if (!sJoin.empty()) {
            sJoin += ",";
            sKeys += ",";
        }
        uiJoinLength += len;
        sJoin += name;
        if (!key.empty()) {
            sKeys += key;
            bHaveKey = true;
        }
        sChans.erase(it);
    }

    if (bHaveKey)
        putIrc("JOIN " + sJoin + " " + sKeys);
    else
        putIrc("JOIN " + sJoin);
}

bool NoNetwork::joinChan(NoChannel* channel)
{
    bool bReturn = false;
    NETWORKMODULECALL(onJoining(*channel), d->user, this, nullptr, &bReturn);

    if (bReturn)
        return false;

    if (d->user->joinTries() != 0 && channel->joinTries() >= d->user->joinTries()) {
        putStatus("The channel " + channel->name() + " could not be joined, disabling it.");
        channel->disable();
    } else {
        channel->incJoinTries();
        bool bFailed = false;
        NETWORKMODULECALL(onTimerAutoJoin(*channel), d->user, this, nullptr, &bFailed);
        if (bFailed)
            return false;
        return true;
    }
    return false;
}

NoString NoNetwork::channelPrefixes() const
{
    return d->chanPrefixes;
}
void NoNetwork::setChannelPrefixes(const NoString& s)
{
    d->chanPrefixes = s;
}

bool NoNetwork::isChannel(const NoString& sChan) const
{
    if (sChan.empty())
        return false; // There is no way this is a chan
    if (channelPrefixes().empty())
        return true; // We can't know, so we allow everything
    // Thanks to the above if (empty), we can do sChan[0]
    return channelPrefixes().contains(sChan[0]);
}

// Queries

std::vector<NoQuery*> NoNetwork::queries() const
{
    return d->queries;
}

NoQuery* NoNetwork::findQuery(const NoString& name) const
{
    for (NoQuery* query : d->queries) {
        if (name.equals(query->name())) {
            return query;
        }
    }

    return nullptr;
}

std::vector<NoQuery*> NoNetwork::findQueries(const NoString& wild) const
{
    std::vector<NoQuery*> vQueries;
    vQueries.reserve(d->queries.size());
    for (NoQuery* query : d->queries) {
        if (No::wildCmp(query->name(), wild, No::CaseInsensitive))
            vQueries.push_back(query);
    }
    return vQueries;
}

NoQuery* NoNetwork::addQuery(const NoString& name)
{
    if (name.empty()) {
        return nullptr;
    }

    NoQuery* query = findQuery(name);
    if (!query) {
        query = new NoQuery(name, this);
        d->queries.push_back(query);

        if (d->user->maxQueryBuffers() > 0) {
            while (d->queries.size() > d->user->maxQueryBuffers()) {
                delete *d->queries.begin();
                d->queries.erase(d->queries.begin());
            }
        }
    }

    return query;
}

bool NoNetwork::removeQuery(const NoString& name)
{
    for (std::vector<NoQuery*>::iterator a = d->queries.begin(); a != d->queries.end(); ++a) {
        if (name.equals((*a)->name())) {
            delete *a;
            d->queries.erase(a);
            return true;
        }
    }

    return false;
}

// Server list

std::vector<NoServerInfo*> NoNetwork::servers() const
{
    return d->servers;
}

bool NoNetwork::hasServers() const
{
    return !d->servers.empty();
}

NoServerInfo* NoNetwork::findServer(const NoString& name) const
{
    for (NoServerInfo* server : d->servers) {
        if (name.equals(server->host())) {
            return server;
        }
    }

    return nullptr;
}

bool NoNetwork::removeServer(const NoString& name, ushort port, const NoString& pass)
{
    if (name.empty()) {
        return false;
    }

    uint a = 0;
    bool bSawCurrentServer = false;
    NoServerInfo* pCurServer = currentServer();

    for (std::vector<NoServerInfo*>::iterator it = d->servers.begin(); it != d->servers.end(); ++it, a++) {
        NoServerInfo* server = *it;

        if (server == pCurServer)
            bSawCurrentServer = true;

        if (!server->host().equals(name))
            continue;

        if (port != 0 && server->port() != port)
            continue;

        if (!pass.empty() && server->password() != pass)
            continue;

        d->servers.erase(it);

        if (server == pCurServer) {
            NoIrcSocket* socket = ircSocket();

            // Make sure we don't skip the next server in the list!
            if (d->serverIndex) {
                d->serverIndex--;
            }

            if (socket) {
                socket->quit();
                putStatus("Your current server was removed, jumping...");
            }
        } else if (!bSawCurrentServer) {
            // Our current server comes after the server which we
            // are removing. This means that it now got a different
            // index in d->vServers!
            d->serverIndex--;
        }

        delete server;

        return true;
    }

    return false;
}

bool NoNetwork::addServer(const NoString& name)
{
    if (name.empty()) {
        return false;
    }

    bool ssl = false;
    NoString line = name;
    line.trim();

    NoString host = No::token(line, 0);
    NoString port = No::token(line, 1);
    NoString pass = No::tokens(line, 2);

    if (port.left(1) == "+") {
        ssl = true;
        port.leftChomp(1);
    }

    return addServer(host, port.toUShort(), pass, ssl);
}

bool NoNetwork::addServer(const NoString& name, ushort port, const NoString& pass, bool ssl)
{
#ifndef HAVE_LIBSSL
    if (ssl) {
        return false;
    }
#endif

    if (name.empty()) {
        return false;
    }

    if (!port) {
        port = 6667;
    }

    // Check if server is already added
    for (NoServerInfo* server : d->servers) {
        if (!name.equals(server->host()))
            continue;

        if (port != server->port())
            continue;

        if (pass != server->password())
            continue;

        if (ssl != server->isSsl())
            continue;

        // Server is already added
        return false;
    }

    NoServerInfo* server = new NoServerInfo(name, port);
    server->setPassword(pass);
    server->setSsl(ssl);
    d->servers.push_back(server);

    checkIrcConnect();

    return true;
}

NoServerInfo* NoNetwork::nextServer()
{
    if (d->servers.empty()) {
        return nullptr;
    }

    if (d->serverIndex >= d->servers.size()) {
        d->serverIndex = 0;
    }

    return d->servers[d->serverIndex++];
}

NoServerInfo* NoNetwork::currentServer() const
{
    size_t uIdx = (d->serverIndex) ? d->serverIndex - 1 : 0;

    if (uIdx >= d->servers.size()) {
        return nullptr;
    }

    return d->servers[uIdx];
}

void NoNetwork::setIrcServer(const NoString& s)
{
    d->server = s;
}

bool NoNetwork::setNextServer(const NoServerInfo* server)
{
    for (uint a = 0; a < d->servers.size(); a++) {
        if (d->servers[a] == server) {
            d->serverIndex = a;
            return true;
        }
    }

    return false;
}

bool NoNetwork::isLastServer() const
{
    return (d->serverIndex >= d->servers.size());
}

NoStringSet NoNetwork::trustedFingerprints() const
{
    return d->trustedFingerprints;
}
void NoNetwork::addTrustedFingerprint(const NoString& fingerprint)
{
    d->trustedFingerprints.insert(No::escape(fingerprint, No::HexColonFormat, No::HexColonFormat));
}
void NoNetwork::removeTrustedFingerprint(const NoString& fingerprint)
{
    d->trustedFingerprints.erase(fingerprint);
}

NoIrcSocket* NoNetwork::ircSocket() const
{
    return d->socket;
}
NoString NoNetwork::ircServer() const
{
    return d->server;
}
NoNick NoNetwork::ircNick() const
{
    return d->ircNick;
}

void NoNetwork::setIrcNick(const NoNick& n)
{
    d->ircNick = n;

    for (NoClient* client : d->clients) {
        client->setNick(n.nick());
    }
}

NoString NoNetwork::currentNick() const
{
    const NoIrcSocket* socket = ircSocket();

    if (socket) {
        return socket->nick();
    }

    if (!d->clients.empty()) {
        return d->clients[0]->nick();
    }

    return "";
}

bool NoNetwork::isIrcAway() const
{
    return d->away;
}
void NoNetwork::setIrcAway(bool b)
{
    d->away = b;
}

bool NoNetwork::connect()
{
    if (!isEnabled() || d->socket || !hasServers())
        return false;

    NoServerInfo* server = nextServer();
    if (!server)
        return false;

    if (noApp->serverThrottle(server->host())) {
        // Can't connect right now, schedule retry later
        noApp->addNetworkToQueue(this);
        return false;
    }

    noApp->addServerThrottle(server->host());

    bool ssl = server->isSsl();
#ifndef HAVE_LIBSSL
    if (ssl) {
        putStatus("Cannot connect to [" + server->GetString(false) + "], ZNC is not compiled with SSL.");
        noApp->AddNetworkToQueue(this);
        return false;
    }
#endif

    NoIrcSocket* socket = new NoIrcSocket(this);
    socket->setPassword(server->password());
    socket->setTrustedFingerprints(d->trustedFingerprints);

    NO_DEBUG("Connecting user/network [" << d->user->userName() << "/" << d->name << "]");

    bool bAbort = false;
    NETWORKMODULECALL(onIrcConnecting(socket), d->user, this, nullptr, &bAbort);
    if (bAbort) {
        NO_DEBUG("Some module aborted the connection attempt");
        putStatus("Some module aborted the connection attempt");
        delete socket;
        noApp->addNetworkToQueue(this);
        return false;
    }

    NoString sSockName = "IRC::" + d->user->userName() + "::" + d->name;
    noApp->manager()->connect(server->host(), server->port(), sSockName, 120, ssl, bindHost(), socket);

    return true;
}

bool NoNetwork::isIrcConnected() const
{
    const NoIrcSocket* socket = ircSocket();
    return (socket && socket->isAuthed());
}

void NoNetwork::setIrcSocket(NoIrcSocket* socket)
{
    d->socket = socket;
}

void NoNetwork::ircConnected()
{
    if (d->joinDelay > 0) {
        d->joinTimer->Delay(d->joinDelay);
    } else {
        joinChannels();
    }
}

void NoNetwork::ircDisconnected()
{
    d->socket = nullptr;

    setIrcServer("");
    d->away = false;

    // Get the reconnect going
    checkIrcConnect();
}

bool NoNetwork::isEnabled() const
{
    return d->enabled;
}

void NoNetwork::setEnabled(bool b)
{
    d->enabled = b;

    if (d->enabled) {
        checkIrcConnect();
    } else if (ircSocket()) {
        if (ircSocket()->isConnected()) {
            ircSocket()->quit();
        } else {
            ircSocket()->close();
        }
    }
}

void NoNetwork::checkIrcConnect()
{
    // Do we want to connect?
    if (isEnabled() && ircSocket() == nullptr)
        noApp->addNetworkToQueue(this);
}

bool NoNetwork::putIrc(const NoString& line)
{
    NoIrcSocket* socket = ircSocket();

    if (!socket) {
        return false;
    }

    socket->putIrc(line);
    return true;
}

void NoNetwork::addRawBuffer(const NoString& format, const NoString& text)
{
    d->rawBuffer.addMessage(format, text);
}
void NoNetwork::updateRawBuffer(const NoString& match, const NoString& format, const NoString& text)
{
    d->rawBuffer.updateMessage(match, format, text);
}
void NoNetwork::updateExactRawBuffer(const NoString& format, const NoString& text)
{
    d->rawBuffer.updateExactMessage(format, text);
}
void NoNetwork::clearRawBuffer()
{
    d->rawBuffer.clear();
}

void NoNetwork::addMotdBuffer(const NoString& format, const NoString& text)
{
    d->motdBuffer.addMessage(format, text);
}
void NoNetwork::updateMotdBuffer(const NoString& match, const NoString& format, const NoString& text)
{
    d->motdBuffer.updateMessage(match, format, text);
}
void NoNetwork::clearMotdBuffer()
{
    d->motdBuffer.clear();
}

void NoNetwork::addNoticeBuffer(const NoString& format, const NoString& text)
{
    d->noticeBuffer.addMessage(format, text);
}
void NoNetwork::updateNoticeBuffer(const NoString& match, const NoString& format, const NoString& text)
{
    d->noticeBuffer.updateMessage(match, format, text);
}
void NoNetwork::clearNoticeBuffer()
{
    d->noticeBuffer.clear();
}

void NoNetwork::clearQueryBuffer()
{
    std::for_each(d->queries.begin(), d->queries.end(), std::default_delete<NoQuery>());
    d->queries.clear();
}

NoString NoNetwork::nick(const bool allowDefault) const
{
    if (d->nickName.empty()) {
        return d->user->nick(allowDefault);
    }

    return d->nickName;
}

NoString NoNetwork::altNick(const bool allowDefault) const
{
    if (d->altNick.empty()) {
        return d->user->altNick(allowDefault);
    }

    return d->altNick;
}

NoString NoNetwork::ident(const bool allowDefault) const
{
    if (d->ident.empty()) {
        return d->user->ident(allowDefault);
    }

    return d->ident;
}

NoString NoNetwork::realName() const
{
    if (d->realName.empty()) {
        return d->user->realName();
    }

    return d->realName;
}

NoString NoNetwork::bindHost() const
{
    if (d->bindHost.empty()) {
        return d->user->bindHost();
    }

    return d->bindHost;
}

NoString NoNetwork::encoding() const
{
    return d->encoding;
}

NoString NoNetwork::quitMsg() const
{
    if (d->quitMsg.empty()) {
        return d->user->quitMsg();
    }

    return d->quitMsg;
}

void NoNetwork::setNick(const NoString& s)
{
    if (d->user->nick().equals(s)) {
        d->nickName = "";
    } else {
        d->nickName = s;
    }
}

void NoNetwork::setAltNick(const NoString& s)
{
    if (d->user->altNick().equals(s)) {
        d->altNick = "";
    } else {
        d->altNick = s;
    }
}

void NoNetwork::setIdent(const NoString& s)
{
    if (d->user->ident().equals(s)) {
        d->ident = "";
    } else {
        d->ident = s;
    }
}

void NoNetwork::setRealName(const NoString& s)
{
    if (d->user->realName().equals(s)) {
        d->realName = "";
    } else {
        d->realName = s;
    }
}

void NoNetwork::setBindHost(const NoString& s)
{
    if (d->user->bindHost().equals(s)) {
        d->bindHost = "";
    } else {
        d->bindHost = s;
    }
}

void NoNetwork::setEncoding(const NoString& s)
{
    d->encoding = s;
}

void NoNetwork::setQuitMsg(const NoString& s)
{
    if (d->user->quitMsg().equals(s)) {
        d->quitMsg = "";
    } else {
        d->quitMsg = s;
    }
}

double NoNetwork::floodRate() const
{
    return d->floodRate;
}
ushort NoNetwork::floodBurst() const
{
    return d->floodBurst;
}
void NoNetwork::setFloodRate(double fFloodRate)
{
    d->floodRate = fFloodRate;
}
void NoNetwork::setFloodBurst(ushort uFloodBurst)
{
    d->floodBurst = uFloodBurst;
}

ushort NoNetwork::joinDelay() const
{
    return d->joinDelay;
}
void NoNetwork::setJoinDelay(ushort uJoinDelay)
{
    d->joinDelay = uJoinDelay;
}

NoString NoNetwork::expandString(const NoString& str) const
{
    NoString ret;
    return expandString(str, ret);
}

NoString& NoNetwork::expandString(const NoString& str, NoString& ret) const
{
    ret = str;
    ret.replace("%defnick%", nick());
    ret.replace("%nick%", currentNick());
    ret.replace("%altnick%", altNick());
    ret.replace("%ident%", ident());
    ret.replace("%realname%", realName());
    ret.replace("%bindhost%", bindHost());

    return d->user->expandString(ret, ret);
}

bool NoNetwork::loadModule(const NoString& name, const NoString& args, const NoString& notice, NoString& error)
{
    No::printAction(notice);
    NoString sModRet;

    bool bModRet = loader()->loadModule(name, args, No::NetworkModule, user(), this, sModRet);

    No::printStatus(bModRet, sModRet);
    if (!bModRet) {
        error = sModRet;
    }
    return bModRet;
}
