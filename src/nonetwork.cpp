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
#include "nonick.h"
#include "nobuffer.h"
#include "Csocket/Csocket.h"
#include <algorithm>
#include <memory>

class NoNetworkPingTimer : public CCron
{
public:
    NoNetworkPingTimer(NoNetwork* pNetwork) : CCron(), m_pNetwork(pNetwork)
    {
        SetName("NoNetworkPingTimer::" + m_pNetwork->user()->userName() + "::" + m_pNetwork->name());
        Start(NoNetwork::PingSlack);
    }

    NoNetworkPingTimer(const NoNetworkPingTimer&) = delete;
    NoNetworkPingTimer& operator=(const NoNetworkPingTimer&) = delete;

protected:
    void RunJob() override
    {
        NoIrcSocket* pIRCSock = m_pNetwork->ircSocket();

        if (pIRCSock && pIRCSock->GetTimeSinceLastDataTransaction() >= NoNetwork::PingFrequency) {
            pIRCSock->PutIRC("PING :ZNC");
        }

        const std::vector<NoClient*>& vClients = m_pNetwork->clients();
        for (NoClient* pClient : vClients) {
            if (pClient->GetSocket()->GetTimeSinceLastDataTransaction() >= NoNetwork::PingFrequency) {
                pClient->PutClient("PING :ZNC");
            }
        }
    }

private:
    NoNetwork* m_pNetwork;
};

class NoNetworkJoinTimer : public CCron
{
public:
    NoNetworkJoinTimer(NoNetwork* pNetwork) : CCron(), m_bDelayed(false), m_pNetwork(pNetwork)
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

NoNetwork::NoNetwork(NoUser* pUser, const NoString& sName) : d(new NoNetworkPrivate)
{
    d->name = sName;
    d->modules = new NoModuleLoader;

    setUser(pUser);

    d->rawBuffer.setLimit(100, true); // This should be more than enough raws, especially since we are buffering the
    // MOTD separately
    d->motdBuffer.setLimit(200, true); // This should be more than enough motd lines
    d->noticeBuffer.setLimit(250, true);

    d->pingTimer = new NoNetworkPingTimer(this);
    NoApp::Get().GetManager().AddCron(d->pingTimer);

    d->joinTimer = new NoNetworkJoinTimer(this);
    NoApp::Get().GetManager().AddCron(d->joinTimer);

    setEnabled(true);
}

NoNetwork::NoNetwork(NoUser* pUser, const NoNetwork& Network) : NoNetwork(pUser, "") { clone(Network); }

void NoNetwork::clone(const NoNetwork& Network, bool bCloneName)
{
    if (bCloneName) {
        d->name = Network.name();
    }

    d->floodRate = Network.floodRate();
    d->floodBurst = Network.floodBurst();
    d->joinDelay = Network.joinDelay();

    setNick(Network.nick());
    setAltNick(Network.altNick());
    setIdent(Network.ident());
    setRealName(Network.realName());
    setBindHost(Network.bindHost());
    setEncoding(Network.encoding());
    setQuitMsg(Network.quitMsg());
    d->trustedFingerprints = Network.d->trustedFingerprints;

    // Servers
    const std::vector<NoServerInfo*>& vServers = Network.servers();
    NoString sServer;
    NoServerInfo* pCurServ = currentServer();

    if (pCurServ) {
        sServer = pCurServ->host();
    }

    delServers();

    for (NoServerInfo* pServer : vServers) {
        addServer(pServer->host(), pServer->port(), pServer->password(), pServer->isSsl());
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
        NoIrcSocket* pSock = ircSocket();

        if (pSock) {
            putStatus("Jumping servers because this server is no longer in the list");
            pSock->Quit();
        }
    }
    // !Servers

    // Chans
    const std::vector<NoChannel*>& vChans = Network.channels();
    for (NoChannel* pNewChan : vChans) {
        NoChannel* pChan = findChannel(pNewChan->name());

        if (pChan) {
            pChan->setInConfig(pNewChan->inConfig());
        } else {
            addChannel(pNewChan->name(), pNewChan->inConfig());
        }
    }

    for (NoChannel* pChan : d->channels) {
        NoChannel* pNewChan = Network.findChannel(pChan->name());

        if (!pNewChan) {
            pChan->setInConfig(false);
        } else {
            pChan->clone(*pNewChan);
        }
    }
    // !Chans

    // Modules
    std::set<NoString> ssUnloadMods;
    NoModuleLoader* vCurMods = loader();
    const NoModuleLoader* vNewMods = Network.loader();

    for (NoModule* pNewMod : vNewMods->modules()) {
        NoString sModRet;
        NoModule* pCurMod = vCurMods->findModule(pNewMod->GetModName());

        if (!pCurMod) {
            vCurMods->loadModule(pNewMod->GetModName(), pNewMod->GetArgs(), No::NetworkModule, d->user, this, sModRet);
        } else if (pNewMod->GetArgs() != pCurMod->GetArgs()) {
            vCurMods->reloadModule(pNewMod->GetModName(), pNewMod->GetArgs(), d->user, this, sModRet);
        }
    }

    for (NoModule* pCurMod : vCurMods->modules()) {
        NoModule* pNewMod = vNewMods->findModule(pCurMod->GetModName());

        if (!pNewMod) {
            ssUnloadMods.insert(pCurMod->GetModName());
        }
    }

    for (const NoString& sMod : ssUnloadMods) {
        vCurMods->unloadModule(sMod);
    }
    // !Modules

    setEnabled(Network.isEnabled());
}

NoNetwork::~NoNetwork()
{
    if (d->socket) {
        NoApp::Get().GetManager().DelSockByAddr(d->socket);
        d->socket = nullptr;
    }

    // Delete clients
    while (!d->clients.empty()) {
        NoApp::Get().GetManager().DelSockByAddr(d->clients[0]->GetSocket());
    }
    d->clients.clear();

    // Delete servers
    delServers();

    // Delete modules (this unloads all modules)
    delete d->modules;
    d->modules = nullptr;

    // Delete Channels
    for (NoChannel* pChan : d->channels) {
        delete pChan;
    }
    d->channels.clear();

    // Delete Queries
    for (NoQuery* pQuery : d->queries) {
        delete pQuery;
    }
    d->queries.clear();

    setUser(nullptr);

    // Make sure we are not in the connection queue
    NoApp::Get().GetConnectionQueue().remove(this);

    NoApp::Get().GetManager().DelCronByAddr(d->pingTimer);
    NoApp::Get().GetManager().DelCronByAddr(d->joinTimer);
}

void NoNetwork::delServers()
{
    for (NoServerInfo* pServer : d->servers) {
        delete pServer;
    }
    d->servers.clear();
}

NoString NoNetwork::networkPath() const
{
    NoString sNetworkPath = d->user->userPath() + "/networks/" + d->name;

    if (!NoFile::Exists(sNetworkPath)) {
        NoDir::MakeDir(sNetworkPath);
    }

    return sNetworkPath;
}

template <class T> struct TOption
{
    const char* name;
    void (NoNetwork::*pSetter)(T);
};

bool NoNetwork::parseConfig(NoSettings* pConfig, NoString& sError, bool bUpgrade)
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
            NoString sValue;
            if (pConfig->FindStringEntry(Option.name, sValue)) (this->*Option.pSetter)(sValue);
        }

        for (const auto& Option : BoolOptions) {
            NoString sValue;
            if (pConfig->FindStringEntry(Option.name, sValue)) (this->*Option.pSetter)(sValue.toBool());
        }

        for (const auto& Option : DoubleOptions) {
            double fValue;
            if (pConfig->FindDoubleEntry(Option.name, fValue)) (this->*Option.pSetter)(fValue);
        }

        for (const auto& Option : SUIntOptions) {
            ushort value;
            if (pConfig->FindUShortEntry(Option.name, value)) (this->*Option.pSetter)(value);
        }

        pConfig->FindStringVector("loadmodule", vsList);
        for (const NoString& sValue : vsList) {
            NoString sModName = No::token(sValue, 0);
            NoString sNotice = "Loading network module [" + sModName + "]";

            // XXX Legacy crap, added in ZNC 0.203, modified in 0.207
            // Note that 0.203 == 0.207
            if (sModName == "away") {
                sNotice = "NOTICE: [away] was renamed, loading [awaystore] instead";
                sModName = "awaystore";
            }

            // XXX Legacy crap, added in ZNC 0.207
            if (sModName == "autoaway") {
                sNotice = "NOTICE: [autoaway] was renamed, loading [awaystore] instead";
                sModName = "awaystore";
            }

            // XXX Legacy crap, added in 1.1; fakeonline module was dropped in 1.0 and returned in 1.1
            if (sModName == "fakeonline") {
                sNotice = "NOTICE: [fakeonline] was renamed, loading [modules_online] instead";
                sModName = "modules_online";
            }

            NoString sModRet;
            NoString sArgs = No::tokens(sValue, 1);

            bool bModRet = loadModule(sModName, sArgs, sNotice, sModRet);

            if (!bModRet) {
                // XXX The awaynick module was retired in 1.6 (still available as external module)
                if (sModName == "awaynick") {
                    // load simple_away instead, unless it's already on the list
                    if (std::find(vsList.begin(), vsList.end(), "simple_away") == vsList.end()) {
                        sNotice = "Loading network module [simple_away] instead";
                        sModName = "simple_away";
                        // not a fatal error if simple_away is not available
                        loadModule(sModName, sArgs, sNotice, sModRet);
                    }
                } else {
                    sError = sModRet;
                    return false;
                }
            }
        }
    }

    pConfig->FindStringVector("server", vsList);
    for (const NoString& sServer : vsList) {
        No::printAction("Adding server [" + sServer + "]");
        No::printStatus(addServer(sServer));
    }

    pConfig->FindStringVector("trustedserverfingerprint", vsList);
    for (const NoString& sFP : vsList) {
        addTrustedFingerprint(sFP);
    }

    pConfig->FindStringVector("chan", vsList);
    for (const NoString& sChan : vsList) {
        addChannel(sChan, true);
    }

    NoSettings::SubConfig subConf;
    NoSettings::SubConfig::const_iterator subIt;

    pConfig->FindSubConfig("chan", subConf);
    for (subIt = subConf.begin(); subIt != subConf.end(); ++subIt) {
        const NoString& sChanName = subIt->first;
        NoSettings* pSubConf = subIt->second.m_subConfig;
        NoChannel* pChan = new NoChannel(sChanName, this, true, pSubConf);

        if (!pSubConf->empty()) {
            sError = "Unhandled lines in config for User [" + d->user->userName() + "], Network [" + name() +
                     "], Channel [" + sChanName + "]!";
            No::printError(sError);

            NoApp::DumpConfig(pSubConf);
            return false;
        }

        // Save the channel name, because addChannel
        // deletes the NoChannelnel*, if adding fails
        sError = pChan->name();
        if (!addChannel(pChan)) {
            sError = "Channel [" + sError + "] defined more than once";
            No::printError(sError);
            return false;
        }
        sError.clear();
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

    for (NoModule* pMod : Mods->modules()) {
        NoString sArgs = pMod->GetArgs();

        if (!sArgs.empty()) {
            sArgs = " " + sArgs;
        }

        config.AddKeyValuePair("LoadModule", pMod->GetModName() + sArgs);
    }

    // Servers
    for (NoServerInfo* pServer : d->servers) {
        config.AddKeyValuePair("Server", pServer->toString());
    }

    for (const NoString& sFP : d->trustedFingerprints) {
        config.AddKeyValuePair("TrustedServerFingerprint", sFP);
    }

    // Chans
    for (NoChannel* pChan : d->channels) {
        if (pChan->inConfig()) {
            config.AddSubConfig("Chan", pChan->name(), pChan->toConfig());
        }
    }

    return config;
}

void NoNetwork::bounceAllClients()
{
    for (NoClient* pClient : d->clients) {
        pClient->BouncedOff();
    }

    d->clients.clear();
}

bool NoNetwork::isUserAttached() const { return !d->clients.empty(); }

bool NoNetwork::isUserOnline() const
{
    for (NoClient* pClient : d->clients) {
        if (!pClient->IsAway()) {
            return true;
        }
    }

    return false;
}

void NoNetwork::clientConnected(NoClient* pClient)
{
    if (!d->user->multiClients()) {
        bounceAllClients();
    }

    d->clients.push_back(pClient);

    size_t uIdx, uSize;

    pClient->SetPlaybackActive(true);

    if (d->rawBuffer.isEmpty()) {
        pClient->PutClient(":irc.znc.in 001 " + pClient->GetNick() + " :- Welcome to ZNC -");
    } else {
        const NoString& sClientNick = pClient->GetNick(false);
        NoStringMap msParams;
        msParams["target"] = sClientNick;

        uSize = d->rawBuffer.size();
        for (uIdx = 0; uIdx < uSize; uIdx++) {
            pClient->PutClient(d->rawBuffer.getMessage(uIdx, *pClient, msParams));
        }

        const NoNick& Nick = ircNick();
        if (sClientNick != Nick.nick()) { // case-sensitive match
            pClient->PutClient(":" + sClientNick + "!" + Nick.ident() + "@" + Nick.host() + " NICK :" + Nick.nick());
            pClient->SetNick(Nick.nick());
        }
    }

    NoStringMap msParams;
    msParams["target"] = ircNick().nick();

    // Send the cached MOTD
    uSize = d->motdBuffer.size();
    if (uSize > 0) {
        for (uIdx = 0; uIdx < uSize; uIdx++) {
            pClient->PutClient(d->motdBuffer.getMessage(uIdx, *pClient, msParams));
        }
    }

    if (ircSocket() != nullptr) {
        NoString sUserMode("");
        const std::set<uchar>& scUserModes = ircSocket()->GetUserModes();
        for (uchar cMode : scUserModes) {
            sUserMode += cMode;
        }
        if (!sUserMode.empty()) {
            pClient->PutClient(":" + ircNick().nickMask() + " MODE " + ircNick().nick() + " :+" + sUserMode);
        }
    }

    if (d->away) {
        // If they want to know their away reason they'll have to whois
        // themselves. At least we can tell them their away status...
        pClient->PutClient(":irc.znc.in 306 " + ircNick().nick() + " :You have been marked as being away");
    }

    const std::vector<NoChannel*>& vChans = channels();
    for (NoChannel* pChan : vChans) {
        if ((pChan->isOn()) && (!pChan->isDetached())) {
            pChan->attachUser(pClient);
        }
    }

    bool bClearQuery = d->user->autoclearQueryBuffer();
    for (NoQuery* pQuery : d->queries) {
        pQuery->sendBuffer(pClient);
        if (bClearQuery) {
            delete pQuery;
        }
    }
    if (bClearQuery) {
        d->queries.clear();
    }

    uSize = d->noticeBuffer.size();
    for (uIdx = 0; uIdx < uSize; uIdx++) {
        const NoMessage& BufLine = d->noticeBuffer.getMessage(uIdx);
        NoString sLine = BufLine.formatted(*pClient, msParams);
        bool bContinue = false;
        NETWORKMODULECALL(onPrivBufferPlayLine2(*pClient, sLine, BufLine.timestamp()), d->user, this, nullptr, &bContinue);
        if (bContinue) continue;
        pClient->PutClient(sLine);
    }
    d->noticeBuffer.clear();

    pClient->SetPlaybackActive(false);

    // Tell them why they won't connect
    if (!isEnabled())
        pClient->PutStatus("You are currently disconnected from IRC. "
                           "Use 'connect' to reconnect.");
}

void NoNetwork::clientDisconnected(NoClient* pClient)
{
    auto it = std::find(d->clients.begin(), d->clients.end(), pClient);
    if (it != d->clients.end()) {
        d->clients.erase(it);
    }
}

NoUser* NoNetwork::user() const { return d->user; }

NoString NoNetwork::name() const { return d->name; }

bool NoNetwork::isNetworkAttached() const { return !d->clients.empty(); }
std::vector<NoClient*> NoNetwork::clients() const { return d->clients; }

std::vector<NoClient*> NoNetwork::findClients(const NoString& sIdentifier) const
{
    std::vector<NoClient*> vClients;
    for (NoClient* pClient : d->clients) {
        if (pClient->GetIdentifier().equals(sIdentifier)) {
            vClients.push_back(pClient);
        }
    }

    return vClients;
}

void NoNetwork::setUser(NoUser* pUser)
{
    for (NoClient* pClient : d->clients) {
        pClient->PutStatus("This network is being deleted or moved to another user.");
        pClient->SetNetwork(nullptr);
    }

    d->clients.clear();

    if (d->user) {
        d->user->removeNetwork(this);
    }

    d->user = pUser;
    if (d->user) {
        d->user->addNetwork(this);
    }
}

bool NoNetwork::setName(const NoString& sName)
{
    if (isValidNetwork(sName)) {
        d->name = sName;
        return true;
    }

    return false;
}

NoModuleLoader* NoNetwork::loader() const { return d->modules; }

bool NoNetwork::putUser(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    for (NoClient* pEachClient : d->clients) {
        if ((!pClient || pClient == pEachClient) && pSkipClient != pEachClient) {
            pEachClient->PutClient(sLine);

            if (pClient) {
                return true;
            }
        }
    }

    return (pClient == nullptr);
}

bool NoNetwork::putStatus(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    for (NoClient* pEachClient : d->clients) {
        if ((!pClient || pClient == pEachClient) && pSkipClient != pEachClient) {
            pEachClient->PutStatus(sLine);

            if (pClient) {
                return true;
            }
        }
    }

    return (pClient == nullptr);
}

bool NoNetwork::putModule(const NoString& sModule, const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    for (NoClient* pEachClient : d->clients) {
        if ((!pClient || pClient == pEachClient) && pSkipClient != pEachClient) {
            pEachClient->PutModule(sModule, sLine);

            if (pClient) {
                return true;
            }
        }
    }

    return (pClient == nullptr);
}

// Channels

std::vector<NoChannel*> NoNetwork::channels() const { return d->channels; }

NoChannel* NoNetwork::findChannel(NoString sName) const
{
    if (ircSocket()) {
        // See https://tools.ietf.org/html/draft-brocklesby-irc-isupport-03#section-3.16
        sName.trimLeft(ircSocket()->GetISupport("STATUSMSG", ""));
    }

    for (NoChannel* pChan : d->channels) {
        if (sName.equals(pChan->name())) {
            return pChan;
        }
    }

    return nullptr;
}

std::vector<NoChannel*> NoNetwork::findChannels(const NoString& sWild) const
{
    std::vector<NoChannel*> vChans;
    vChans.reserve(d->channels.size());
    for (NoChannel* pChan : d->channels) {
        if (No::wildCmp(pChan->name(), sWild, No::CaseInsensitive))
            vChans.push_back(pChan);
    }
    return vChans;
}

bool NoNetwork::addChannel(NoChannel* pChan)
{
    if (!pChan) {
        return false;
    }

    for (NoChannel* pEachChan : d->channels) {
        if (pEachChan->name().equals(pChan->name())) {
            delete pChan;
            return false;
        }
    }

    d->channels.push_back(pChan);
    return true;
}

bool NoNetwork::addChannel(const NoString& sName, bool bInConfig)
{
    if (sName.empty() || findChannel(sName)) {
        return false;
    }

    NoChannel* pChan = new NoChannel(sName, this, bInConfig);
    d->channels.push_back(pChan);
    return true;
}

bool NoNetwork::removeChannel(const NoString& sName)
{
    for (std::vector<NoChannel*>::iterator a = d->channels.begin(); a != d->channels.end(); ++a) {
        if (sName.equals((*a)->name())) {
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
    if (d->channels.empty()) return;

    // We start at a random offset into the channel list so that if your
    // first 3 channels are invite-only and you got MaxJoins == 3, ZNC will
    // still be able to join the rest of your channels.
    uint start = rand() % d->channels.size();
    uint uJoins = d->user->maxJoins();
    std::set<NoChannel*> sChans;
    for (uint a = 0; a < d->channels.size(); a++) {
        uint idx = (start + a) % d->channels.size();
        NoChannel* pChan = d->channels[idx];
        if (!pChan->isOn() && !pChan->isDisabled()) {
            if (!joinChan(pChan)) continue;

            sChans.insert(pChan);

            // Limit the number of joins
            if (uJoins != 0 && --uJoins == 0) {
                // Reset the timer.
                d->joinTimer->Reset();
                break;
            }
        }
    }

    while (!sChans.empty()) joinChannels(sChans);
}

void NoNetwork::joinChannels(std::set<NoChannel*>& sChans)
{
    NoString sKeys, sJoin;
    bool bHaveKey = false;
    size_t uiJoinLength = strlen("JOIN ");

    while (!sChans.empty()) {
        std::set<NoChannel*>::iterator it = sChans.begin();
        const NoString& sName = (*it)->name();
        const NoString& sKey = (*it)->key();
        size_t len = sName.length() + sKey.length();
        len += 2; // two comma

        if (!sKeys.empty() && uiJoinLength + len >= 512) break;

        if (!sJoin.empty()) {
            sJoin += ",";
            sKeys += ",";
        }
        uiJoinLength += len;
        sJoin += sName;
        if (!sKey.empty()) {
            sKeys += sKey;
            bHaveKey = true;
        }
        sChans.erase(it);
    }

    if (bHaveKey)
        putIrc("JOIN " + sJoin + " " + sKeys);
    else
        putIrc("JOIN " + sJoin);
}

bool NoNetwork::joinChan(NoChannel* pChan)
{
    bool bReturn = false;
    NETWORKMODULECALL(onJoining(*pChan), d->user, this, nullptr, &bReturn);

    if (bReturn) return false;

    if (d->user->joinTries() != 0 && pChan->joinTries() >= d->user->joinTries()) {
        putStatus("The channel " + pChan->name() + " could not be joined, disabling it.");
        pChan->disable();
    } else {
        pChan->incJoinTries();
        bool bFailed = false;
        NETWORKMODULECALL(onTimerAutoJoin(*pChan), d->user, this, nullptr, &bFailed);
        if (bFailed) return false;
        return true;
    }
    return false;
}

NoString NoNetwork::channelPrefixes() const { return d->chanPrefixes; }
void NoNetwork::setChannelPrefixes(const NoString& s) { d->chanPrefixes = s; }

bool NoNetwork::isChannel(const NoString& sChan) const
{
    if (sChan.empty()) return false; // There is no way this is a chan
    if (channelPrefixes().empty()) return true; // We can't know, so we allow everything
    // Thanks to the above if (empty), we can do sChan[0]
    return channelPrefixes().contains(sChan[0]);
}

// Queries

std::vector<NoQuery*> NoNetwork::queries() const { return d->queries; }

NoQuery* NoNetwork::findQuery(const NoString& sName) const
{
    for (NoQuery* pQuery : d->queries) {
        if (sName.equals(pQuery->name())) {
            return pQuery;
        }
    }

    return nullptr;
}

std::vector<NoQuery*> NoNetwork::findQueries(const NoString& sWild) const
{
    std::vector<NoQuery*> vQueries;
    vQueries.reserve(d->queries.size());
    for (NoQuery* pQuery : d->queries) {
        if (No::wildCmp(pQuery->name(), sWild, No::CaseInsensitive))
            vQueries.push_back(pQuery);
    }
    return vQueries;
}

NoQuery* NoNetwork::addQuery(const NoString& sName)
{
    if (sName.empty()) {
        return nullptr;
    }

    NoQuery* pQuery = findQuery(sName);
    if (!pQuery) {
        pQuery = new NoQuery(sName, this);
        d->queries.push_back(pQuery);

        if (d->user->maxQueryBuffers() > 0) {
            while (d->queries.size() > d->user->maxQueryBuffers()) {
                delete *d->queries.begin();
                d->queries.erase(d->queries.begin());
            }
        }
    }

    return pQuery;
}

bool NoNetwork::removeQuery(const NoString& sName)
{
    for (std::vector<NoQuery*>::iterator a = d->queries.begin(); a != d->queries.end(); ++a) {
        if (sName.equals((*a)->name())) {
            delete *a;
            d->queries.erase(a);
            return true;
        }
    }

    return false;
}

// Server list

std::vector<NoServerInfo*> NoNetwork::servers() const { return d->servers; }

bool NoNetwork::hasServers() const { return !d->servers.empty(); }

NoServerInfo* NoNetwork::findServer(const NoString& sName) const
{
    for (NoServerInfo* pServer : d->servers) {
        if (sName.equals(pServer->host())) {
            return pServer;
        }
    }

    return nullptr;
}

bool NoNetwork::removeServer(const NoString& sName, ushort uPort, const NoString& sPass)
{
    if (sName.empty()) {
        return false;
    }

    uint a = 0;
    bool bSawCurrentServer = false;
    NoServerInfo* pCurServer = currentServer();

    for (std::vector<NoServerInfo*>::iterator it = d->servers.begin(); it != d->servers.end(); ++it, a++) {
        NoServerInfo* pServer = *it;

        if (pServer == pCurServer) bSawCurrentServer = true;

        if (!pServer->host().equals(sName)) continue;

        if (uPort != 0 && pServer->port() != uPort) continue;

        if (!sPass.empty() && pServer->password() != sPass) continue;

        d->servers.erase(it);

        if (pServer == pCurServer) {
            NoIrcSocket* pIRCSock = ircSocket();

            // Make sure we don't skip the next server in the list!
            if (d->serverIndex) {
                d->serverIndex--;
            }

            if (pIRCSock) {
                pIRCSock->Quit();
                putStatus("Your current server was removed, jumping...");
            }
        } else if (!bSawCurrentServer) {
            // Our current server comes after the server which we
            // are removing. This means that it now got a different
            // index in d->vServers!
            d->serverIndex--;
        }

        delete pServer;

        return true;
    }

    return false;
}

bool NoNetwork::addServer(const NoString& sName)
{
    if (sName.empty()) {
        return false;
    }

    bool bSSL = false;
    NoString sLine = sName;
    sLine.trim();

    NoString sHost = No::token(sLine, 0);
    NoString sPort = No::token(sLine, 1);

    if (sPort.left(1) == "+") {
        bSSL = true;
        sPort.leftChomp(1);
    }

    ushort uPort = sPort.toUShort();
    NoString sPass = No::tokens(sLine, 2);

    return addServer(sHost, uPort, sPass, bSSL);
}

bool NoNetwork::addServer(const NoString& sName, ushort uPort, const NoString& sPass, bool bSSL)
{
#ifndef HAVE_LIBSSL
    if (bSSL) {
        return false;
    }
#endif

    if (sName.empty()) {
        return false;
    }

    if (!uPort) {
        uPort = 6667;
    }

    // Check if server is already added
    for (NoServerInfo* pServer : d->servers) {
        if (!sName.equals(pServer->host())) continue;

        if (uPort != pServer->port()) continue;

        if (sPass != pServer->password()) continue;

        if (bSSL != pServer->isSsl()) continue;

        // Server is already added
        return false;
    }

    NoServerInfo* pServer = new NoServerInfo(sName, uPort);
    pServer->setPassword(sPass);
    pServer->setSsl(bSSL);
    d->servers.push_back(pServer);

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

void NoNetwork::setIrcServer(const NoString& s) { d->server = s; }

bool NoNetwork::setNextServer(const NoServerInfo* pServer)
{
    for (uint a = 0; a < d->servers.size(); a++) {
        if (d->servers[a] == pServer) {
            d->serverIndex = a;
            return true;
        }
    }

    return false;
}

bool NoNetwork::isLastServer() const { return (d->serverIndex >= d->servers.size()); }

NoStringSet NoNetwork::trustedFingerprints() const { return d->trustedFingerprints; }
void NoNetwork::addTrustedFingerprint(const NoString& sFP)
{
    d->trustedFingerprints.insert(No::escape(sFP, No::HexColonFormat, No::HexColonFormat));
}
void NoNetwork::removeTrustedFingerprint(const NoString& sFP) { d->trustedFingerprints.erase(sFP); }

NoIrcSocket* NoNetwork::ircSocket() const { return d->socket; }
NoString NoNetwork::ircServer() const { return d->server; }
const NoNick& NoNetwork::ircNick() const { return d->ircNick; }

void NoNetwork::setIrcNick(const NoNick& n)
{
    d->ircNick = n;

    for (NoClient* pClient : d->clients) {
        pClient->SetNick(n.nick());
    }
}

NoString NoNetwork::currentNick() const
{
    const NoIrcSocket* pIRCSock = ircSocket();

    if (pIRCSock) {
        return pIRCSock->GetNick();
    }

    if (!d->clients.empty()) {
        return d->clients[0]->GetNick();
    }

    return "";
}

bool NoNetwork::isIrcAway() const { return d->away; }
void NoNetwork::setIrcAway(bool b) { d->away = b; }

bool NoNetwork::connect()
{
    if (!isEnabled() || d->socket || !hasServers()) return false;

    NoServerInfo* pServer = nextServer();
    if (!pServer) return false;

    if (NoApp::Get().GetServerThrottle(pServer->host())) {
        // Can't connect right now, schedule retry later
        NoApp::Get().AddNetworkToQueue(this);
        return false;
    }

    NoApp::Get().AddServerThrottle(pServer->host());

    bool bSSL = pServer->isSsl();
#ifndef HAVE_LIBSSL
    if (bSSL) {
        PutStatus("Cannot connect to [" + pServer->GetString(false) + "], ZNC is not compiled with SSL.");
        NoApp::Get().AddNetworkToQueue(this);
        return false;
    }
#endif

    NoIrcSocket* pIRCSock = new NoIrcSocket(this);
    pIRCSock->SetPass(pServer->password());
    pIRCSock->SetSSLTrustedPeerFingerprints(d->trustedFingerprints);

    NO_DEBUG("Connecting user/network [" << d->user->userName() << "/" << d->name << "]");

    bool bAbort = false;
    NETWORKMODULECALL(onIrcConnecting(pIRCSock), d->user, this, nullptr, &bAbort);
    if (bAbort) {
        NO_DEBUG("Some module aborted the connection attempt");
        putStatus("Some module aborted the connection attempt");
        delete pIRCSock;
        NoApp::Get().AddNetworkToQueue(this);
        return false;
    }

    NoString sSockName = "IRC::" + d->user->userName() + "::" + d->name;
    NoApp::Get().GetManager().Connect(pServer->host(), pServer->port(), sSockName, 120, bSSL, bindHost(), pIRCSock);

    return true;
}

bool NoNetwork::isIrcConnected() const
{
    const NoIrcSocket* pSock = ircSocket();
    return (pSock && pSock->IsAuthed());
}

void NoNetwork::setIrcSocket(NoIrcSocket* pIRCSock) { d->socket = pIRCSock; }

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

bool NoNetwork::isEnabled() const { return d->enabled; }

void NoNetwork::setEnabled(bool b)
{
    d->enabled = b;

    if (d->enabled) {
        checkIrcConnect();
    } else if (ircSocket()) {
        if (ircSocket()->IsConnected()) {
            ircSocket()->Quit();
        } else {
            ircSocket()->Close();
        }
    }
}

void NoNetwork::checkIrcConnect()
{
    // Do we want to connect?
    if (isEnabled() && ircSocket() == nullptr) NoApp::Get().AddNetworkToQueue(this);
}

bool NoNetwork::putIrc(const NoString& sLine)
{
    NoIrcSocket* pIRCSock = ircSocket();

    if (!pIRCSock) {
        return false;
    }

    pIRCSock->PutIRC(sLine);
    return true;
}

void NoNetwork::addRawBuffer(const NoString& sFormat, const NoString& sText) { d->rawBuffer.addMessage(sFormat, sText); }
void NoNetwork::updateRawBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText)
{
    d->rawBuffer.updateMessage(sMatch, sFormat, sText);
}
void NoNetwork::updateExactRawBuffer(const NoString& sFormat, const NoString& sText)
{
    d->rawBuffer.updateExactMessage(sFormat, sText);
}
void NoNetwork::clearRawBuffer() { d->rawBuffer.clear(); }

void NoNetwork::addMotdBuffer(const NoString& sFormat, const NoString& sText) { d->motdBuffer.addMessage(sFormat, sText); }
void NoNetwork::updateMotdBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText)
{
    d->motdBuffer.updateMessage(sMatch, sFormat, sText);
}
void NoNetwork::clearMotdBuffer() { d->motdBuffer.clear(); }

void NoNetwork::addNoticeBuffer(const NoString& sFormat, const NoString& sText) { d->noticeBuffer.addMessage(sFormat, sText); }
void NoNetwork::updateNoticeBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText)
{
    d->noticeBuffer.updateMessage(sMatch, sFormat, sText);
}
void NoNetwork::clearNoticeBuffer() { d->noticeBuffer.clear(); }

void NoNetwork::clearQueryBuffer()
{
    std::for_each(d->queries.begin(), d->queries.end(), std::default_delete<NoQuery>());
    d->queries.clear();
}

NoString NoNetwork::nick(const bool bAllowDefault) const
{
    if (d->nickName.empty()) {
        return d->user->nick(bAllowDefault);
    }

    return d->nickName;
}

NoString NoNetwork::altNick(const bool bAllowDefault) const
{
    if (d->altNick.empty()) {
        return d->user->altNick(bAllowDefault);
    }

    return d->altNick;
}

NoString NoNetwork::ident(const bool bAllowDefault) const
{
    if (d->ident.empty()) {
        return d->user->ident(bAllowDefault);
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

NoString NoNetwork::encoding() const { return d->encoding; }

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

void NoNetwork::setEncoding(const NoString& s) { d->encoding = s; }

void NoNetwork::setQuitMsg(const NoString& s)
{
    if (d->user->quitMsg().equals(s)) {
        d->quitMsg = "";
    } else {
        d->quitMsg = s;
    }
}

double NoNetwork::floodRate() const { return d->floodRate; }
ushort NoNetwork::floodBurst() const { return d->floodBurst; }
void NoNetwork::setFloodRate(double fFloodRate) { d->floodRate = fFloodRate; }
void NoNetwork::setFloodBurst(ushort uFloodBurst) { d->floodBurst = uFloodBurst; }

ushort NoNetwork::joinDelay() const { return d->joinDelay; }
void NoNetwork::setJoinDelay(ushort uJoinDelay) { d->joinDelay = uJoinDelay; }

NoString NoNetwork::expandString(const NoString& sStr) const
{
    NoString sRet;
    return expandString(sStr, sRet);
}

NoString& NoNetwork::expandString(const NoString& sStr, NoString& sRet) const
{
    sRet = sStr;
    sRet.replace("%defnick%", nick());
    sRet.replace("%nick%", currentNick());
    sRet.replace("%altnick%", altNick());
    sRet.replace("%ident%", ident());
    sRet.replace("%realname%", realName());
    sRet.replace("%bindhost%", bindHost());

    return d->user->expandString(sRet, sRet);
}

bool NoNetwork::loadModule(const NoString& sModName, const NoString& sArgs, const NoString& sNotice, NoString& sError)
{
    No::printAction(sNotice);
    NoString sModRet;

    bool bModRet = loader()->loadModule(sModName, sArgs, No::NetworkModule, user(), this, sModRet);

    No::printStatus(bModRet, sModRet);
    if (!bModRet) {
        sError = sModRet;
    }
    return bModRet;
}
