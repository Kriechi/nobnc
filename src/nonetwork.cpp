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
        SetName("NoNetworkPingTimer::" + m_pNetwork->GetUser()->GetUserName() + "::" + m_pNetwork->GetName());
        Start(NoNetwork::PING_SLACK);
    }

    NoNetworkPingTimer(const NoNetworkPingTimer&) = delete;
    NoNetworkPingTimer& operator=(const NoNetworkPingTimer&) = delete;

protected:
    void RunJob() override
    {
        NoIrcSocket* pIRCSock = m_pNetwork->GetIRCSock();

        if (pIRCSock && pIRCSock->GetTimeSinceLastDataTransaction() >= NoNetwork::PING_FREQUENCY) {
            pIRCSock->PutIRC("PING :ZNC");
        }

        const std::vector<NoClient*>& vClients = m_pNetwork->GetClients();
        for (NoClient* pClient : vClients) {
            if (pClient->GetSocket()->GetTimeSinceLastDataTransaction() >= NoNetwork::PING_FREQUENCY) {
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
        SetName("NoNetworkJoinTimer::" + m_pNetwork->GetUser()->GetUserName() + "::" + m_pNetwork->GetName());
        Start(NoNetwork::JOIN_FREQUENCY);
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
            Start(NoNetwork::JOIN_FREQUENCY);
        }
        if (m_pNetwork->IsIRCConnected()) {
            m_pNetwork->JoinChans();
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

bool NoNetwork::IsValidNetwork(const NoString& sNetwork)
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

    SetUser(pUser);

    d->rawBuffer.setLimit(100, true); // This should be more than enough raws, especially since we are buffering the
    // MOTD separately
    d->motdBuffer.setLimit(200, true); // This should be more than enough motd lines
    d->noticeBuffer.setLimit(250, true);

    d->pingTimer = new NoNetworkPingTimer(this);
    NoApp::Get().GetManager().AddCron(d->pingTimer);

    d->joinTimer = new NoNetworkJoinTimer(this);
    NoApp::Get().GetManager().AddCron(d->joinTimer);

    SetIRCConnectEnabled(true);
}

NoNetwork::NoNetwork(NoUser* pUser, const NoNetwork& Network) : NoNetwork(pUser, "") { Clone(Network); }

void NoNetwork::Clone(const NoNetwork& Network, bool bCloneName)
{
    if (bCloneName) {
        d->name = Network.GetName();
    }

    d->floodRate = Network.GetFloodRate();
    d->floodBurst = Network.GetFloodBurst();
    d->joinDelay = Network.GetJoinDelay();

    SetNick(Network.GetNick());
    SetAltNick(Network.GetAltNick());
    SetIdent(Network.GetIdent());
    SetRealName(Network.GetRealName());
    SetBindHost(Network.GetBindHost());
    SetEncoding(Network.GetEncoding());
    SetQuitMsg(Network.GetQuitMsg());
    d->trustedFingerprints = Network.d->trustedFingerprints;

    // Servers
    const std::vector<NoServerInfo*>& vServers = Network.GetServers();
    NoString sServer;
    NoServerInfo* pCurServ = GetCurrentServer();

    if (pCurServ) {
        sServer = pCurServ->host();
    }

    DelServers();

    for (NoServerInfo* pServer : vServers) {
        AddServer(pServer->host(), pServer->port(), pServer->password(), pServer->isSsl());
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
        NoIrcSocket* pSock = GetIRCSock();

        if (pSock) {
            PutStatus("Jumping servers because this server is no longer in the list");
            pSock->Quit();
        }
    }
    // !Servers

    // Chans
    const std::vector<NoChannel*>& vChans = Network.GetChans();
    for (NoChannel* pNewChan : vChans) {
        NoChannel* pChan = FindChan(pNewChan->getName());

        if (pChan) {
            pChan->setInConfig(pNewChan->inConfig());
        } else {
            AddChan(pNewChan->getName(), pNewChan->inConfig());
        }
    }

    for (NoChannel* pChan : d->channels) {
        NoChannel* pNewChan = Network.FindChan(pChan->getName());

        if (!pNewChan) {
            pChan->setInConfig(false);
        } else {
            pChan->clone(*pNewChan);
        }
    }
    // !Chans

    // Modules
    std::set<NoString> ssUnloadMods;
    NoModuleLoader* vCurMods = GetLoader();
    const NoModuleLoader* vNewMods = Network.GetLoader();

    for (NoModule* pNewMod : vNewMods->GetModules()) {
        NoString sModRet;
        NoModule* pCurMod = vCurMods->findModule(pNewMod->GetModName());

        if (!pCurMod) {
            vCurMods->loadModule(pNewMod->GetModName(), pNewMod->GetArgs(), No::NetworkModule, d->user, this, sModRet);
        } else if (pNewMod->GetArgs() != pCurMod->GetArgs()) {
            vCurMods->reloadModule(pNewMod->GetModName(), pNewMod->GetArgs(), d->user, this, sModRet);
        }
    }

    for (NoModule* pCurMod : vCurMods->GetModules()) {
        NoModule* pNewMod = vNewMods->findModule(pCurMod->GetModName());

        if (!pNewMod) {
            ssUnloadMods.insert(pCurMod->GetModName());
        }
    }

    for (const NoString& sMod : ssUnloadMods) {
        vCurMods->unloadModule(sMod);
    }
    // !Modules

    SetIRCConnectEnabled(Network.GetIRCConnectEnabled());
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
    DelServers();

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

    SetUser(nullptr);

    // Make sure we are not in the connection queue
    NoApp::Get().GetConnectionQueue().remove(this);

    NoApp::Get().GetManager().DelCronByAddr(d->pingTimer);
    NoApp::Get().GetManager().DelCronByAddr(d->joinTimer);
}

void NoNetwork::DelServers()
{
    for (NoServerInfo* pServer : d->servers) {
        delete pServer;
    }
    d->servers.clear();
}

NoString NoNetwork::GetNetworkPath() const
{
    NoString sNetworkPath = d->user->GetUserPath() + "/networks/" + d->name;

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

bool NoNetwork::ParseConfig(NoSettings* pConfig, NoString& sError, bool bUpgrade)
{
    NoStringVector vsList;

    if (!bUpgrade) {
        TOption<const NoString&> StringOptions[] = {
            { "nick", &NoNetwork::SetNick },
            { "altnick", &NoNetwork::SetAltNick },
            { "ident", &NoNetwork::SetIdent },
            { "realname", &NoNetwork::SetRealName },
            { "bindhost", &NoNetwork::SetBindHost },
            { "encoding", &NoNetwork::SetEncoding },
            { "quitmsg", &NoNetwork::SetQuitMsg },
        };
        TOption<bool> BoolOptions[] = {
            { "ircconnectenabled", &NoNetwork::SetIRCConnectEnabled },
        };
        TOption<double> DoubleOptions[] = {
            { "floodrate", &NoNetwork::SetFloodRate },
        };
        TOption<ushort> SUIntOptions[] = {
            { "floodburst", &NoNetwork::SetFloodBurst }, { "joindelay", &NoNetwork::SetJoinDelay },
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

            bool bModRet = LoadModule(sModName, sArgs, sNotice, sModRet);

            if (!bModRet) {
                // XXX The awaynick module was retired in 1.6 (still available as external module)
                if (sModName == "awaynick") {
                    // load simple_away instead, unless it's already on the list
                    if (std::find(vsList.begin(), vsList.end(), "simple_away") == vsList.end()) {
                        sNotice = "Loading network module [simple_away] instead";
                        sModName = "simple_away";
                        // not a fatal error if simple_away is not available
                        LoadModule(sModName, sArgs, sNotice, sModRet);
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
        No::printStatus(AddServer(sServer));
    }

    pConfig->FindStringVector("trustedserverfingerprint", vsList);
    for (const NoString& sFP : vsList) {
        AddTrustedFingerprint(sFP);
    }

    pConfig->FindStringVector("chan", vsList);
    for (const NoString& sChan : vsList) {
        AddChan(sChan, true);
    }

    NoSettings::SubConfig subConf;
    NoSettings::SubConfig::const_iterator subIt;

    pConfig->FindSubConfig("chan", subConf);
    for (subIt = subConf.begin(); subIt != subConf.end(); ++subIt) {
        const NoString& sChanName = subIt->first;
        NoSettings* pSubConf = subIt->second.m_subConfig;
        NoChannel* pChan = new NoChannel(sChanName, this, true, pSubConf);

        if (!pSubConf->empty()) {
            sError = "Unhandled lines in config for User [" + d->user->GetUserName() + "], Network [" + GetName() +
                     "], Channel [" + sChanName + "]!";
            No::printError(sError);

            NoApp::DumpConfig(pSubConf);
            return false;
        }

        // Save the channel name, because AddChan
        // deletes the NoChannelnel*, if adding fails
        sError = pChan->getName();
        if (!AddChan(pChan)) {
            sError = "Channel [" + sError + "] defined more than once";
            No::printError(sError);
            return false;
        }
        sError.clear();
    }

    return true;
}

NoSettings NoNetwork::ToConfig() const
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

    config.AddKeyValuePair("IRCConnectEnabled", NoString(GetIRCConnectEnabled()));
    config.AddKeyValuePair("FloodRate", NoString(GetFloodRate()));
    config.AddKeyValuePair("FloodBurst", NoString(GetFloodBurst()));
    config.AddKeyValuePair("JoinDelay", NoString(GetJoinDelay()));
    config.AddKeyValuePair("Encoding", d->encoding);

    if (!d->quitMsg.empty()) {
        config.AddKeyValuePair("QuitMsg", d->quitMsg);
    }

    // Modules
    const NoModuleLoader* Mods = GetLoader();

    for (NoModule* pMod : Mods->GetModules()) {
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
            config.AddSubConfig("Chan", pChan->getName(), pChan->toConfig());
        }
    }

    return config;
}

void NoNetwork::BounceAllClients()
{
    for (NoClient* pClient : d->clients) {
        pClient->BouncedOff();
    }

    d->clients.clear();
}

bool NoNetwork::IsUserAttached() const { return !d->clients.empty(); }

bool NoNetwork::IsUserOnline() const
{
    for (NoClient* pClient : d->clients) {
        if (!pClient->IsAway()) {
            return true;
        }
    }

    return false;
}

void NoNetwork::ClientConnected(NoClient* pClient)
{
    if (!d->user->MultiClients()) {
        BounceAllClients();
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

        const NoNick& Nick = GetIRCNick();
        if (sClientNick != Nick.nick()) { // case-sensitive match
            pClient->PutClient(":" + sClientNick + "!" + Nick.ident() + "@" + Nick.host() + " NICK :" + Nick.nick());
            pClient->SetNick(Nick.nick());
        }
    }

    NoStringMap msParams;
    msParams["target"] = GetIRCNick().nick();

    // Send the cached MOTD
    uSize = d->motdBuffer.size();
    if (uSize > 0) {
        for (uIdx = 0; uIdx < uSize; uIdx++) {
            pClient->PutClient(d->motdBuffer.getMessage(uIdx, *pClient, msParams));
        }
    }

    if (GetIRCSock() != nullptr) {
        NoString sUserMode("");
        const std::set<uchar>& scUserModes = GetIRCSock()->GetUserModes();
        for (uchar cMode : scUserModes) {
            sUserMode += cMode;
        }
        if (!sUserMode.empty()) {
            pClient->PutClient(":" + GetIRCNick().nickMask() + " MODE " + GetIRCNick().nick() + " :+" + sUserMode);
        }
    }

    if (d->away) {
        // If they want to know their away reason they'll have to whois
        // themselves. At least we can tell them their away status...
        pClient->PutClient(":irc.znc.in 306 " + GetIRCNick().nick() + " :You have been marked as being away");
    }

    const std::vector<NoChannel*>& vChans = GetChans();
    for (NoChannel* pChan : vChans) {
        if ((pChan->isOn()) && (!pChan->isDetached())) {
            pChan->attachUser(pClient);
        }
    }

    bool bClearQuery = d->user->AutoClearQueryBuffer();
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
        NETWORKMODULECALL(OnPrivBufferPlayLine2(*pClient, sLine, BufLine.timestamp()), d->user, this, nullptr, &bContinue);
        if (bContinue) continue;
        pClient->PutClient(sLine);
    }
    d->noticeBuffer.clear();

    pClient->SetPlaybackActive(false);

    // Tell them why they won't connect
    if (!GetIRCConnectEnabled())
        pClient->PutStatus("You are currently disconnected from IRC. "
                           "Use 'connect' to reconnect.");
}

void NoNetwork::ClientDisconnected(NoClient* pClient)
{
    auto it = std::find(d->clients.begin(), d->clients.end(), pClient);
    if (it != d->clients.end()) {
        d->clients.erase(it);
    }
}

NoUser* NoNetwork::GetUser() const { return d->user; }

NoString NoNetwork::GetName() const { return d->name; }

bool NoNetwork::IsNetworkAttached() const { return !d->clients.empty(); }
std::vector<NoClient*> NoNetwork::GetClients() const { return d->clients; }

std::vector<NoClient*> NoNetwork::FindClients(const NoString& sIdentifier) const
{
    std::vector<NoClient*> vClients;
    for (NoClient* pClient : d->clients) {
        if (pClient->GetIdentifier().equals(sIdentifier)) {
            vClients.push_back(pClient);
        }
    }

    return vClients;
}

void NoNetwork::SetUser(NoUser* pUser)
{
    for (NoClient* pClient : d->clients) {
        pClient->PutStatus("This network is being deleted or moved to another user.");
        pClient->SetNetwork(nullptr);
    }

    d->clients.clear();

    if (d->user) {
        d->user->RemoveNetwork(this);
    }

    d->user = pUser;
    if (d->user) {
        d->user->AddNetwork(this);
    }
}

bool NoNetwork::SetName(const NoString& sName)
{
    if (IsValidNetwork(sName)) {
        d->name = sName;
        return true;
    }

    return false;
}

NoModuleLoader* NoNetwork::GetLoader() const { return d->modules; }

bool NoNetwork::PutUser(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
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

bool NoNetwork::PutStatus(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
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

bool NoNetwork::PutModule(const NoString& sModule, const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
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

std::vector<NoChannel*> NoNetwork::GetChans() const { return d->channels; }

NoChannel* NoNetwork::FindChan(NoString sName) const
{
    if (GetIRCSock()) {
        // See https://tools.ietf.org/html/draft-brocklesby-irc-isupport-03#section-3.16
        sName.trimLeft(GetIRCSock()->GetISupport("STATUSMSG", ""));
    }

    for (NoChannel* pChan : d->channels) {
        if (sName.equals(pChan->getName())) {
            return pChan;
        }
    }

    return nullptr;
}

std::vector<NoChannel*> NoNetwork::FindChans(const NoString& sWild) const
{
    std::vector<NoChannel*> vChans;
    vChans.reserve(d->channels.size());
    for (NoChannel* pChan : d->channels) {
        if (No::wildCmp(pChan->getName(), sWild, No::CaseInsensitive))
            vChans.push_back(pChan);
    }
    return vChans;
}

bool NoNetwork::AddChan(NoChannel* pChan)
{
    if (!pChan) {
        return false;
    }

    for (NoChannel* pEachChan : d->channels) {
        if (pEachChan->getName().equals(pChan->getName())) {
            delete pChan;
            return false;
        }
    }

    d->channels.push_back(pChan);
    return true;
}

bool NoNetwork::AddChan(const NoString& sName, bool bInConfig)
{
    if (sName.empty() || FindChan(sName)) {
        return false;
    }

    NoChannel* pChan = new NoChannel(sName, this, bInConfig);
    d->channels.push_back(pChan);
    return true;
}

bool NoNetwork::DelChan(const NoString& sName)
{
    for (std::vector<NoChannel*>::iterator a = d->channels.begin(); a != d->channels.end(); ++a) {
        if (sName.equals((*a)->getName())) {
            delete *a;
            d->channels.erase(a);
            return true;
        }
    }

    return false;
}

void NoNetwork::JoinChans()
{
    // Avoid divsion by zero, it's bad!
    if (d->channels.empty()) return;

    // We start at a random offset into the channel list so that if your
    // first 3 channels are invite-only and you got MaxJoins == 3, ZNC will
    // still be able to join the rest of your channels.
    uint start = rand() % d->channels.size();
    uint uJoins = d->user->MaxJoins();
    std::set<NoChannel*> sChans;
    for (uint a = 0; a < d->channels.size(); a++) {
        uint idx = (start + a) % d->channels.size();
        NoChannel* pChan = d->channels[idx];
        if (!pChan->isOn() && !pChan->isDisabled()) {
            if (!JoinChan(pChan)) continue;

            sChans.insert(pChan);

            // Limit the number of joins
            if (uJoins != 0 && --uJoins == 0) {
                // Reset the timer.
                d->joinTimer->Reset();
                break;
            }
        }
    }

    while (!sChans.empty()) JoinChans(sChans);
}

void NoNetwork::JoinChans(std::set<NoChannel*>& sChans)
{
    NoString sKeys, sJoin;
    bool bHaveKey = false;
    size_t uiJoinLength = strlen("JOIN ");

    while (!sChans.empty()) {
        std::set<NoChannel*>::iterator it = sChans.begin();
        const NoString& sName = (*it)->getName();
        const NoString& sKey = (*it)->getKey();
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
        PutIRC("JOIN " + sJoin + " " + sKeys);
    else
        PutIRC("JOIN " + sJoin);
}

bool NoNetwork::JoinChan(NoChannel* pChan)
{
    bool bReturn = false;
    NETWORKMODULECALL(OnJoining(*pChan), d->user, this, nullptr, &bReturn);

    if (bReturn) return false;

    if (d->user->JoinTries() != 0 && pChan->getJoinTries() >= d->user->JoinTries()) {
        PutStatus("The channel " + pChan->getName() + " could not be joined, disabling it.");
        pChan->disable();
    } else {
        pChan->incJoinTries();
        bool bFailed = false;
        NETWORKMODULECALL(OnTimerAutoJoin(*pChan), d->user, this, nullptr, &bFailed);
        if (bFailed) return false;
        return true;
    }
    return false;
}

NoString NoNetwork::GetChanPrefixes() const { return d->chanPrefixes; }
void NoNetwork::SetChanPrefixes(const NoString& s) { d->chanPrefixes = s; }

bool NoNetwork::IsChan(const NoString& sChan) const
{
    if (sChan.empty()) return false; // There is no way this is a chan
    if (GetChanPrefixes().empty()) return true; // We can't know, so we allow everything
    // Thanks to the above if (empty), we can do sChan[0]
    return GetChanPrefixes().contains(sChan[0]);
}

// Queries

std::vector<NoQuery*> NoNetwork::GetQueries() const { return d->queries; }

NoQuery* NoNetwork::FindQuery(const NoString& sName) const
{
    for (NoQuery* pQuery : d->queries) {
        if (sName.equals(pQuery->getName())) {
            return pQuery;
        }
    }

    return nullptr;
}

std::vector<NoQuery*> NoNetwork::FindQueries(const NoString& sWild) const
{
    std::vector<NoQuery*> vQueries;
    vQueries.reserve(d->queries.size());
    for (NoQuery* pQuery : d->queries) {
        if (No::wildCmp(pQuery->getName(), sWild, No::CaseInsensitive))
            vQueries.push_back(pQuery);
    }
    return vQueries;
}

NoQuery* NoNetwork::AddQuery(const NoString& sName)
{
    if (sName.empty()) {
        return nullptr;
    }

    NoQuery* pQuery = FindQuery(sName);
    if (!pQuery) {
        pQuery = new NoQuery(sName, this);
        d->queries.push_back(pQuery);

        if (d->user->MaxQueryBuffers() > 0) {
            while (d->queries.size() > d->user->MaxQueryBuffers()) {
                delete *d->queries.begin();
                d->queries.erase(d->queries.begin());
            }
        }
    }

    return pQuery;
}

bool NoNetwork::DelQuery(const NoString& sName)
{
    for (std::vector<NoQuery*>::iterator a = d->queries.begin(); a != d->queries.end(); ++a) {
        if (sName.equals((*a)->getName())) {
            delete *a;
            d->queries.erase(a);
            return true;
        }
    }

    return false;
}

// Server list

std::vector<NoServerInfo*> NoNetwork::GetServers() const { return d->servers; }

bool NoNetwork::HasServers() const { return !d->servers.empty(); }

NoServerInfo* NoNetwork::FindServer(const NoString& sName) const
{
    for (NoServerInfo* pServer : d->servers) {
        if (sName.equals(pServer->host())) {
            return pServer;
        }
    }

    return nullptr;
}

bool NoNetwork::DelServer(const NoString& sName, ushort uPort, const NoString& sPass)
{
    if (sName.empty()) {
        return false;
    }

    uint a = 0;
    bool bSawCurrentServer = false;
    NoServerInfo* pCurServer = GetCurrentServer();

    for (std::vector<NoServerInfo*>::iterator it = d->servers.begin(); it != d->servers.end(); ++it, a++) {
        NoServerInfo* pServer = *it;

        if (pServer == pCurServer) bSawCurrentServer = true;

        if (!pServer->host().equals(sName)) continue;

        if (uPort != 0 && pServer->port() != uPort) continue;

        if (!sPass.empty() && pServer->password() != sPass) continue;

        d->servers.erase(it);

        if (pServer == pCurServer) {
            NoIrcSocket* pIRCSock = GetIRCSock();

            // Make sure we don't skip the next server in the list!
            if (d->serverIndex) {
                d->serverIndex--;
            }

            if (pIRCSock) {
                pIRCSock->Quit();
                PutStatus("Your current server was removed, jumping...");
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

bool NoNetwork::AddServer(const NoString& sName)
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

    return AddServer(sHost, uPort, sPass, bSSL);
}

bool NoNetwork::AddServer(const NoString& sName, ushort uPort, const NoString& sPass, bool bSSL)
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

    CheckIRCConnect();

    return true;
}

NoServerInfo* NoNetwork::GetNextServer()
{
    if (d->servers.empty()) {
        return nullptr;
    }

    if (d->serverIndex >= d->servers.size()) {
        d->serverIndex = 0;
    }

    return d->servers[d->serverIndex++];
}

NoServerInfo* NoNetwork::GetCurrentServer() const
{
    size_t uIdx = (d->serverIndex) ? d->serverIndex - 1 : 0;

    if (uIdx >= d->servers.size()) {
        return nullptr;
    }

    return d->servers[uIdx];
}

void NoNetwork::SetIRCServer(const NoString& s) { d->server = s; }

bool NoNetwork::SetNextServer(const NoServerInfo* pServer)
{
    for (uint a = 0; a < d->servers.size(); a++) {
        if (d->servers[a] == pServer) {
            d->serverIndex = a;
            return true;
        }
    }

    return false;
}

bool NoNetwork::IsLastServer() const { return (d->serverIndex >= d->servers.size()); }

NoStringSet NoNetwork::GetTrustedFingerprints() const { return d->trustedFingerprints; }
void NoNetwork::AddTrustedFingerprint(const NoString& sFP)
{
    d->trustedFingerprints.insert(No::escape(sFP, No::HexColonFormat, No::HexColonFormat));
}
void NoNetwork::DelTrustedFingerprint(const NoString& sFP) { d->trustedFingerprints.erase(sFP); }

NoIrcSocket* NoNetwork::GetIRCSock() const { return d->socket; }
NoString NoNetwork::GetIRCServer() const { return d->server; }
const NoNick& NoNetwork::GetIRCNick() const { return d->ircNick; }

void NoNetwork::SetIRCNick(const NoNick& n)
{
    d->ircNick = n;

    for (NoClient* pClient : d->clients) {
        pClient->SetNick(n.nick());
    }
}

NoString NoNetwork::GetCurNick() const
{
    const NoIrcSocket* pIRCSock = GetIRCSock();

    if (pIRCSock) {
        return pIRCSock->GetNick();
    }

    if (!d->clients.empty()) {
        return d->clients[0]->GetNick();
    }

    return "";
}

bool NoNetwork::IsIRCAway() const { return d->away; }
void NoNetwork::SetIRCAway(bool b) { d->away = b; }

bool NoNetwork::Connect()
{
    if (!GetIRCConnectEnabled() || d->socket || !HasServers()) return false;

    NoServerInfo* pServer = GetNextServer();
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

    NO_DEBUG("Connecting user/network [" << d->user->GetUserName() << "/" << d->name << "]");

    bool bAbort = false;
    NETWORKMODULECALL(OnIRCConnecting(pIRCSock), d->user, this, nullptr, &bAbort);
    if (bAbort) {
        NO_DEBUG("Some module aborted the connection attempt");
        PutStatus("Some module aborted the connection attempt");
        delete pIRCSock;
        NoApp::Get().AddNetworkToQueue(this);
        return false;
    }

    NoString sSockName = "IRC::" + d->user->GetUserName() + "::" + d->name;
    NoApp::Get().GetManager().Connect(pServer->host(), pServer->port(), sSockName, 120, bSSL, GetBindHost(), pIRCSock);

    return true;
}

bool NoNetwork::IsIRCConnected() const
{
    const NoIrcSocket* pSock = GetIRCSock();
    return (pSock && pSock->IsAuthed());
}

void NoNetwork::SetIRCSocket(NoIrcSocket* pIRCSock) { d->socket = pIRCSock; }

void NoNetwork::IRCConnected()
{
    if (d->joinDelay > 0) {
        d->joinTimer->Delay(d->joinDelay);
    } else {
        JoinChans();
    }
}

void NoNetwork::IRCDisconnected()
{
    d->socket = nullptr;

    SetIRCServer("");
    d->away = false;

    // Get the reconnect going
    CheckIRCConnect();
}

bool NoNetwork::GetIRCConnectEnabled() const { return d->enabled; }

void NoNetwork::SetIRCConnectEnabled(bool b)
{
    d->enabled = b;

    if (d->enabled) {
        CheckIRCConnect();
    } else if (GetIRCSock()) {
        if (GetIRCSock()->IsConnected()) {
            GetIRCSock()->Quit();
        } else {
            GetIRCSock()->Close();
        }
    }
}

void NoNetwork::CheckIRCConnect()
{
    // Do we want to connect?
    if (GetIRCConnectEnabled() && GetIRCSock() == nullptr) NoApp::Get().AddNetworkToQueue(this);
}

bool NoNetwork::PutIRC(const NoString& sLine)
{
    NoIrcSocket* pIRCSock = GetIRCSock();

    if (!pIRCSock) {
        return false;
    }

    pIRCSock->PutIRC(sLine);
    return true;
}

void NoNetwork::AddRawBuffer(const NoString& sFormat, const NoString& sText) { d->rawBuffer.addMessage(sFormat, sText); }
void NoNetwork::UpdateRawBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText)
{
    d->rawBuffer.updateMessage(sMatch, sFormat, sText);
}
void NoNetwork::UpdateExactRawBuffer(const NoString& sFormat, const NoString& sText)
{
    d->rawBuffer.updateExactMessage(sFormat, sText);
}
void NoNetwork::ClearRawBuffer() { d->rawBuffer.clear(); }

void NoNetwork::AddMotdBuffer(const NoString& sFormat, const NoString& sText) { d->motdBuffer.addMessage(sFormat, sText); }
void NoNetwork::UpdateMotdBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText)
{
    d->motdBuffer.updateMessage(sMatch, sFormat, sText);
}
void NoNetwork::ClearMotdBuffer() { d->motdBuffer.clear(); }

void NoNetwork::AddNoticeBuffer(const NoString& sFormat, const NoString& sText) { d->noticeBuffer.addMessage(sFormat, sText); }
void NoNetwork::UpdateNoticeBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText)
{
    d->noticeBuffer.updateMessage(sMatch, sFormat, sText);
}
void NoNetwork::ClearNoticeBuffer() { d->noticeBuffer.clear(); }

void NoNetwork::ClearQueryBuffer()
{
    std::for_each(d->queries.begin(), d->queries.end(), std::default_delete<NoQuery>());
    d->queries.clear();
}

NoString NoNetwork::GetNick(const bool bAllowDefault) const
{
    if (d->nickName.empty()) {
        return d->user->GetNick(bAllowDefault);
    }

    return d->nickName;
}

NoString NoNetwork::GetAltNick(const bool bAllowDefault) const
{
    if (d->altNick.empty()) {
        return d->user->GetAltNick(bAllowDefault);
    }

    return d->altNick;
}

NoString NoNetwork::GetIdent(const bool bAllowDefault) const
{
    if (d->ident.empty()) {
        return d->user->GetIdent(bAllowDefault);
    }

    return d->ident;
}

NoString NoNetwork::GetRealName() const
{
    if (d->realName.empty()) {
        return d->user->GetRealName();
    }

    return d->realName;
}

NoString NoNetwork::GetBindHost() const
{
    if (d->bindHost.empty()) {
        return d->user->GetBindHost();
    }

    return d->bindHost;
}

NoString NoNetwork::GetEncoding() const { return d->encoding; }

NoString NoNetwork::GetQuitMsg() const
{
    if (d->quitMsg.empty()) {
        return d->user->GetQuitMsg();
    }

    return d->quitMsg;
}

void NoNetwork::SetNick(const NoString& s)
{
    if (d->user->GetNick().equals(s)) {
        d->nickName = "";
    } else {
        d->nickName = s;
    }
}

void NoNetwork::SetAltNick(const NoString& s)
{
    if (d->user->GetAltNick().equals(s)) {
        d->altNick = "";
    } else {
        d->altNick = s;
    }
}

void NoNetwork::SetIdent(const NoString& s)
{
    if (d->user->GetIdent().equals(s)) {
        d->ident = "";
    } else {
        d->ident = s;
    }
}

void NoNetwork::SetRealName(const NoString& s)
{
    if (d->user->GetRealName().equals(s)) {
        d->realName = "";
    } else {
        d->realName = s;
    }
}

void NoNetwork::SetBindHost(const NoString& s)
{
    if (d->user->GetBindHost().equals(s)) {
        d->bindHost = "";
    } else {
        d->bindHost = s;
    }
}

void NoNetwork::SetEncoding(const NoString& s) { d->encoding = s; }

void NoNetwork::SetQuitMsg(const NoString& s)
{
    if (d->user->GetQuitMsg().equals(s)) {
        d->quitMsg = "";
    } else {
        d->quitMsg = s;
    }
}

double NoNetwork::GetFloodRate() const { return d->floodRate; }
ushort NoNetwork::GetFloodBurst() const { return d->floodBurst; }
void NoNetwork::SetFloodRate(double fFloodRate) { d->floodRate = fFloodRate; }
void NoNetwork::SetFloodBurst(ushort uFloodBurst) { d->floodBurst = uFloodBurst; }

ushort NoNetwork::GetJoinDelay() const { return d->joinDelay; }
void NoNetwork::SetJoinDelay(ushort uJoinDelay) { d->joinDelay = uJoinDelay; }

NoString NoNetwork::ExpandString(const NoString& sStr) const
{
    NoString sRet;
    return ExpandString(sStr, sRet);
}

NoString& NoNetwork::ExpandString(const NoString& sStr, NoString& sRet) const
{
    sRet = sStr;
    sRet.replace("%defnick%", GetNick());
    sRet.replace("%nick%", GetCurNick());
    sRet.replace("%altnick%", GetAltNick());
    sRet.replace("%ident%", GetIdent());
    sRet.replace("%realname%", GetRealName());
    sRet.replace("%bindhost%", GetBindHost());

    return d->user->ExpandString(sRet, sRet);
}

bool NoNetwork::LoadModule(const NoString& sModName, const NoString& sArgs, const NoString& sNotice, NoString& sError)
{
    No::printAction(sNotice);
    NoString sModRet;

    bool bModRet = GetLoader()->loadModule(sModName, sArgs, No::NetworkModule, GetUser(), this, sModRet);

    No::printStatus(bModRet, sModRet);
    if (!bModRet) {
        sError = sModRet;
    }
    return bModRet;
}
