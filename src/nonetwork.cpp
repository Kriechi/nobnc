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

NoNetwork::NoNetwork(NoUser* pUser, const NoString& sName)
    : m_name(sName), m_user(nullptr), m_nickName(""), m_altNick(""), m_ident(""), m_realName(""), m_bindHost(""),
      m_encoding(""), m_quitMsg(""), m_trustedFingerprints(), m_modules(new NoModules), m_clients(),
      m_socket(nullptr), m_channels(), m_queries(), m_chanPrefixes(""), m_enabled(true), m_server(""),
      m_servers(), m_serverIndex(0), m_ircNick(), m_away(false), m_floodRate(1), m_floodBurst(4), m_rawBuffer(),
      m_motdBuffer(), m_noticeBuffer(), m_pingTimer(nullptr), m_joinTimer(nullptr), m_joinDelay(0)
{
    SetUser(pUser);

    m_rawBuffer.setLimit(100, true); // This should be more than enough raws, especially since we are buffering the
    // MOTD separately
    m_motdBuffer.setLimit(200, true); // This should be more than enough motd lines
    m_noticeBuffer.setLimit(250, true);

    m_pingTimer = new NoNetworkPingTimer(this);
    NoApp::Get().GetManager().AddCron(m_pingTimer);

    m_joinTimer = new NoNetworkJoinTimer(this);
    NoApp::Get().GetManager().AddCron(m_joinTimer);

    SetIRCConnectEnabled(true);
}

NoNetwork::NoNetwork(NoUser* pUser, const NoNetwork& Network) : NoNetwork(pUser, "") { Clone(Network); }

void NoNetwork::Clone(const NoNetwork& Network, bool bCloneName)
{
    if (bCloneName) {
        m_name = Network.GetName();
    }

    m_floodRate = Network.GetFloodRate();
    m_floodBurst = Network.GetFloodBurst();
    m_joinDelay = Network.GetJoinDelay();

    SetNick(Network.GetNick());
    SetAltNick(Network.GetAltNick());
    SetIdent(Network.GetIdent());
    SetRealName(Network.GetRealName());
    SetBindHost(Network.GetBindHost());
    SetEncoding(Network.GetEncoding());
    SetQuitMsg(Network.GetQuitMsg());
    m_trustedFingerprints = Network.m_trustedFingerprints;

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

    m_serverIndex = 0;
    for (size_t a = 0; a < m_servers.size(); a++) {
        if (sServer.equals(m_servers[a]->host())) {
            m_serverIndex = a + 1;
            break;
        }
    }
    if (m_serverIndex == 0) {
        m_serverIndex = m_servers.size();
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

    for (NoChannel* pChan : m_channels) {
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
    NoModules& vCurMods = GetModules();
    const NoModules& vNewMods = Network.GetModules();

    for (NoModule* pNewMod : vNewMods) {
        NoString sModRet;
        NoModule* pCurMod = vCurMods.FindModule(pNewMod->GetModName());

        if (!pCurMod) {
            vCurMods.LoadModule(pNewMod->GetModName(), pNewMod->GetArgs(), No::NetworkModule, m_user, this, sModRet);
        } else if (pNewMod->GetArgs() != pCurMod->GetArgs()) {
            vCurMods.ReloadModule(pNewMod->GetModName(), pNewMod->GetArgs(), m_user, this, sModRet);
        }
    }

    for (NoModule* pCurMod : vCurMods) {
        NoModule* pNewMod = vNewMods.FindModule(pCurMod->GetModName());

        if (!pNewMod) {
            ssUnloadMods.insert(pCurMod->GetModName());
        }
    }

    for (const NoString& sMod : ssUnloadMods) {
        vCurMods.UnloadModule(sMod);
    }
    // !Modules

    SetIRCConnectEnabled(Network.GetIRCConnectEnabled());
}

NoNetwork::~NoNetwork()
{
    if (m_socket) {
        NoApp::Get().GetManager().DelSockByAddr(m_socket);
        m_socket = nullptr;
    }

    // Delete clients
    while (!m_clients.empty()) {
        NoApp::Get().GetManager().DelSockByAddr(m_clients[0]->GetSocket());
    }
    m_clients.clear();

    // Delete servers
    DelServers();

    // Delete modules (this unloads all modules)
    delete m_modules;
    m_modules = nullptr;

    // Delete Channels
    for (NoChannel* pChan : m_channels) {
        delete pChan;
    }
    m_channels.clear();

    // Delete Queries
    for (NoQuery* pQuery : m_queries) {
        delete pQuery;
    }
    m_queries.clear();

    SetUser(nullptr);

    // Make sure we are not in the connection queue
    NoApp::Get().GetConnectionQueue().remove(this);

    NoApp::Get().GetManager().DelCronByAddr(m_pingTimer);
    NoApp::Get().GetManager().DelCronByAddr(m_joinTimer);
}

void NoNetwork::DelServers()
{
    for (NoServerInfo* pServer : m_servers) {
        delete pServer;
    }
    m_servers.clear();
}

NoString NoNetwork::GetNetworkPath() const
{
    NoString sNetworkPath = m_user->GetUserPath() + "/networks/" + m_name;

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
            sError = "Unhandled lines in config for User [" + m_user->GetUserName() + "], Network [" + GetName() +
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

    if (!m_nickName.empty()) {
        config.AddKeyValuePair("Nick", m_nickName);
    }

    if (!m_altNick.empty()) {
        config.AddKeyValuePair("AltNick", m_altNick);
    }

    if (!m_ident.empty()) {
        config.AddKeyValuePair("Ident", m_ident);
    }

    if (!m_realName.empty()) {
        config.AddKeyValuePair("RealName", m_realName);
    }
    if (!m_bindHost.empty()) {
        config.AddKeyValuePair("BindHost", m_bindHost);
    }

    config.AddKeyValuePair("IRCConnectEnabled", NoString(GetIRCConnectEnabled()));
    config.AddKeyValuePair("FloodRate", NoString(GetFloodRate()));
    config.AddKeyValuePair("FloodBurst", NoString(GetFloodBurst()));
    config.AddKeyValuePair("JoinDelay", NoString(GetJoinDelay()));
    config.AddKeyValuePair("Encoding", m_encoding);

    if (!m_quitMsg.empty()) {
        config.AddKeyValuePair("QuitMsg", m_quitMsg);
    }

    // Modules
    const NoModules& Mods = GetModules();

    if (!Mods.empty()) {
        for (NoModule* pMod : Mods) {
            NoString sArgs = pMod->GetArgs();

            if (!sArgs.empty()) {
                sArgs = " " + sArgs;
            }

            config.AddKeyValuePair("LoadModule", pMod->GetModName() + sArgs);
        }
    }

    // Servers
    for (NoServerInfo* pServer : m_servers) {
        config.AddKeyValuePair("Server", pServer->toString());
    }

    for (const NoString& sFP : m_trustedFingerprints) {
        config.AddKeyValuePair("TrustedServerFingerprint", sFP);
    }

    // Chans
    for (NoChannel* pChan : m_channels) {
        if (pChan->inConfig()) {
            config.AddSubConfig("Chan", pChan->getName(), pChan->toConfig());
        }
    }

    return config;
}

void NoNetwork::BounceAllClients()
{
    for (NoClient* pClient : m_clients) {
        pClient->BouncedOff();
    }

    m_clients.clear();
}

bool NoNetwork::IsUserAttached() const { return !m_clients.empty(); }

bool NoNetwork::IsUserOnline() const
{
    for (NoClient* pClient : m_clients) {
        if (!pClient->IsAway()) {
            return true;
        }
    }

    return false;
}

void NoNetwork::ClientConnected(NoClient* pClient)
{
    if (!m_user->MultiClients()) {
        BounceAllClients();
    }

    m_clients.push_back(pClient);

    size_t uIdx, uSize;

    pClient->SetPlaybackActive(true);

    if (m_rawBuffer.isEmpty()) {
        pClient->PutClient(":irc.znc.in 001 " + pClient->GetNick() + " :- Welcome to ZNC -");
    } else {
        const NoString& sClientNick = pClient->GetNick(false);
        NoStringMap msParams;
        msParams["target"] = sClientNick;

        uSize = m_rawBuffer.size();
        for (uIdx = 0; uIdx < uSize; uIdx++) {
            pClient->PutClient(m_rawBuffer.getMessage(uIdx, *pClient, msParams));
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
    uSize = m_motdBuffer.size();
    if (uSize > 0) {
        for (uIdx = 0; uIdx < uSize; uIdx++) {
            pClient->PutClient(m_motdBuffer.getMessage(uIdx, *pClient, msParams));
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

    if (m_away) {
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

    bool bClearQuery = m_user->AutoClearQueryBuffer();
    for (NoQuery* pQuery : m_queries) {
        pQuery->sendBuffer(pClient);
        if (bClearQuery) {
            delete pQuery;
        }
    }
    if (bClearQuery) {
        m_queries.clear();
    }

    uSize = m_noticeBuffer.size();
    for (uIdx = 0; uIdx < uSize; uIdx++) {
        const NoMessage& BufLine = m_noticeBuffer.getMessage(uIdx);
        NoString sLine = BufLine.GetLine(*pClient, msParams);
        bool bContinue = false;
        NETWORKMODULECALL(OnPrivBufferPlayLine2(*pClient, sLine, BufLine.GetTime()), m_user, this, nullptr, &bContinue);
        if (bContinue) continue;
        pClient->PutClient(sLine);
    }
    m_noticeBuffer.clear();

    pClient->SetPlaybackActive(false);

    // Tell them why they won't connect
    if (!GetIRCConnectEnabled())
        pClient->PutStatus("You are currently disconnected from IRC. "
                           "Use 'connect' to reconnect.");
}

void NoNetwork::ClientDisconnected(NoClient* pClient)
{
    auto it = std::find(m_clients.begin(), m_clients.end(), pClient);
    if (it != m_clients.end()) {
        m_clients.erase(it);
    }
}

NoUser* NoNetwork::GetUser() const { return m_user; }

NoString NoNetwork::GetName() const { return m_name; }

bool NoNetwork::IsNetworkAttached() const { return !m_clients.empty(); }
std::vector<NoClient*> NoNetwork::GetClients() const { return m_clients; }

std::vector<NoClient*> NoNetwork::FindClients(const NoString& sIdentifier) const
{
    std::vector<NoClient*> vClients;
    for (NoClient* pClient : m_clients) {
        if (pClient->GetIdentifier().equals(sIdentifier)) {
            vClients.push_back(pClient);
        }
    }

    return vClients;
}

void NoNetwork::SetUser(NoUser* pUser)
{
    for (NoClient* pClient : m_clients) {
        pClient->PutStatus("This network is being deleted or moved to another user.");
        pClient->SetNetwork(nullptr);
    }

    m_clients.clear();

    if (m_user) {
        m_user->RemoveNetwork(this);
    }

    m_user = pUser;
    if (m_user) {
        m_user->AddNetwork(this);
    }
}

bool NoNetwork::SetName(const NoString& sName)
{
    if (IsValidNetwork(sName)) {
        m_name = sName;
        return true;
    }

    return false;
}

NoModules& NoNetwork::GetModules() { return *m_modules; }
const NoModules& NoNetwork::GetModules() const { return *m_modules; }

bool NoNetwork::PutUser(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    for (NoClient* pEachClient : m_clients) {
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
    for (NoClient* pEachClient : m_clients) {
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
    for (NoClient* pEachClient : m_clients) {
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

std::vector<NoChannel*> NoNetwork::GetChans() const { return m_channels; }

NoChannel* NoNetwork::FindChan(NoString sName) const
{
    if (GetIRCSock()) {
        // See https://tools.ietf.org/html/draft-brocklesby-irc-isupport-03#section-3.16
        sName.trimLeft(GetIRCSock()->GetISupport("STATUSMSG", ""));
    }

    for (NoChannel* pChan : m_channels) {
        if (sName.equals(pChan->getName())) {
            return pChan;
        }
    }

    return nullptr;
}

std::vector<NoChannel*> NoNetwork::FindChans(const NoString& sWild) const
{
    std::vector<NoChannel*> vChans;
    vChans.reserve(m_channels.size());
    for (NoChannel* pChan : m_channels) {
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

    for (NoChannel* pEachChan : m_channels) {
        if (pEachChan->getName().equals(pChan->getName())) {
            delete pChan;
            return false;
        }
    }

    m_channels.push_back(pChan);
    return true;
}

bool NoNetwork::AddChan(const NoString& sName, bool bInConfig)
{
    if (sName.empty() || FindChan(sName)) {
        return false;
    }

    NoChannel* pChan = new NoChannel(sName, this, bInConfig);
    m_channels.push_back(pChan);
    return true;
}

bool NoNetwork::DelChan(const NoString& sName)
{
    for (std::vector<NoChannel*>::iterator a = m_channels.begin(); a != m_channels.end(); ++a) {
        if (sName.equals((*a)->getName())) {
            delete *a;
            m_channels.erase(a);
            return true;
        }
    }

    return false;
}

void NoNetwork::JoinChans()
{
    // Avoid divsion by zero, it's bad!
    if (m_channels.empty()) return;

    // We start at a random offset into the channel list so that if your
    // first 3 channels are invite-only and you got MaxJoins == 3, ZNC will
    // still be able to join the rest of your channels.
    uint start = rand() % m_channels.size();
    uint uJoins = m_user->MaxJoins();
    std::set<NoChannel*> sChans;
    for (uint a = 0; a < m_channels.size(); a++) {
        uint idx = (start + a) % m_channels.size();
        NoChannel* pChan = m_channels[idx];
        if (!pChan->isOn() && !pChan->isDisabled()) {
            if (!JoinChan(pChan)) continue;

            sChans.insert(pChan);

            // Limit the number of joins
            if (uJoins != 0 && --uJoins == 0) {
                // Reset the timer.
                m_joinTimer->Reset();
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
    NETWORKMODULECALL(OnJoining(*pChan), m_user, this, nullptr, &bReturn);

    if (bReturn) return false;

    if (m_user->JoinTries() != 0 && pChan->getJoinTries() >= m_user->JoinTries()) {
        PutStatus("The channel " + pChan->getName() + " could not be joined, disabling it.");
        pChan->disable();
    } else {
        pChan->incJoinTries();
        bool bFailed = false;
        NETWORKMODULECALL(OnTimerAutoJoin(*pChan), m_user, this, nullptr, &bFailed);
        if (bFailed) return false;
        return true;
    }
    return false;
}

NoString NoNetwork::GetChanPrefixes() const { return m_chanPrefixes; }
void NoNetwork::SetChanPrefixes(const NoString& s) { m_chanPrefixes = s; }

bool NoNetwork::IsChan(const NoString& sChan) const
{
    if (sChan.empty()) return false; // There is no way this is a chan
    if (GetChanPrefixes().empty()) return true; // We can't know, so we allow everything
    // Thanks to the above if (empty), we can do sChan[0]
    return GetChanPrefixes().find(sChan[0]) != NoString::npos;
}

// Queries

std::vector<NoQuery*> NoNetwork::GetQueries() const { return m_queries; }

NoQuery* NoNetwork::FindQuery(const NoString& sName) const
{
    for (NoQuery* pQuery : m_queries) {
        if (sName.equals(pQuery->getName())) {
            return pQuery;
        }
    }

    return nullptr;
}

std::vector<NoQuery*> NoNetwork::FindQueries(const NoString& sWild) const
{
    std::vector<NoQuery*> vQueries;
    vQueries.reserve(m_queries.size());
    for (NoQuery* pQuery : m_queries) {
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
        m_queries.push_back(pQuery);

        if (m_user->MaxQueryBuffers() > 0) {
            while (m_queries.size() > m_user->MaxQueryBuffers()) {
                delete *m_queries.begin();
                m_queries.erase(m_queries.begin());
            }
        }
    }

    return pQuery;
}

bool NoNetwork::DelQuery(const NoString& sName)
{
    for (std::vector<NoQuery*>::iterator a = m_queries.begin(); a != m_queries.end(); ++a) {
        if (sName.equals((*a)->getName())) {
            delete *a;
            m_queries.erase(a);
            return true;
        }
    }

    return false;
}

// Server list

std::vector<NoServerInfo*> NoNetwork::GetServers() const { return m_servers; }

bool NoNetwork::HasServers() const { return !m_servers.empty(); }

NoServerInfo* NoNetwork::FindServer(const NoString& sName) const
{
    for (NoServerInfo* pServer : m_servers) {
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

    for (std::vector<NoServerInfo*>::iterator it = m_servers.begin(); it != m_servers.end(); ++it, a++) {
        NoServerInfo* pServer = *it;

        if (pServer == pCurServer) bSawCurrentServer = true;

        if (!pServer->host().equals(sName)) continue;

        if (uPort != 0 && pServer->port() != uPort) continue;

        if (!sPass.empty() && pServer->password() != sPass) continue;

        m_servers.erase(it);

        if (pServer == pCurServer) {
            NoIrcSocket* pIRCSock = GetIRCSock();

            // Make sure we don't skip the next server in the list!
            if (m_serverIndex) {
                m_serverIndex--;
            }

            if (pIRCSock) {
                pIRCSock->Quit();
                PutStatus("Your current server was removed, jumping...");
            }
        } else if (!bSawCurrentServer) {
            // Our current server comes after the server which we
            // are removing. This means that it now got a different
            // index in m_vServers!
            m_serverIndex--;
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
    for (NoServerInfo* pServer : m_servers) {
        if (!sName.equals(pServer->host())) continue;

        if (uPort != pServer->port()) continue;

        if (sPass != pServer->password()) continue;

        if (bSSL != pServer->isSsl()) continue;

        // Server is already added
        return false;
    }

    NoServerInfo* pServer = new NoServerInfo(sName, uPort);
    pServer->setPassword(sPass);
    pServer->setPort(uPort);
    m_servers.push_back(pServer);

    CheckIRCConnect();

    return true;
}

NoServerInfo* NoNetwork::GetNextServer()
{
    if (m_servers.empty()) {
        return nullptr;
    }

    if (m_serverIndex >= m_servers.size()) {
        m_serverIndex = 0;
    }

    return m_servers[m_serverIndex++];
}

NoServerInfo* NoNetwork::GetCurrentServer() const
{
    size_t uIdx = (m_serverIndex) ? m_serverIndex - 1 : 0;

    if (uIdx >= m_servers.size()) {
        return nullptr;
    }

    return m_servers[uIdx];
}

void NoNetwork::SetIRCServer(const NoString& s) { m_server = s; }

bool NoNetwork::SetNextServer(const NoServerInfo* pServer)
{
    for (uint a = 0; a < m_servers.size(); a++) {
        if (m_servers[a] == pServer) {
            m_serverIndex = a;
            return true;
        }
    }

    return false;
}

bool NoNetwork::IsLastServer() const { return (m_serverIndex >= m_servers.size()); }

NoStringSet NoNetwork::GetTrustedFingerprints() const { return m_trustedFingerprints; }
void NoNetwork::AddTrustedFingerprint(const NoString& sFP)
{
    m_trustedFingerprints.insert(No::escape(sFP, No::HexColonFormat, No::HexColonFormat));
}
void NoNetwork::DelTrustedFingerprint(const NoString& sFP) { m_trustedFingerprints.erase(sFP); }

NoIrcSocket* NoNetwork::GetIRCSock() const { return m_socket; }
NoString NoNetwork::GetIRCServer() const { return m_server; }
const NoNick& NoNetwork::GetIRCNick() const { return m_ircNick; }

void NoNetwork::SetIRCNick(const NoNick& n)
{
    m_ircNick = n;

    for (NoClient* pClient : m_clients) {
        pClient->SetNick(n.nick());
    }
}

NoString NoNetwork::GetCurNick() const
{
    const NoIrcSocket* pIRCSock = GetIRCSock();

    if (pIRCSock) {
        return pIRCSock->GetNick();
    }

    if (!m_clients.empty()) {
        return m_clients[0]->GetNick();
    }

    return "";
}

bool NoNetwork::IsIRCAway() const { return m_away; }
void NoNetwork::SetIRCAway(bool b) { m_away = b; }

bool NoNetwork::Connect()
{
    if (!GetIRCConnectEnabled() || m_socket || !HasServers()) return false;

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
    pIRCSock->SetSSLTrustedPeerFingerprints(m_trustedFingerprints);

    NO_DEBUG("Connecting user/network [" << m_user->GetUserName() << "/" << m_name << "]");

    bool bAbort = false;
    NETWORKMODULECALL(OnIRCConnecting(pIRCSock), m_user, this, nullptr, &bAbort);
    if (bAbort) {
        NO_DEBUG("Some module aborted the connection attempt");
        PutStatus("Some module aborted the connection attempt");
        delete pIRCSock;
        NoApp::Get().AddNetworkToQueue(this);
        return false;
    }

    NoString sSockName = "IRC::" + m_user->GetUserName() + "::" + m_name;
    NoApp::Get().GetManager().Connect(pServer->host(), pServer->port(), sSockName, 120, bSSL, GetBindHost(), pIRCSock);

    return true;
}

bool NoNetwork::IsIRCConnected() const
{
    const NoIrcSocket* pSock = GetIRCSock();
    return (pSock && pSock->IsAuthed());
}

void NoNetwork::SetIRCSocket(NoIrcSocket* pIRCSock) { m_socket = pIRCSock; }

void NoNetwork::IRCConnected()
{
    if (m_joinDelay > 0) {
        m_joinTimer->Delay(m_joinDelay);
    } else {
        JoinChans();
    }
}

void NoNetwork::IRCDisconnected()
{
    m_socket = nullptr;

    SetIRCServer("");
    m_away = false;

    // Get the reconnect going
    CheckIRCConnect();
}

bool NoNetwork::GetIRCConnectEnabled() const { return m_enabled; }

void NoNetwork::SetIRCConnectEnabled(bool b)
{
    m_enabled = b;

    if (m_enabled) {
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

void NoNetwork::AddRawBuffer(const NoString& sFormat, const NoString& sText) { m_rawBuffer.addMessage(sFormat, sText); }
void NoNetwork::UpdateRawBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText)
{
    m_rawBuffer.updateMessage(sMatch, sFormat, sText);
}
void NoNetwork::UpdateExactRawBuffer(const NoString& sFormat, const NoString& sText)
{
    m_rawBuffer.updateExactMessage(sFormat, sText);
}
void NoNetwork::ClearRawBuffer() { m_rawBuffer.clear(); }

void NoNetwork::AddMotdBuffer(const NoString& sFormat, const NoString& sText) { m_motdBuffer.addMessage(sFormat, sText); }
void NoNetwork::UpdateMotdBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText)
{
    m_motdBuffer.updateMessage(sMatch, sFormat, sText);
}
void NoNetwork::ClearMotdBuffer() { m_motdBuffer.clear(); }

void NoNetwork::AddNoticeBuffer(const NoString& sFormat, const NoString& sText) { m_noticeBuffer.addMessage(sFormat, sText); }
void NoNetwork::UpdateNoticeBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText)
{
    m_noticeBuffer.updateMessage(sMatch, sFormat, sText);
}
void NoNetwork::ClearNoticeBuffer() { m_noticeBuffer.clear(); }

void NoNetwork::ClearQueryBuffer()
{
    std::for_each(m_queries.begin(), m_queries.end(), std::default_delete<NoQuery>());
    m_queries.clear();
}

NoString NoNetwork::GetNick(const bool bAllowDefault) const
{
    if (m_nickName.empty()) {
        return m_user->GetNick(bAllowDefault);
    }

    return m_nickName;
}

NoString NoNetwork::GetAltNick(const bool bAllowDefault) const
{
    if (m_altNick.empty()) {
        return m_user->GetAltNick(bAllowDefault);
    }

    return m_altNick;
}

NoString NoNetwork::GetIdent(const bool bAllowDefault) const
{
    if (m_ident.empty()) {
        return m_user->GetIdent(bAllowDefault);
    }

    return m_ident;
}

NoString NoNetwork::GetRealName() const
{
    if (m_realName.empty()) {
        return m_user->GetRealName();
    }

    return m_realName;
}

NoString NoNetwork::GetBindHost() const
{
    if (m_bindHost.empty()) {
        return m_user->GetBindHost();
    }

    return m_bindHost;
}

NoString NoNetwork::GetEncoding() const { return m_encoding; }

NoString NoNetwork::GetQuitMsg() const
{
    if (m_quitMsg.empty()) {
        return m_user->GetQuitMsg();
    }

    return m_quitMsg;
}

void NoNetwork::SetNick(const NoString& s)
{
    if (m_user->GetNick().equals(s)) {
        m_nickName = "";
    } else {
        m_nickName = s;
    }
}

void NoNetwork::SetAltNick(const NoString& s)
{
    if (m_user->GetAltNick().equals(s)) {
        m_altNick = "";
    } else {
        m_altNick = s;
    }
}

void NoNetwork::SetIdent(const NoString& s)
{
    if (m_user->GetIdent().equals(s)) {
        m_ident = "";
    } else {
        m_ident = s;
    }
}

void NoNetwork::SetRealName(const NoString& s)
{
    if (m_user->GetRealName().equals(s)) {
        m_realName = "";
    } else {
        m_realName = s;
    }
}

void NoNetwork::SetBindHost(const NoString& s)
{
    if (m_user->GetBindHost().equals(s)) {
        m_bindHost = "";
    } else {
        m_bindHost = s;
    }
}

void NoNetwork::SetEncoding(const NoString& s) { m_encoding = s; }

void NoNetwork::SetQuitMsg(const NoString& s)
{
    if (m_user->GetQuitMsg().equals(s)) {
        m_quitMsg = "";
    } else {
        m_quitMsg = s;
    }
}

double NoNetwork::GetFloodRate() const { return m_floodRate; }
ushort NoNetwork::GetFloodBurst() const { return m_floodBurst; }
void NoNetwork::SetFloodRate(double fFloodRate) { m_floodRate = fFloodRate; }
void NoNetwork::SetFloodBurst(ushort uFloodBurst) { m_floodBurst = uFloodBurst; }

ushort NoNetwork::GetJoinDelay() const { return m_joinDelay; }
void NoNetwork::SetJoinDelay(ushort uJoinDelay) { m_joinDelay = uJoinDelay; }

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

    return m_user->ExpandString(sRet, sRet);
}

bool NoNetwork::LoadModule(const NoString& sModName, const NoString& sArgs, const NoString& sNotice, NoString& sError)
{
    No::printAction(sNotice);
    NoString sModRet;

    bool bModRet = GetModules().LoadModule(sModName, sArgs, No::NetworkModule, GetUser(), this, sModRet);

    No::printStatus(bModRet, sModRet);
    if (!bModRet) {
        sError = sModRet;
    }
    return bModRet;
}
