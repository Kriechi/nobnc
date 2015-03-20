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
#include "noircconnection.h"
#include "noserver.h"
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
        NoIrcConnection* pIRCSock = m_pNetwork->GetIRCSock();

        if (pIRCSock && pIRCSock->GetTimeSinceLastDataTransaction() >= NoNetwork::PING_FREQUENCY) {
            pIRCSock->PutIRC("PING :ZNC");
        }

        const std::vector<NoClient*>& vClients = m_pNetwork->GetClients();
        for (NoClient* pClient : vClients) {
            if (pClient->GetTimeSinceLastDataTransaction() >= NoNetwork::PING_FREQUENCY) {
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
    : m_sName(sName), m_pUser(nullptr), m_sNick(""), m_sAltNick(""), m_sIdent(""), m_sRealName(""), m_sBindHost(""),
      m_sEncoding(""), m_sQuitMsg(""), m_ssTrustedFingerprints(), m_pModules(new NoModules), m_vClients(),
      m_pIRCSock(nullptr), m_vChans(), m_vQueries(), m_sChanPrefixes(""), m_bIRCConnectEnabled(true), m_sIRCServer(""),
      m_vServers(), m_uServerIdx(0), m_IRCNick(), m_bIRCAway(false), m_fFloodRate(1), m_uFloodBurst(4), m_RawBuffer(),
      m_MotdBuffer(), m_NoticeBuffer(), m_pPingTimer(nullptr), m_pJoinTimer(nullptr), m_uJoinDelay(0)
{
    SetUser(pUser);

    m_RawBuffer.setLimit(100, true); // This should be more than enough raws, especially since we are buffering the
    // MOTD separately
    m_MotdBuffer.setLimit(200, true); // This should be more than enough motd lines
    m_NoticeBuffer.setLimit(250, true);

    m_pPingTimer = new NoNetworkPingTimer(this);
    NoApp::Get().GetManager().AddCron(m_pPingTimer);

    m_pJoinTimer = new NoNetworkJoinTimer(this);
    NoApp::Get().GetManager().AddCron(m_pJoinTimer);

    SetIRCConnectEnabled(true);
}

NoNetwork::NoNetwork(NoUser* pUser, const NoNetwork& Network) : NoNetwork(pUser, "") { Clone(Network); }

void NoNetwork::Clone(const NoNetwork& Network, bool bCloneName)
{
    if (bCloneName) {
        m_sName = Network.GetName();
    }

    m_fFloodRate = Network.GetFloodRate();
    m_uFloodBurst = Network.GetFloodBurst();
    m_uJoinDelay = Network.GetJoinDelay();

    SetNick(Network.GetNick());
    SetAltNick(Network.GetAltNick());
    SetIdent(Network.GetIdent());
    SetRealName(Network.GetRealName());
    SetBindHost(Network.GetBindHost());
    SetEncoding(Network.GetEncoding());
    SetQuitMsg(Network.GetQuitMsg());
    m_ssTrustedFingerprints = Network.m_ssTrustedFingerprints;

    // Servers
    const std::vector<NoServer*>& vServers = Network.GetServers();
    NoString sServer;
    NoServer* pCurServ = GetCurrentServer();

    if (pCurServ) {
        sServer = pCurServ->GetName();
    }

    DelServers();

    for (NoServer* pServer : vServers) {
        AddServer(pServer->GetName(), pServer->GetPort(), pServer->GetPass(), pServer->IsSSL());
    }

    m_uServerIdx = 0;
    for (size_t a = 0; a < m_vServers.size(); a++) {
        if (sServer.equals(m_vServers[a]->GetName())) {
            m_uServerIdx = a + 1;
            break;
        }
    }
    if (m_uServerIdx == 0) {
        m_uServerIdx = m_vServers.size();
        NoIrcConnection* pSock = GetIRCSock();

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

    for (NoChannel* pChan : m_vChans) {
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
            vCurMods.LoadModule(pNewMod->GetModName(), pNewMod->GetArgs(), No::NetworkModule, m_pUser, this, sModRet);
        } else if (pNewMod->GetArgs() != pCurMod->GetArgs()) {
            vCurMods.ReloadModule(pNewMod->GetModName(), pNewMod->GetArgs(), m_pUser, this, sModRet);
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
    if (m_pIRCSock) {
        NoApp::Get().GetManager().DelSockByAddr(m_pIRCSock);
        m_pIRCSock = nullptr;
    }

    // Delete clients
    while (!m_vClients.empty()) {
        NoApp::Get().GetManager().DelSockByAddr(m_vClients[0]);
    }
    m_vClients.clear();

    // Delete servers
    DelServers();

    // Delete modules (this unloads all modules)
    delete m_pModules;
    m_pModules = nullptr;

    // Delete Channels
    for (NoChannel* pChan : m_vChans) {
        delete pChan;
    }
    m_vChans.clear();

    // Delete Queries
    for (NoQuery* pQuery : m_vQueries) {
        delete pQuery;
    }
    m_vQueries.clear();

    SetUser(nullptr);

    // Make sure we are not in the connection queue
    NoApp::Get().GetConnectionQueue().remove(this);

    NoApp::Get().GetManager().DelCronByAddr(m_pPingTimer);
    NoApp::Get().GetManager().DelCronByAddr(m_pJoinTimer);
}

void NoNetwork::DelServers()
{
    for (NoServer* pServer : m_vServers) {
        delete pServer;
    }
    m_vServers.clear();
}

NoString NoNetwork::GetNetworkPath() const
{
    NoString sNetworkPath = m_pUser->GetUserPath() + "/networks/" + m_sName;

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
            NoString sModName = sValue.token(0);
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
            NoString sArgs = sValue.tokens(1);

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
        NoSettings* pSubConf = subIt->second.m_pSubConfig;
        NoChannel* pChan = new NoChannel(sChanName, this, true, pSubConf);

        if (!pSubConf->empty()) {
            sError = "Unhandled lines in config for User [" + m_pUser->GetUserName() + "], Network [" + GetName() +
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

    if (!m_sNick.empty()) {
        config.AddKeyValuePair("Nick", m_sNick);
    }

    if (!m_sAltNick.empty()) {
        config.AddKeyValuePair("AltNick", m_sAltNick);
    }

    if (!m_sIdent.empty()) {
        config.AddKeyValuePair("Ident", m_sIdent);
    }

    if (!m_sRealName.empty()) {
        config.AddKeyValuePair("RealName", m_sRealName);
    }
    if (!m_sBindHost.empty()) {
        config.AddKeyValuePair("BindHost", m_sBindHost);
    }

    config.AddKeyValuePair("IRCConnectEnabled", NoString(GetIRCConnectEnabled()));
    config.AddKeyValuePair("FloodRate", NoString(GetFloodRate()));
    config.AddKeyValuePair("FloodBurst", NoString(GetFloodBurst()));
    config.AddKeyValuePair("JoinDelay", NoString(GetJoinDelay()));
    config.AddKeyValuePair("Encoding", m_sEncoding);

    if (!m_sQuitMsg.empty()) {
        config.AddKeyValuePair("QuitMsg", m_sQuitMsg);
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
    for (NoServer* pServer : m_vServers) {
        config.AddKeyValuePair("Server", pServer->GetString());
    }

    for (const NoString& sFP : m_ssTrustedFingerprints) {
        config.AddKeyValuePair("TrustedServerFingerprint", sFP);
    }

    // Chans
    for (NoChannel* pChan : m_vChans) {
        if (pChan->inConfig()) {
            config.AddSubConfig("Chan", pChan->getName(), pChan->toConfig());
        }
    }

    return config;
}

void NoNetwork::BounceAllClients()
{
    for (NoClient* pClient : m_vClients) {
        pClient->BouncedOff();
    }

    m_vClients.clear();
}

bool NoNetwork::IsUserAttached() const { return !m_vClients.empty(); }

bool NoNetwork::IsUserOnline() const
{
    for (NoClient* pClient : m_vClients) {
        if (!pClient->IsAway()) {
            return true;
        }
    }

    return false;
}

void NoNetwork::ClientConnected(NoClient* pClient)
{
    if (!m_pUser->MultiClients()) {
        BounceAllClients();
    }

    m_vClients.push_back(pClient);

    size_t uIdx, uSize;

    pClient->SetPlaybackActive(true);

    if (m_RawBuffer.isEmpty()) {
        pClient->PutClient(":irc.znc.in 001 " + pClient->GetNick() + " :- Welcome to ZNC -");
    } else {
        const NoString& sClientNick = pClient->GetNick(false);
        NoStringMap msParams;
        msParams["target"] = sClientNick;

        uSize = m_RawBuffer.size();
        for (uIdx = 0; uIdx < uSize; uIdx++) {
            pClient->PutClient(m_RawBuffer.getMessage(uIdx, *pClient, msParams));
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
    uSize = m_MotdBuffer.size();
    if (uSize > 0) {
        for (uIdx = 0; uIdx < uSize; uIdx++) {
            pClient->PutClient(m_MotdBuffer.getMessage(uIdx, *pClient, msParams));
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

    if (m_bIRCAway) {
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

    bool bClearQuery = m_pUser->AutoClearQueryBuffer();
    for (NoQuery* pQuery : m_vQueries) {
        pQuery->sendBuffer(pClient);
        if (bClearQuery) {
            delete pQuery;
        }
    }
    if (bClearQuery) {
        m_vQueries.clear();
    }

    uSize = m_NoticeBuffer.size();
    for (uIdx = 0; uIdx < uSize; uIdx++) {
        const NoMessage& BufLine = m_NoticeBuffer.getMessage(uIdx);
        NoString sLine = BufLine.GetLine(*pClient, msParams);
        bool bContinue = false;
        NETWORKMODULECALL(OnPrivBufferPlayLine2(*pClient, sLine, BufLine.GetTime()), m_pUser, this, nullptr, &bContinue);
        if (bContinue) continue;
        pClient->PutClient(sLine);
    }
    m_NoticeBuffer.clear();

    pClient->SetPlaybackActive(false);

    // Tell them why they won't connect
    if (!GetIRCConnectEnabled())
        pClient->PutStatus("You are currently disconnected from IRC. "
                           "Use 'connect' to reconnect.");
}

void NoNetwork::ClientDisconnected(NoClient* pClient)
{
    auto it = std::find(m_vClients.begin(), m_vClients.end(), pClient);
    if (it != m_vClients.end()) {
        m_vClients.erase(it);
    }
}

NoUser* NoNetwork::GetUser() const { return m_pUser; }

NoString NoNetwork::GetName() const { return m_sName; }

bool NoNetwork::IsNetworkAttached() const { return !m_vClients.empty(); }
std::vector<NoClient*> NoNetwork::GetClients() const { return m_vClients; }

std::vector<NoClient*> NoNetwork::FindClients(const NoString& sIdentifier) const
{
    std::vector<NoClient*> vClients;
    for (NoClient* pClient : m_vClients) {
        if (pClient->GetIdentifier().equals(sIdentifier)) {
            vClients.push_back(pClient);
        }
    }

    return vClients;
}

void NoNetwork::SetUser(NoUser* pUser)
{
    for (NoClient* pClient : m_vClients) {
        pClient->PutStatus("This network is being deleted or moved to another user.");
        pClient->SetNetwork(nullptr);
    }

    m_vClients.clear();

    if (m_pUser) {
        m_pUser->RemoveNetwork(this);
    }

    m_pUser = pUser;
    if (m_pUser) {
        m_pUser->AddNetwork(this);
    }
}

bool NoNetwork::SetName(const NoString& sName)
{
    if (IsValidNetwork(sName)) {
        m_sName = sName;
        return true;
    }

    return false;
}

NoModules& NoNetwork::GetModules() { return *m_pModules; }
const NoModules& NoNetwork::GetModules() const { return *m_pModules; }

bool NoNetwork::PutUser(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    for (NoClient* pEachClient : m_vClients) {
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
    for (NoClient* pEachClient : m_vClients) {
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
    for (NoClient* pEachClient : m_vClients) {
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

std::vector<NoChannel*> NoNetwork::GetChans() const { return m_vChans; }

NoChannel* NoNetwork::FindChan(NoString sName) const
{
    if (GetIRCSock()) {
        // See https://tools.ietf.org/html/draft-brocklesby-irc-isupport-03#section-3.16
        sName.trimLeft(GetIRCSock()->GetISupport("STATUSMSG", ""));
    }

    for (NoChannel* pChan : m_vChans) {
        if (sName.equals(pChan->getName())) {
            return pChan;
        }
    }

    return nullptr;
}

std::vector<NoChannel*> NoNetwork::FindChans(const NoString& sWild) const
{
    std::vector<NoChannel*> vChans;
    vChans.reserve(m_vChans.size());
    const NoString sLower = sWild.toLower();
    for (NoChannel* pChan : m_vChans) {
        if (pChan->getName().toLower().wildCmp(sLower)) vChans.push_back(pChan);
    }
    return vChans;
}

bool NoNetwork::AddChan(NoChannel* pChan)
{
    if (!pChan) {
        return false;
    }

    for (NoChannel* pEachChan : m_vChans) {
        if (pEachChan->getName().equals(pChan->getName())) {
            delete pChan;
            return false;
        }
    }

    m_vChans.push_back(pChan);
    return true;
}

bool NoNetwork::AddChan(const NoString& sName, bool bInConfig)
{
    if (sName.empty() || FindChan(sName)) {
        return false;
    }

    NoChannel* pChan = new NoChannel(sName, this, bInConfig);
    m_vChans.push_back(pChan);
    return true;
}

bool NoNetwork::DelChan(const NoString& sName)
{
    for (std::vector<NoChannel*>::iterator a = m_vChans.begin(); a != m_vChans.end(); ++a) {
        if (sName.equals((*a)->getName())) {
            delete *a;
            m_vChans.erase(a);
            return true;
        }
    }

    return false;
}

void NoNetwork::JoinChans()
{
    // Avoid divsion by zero, it's bad!
    if (m_vChans.empty()) return;

    // We start at a random offset into the channel list so that if your
    // first 3 channels are invite-only and you got MaxJoins == 3, ZNC will
    // still be able to join the rest of your channels.
    uint start = rand() % m_vChans.size();
    uint uJoins = m_pUser->MaxJoins();
    std::set<NoChannel*> sChans;
    for (uint a = 0; a < m_vChans.size(); a++) {
        uint idx = (start + a) % m_vChans.size();
        NoChannel* pChan = m_vChans[idx];
        if (!pChan->isOn() && !pChan->isDisabled()) {
            if (!JoinChan(pChan)) continue;

            sChans.insert(pChan);

            // Limit the number of joins
            if (uJoins != 0 && --uJoins == 0) {
                // Reset the timer.
                m_pJoinTimer->Reset();
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
    NETWORKMODULECALL(OnJoining(*pChan), m_pUser, this, nullptr, &bReturn);

    if (bReturn) return false;

    if (m_pUser->JoinTries() != 0 && pChan->getJoinTries() >= m_pUser->JoinTries()) {
        PutStatus("The channel " + pChan->getName() + " could not be joined, disabling it.");
        pChan->disable();
    } else {
        pChan->incJoinTries();
        bool bFailed = false;
        NETWORKMODULECALL(OnTimerAutoJoin(*pChan), m_pUser, this, nullptr, &bFailed);
        if (bFailed) return false;
        return true;
    }
    return false;
}

NoString NoNetwork::GetChanPrefixes() const { return m_sChanPrefixes; }
void NoNetwork::SetChanPrefixes(const NoString& s) { m_sChanPrefixes = s; }

bool NoNetwork::IsChan(const NoString& sChan) const
{
    if (sChan.empty()) return false; // There is no way this is a chan
    if (GetChanPrefixes().empty()) return true; // We can't know, so we allow everything
    // Thanks to the above if (empty), we can do sChan[0]
    return GetChanPrefixes().find(sChan[0]) != NoString::npos;
}

// Queries

std::vector<NoQuery*> NoNetwork::GetQueries() const { return m_vQueries; }

NoQuery* NoNetwork::FindQuery(const NoString& sName) const
{
    for (NoQuery* pQuery : m_vQueries) {
        if (sName.equals(pQuery->getName())) {
            return pQuery;
        }
    }

    return nullptr;
}

std::vector<NoQuery*> NoNetwork::FindQueries(const NoString& sWild) const
{
    std::vector<NoQuery*> vQueries;
    vQueries.reserve(m_vQueries.size());
    const NoString sLower = sWild.toLower();
    for (NoQuery* pQuery : m_vQueries) {
        if (pQuery->getName().toLower().wildCmp(sLower)) vQueries.push_back(pQuery);
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
        m_vQueries.push_back(pQuery);

        if (m_pUser->MaxQueryBuffers() > 0) {
            while (m_vQueries.size() > m_pUser->MaxQueryBuffers()) {
                delete *m_vQueries.begin();
                m_vQueries.erase(m_vQueries.begin());
            }
        }
    }

    return pQuery;
}

bool NoNetwork::DelQuery(const NoString& sName)
{
    for (std::vector<NoQuery*>::iterator a = m_vQueries.begin(); a != m_vQueries.end(); ++a) {
        if (sName.equals((*a)->getName())) {
            delete *a;
            m_vQueries.erase(a);
            return true;
        }
    }

    return false;
}

// Server list

std::vector<NoServer*> NoNetwork::GetServers() const { return m_vServers; }

bool NoNetwork::HasServers() const { return !m_vServers.empty(); }

NoServer* NoNetwork::FindServer(const NoString& sName) const
{
    for (NoServer* pServer : m_vServers) {
        if (sName.equals(pServer->GetName())) {
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
    NoServer* pCurServer = GetCurrentServer();

    for (std::vector<NoServer*>::iterator it = m_vServers.begin(); it != m_vServers.end(); ++it, a++) {
        NoServer* pServer = *it;

        if (pServer == pCurServer) bSawCurrentServer = true;

        if (!pServer->GetName().equals(sName)) continue;

        if (uPort != 0 && pServer->GetPort() != uPort) continue;

        if (!sPass.empty() && pServer->GetPass() != sPass) continue;

        m_vServers.erase(it);

        if (pServer == pCurServer) {
            NoIrcConnection* pIRCSock = GetIRCSock();

            // Make sure we don't skip the next server in the list!
            if (m_uServerIdx) {
                m_uServerIdx--;
            }

            if (pIRCSock) {
                pIRCSock->Quit();
                PutStatus("Your current server was removed, jumping...");
            }
        } else if (!bSawCurrentServer) {
            // Our current server comes after the server which we
            // are removing. This means that it now got a different
            // index in m_vServers!
            m_uServerIdx--;
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

    NoString sHost = sLine.token(0);
    NoString sPort = sLine.token(1);

    if (sPort.left(1) == "+") {
        bSSL = true;
        sPort.leftChomp(1);
    }

    ushort uPort = sPort.toUShort();
    NoString sPass = sLine.tokens(2);

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
    for (NoServer* pServer : m_vServers) {
        if (!sName.equals(pServer->GetName())) continue;

        if (uPort != pServer->GetPort()) continue;

        if (sPass != pServer->GetPass()) continue;

        if (bSSL != pServer->IsSSL()) continue;

        // Server is already added
        return false;
    }

    NoServer* pServer = new NoServer(sName, uPort, sPass, bSSL);
    m_vServers.push_back(pServer);

    CheckIRCConnect();

    return true;
}

NoServer* NoNetwork::GetNextServer()
{
    if (m_vServers.empty()) {
        return nullptr;
    }

    if (m_uServerIdx >= m_vServers.size()) {
        m_uServerIdx = 0;
    }

    return m_vServers[m_uServerIdx++];
}

NoServer* NoNetwork::GetCurrentServer() const
{
    size_t uIdx = (m_uServerIdx) ? m_uServerIdx - 1 : 0;

    if (uIdx >= m_vServers.size()) {
        return nullptr;
    }

    return m_vServers[uIdx];
}

void NoNetwork::SetIRCServer(const NoString& s) { m_sIRCServer = s; }

bool NoNetwork::SetNextServer(const NoServer* pServer)
{
    for (uint a = 0; a < m_vServers.size(); a++) {
        if (m_vServers[a] == pServer) {
            m_uServerIdx = a;
            return true;
        }
    }

    return false;
}

bool NoNetwork::IsLastServer() const { return (m_uServerIdx >= m_vServers.size()); }

NoStringSet NoNetwork::GetTrustedFingerprints() const { return m_ssTrustedFingerprints; }
void NoNetwork::AddTrustedFingerprint(const NoString& sFP)
{
    m_ssTrustedFingerprints.insert(No::escape(sFP, No::HexColonFormat, No::HexColonFormat));
}
void NoNetwork::DelTrustedFingerprint(const NoString& sFP) { m_ssTrustedFingerprints.erase(sFP); }

NoIrcConnection* NoNetwork::GetIRCSock() const { return m_pIRCSock; }
NoString NoNetwork::GetIRCServer() const { return m_sIRCServer; }
const NoNick& NoNetwork::GetIRCNick() const { return m_IRCNick; }

void NoNetwork::SetIRCNick(const NoNick& n)
{
    m_IRCNick = n;

    for (NoClient* pClient : m_vClients) {
        pClient->SetNick(n.nick());
    }
}

NoString NoNetwork::GetCurNick() const
{
    const NoIrcConnection* pIRCSock = GetIRCSock();

    if (pIRCSock) {
        return pIRCSock->GetNick();
    }

    if (!m_vClients.empty()) {
        return m_vClients[0]->GetNick();
    }

    return "";
}

bool NoNetwork::IsIRCAway() const { return m_bIRCAway; }
void NoNetwork::SetIRCAway(bool b) { m_bIRCAway = b; }

bool NoNetwork::Connect()
{
    if (!GetIRCConnectEnabled() || m_pIRCSock || !HasServers()) return false;

    NoServer* pServer = GetNextServer();
    if (!pServer) return false;

    if (NoApp::Get().GetServerThrottle(pServer->GetName())) {
        // Can't connect right now, schedule retry later
        NoApp::Get().AddNetworkToQueue(this);
        return false;
    }

    NoApp::Get().AddServerThrottle(pServer->GetName());

    bool bSSL = pServer->IsSSL();
#ifndef HAVE_LIBSSL
    if (bSSL) {
        PutStatus("Cannot connect to [" + pServer->GetString(false) + "], ZNC is not compiled with SSL.");
        NoApp::Get().AddNetworkToQueue(this);
        return false;
    }
#endif

    NoIrcConnection* pIRCSock = new NoIrcConnection(this);
    pIRCSock->SetPass(pServer->GetPass());
    pIRCSock->SetSSLTrustedPeerFingerprints(m_ssTrustedFingerprints);

    NO_DEBUG("Connecting user/network [" << m_pUser->GetUserName() << "/" << m_sName << "]");

    bool bAbort = false;
    NETWORKMODULECALL(OnIRCConnecting(pIRCSock), m_pUser, this, nullptr, &bAbort);
    if (bAbort) {
        NO_DEBUG("Some module aborted the connection attempt");
        PutStatus("Some module aborted the connection attempt");
        delete pIRCSock;
        NoApp::Get().AddNetworkToQueue(this);
        return false;
    }

    NoString sSockName = "IRC::" + m_pUser->GetUserName() + "::" + m_sName;
    NoApp::Get().GetManager().Connect(pServer->GetName(), pServer->GetPort(), sSockName, 120, bSSL, GetBindHost(), pIRCSock);

    return true;
}

bool NoNetwork::IsIRCConnected() const
{
    const NoIrcConnection* pSock = GetIRCSock();
    return (pSock && pSock->IsAuthed());
}

void NoNetwork::SetIRCSocket(NoIrcConnection* pIRCSock) { m_pIRCSock = pIRCSock; }

void NoNetwork::IRCConnected()
{
    if (m_uJoinDelay > 0) {
        m_pJoinTimer->Delay(m_uJoinDelay);
    } else {
        JoinChans();
    }
}

void NoNetwork::IRCDisconnected()
{
    m_pIRCSock = nullptr;

    SetIRCServer("");
    m_bIRCAway = false;

    // Get the reconnect going
    CheckIRCConnect();
}

bool NoNetwork::GetIRCConnectEnabled() const { return m_bIRCConnectEnabled; }

void NoNetwork::SetIRCConnectEnabled(bool b)
{
    m_bIRCConnectEnabled = b;

    if (m_bIRCConnectEnabled) {
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
    NoIrcConnection* pIRCSock = GetIRCSock();

    if (!pIRCSock) {
        return false;
    }

    pIRCSock->PutIRC(sLine);
    return true;
}

void NoNetwork::AddRawBuffer(const NoString& sFormat, const NoString& sText) { m_RawBuffer.addMessage(sFormat, sText); }
void NoNetwork::UpdateRawBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText)
{
    m_RawBuffer.updateMessage(sMatch, sFormat, sText);
}
void NoNetwork::UpdateExactRawBuffer(const NoString& sFormat, const NoString& sText)
{
    m_RawBuffer.updateExactMessage(sFormat, sText);
}
void NoNetwork::ClearRawBuffer() { m_RawBuffer.clear(); }

void NoNetwork::AddMotdBuffer(const NoString& sFormat, const NoString& sText) { m_MotdBuffer.addMessage(sFormat, sText); }
void NoNetwork::UpdateMotdBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText)
{
    m_MotdBuffer.updateMessage(sMatch, sFormat, sText);
}
void NoNetwork::ClearMotdBuffer() { m_MotdBuffer.clear(); }

void NoNetwork::AddNoticeBuffer(const NoString& sFormat, const NoString& sText) { m_NoticeBuffer.addMessage(sFormat, sText); }
void NoNetwork::UpdateNoticeBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText)
{
    m_NoticeBuffer.updateMessage(sMatch, sFormat, sText);
}
void NoNetwork::ClearNoticeBuffer() { m_NoticeBuffer.clear(); }

void NoNetwork::ClearQueryBuffer()
{
    std::for_each(m_vQueries.begin(), m_vQueries.end(), std::default_delete<NoQuery>());
    m_vQueries.clear();
}

NoString NoNetwork::GetNick(const bool bAllowDefault) const
{
    if (m_sNick.empty()) {
        return m_pUser->GetNick(bAllowDefault);
    }

    return m_sNick;
}

NoString NoNetwork::GetAltNick(const bool bAllowDefault) const
{
    if (m_sAltNick.empty()) {
        return m_pUser->GetAltNick(bAllowDefault);
    }

    return m_sAltNick;
}

NoString NoNetwork::GetIdent(const bool bAllowDefault) const
{
    if (m_sIdent.empty()) {
        return m_pUser->GetIdent(bAllowDefault);
    }

    return m_sIdent;
}

NoString NoNetwork::GetRealName() const
{
    if (m_sRealName.empty()) {
        return m_pUser->GetRealName();
    }

    return m_sRealName;
}

NoString NoNetwork::GetBindHost() const
{
    if (m_sBindHost.empty()) {
        return m_pUser->GetBindHost();
    }

    return m_sBindHost;
}

NoString NoNetwork::GetEncoding() const { return m_sEncoding; }

NoString NoNetwork::GetQuitMsg() const
{
    if (m_sQuitMsg.empty()) {
        return m_pUser->GetQuitMsg();
    }

    return m_sQuitMsg;
}

void NoNetwork::SetNick(const NoString& s)
{
    if (m_pUser->GetNick().equals(s)) {
        m_sNick = "";
    } else {
        m_sNick = s;
    }
}

void NoNetwork::SetAltNick(const NoString& s)
{
    if (m_pUser->GetAltNick().equals(s)) {
        m_sAltNick = "";
    } else {
        m_sAltNick = s;
    }
}

void NoNetwork::SetIdent(const NoString& s)
{
    if (m_pUser->GetIdent().equals(s)) {
        m_sIdent = "";
    } else {
        m_sIdent = s;
    }
}

void NoNetwork::SetRealName(const NoString& s)
{
    if (m_pUser->GetRealName().equals(s)) {
        m_sRealName = "";
    } else {
        m_sRealName = s;
    }
}

void NoNetwork::SetBindHost(const NoString& s)
{
    if (m_pUser->GetBindHost().equals(s)) {
        m_sBindHost = "";
    } else {
        m_sBindHost = s;
    }
}

void NoNetwork::SetEncoding(const NoString& s) { m_sEncoding = s; }

void NoNetwork::SetQuitMsg(const NoString& s)
{
    if (m_pUser->GetQuitMsg().equals(s)) {
        m_sQuitMsg = "";
    } else {
        m_sQuitMsg = s;
    }
}

double NoNetwork::GetFloodRate() const { return m_fFloodRate; }
ushort NoNetwork::GetFloodBurst() const { return m_uFloodBurst; }
void NoNetwork::SetFloodRate(double fFloodRate) { m_fFloodRate = fFloodRate; }
void NoNetwork::SetFloodBurst(ushort uFloodBurst) { m_uFloodBurst = uFloodBurst; }

ushort NoNetwork::GetJoinDelay() const { return m_uJoinDelay; }
void NoNetwork::SetJoinDelay(ushort uJoinDelay) { m_uJoinDelay = uJoinDelay; }

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

    return m_pUser->ExpandString(sRet, sRet);
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
