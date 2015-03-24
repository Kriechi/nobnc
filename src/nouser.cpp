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

#include "nouser.h"
#include "nosettings.h"
#include "nofile.h"
#include "nodir.h"
#include "nonetwork.h"
#include "noircsocket.h"
#include "nochannel.h"
#include "noclient.h"
#include "nomodulecall.h"
#include "noapp.h"
#include "noregistry.h"
#include "Csocket/Csocket.h"
#include <math.h>
#include <algorithm>

class NoUserTimer : public CCron
{
public:
    NoUserTimer(NoUser* pUser) : CCron(), m_pUser(pUser)
    {
        SetName("NoUserTimer::" + m_pUser->GetUserName());
        Start(NoNetwork::PING_SLACK);
    }

protected:
    void RunJob() override
    {
        const std::vector<NoClient*>& vUserClients = m_pUser->GetUserClients();

        for (NoClient* pUserClient : vUserClients) {
            if (pUserClient->GetSocket()->GetTimeSinceLastDataTransaction() >= NoNetwork::PING_FREQUENCY) {
                pUserClient->PutClient("PING :ZNC");
            }
        }
    }

    NoUser* m_pUser;
};

class NoUserPrivate
{
public:
    NoString userName = "";
    NoString cleanUserName = "";
    NoString nickName = "";
    NoString altNick = "";
    NoString ident = "";
    NoString realName = "";
    NoString bindHost = "";
    NoString dccBindHost = "";
    NoString password = "";
    NoString passwordSalt = "";
    NoString statusPrefix = "*";
    NoString defaultChanModes = "";
    NoString clientEncoding = "";

    NoString quitMsg = "";
    NoStringMap ctcpReplies;
    NoString timestampFormat = "[%H:%M:%S]";
    NoString timezone = "";
    NoUser::eHashType hashType = NoUser::HASH_NONE;

    NoString userPath = "";

    bool multiClients = true;
    bool denyLoadMod = false;
    bool admin = false;
    bool denySetBindHost = false;
    bool autoClearChanBuffer = true;
    bool autoClearQueryBuffer = true;
    bool beingDeleted = false;
    bool appendTimestamp = false;
    bool prependTimestamp = true;

    NoUserTimer* userTimer = nullptr;

    std::vector<NoNetwork*> networks;
    std::vector<NoClient*> clients;
    std::set<NoString> allowedHosts;
    uint bufferCount = 50;
    ulonglong bytesRead = 0;
    ulonglong bytesWritten = 0;
    uint maxJoinTries = 10;
    uint maxNetworks = 1;
    uint maxQueryBuffers = 50;
    uint maxJoins = 0;
    NoString skinName = "";

    NoModules* modules = nullptr;
};

NoUser::NoUser(const NoString& sUserName) : d(new NoUserPrivate)
{
    d->userName = sUserName;
    d->cleanUserName = MakeCleanUserName(sUserName);
    d->ident = d->cleanUserName;
    d->realName = sUserName;
    d->userPath = NoApp::Get().GetUserPath() + "/" + sUserName;
    d->modules = new NoModules;
    d->userTimer = new NoUserTimer(this);
    NoApp::Get().GetManager().AddCron(d->userTimer);
}

NoUser::~NoUser()
{
    // Delete networks
    while (!d->networks.empty()) {
        delete *d->networks.begin();
    }

    // Delete clients
    while (!d->clients.empty()) {
        NoApp::Get().GetManager().DelSockByAddr(d->clients[0]->GetSocket());
    }
    d->clients.clear();

    // Delete modules (unloads all modules!)
    delete d->modules;
    d->modules = nullptr;

    NoApp::Get().GetManager().DelCronByAddr(d->userTimer);

    NoApp::Get().AddBytesRead(BytesRead());
    NoApp::Get().AddBytesWritten(BytesWritten());
}

template <class T> struct TOption
{
    const char* name;
    void (NoUser::*pSetter)(T);
};

bool NoUser::ParseConfig(NoSettings* pConfig, NoString& sError)
{
    TOption<const NoString&> StringOptions[] = {
        { "nick", &NoUser::SetNick },
        { "quitmsg", &NoUser::SetQuitMsg },
        { "altnick", &NoUser::SetAltNick },
        { "ident", &NoUser::SetIdent },
        { "realname", &NoUser::SetRealName },
        { "chanmodes", &NoUser::SetDefaultChanModes },
        { "bindhost", &NoUser::SetBindHost },
        { "vhost", &NoUser::SetBindHost },
        { "dccbindhost", &NoUser::SetDCCBindHost },
        { "dccvhost", &NoUser::SetDCCBindHost },
        { "timestampformat", &NoUser::SetTimestampFormat },
        { "skin", &NoUser::SetSkinName },
        { "clientencoding", &NoUser::SetClientEncoding },
    };
    TOption<uint> UIntOptions[] = {
        { "jointries", &NoUser::SetJoinTries },
        { "maxnetworks", &NoUser::SetMaxNetworks },
        { "maxquerybuffers", &NoUser::SetMaxQueryBuffers },
        { "maxjoins", &NoUser::SetMaxJoins },
    };
    TOption<bool> BoolOptions[] = {
        { "keepbuffer", &NoUser::SetKeepBuffer }, // XXX compatibility crap from pre-0.207
        { "autoclearchanbuffer", &NoUser::SetAutoClearChanBuffer },
        { "autoclearquerybuffer", &NoUser::SetAutoClearQueryBuffer },
        { "multiclients", &NoUser::SetMultiClients },
        { "denyloadmod", &NoUser::SetDenyLoadMod },
        { "admin", &NoUser::SetAdmin },
        { "denysetbindhost", &NoUser::SetDenySetBindHost },
        { "denysetvhost", &NoUser::SetDenySetBindHost },
        { "appendtimestamp", &NoUser::SetTimestampAppend },
        { "prependtimestamp", &NoUser::SetTimestampPrepend },
    };

    for (const auto& Option : StringOptions) {
        NoString sValue;
        if (pConfig->FindStringEntry(Option.name, sValue)) (this->*Option.pSetter)(sValue);
    }
    for (const auto& Option : UIntOptions) {
        NoString sValue;
        if (pConfig->FindStringEntry(Option.name, sValue)) (this->*Option.pSetter)(sValue.toUInt());
    }
    for (const auto& Option : BoolOptions) {
        NoString sValue;
        if (pConfig->FindStringEntry(Option.name, sValue)) (this->*Option.pSetter)(sValue.toBool());
    }

    NoStringVector vsList;
    pConfig->FindStringVector("allow", vsList);
    for (const NoString& sHost : vsList) {
        AddAllowedHost(sHost);
    }
    pConfig->FindStringVector("ctcpreply", vsList);
    for (const NoString& sReply : vsList) {
        AddCTCPReply(No::token(sReply, 0), No::tokens(sReply, 1));
    }

    NoString sValue;

    NoString sDCCLookupValue;
    pConfig->FindStringEntry("dcclookupmethod", sDCCLookupValue);
    if (pConfig->FindStringEntry("bouncedccs", sValue)) {
        if (sValue.toBool()) {
            No::printAction("Loading Module [bouncedcc]");
            NoString sModRet;
            bool bModRet = GetModules().LoadModule("bouncedcc", "", No::UserModule, this, nullptr, sModRet);

            No::printStatus(bModRet, sModRet);
            if (!bModRet) {
                sError = sModRet;
                return false;
            }

            if (sDCCLookupValue.equals("Client")) {
                NoModule* pMod = GetModules().FindModule("bouncedcc");
                if (pMod) {
                    NoRegistry registry(pMod);
                    registry.setValue("UseClientIP", "1");
                }
            }
        }
    }
    if (pConfig->FindStringEntry("buffer", sValue)) SetBufferCount(sValue.toUInt(), true);
    if (pConfig->FindStringEntry("awaysuffix", sValue)) {
        No::printMessage("WARNING: AwaySuffix has been deprecated, instead try -> LoadModule = awaynick %nick%_" + sValue);
    }
    if (pConfig->FindStringEntry("autocycle", sValue)) {
        if (sValue.equals("true"))
            No::printError("WARNING: AutoCycle has been removed, instead try -> LoadModule = autocycle");
    }
    if (pConfig->FindStringEntry("keepnick", sValue)) {
        if (sValue.equals("true"))
            No::printError("WARNING: KeepNick has been deprecated, instead try -> LoadModule = keepnick");
    }
    if (pConfig->FindStringEntry("statusprefix", sValue)) {
        if (!SetStatusPrefix(sValue)) {
            sError = "Invalid StatusPrefix [" + sValue + "] Must be 1-5 chars, no spaces.";
            No::printError(sError);
            return false;
        }
    }
    if (pConfig->FindStringEntry("timezone", sValue)) {
        SetTimezone(sValue);
    }
    if (pConfig->FindStringEntry("timezoneoffset", sValue)) {
        if (fabs(sValue.toDouble()) > 0.1) {
            No::printError("WARNING: TimezoneOffset has been deprecated, now you can set your timezone by name");
        }
    }
    if (pConfig->FindStringEntry("timestamp", sValue)) {
        if (!sValue.trim_n().equals("true")) {
            if (sValue.trim_n().equals("append")) {
                SetTimestampAppend(true);
                SetTimestampPrepend(false);
            } else if (sValue.trim_n().equals("prepend")) {
                SetTimestampAppend(false);
                SetTimestampPrepend(true);
            } else if (sValue.trim_n().equals("false")) {
                SetTimestampAppend(false);
                SetTimestampPrepend(false);
            } else {
                SetTimestampFormat(sValue);
            }
        }
    }
    pConfig->FindStringEntry("pass", sValue);
    // There are different formats for this available:
    // Pass = <plain text>
    // Pass = <md5 hash> -
    // Pass = plain#<plain text>
    // Pass = <hash name>#<hash>
    // Pass = <hash name>#<salted hash>#<salt>#
    // 'Salted hash' means hash of 'password' + 'salt'
    // Possible hashes are md5 and sha256
    if (sValue.right(1) == "-") {
        sValue.rightChomp(1);
        sValue.trim();
        SetPass(sValue, NoUser::HASH_MD5);
    } else {
        NoString sMethod = No::token(sValue, 0, "#");
        NoString sPass = No::tokens(sValue, 1, "#");
        if (sMethod == "md5" || sMethod == "sha256") {
            NoUser::eHashType type = NoUser::HASH_MD5;
            if (sMethod == "sha256") type = NoUser::HASH_SHA256;

            NoString sSalt = No::token(sPass, 1, "#");
            sPass = No::token(sPass, 0, "#");
            SetPass(sPass, type, sSalt);
        } else if (sMethod == "plain") {
            SetPass(sPass, NoUser::HASH_NONE);
        } else {
            SetPass(sValue, NoUser::HASH_NONE);
        }
    }
    NoSettings::SubConfig subConf;
    NoSettings::SubConfig::const_iterator subIt;
    pConfig->FindSubConfig("pass", subConf);
    if (!sValue.empty() && !subConf.empty()) {
        sError = "Password defined more than once";
        No::printError(sError);
        return false;
    }
    subIt = subConf.begin();
    if (subIt != subConf.end()) {
        NoSettings* pSubConf = subIt->second.m_subConfig;
        NoString sHash;
        NoString sMethod;
        NoString sSalt;
        NoUser::eHashType method;
        pSubConf->FindStringEntry("hash", sHash);
        pSubConf->FindStringEntry("method", sMethod);
        pSubConf->FindStringEntry("salt", sSalt);
        if (sMethod.empty() || sMethod.equals("plain"))
            method = NoUser::HASH_NONE;
        else if (sMethod.equals("md5"))
            method = NoUser::HASH_MD5;
        else if (sMethod.equals("sha256"))
            method = NoUser::HASH_SHA256;
        else {
            sError = "Invalid hash method";
            No::printError(sError);
            return false;
        }

        SetPass(sHash, method, sSalt);
        if (!pSubConf->empty()) {
            sError = "Unhandled lines in config!";
            No::printError(sError);

            NoApp::DumpConfig(pSubConf);
            return false;
        }
        ++subIt;
    }
    if (subIt != subConf.end()) {
        sError = "Password defined more than once";
        No::printError(sError);
        return false;
    }

    pConfig->FindSubConfig("network", subConf);
    for (subIt = subConf.begin(); subIt != subConf.end(); ++subIt) {
        const NoString& sNetworkName = subIt->first;

        No::printMessage("Loading network [" + sNetworkName + "]");

        NoNetwork* pNetwork = FindNetwork(sNetworkName);

        if (!pNetwork) {
            pNetwork = new NoNetwork(this, sNetworkName);
        }

        if (!pNetwork->ParseConfig(subIt->second.m_subConfig, sError)) {
            return false;
        }
    }

    if (pConfig->FindStringVector("server", vsList, false) || pConfig->FindStringVector("chan", vsList, false) ||
        pConfig->FindSubConfig("chan", subConf, false)) {
        NoNetwork* pNetwork = FindNetwork("default");
        if (!pNetwork) {
            NoString sErrorDummy;
            pNetwork = AddNetwork("default", sErrorDummy);
        }

        if (pNetwork) {
            No::printMessage("NOTICE: Found deprecated config, upgrading to a network");

            if (!pNetwork->ParseConfig(pConfig, sError, true)) {
                return false;
            }
        }
    }

    pConfig->FindStringVector("loadmodule", vsList);
    for (const NoString& sMod : vsList) {
        NoString sModName = No::token(sMod, 0);
        NoString sNotice = "Loading user module [" + sModName + "]";

        // XXX Legacy crap, added in ZNC 0.089
        if (sModName == "discon_kick") {
            sNotice = "NOTICE: [discon_kick] was renamed, loading [disconkick] instead";
            sModName = "disconkick";
        }

        // XXX Legacy crap, added in ZNC 0.099
        if (sModName == "fixfreenode") {
            sNotice = "NOTICE: [fixfreenode] doesn't do anything useful anymore, ignoring it";
            continue;
        }

        // XXX Legacy crap, added in ZNC 0.207
        if (sModName == "admin") {
            sNotice = "NOTICE: [admin] module was renamed, loading [controlpanel] instead";
            sModName = "controlpanel";
        }

        // XXX Legacy crap, should have been added ZNC 0.207, but added only in 1.1 :(
        if (sModName == "away") {
            sNotice = "NOTICE: [away] was renamed, loading [awaystore] instead";
            sModName = "awaystore";
        }

        // XXX Legacy crap, added in 1.1; fakeonline module was dropped in 1.0 and returned in 1.1
        if (sModName == "fakeonline") {
            sNotice = "NOTICE: [fakeonline] was renamed, loading [modules_online] instead";
            sModName = "modules_online";
        }

        // XXX Legacy crap, added in 1.3
        if (sModName == "charset") {
            No::printAction("NOTICE: Charset support was moved to core, importing old charset module settings");
            size_t uIndex = 1;
            if (No::token(sMod, uIndex).equals("-force")) {
                uIndex++;
            }
            NoStringVector vsClient = No::token(sMod, uIndex).split(",");
            NoStringVector vsServer = No::token(sMod, uIndex + 1).split(",");
            if (vsClient.empty() || vsServer.empty()) {
                No::printStatus(false, "charset module was loaded with wrong parameters.");
                continue;
            }
            SetClientEncoding(vsClient[0]);
            for (NoNetwork* pNetwork : d->networks) {
                pNetwork->SetEncoding(vsServer[0]);
            }
            No::printStatus(true, "Using [" + vsClient[0] + "] for clients, and [" + vsServer[0] + "] for servers");
            continue;
        }

        NoString sModRet;
        NoString sArgs = No::tokens(sMod, 1);

        bool bModRet = LoadModule(sModName, sArgs, sNotice, sModRet);

        No::printStatus(bModRet, sModRet);
        if (!bModRet) {
            // XXX The awaynick module was retired in 1.6 (still available as external module)
            if (sModName == "awaynick") {
                // load simple_away instead, unless it's already on the list
                if (std::find(vsList.begin(), vsList.end(), "simple_away") == vsList.end()) {
                    sNotice = "Loading [simple_away] module instead";
                    sModName = "simple_away";
                    // not a fatal error if simple_away is not available
                    LoadModule(sModName, sArgs, sNotice, sModRet);
                }
            } else {
                sError = sModRet;
                return false;
            }
        }
        continue;
    }

    // Move ircconnectenabled to the networks
    if (pConfig->FindStringEntry("ircconnectenabled", sValue)) {
        for (NoNetwork* pNetwork : d->networks) {
            pNetwork->SetIRCConnectEnabled(sValue.toBool());
        }
    }

    return true;
}

NoNetwork* NoUser::AddNetwork(const NoString& sNetwork, NoString& sErrorRet)
{
    if (!NoNetwork::IsValidNetwork(sNetwork)) {
        sErrorRet = "Invalid network name. It should be alphanumeric. Not to be confused with server name";
        return nullptr;
    } else if (FindNetwork(sNetwork)) {
        sErrorRet = "Network [" + No::token(sNetwork, 0) + "] already exists";
        return nullptr;
    }

    NoNetwork* pNetwork = new NoNetwork(this, sNetwork);

    bool bCancel = false;
    USERMODULECALL(OnAddNetwork(*pNetwork, sErrorRet), this, nullptr, &bCancel);
    if (bCancel) {
        RemoveNetwork(pNetwork);
        delete pNetwork;
        return nullptr;
    }

    return pNetwork;
}

bool NoUser::AddNetwork(NoNetwork* pNetwork)
{
    if (FindNetwork(pNetwork->GetName())) {
        return false;
    }

    d->networks.push_back(pNetwork);

    return true;
}

void NoUser::RemoveNetwork(NoNetwork* pNetwork)
{
    auto it = std::find(d->networks.begin(), d->networks.end(), pNetwork);
    if (it != d->networks.end()) {
        d->networks.erase(it);
    }
}

bool NoUser::DeleteNetwork(const NoString& sNetwork)
{
    NoNetwork* pNetwork = FindNetwork(sNetwork);

    if (pNetwork) {
        bool bCancel = false;
        USERMODULECALL(OnDeleteNetwork(*pNetwork), this, nullptr, &bCancel);
        if (!bCancel) {
            delete pNetwork;
            return true;
        }
    }

    return false;
}

NoNetwork* NoUser::FindNetwork(const NoString& sNetwork) const
{
    for (NoNetwork* pNetwork : d->networks) {
        if (pNetwork->GetName().equals(sNetwork)) {
            return pNetwork;
        }
    }

    return nullptr;
}

std::vector<NoNetwork*> NoUser::GetNetworks() const { return d->networks; }

NoString NoUser::ExpandString(const NoString& sStr) const
{
    NoString sRet;
    return ExpandString(sStr, sRet);
}

NoString& NoUser::ExpandString(const NoString& sStr, NoString& sRet) const
{
    NoString sTime = No::cTime(time(nullptr), d->timezone);

    sRet = sStr;
    sRet.replace("%user%", GetUserName());
    sRet.replace("%defnick%", GetNick());
    sRet.replace("%nick%", GetNick());
    sRet.replace("%altnick%", GetAltNick());
    sRet.replace("%ident%", GetIdent());
    sRet.replace("%realname%", GetRealName());
    sRet.replace("%vhost%", GetBindHost());
    sRet.replace("%bindhost%", GetBindHost());
    sRet.replace("%version%", NoApp::GetVersion());
    sRet.replace("%time%", sTime);
    sRet.replace("%uptime%", NoApp::Get().GetUptime());
    // The following lines do not exist. You must be on DrUgS!
    sRet.replace("%znc%", "All your IRC are belong to ZNC");
    // Chosen by fair zocchihedron dice roll by SilverLeo
    sRet.replace("%rand%", "42");

    return sRet;
}

NoString NoUser::AddTimestamp(const NoString& sStr) const
{
    time_t tm;
    return AddTimestamp(time(&tm), sStr);
}

NoString NoUser::AddTimestamp(time_t tm, const NoString& sStr) const
{
    NoString sRet = sStr;

    if (!GetTimestampFormat().empty() && (d->appendTimestamp || d->prependTimestamp)) {
        NoString sTimestamp = No::formatTime(tm, GetTimestampFormat(), d->timezone);
        if (sTimestamp.empty()) {
            return sRet;
        }

        if (d->prependTimestamp) {
            sRet = sTimestamp;
            sRet += " " + sStr;
        }
        if (d->appendTimestamp) {
            // From http://www.mirc.com/colors.html
            // The Control+O key combination in mIRC inserts ascii character 15,
            // which turns off all previous attributes, including color, bold, underline, and italics.
            //
            // \x02 bold
            // \x03 mIRC-compatible color
            // \x04 RRGGBB color
            // \x0F normal/reset (turn off bold, colors, etc.)
            // \x12 reverse (weechat)
            // \x16 reverse (mirc, kvirc)
            // \x1D italic
            // \x1F underline
            // Also see http://www.visualirc.net/tech-attrs.php
            //
            // Keep in sync with NoSocketPrivate::IcuExt__UCallback
            if (NoString::npos != sRet.find_first_of("\x02\x03\x04\x0F\x12\x16\x1D\x1F")) {
                sRet += "\x0F";
            }

            sRet += " " + sTimestamp;
        }
    }

    return sRet;
}

void NoUser::BounceAllClients()
{
    for (NoClient* pClient : d->clients) {
        pClient->BouncedOff();
    }

    d->clients.clear();
}

void NoUser::SetKeepBuffer(bool b) { SetAutoClearChanBuffer(!b); }

void NoUser::UserConnected(NoClient* pClient)
{
    if (!MultiClients()) {
        BounceAllClients();
    }

    pClient->PutClient(":irc.znc.in 001 " + pClient->GetNick() + " :- Welcome to ZNC -");

    d->clients.push_back(pClient);
}

void NoUser::UserDisconnected(NoClient* pClient)
{
    auto it = std::find(d->clients.begin(), d->clients.end(), pClient);
    if (it != d->clients.end()) {
        d->clients.erase(it);
    }
}

void NoUser::CloneNetworks(const NoUser& User)
{
    const std::vector<NoNetwork*>& vNetworks = User.GetNetworks();
    for (NoNetwork* pUserNetwork : vNetworks) {
        NoNetwork* pNetwork = FindNetwork(pUserNetwork->GetName());

        if (pNetwork) {
            pNetwork->Clone(*pUserNetwork);
        } else {
            new NoNetwork(this, *pUserNetwork);
        }
    }

    std::set<NoString> ssDeleteNetworks;
    for (NoNetwork* pNetwork : d->networks) {
        if (!(User.FindNetwork(pNetwork->GetName()))) {
            ssDeleteNetworks.insert(pNetwork->GetName());
        }
    }

    for (const NoString& sNetwork : ssDeleteNetworks) {
        // The following will move all the clients to the user.
        // So the clients are not disconnected. The client could
        // have requested the rehash. Then when we do
        // client->PutStatus("Rehashing succeeded!") we would
        // crash if there was no client anymore.
        const std::vector<NoClient*>& vClients = FindNetwork(sNetwork)->GetClients();

        while (vClients.begin() != vClients.end()) {
            NoClient* pClient = vClients.front();
            // This line will remove pClient from vClients,
            // because it's a reference to the internal Network's vector.
            pClient->SetNetwork(nullptr);
        }

        DeleteNetwork(sNetwork);
    }
}

bool NoUser::Clone(const NoUser& User, NoString& sErrorRet, bool bCloneNetworks)
{
    sErrorRet.clear();

    if (!User.IsValid(sErrorRet, true)) {
        return false;
    }

    // user names can only specified for the constructor, changing it later
    // on breaks too much stuff (e.g. lots of paths depend on the user name)
    if (GetUserName() != User.GetUserName()) {
        NO_DEBUG("Ignoring username in NoUser::Clone(), old username [" << GetUserName() << "]; New username ["
                                                                    << User.GetUserName() << "]");
    }

    if (!User.GetPass().empty()) {
        SetPass(User.GetPass(), User.GetPassHashType(), User.GetPassSalt());
    }

    SetNick(User.GetNick(false));
    SetAltNick(User.GetAltNick(false));
    SetIdent(User.GetIdent(false));
    SetRealName(User.GetRealName());
    SetStatusPrefix(User.GetStatusPrefix());
    SetBindHost(User.GetBindHost());
    SetDCCBindHost(User.GetDCCBindHost());
    SetQuitMsg(User.GetQuitMsg());
    SetSkinName(User.GetSkinName());
    SetDefaultChanModes(User.GetDefaultChanModes());
    SetBufferCount(User.GetBufferCount(), true);
    SetJoinTries(User.JoinTries());
    SetMaxNetworks(User.MaxNetworks());
    SetMaxQueryBuffers(User.MaxQueryBuffers());
    SetMaxJoins(User.MaxJoins());
    SetClientEncoding(User.GetClientEncoding());

    // Allowed Hosts
    d->allowedHosts.clear();
    const std::set<NoString>& ssHosts = User.GetAllowedHosts();
    for (const NoString& sHost : ssHosts) {
        AddAllowedHost(sHost);
    }

    for (NoClient* pClient : d->clients) {
        NoSocket* pSock = pClient->GetSocket();
        if (!IsHostAllowed(pSock->GetRemoteIP())) {
            pClient->PutStatusNotice(
            "You are being disconnected because your IP is no longer allowed to connect to this user");
            pSock->Close();
        }
    }

    // !Allowed Hosts

    // Networks
    if (bCloneNetworks) {
        CloneNetworks(User);
    }
    // !Networks

    // CTCP Replies
    d->ctcpReplies.clear();
    const NoStringMap& msReplies = User.GetCTCPReplies();
    for (const auto& it : msReplies) {
        AddCTCPReply(it.first, it.second);
    }
    // !CTCP Replies

    // Flags
    SetAutoClearChanBuffer(User.AutoClearChanBuffer());
    SetAutoClearQueryBuffer(User.AutoClearQueryBuffer());
    SetMultiClients(User.MultiClients());
    SetDenyLoadMod(User.DenyLoadMod());
    SetAdmin(User.IsAdmin());
    SetDenySetBindHost(User.DenySetBindHost());
    SetTimestampAppend(User.GetTimestampAppend());
    SetTimestampPrepend(User.GetTimestampPrepend());
    SetTimestampFormat(User.GetTimestampFormat());
    SetTimezone(User.GetTimezone());
    // !Flags

    // Modules
    std::set<NoString> ssUnloadMods;
    NoModules& vCurMods = GetModules();
    const NoModules& vNewMods = User.GetModules();

    for (NoModule* pNewMod : vNewMods) {
        NoString sModRet;
        NoModule* pCurMod = vCurMods.FindModule(pNewMod->GetModName());

        if (!pCurMod) {
            vCurMods.LoadModule(pNewMod->GetModName(), pNewMod->GetArgs(), No::UserModule, this, nullptr, sModRet);
        } else if (pNewMod->GetArgs() != pCurMod->GetArgs()) {
            vCurMods.ReloadModule(pNewMod->GetModName(), pNewMod->GetArgs(), this, nullptr, sModRet);
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

    return true;
}

void NoUser::AddBytesRead(ulonglong u) { d->bytesRead += u; }

void NoUser::AddBytesWritten(ulonglong u) { d->bytesWritten += u; }

std::set<NoString> NoUser::GetAllowedHosts() const { return d->allowedHosts; }
bool NoUser::AddAllowedHost(const NoString& sHostMask)
{
    if (sHostMask.empty() || d->allowedHosts.find(sHostMask) != d->allowedHosts.end()) {
        return false;
    }

    d->allowedHosts.insert(sHostMask);
    return true;
}

bool NoUser::IsHostAllowed(const NoString& sHostMask) const
{
    if (d->allowedHosts.empty()) {
        return true;
    }

    for (const NoString& sHost : d->allowedHosts) {
        if (No::wildCmp(sHostMask, sHost)) {
            return true;
        }
    }

    return false;
}

NoString NoUser::GetTimestampFormat() const { return d->timestampFormat; }
bool NoUser::GetTimestampAppend() const { return d->appendTimestamp; }
bool NoUser::GetTimestampPrepend() const { return d->prependTimestamp; }

bool NoUser::IsValidUserName(const NoString& sUserName)
{
    // /^[a-zA-Z][a-zA-Z@._\-]*$/
    const char* p = sUserName.c_str();

    if (sUserName.empty()) {
        return false;
    }

    if ((*p < 'a' || *p > 'z') && (*p < 'A' || *p > 'Z')) {
        return false;
    }

    while (*p) {
        if (*p != '@' && *p != '.' && *p != '-' && *p != '_' && !isalnum(*p)) {
            return false;
        }

        p++;
    }

    return true;
}

bool NoUser::IsValid(NoString& sErrMsg, bool bSkipPass) const
{
    sErrMsg.clear();

    if (!bSkipPass && d->password.empty()) {
        sErrMsg = "Pass is empty";
        return false;
    }

    if (d->userName.empty()) {
        sErrMsg = "Username is empty";
        return false;
    }

    if (!NoUser::IsValidUserName(d->userName)) {
        sErrMsg = "Username is invalid";
        return false;
    }

    return true;
}

NoSettings NoUser::ToConfig() const
{
    NoSettings config;
    NoSettings passConfig;

    NoString sHash;
    switch (d->hashType) {
    case HASH_NONE:
        sHash = "Plain";
        break;
    case HASH_MD5:
        sHash = "MD5";
        break;
    case HASH_SHA256:
        sHash = "SHA256";
        break;
    }
    passConfig.AddKeyValuePair("Salt", d->passwordSalt);
    passConfig.AddKeyValuePair("Method", sHash);
    passConfig.AddKeyValuePair("Hash", GetPass());
    config.AddSubConfig("Pass", "password", passConfig);

    config.AddKeyValuePair("Nick", GetNick());
    config.AddKeyValuePair("AltNick", GetAltNick());
    config.AddKeyValuePair("Ident", GetIdent());
    config.AddKeyValuePair("RealName", GetRealName());
    config.AddKeyValuePair("BindHost", GetBindHost());
    config.AddKeyValuePair("DCCBindHost", GetDCCBindHost());
    config.AddKeyValuePair("QuitMsg", GetQuitMsg());
    if (NoApp::Get().GetStatusPrefix() != GetStatusPrefix()) config.AddKeyValuePair("StatusPrefix", GetStatusPrefix());
    config.AddKeyValuePair("Skin", GetSkinName());
    config.AddKeyValuePair("ChanModes", GetDefaultChanModes());
    config.AddKeyValuePair("Buffer", NoString(GetBufferCount()));
    config.AddKeyValuePair("AutoClearChanBuffer", NoString(AutoClearChanBuffer()));
    config.AddKeyValuePair("AutoClearQueryBuffer", NoString(AutoClearQueryBuffer()));
    config.AddKeyValuePair("MultiClients", NoString(MultiClients()));
    config.AddKeyValuePair("DenyLoadMod", NoString(DenyLoadMod()));
    config.AddKeyValuePair("Admin", NoString(IsAdmin()));
    config.AddKeyValuePair("DenySetBindHost", NoString(DenySetBindHost()));
    config.AddKeyValuePair("TimestampFormat", GetTimestampFormat());
    config.AddKeyValuePair("AppendTimestamp", NoString(GetTimestampAppend()));
    config.AddKeyValuePair("PrependTimestamp", NoString(GetTimestampPrepend()));
    config.AddKeyValuePair("Timezone", d->timezone);
    config.AddKeyValuePair("JoinTries", NoString(d->maxJoinTries));
    config.AddKeyValuePair("MaxNetworks", NoString(d->maxNetworks));
    config.AddKeyValuePair("MaxQueryBuffers", NoString(d->maxQueryBuffers));
    config.AddKeyValuePair("MaxJoins", NoString(d->maxJoins));
    config.AddKeyValuePair("ClientEncoding", GetClientEncoding());

    // Allow Hosts
    if (!d->allowedHosts.empty()) {
        for (const NoString& sHost : d->allowedHosts) {
            config.AddKeyValuePair("Allow", sHost);
        }
    }

    // CTCP Replies
    if (!d->ctcpReplies.empty()) {
        for (const auto& itb : d->ctcpReplies) {
            config.AddKeyValuePair("CTCPReply", itb.first.toUpper() + " " + itb.second);
        }
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

    // Networks
    for (NoNetwork* pNetwork : d->networks) {
        config.AddSubConfig("Network", pNetwork->GetName(), pNetwork->ToConfig());
    }

    return config;
}

bool NoUser::CheckPass(const NoString& sPass) const
{
    switch (d->hashType) {
    case HASH_MD5:
        return d->password.equals(No::saltedMd5(sPass, d->passwordSalt));
    case HASH_SHA256:
        return d->password.equals(No::saltedSha256(sPass, d->passwordSalt));
    case HASH_NONE:
    default:
        return (sPass == d->password);
    }
}

/*NoClient* NoUser::GetClient() {
    // Todo: optimize this by saving a pointer to the sock
    NoSocketManager& Manager = NoApp::Get().GetManager();
    NoString sSockName = "USR::" + d->sUserName;

    for (uint a = 0; a < Manager.size(); a++) {
        Csock* pSock = Manager[a];
        if (pSock->GetSockName().equals(sSockName)) {
            if (!pSock->IsClosed()) {
                return (NoClient*) pSock;
            }
        }
    }

    return (NoClient*) NoApp::Get().GetManager().FindSockByName(sSockName);
}*/

NoString NoUser::GetLocalDCCIP() const
{
    if (!GetDCCBindHost().empty()) return GetDCCBindHost();

    for (NoNetwork* pNetwork : d->networks) {
        NoIrcSocket* pIRCSock = pNetwork->GetIRCSock();
        if (pIRCSock) {
            return pIRCSock->GetLocalIP();
        }
    }

    if (!GetAllClients().empty()) {
        return GetAllClients()[0]->GetSocket()->GetLocalIP();
    }

    return "";
}

bool NoUser::PutUser(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
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

bool NoUser::PutAllUser(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    PutUser(sLine, pClient, pSkipClient);

    for (NoNetwork* pNetwork : d->networks) {
        if (pNetwork->PutUser(sLine, pClient, pSkipClient)) {
            return true;
        }
    }

    return (pClient == nullptr);
}

bool NoUser::PutStatus(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    std::vector<NoClient*> vClients = GetAllClients();
    for (NoClient* pEachClient : vClients) {
        if ((!pClient || pClient == pEachClient) && pSkipClient != pEachClient) {
            pEachClient->PutStatus(sLine);

            if (pClient) {
                return true;
            }
        }
    }

    return (pClient == nullptr);
}

bool NoUser::PutStatusNotice(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    std::vector<NoClient*> vClients = GetAllClients();
    for (NoClient* pEachClient : vClients) {
        if ((!pClient || pClient == pEachClient) && pSkipClient != pEachClient) {
            pEachClient->PutStatusNotice(sLine);

            if (pClient) {
                return true;
            }
        }
    }

    return (pClient == nullptr);
}

bool NoUser::PutModule(const NoString& sModule, const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
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

bool NoUser::PutModNotice(const NoString& sModule, const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    for (NoClient* pEachClient : d->clients) {
        if ((!pClient || pClient == pEachClient) && pSkipClient != pEachClient) {
            pEachClient->PutModNotice(sModule, sLine);

            if (pClient) {
                return true;
            }
        }
    }

    return (pClient == nullptr);
}

NoString NoUser::MakeCleanUserName(const NoString& sUserName) { return No::token(sUserName, 0, "@").replace_n(".", ""); }

NoModules&NoUser::GetModules() { return *d->modules; }

const NoModules&NoUser::GetModules() const { return *d->modules; }

bool NoUser::IsUserAttached() const
{
    if (!d->clients.empty()) {
        return true;
    }

    for (const NoNetwork* pNetwork : d->networks) {
        if (pNetwork->IsUserAttached()) {
            return true;
        }
    }

    return false;
}

bool NoUser::LoadModule(const NoString& sModName, const NoString& sArgs, const NoString& sNotice, NoString& sError)
{
    bool bModRet = true;
    NoString sModRet;

    NoModuleInfo ModInfo;
    if (!NoApp::Get().GetModules()->GetModInfo(ModInfo, sModName, sModRet)) {
        sError = "Unable to find modinfo [" + sModName + "] [" + sModRet + "]";
        return false;
    }

    No::printAction(sNotice);

    if (!ModInfo.SupportsType(No::UserModule) && ModInfo.SupportsType(No::NetworkModule)) {
        No::printMessage("NOTICE: Module [" + sModName +
                             "] is a network module, loading module for all networks in user.");

        // Do they have old NV?
        NoFile fNVFile = NoFile(GetUserPath() + "/moddata/" + sModName + "/.registry");

        for (NoNetwork* pNetwork : d->networks) {
            if (fNVFile.Exists()) {
                NoString sNetworkModPath = pNetwork->GetNetworkPath() + "/moddata/" + sModName;
                if (!NoFile::Exists(sNetworkModPath)) {
                    NoDir::MakeDir(sNetworkModPath);
                }

                fNVFile.Copy(sNetworkModPath + "/.registry");
            }

            bModRet = pNetwork->GetModules().LoadModule(sModName, sArgs, No::NetworkModule, this, pNetwork, sModRet);
            if (!bModRet) {
                break;
            }
        }
    } else {
        bModRet = GetModules().LoadModule(sModName, sArgs, No::UserModule, this, nullptr, sModRet);
    }

    if (!bModRet) {
        sError = sModRet;
    }
    return bModRet;
}

// Setters
void NoUser::SetNick(const NoString& s) { d->nickName = s; }
void NoUser::SetAltNick(const NoString& s) { d->altNick = s; }
void NoUser::SetIdent(const NoString& s) { d->ident = s; }
void NoUser::SetRealName(const NoString& s) { d->realName = s; }
void NoUser::SetBindHost(const NoString& s) { d->bindHost = s; }
void NoUser::SetDCCBindHost(const NoString& s) { d->dccBindHost = s; }
void NoUser::SetPass(const NoString& s, eHashType eHash, const NoString& sSalt)
{
    d->password = s;
    d->hashType = eHash;
    d->passwordSalt = sSalt;
}
void NoUser::SetMultiClients(bool b) { d->multiClients = b; }
void NoUser::SetDenyLoadMod(bool b) { d->denyLoadMod = b; }
void NoUser::SetAdmin(bool b) { d->admin = b; }
void NoUser::SetDenySetBindHost(bool b) { d->denySetBindHost = b; }
void NoUser::SetDefaultChanModes(const NoString& s) { d->defaultChanModes = s; }
void NoUser::SetClientEncoding(const NoString& s) { d->clientEncoding = s; }
void NoUser::SetQuitMsg(const NoString& s) { d->quitMsg = s; }
void NoUser::SetAutoClearChanBuffer(bool b)
{
    for (NoNetwork* pNetwork : d->networks) {
        for (NoChannel* pChan : pNetwork->GetChans()) {
            pChan->inheritAutoClearChanBuffer(b);
        }
    }
    d->autoClearChanBuffer = b;
}
void NoUser::SetAutoClearQueryBuffer(bool b) { d->autoClearQueryBuffer = b; }

void NoUser::SetBeingDeleted(bool b) { d->beingDeleted = b; }

void NoUser::SetTimestampFormat(const NoString& s) { d->timestampFormat = s; }

void NoUser::SetTimestampAppend(bool b) { d->appendTimestamp = b; }

void NoUser::SetTimestampPrepend(bool b) { d->prependTimestamp = b; }

void NoUser::SetTimezone(const NoString& s) { d->timezone = s; }

void NoUser::SetJoinTries(uint i) { d->maxJoinTries = i; }

void NoUser::SetMaxJoins(uint i) { d->maxJoins = i; }

void NoUser::SetSkinName(const NoString& s) { d->skinName = s; }

void NoUser::SetMaxNetworks(uint i) { d->maxNetworks = i; }

void NoUser::SetMaxQueryBuffers(uint i) { d->maxQueryBuffers = i; }

std::vector<NoClient*> NoUser::GetUserClients() const { return d->clients; }

bool NoUser::SetBufferCount(uint u, bool bForce)
{
    if (!bForce && u > NoApp::Get().GetMaxBufferSize()) return false;
    for (NoNetwork* pNetwork : d->networks) {
        for (NoChannel* pChan : pNetwork->GetChans()) {
            pChan->inheritBufferCount(u, bForce);
        }
    }
    d->bufferCount = u;
    return true;
}

bool NoUser::AddCTCPReply(const NoString& sCTCP, const NoString& sReply)
{
    // Reject CTCP requests containing spaces
    if (sCTCP.find_first_of(' ') != NoString::npos) {
        return false;
    }
    // Reject empty CTCP requests
    if (sCTCP.empty()) {
        return false;
    }
    d->ctcpReplies[sCTCP.toUpper()] = sReply;
    return true;
}

bool NoUser::DelCTCPReply(const NoString& sCTCP) { return d->ctcpReplies.erase(sCTCP) > 0; }

bool NoUser::SetStatusPrefix(const NoString& s)
{
    if (!s.empty() && s.length() < 6 && !s.contains(' ')) {
        d->statusPrefix = (s.empty()) ? "*" : s;
        return true;
    }

    return false;
}
// !Setters

// Getters
std::vector<NoClient*> NoUser::GetAllClients() const
{
    std::vector<NoClient*> vClients;

    for (NoNetwork* pNetwork : d->networks) {
        for (NoClient* pClient : pNetwork->GetClients()) {
            vClients.push_back(pClient);
        }
    }

    for (NoClient* pClient : d->clients) {
        vClients.push_back(pClient);
    }

    return vClients;
}

NoString NoUser::GetUserName() const { return d->userName; }
NoString NoUser::GetCleanUserName() const { return d->cleanUserName; }
NoString NoUser::GetNick(bool bAllowDefault) const
{
    return (bAllowDefault && d->nickName.empty()) ? GetCleanUserName() : d->nickName;
}
NoString NoUser::GetAltNick(bool bAllowDefault) const
{
    return (bAllowDefault && d->altNick.empty()) ? GetCleanUserName() : d->altNick;
}
NoString NoUser::GetIdent(bool bAllowDefault) const
{
    return (bAllowDefault && d->ident.empty()) ? GetCleanUserName() : d->ident;
}
NoString NoUser::GetRealName() const { return d->realName.empty() ? d->userName : d->realName; }
NoString NoUser::GetBindHost() const { return d->bindHost; }
NoString NoUser::GetDCCBindHost() const { return d->dccBindHost; }
NoString NoUser::GetPass() const { return d->password; }
NoUser::eHashType NoUser::GetPassHashType() const { return d->hashType; }
NoString NoUser::GetPassSalt() const { return d->passwordSalt; }
bool NoUser::DenyLoadMod() const { return d->denyLoadMod; }
bool NoUser::IsAdmin() const { return d->admin; }
bool NoUser::DenySetBindHost() const { return d->denySetBindHost; }
bool NoUser::MultiClients() const { return d->multiClients; }
NoString NoUser::GetStatusPrefix() const { return d->statusPrefix; }
NoString NoUser::GetDefaultChanModes() const { return d->defaultChanModes; }
NoString NoUser::GetClientEncoding() const { return d->clientEncoding; }
bool NoUser::HasSpaceForNewNetwork() const { return GetNetworks().size() < MaxNetworks(); }

NoString NoUser::GetQuitMsg() const { return (!d->quitMsg.trim_n().empty()) ? d->quitMsg : NoApp::GetTag(false); }
NoStringMap NoUser::GetCTCPReplies() const { return d->ctcpReplies; }
uint NoUser::GetBufferCount() const { return d->bufferCount; }
bool NoUser::AutoClearChanBuffer() const { return d->autoClearChanBuffer; }
bool NoUser::AutoClearQueryBuffer() const { return d->autoClearQueryBuffer; }

bool NoUser::IsBeingDeleted() const { return d->beingDeleted; }

NoString NoUser::GetTimezone() const { return d->timezone; }

ulonglong NoUser::BytesRead() const { return d->bytesRead; }

ulonglong NoUser::BytesWritten() const { return d->bytesWritten; }

uint NoUser::JoinTries() const { return d->maxJoinTries; }

uint NoUser::MaxJoins() const { return d->maxJoins; }
// NoString NoUser::GetSkinName() const { return (!d->sSkinName.empty()) ? d->sSkinName : NoApp::Get().GetSkinName(); }
NoString NoUser::GetSkinName() const { return d->skinName; }

uint NoUser::MaxNetworks() const { return d->maxNetworks; }

uint NoUser::MaxQueryBuffers() const { return d->maxQueryBuffers; }
NoString NoUser::GetUserPath() const
{
    if (!NoFile::Exists(d->userPath)) {
        NoDir::MakeDir(d->userPath);
    }
    return d->userPath;
}
// !Getters
