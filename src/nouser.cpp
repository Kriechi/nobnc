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
        SetName("NoUserTimer::" + m_pUser->userName());
        Start(NoNetwork::PingSlack);
    }

protected:
    void RunJob() override
    {
        const std::vector<NoClient*>& vUserClients = m_pUser->userClients();

        for (NoClient* pUserClient : vUserClients) {
            if (pUserClient->socket()->GetTimeSinceLastDataTransaction() >= NoNetwork::PingFrequency) {
                pUserClient->putClient("PING :ZNC");
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
    NoUser::HashType hashType = NoUser::HashNone;

    NoString userPath = "";

    bool multiClients = true;
    bool denyLoadMod = false;
    bool admin = false;
    bool denysetBindHost = false;
    bool autoClearChanBuffer = true;
    bool autoclearQueryBuffer = true;
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

    NoModuleLoader* modules = nullptr;
};

NoUser::NoUser(const NoString& sUserName) : d(new NoUserPrivate)
{
    d->userName = sUserName;
    d->cleanUserName = makeCleanUserName(sUserName);
    d->ident = d->cleanUserName;
    d->realName = sUserName;
    d->userPath = NoApp::Get().GetUserPath() + "/" + sUserName;
    d->modules = new NoModuleLoader;
    d->userTimer = new NoUserTimer(this);
    NoApp::Get().manager().AddCron(d->userTimer);
}

NoUser::~NoUser()
{
    // Delete networks
    while (!d->networks.empty()) {
        delete *d->networks.begin();
    }

    // Delete clients
    while (!d->clients.empty()) {
        NoApp::Get().manager().DelSockByAddr(d->clients[0]->socket());
    }
    d->clients.clear();

    // Delete modules (unloads all modules!)
    delete d->modules;
    d->modules = nullptr;

    NoApp::Get().manager().DelCronByAddr(d->userTimer);

    NoApp::Get().AddBytesRead(bytesRead());
    NoApp::Get().AddBytesWritten(bytesWritten());
}

template <class T> struct TOption
{
    const char* name;
    void (NoUser::*pSetter)(T);
};

bool NoUser::parseConfig(NoSettings* pConfig, NoString& sError)
{
    TOption<const NoString&> StringOptions[] = {
        { "nick", &NoUser::setNick },
        { "quitmsg", &NoUser::setQuitMsg },
        { "altnick", &NoUser::setAltNick },
        { "ident", &NoUser::setIdent },
        { "realname", &NoUser::setRealName },
        { "chanmodes", &NoUser::setDefaultChanModes },
        { "bindhost", &NoUser::setBindHost },
        { "vhost", &NoUser::setBindHost },
        { "dccbindhost", &NoUser::setDccBindHost },
        { "dccvhost", &NoUser::setDccBindHost },
        { "timestampformat", &NoUser::setTimestampFormat },
        { "skin", &NoUser::setSkinName },
        { "clientencoding", &NoUser::setClientEncoding },
    };
    TOption<uint> UIntOptions[] = {
        { "jointries", &NoUser::setJoinTries },
        { "maxnetworks", &NoUser::setMaxNetworks },
        { "maxquerybuffers", &NoUser::setMaxQueryBuffers },
        { "maxjoins", &NoUser::setMaxJoins },
    };
    TOption<bool> BoolOptions[] = {
        { "keepbuffer", &NoUser::setKeepBuffer }, // XXX compatibility crap from pre-0.207
        { "autoclearchanbuffer", &NoUser::setAutoClearChanBuffer },
        { "autoclearquerybuffer", &NoUser::setAutoclearQueryBuffer },
        { "multiclients", &NoUser::setMultiClients },
        { "denyloadmod", &NoUser::setDenyLoadMod },
        { "admin", &NoUser::setAdmin },
        { "denysetbindhost", &NoUser::setDenysetBindHost },
        { "denysetvhost", &NoUser::setDenysetBindHost },
        { "appendtimestamp", &NoUser::setTimestampAppend },
        { "prependtimestamp", &NoUser::setTimestampPrepend },
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
        addAllowedHost(sHost);
    }
    pConfig->FindStringVector("ctcpreply", vsList);
    for (const NoString& sReply : vsList) {
        addCtcpReply(No::token(sReply, 0), No::tokens(sReply, 1));
    }

    NoString sValue;

    NoString sDCCLookupValue;
    pConfig->FindStringEntry("dcclookupmethod", sDCCLookupValue);
    if (pConfig->FindStringEntry("bouncedccs", sValue)) {
        if (sValue.toBool()) {
            No::printAction("Loading Module [bouncedcc]");
            NoString sModRet;
            bool bModRet = loader()->loadModule("bouncedcc", "", No::UserModule, this, nullptr, sModRet);

            No::printStatus(bModRet, sModRet);
            if (!bModRet) {
                sError = sModRet;
                return false;
            }

            if (sDCCLookupValue.equals("Client")) {
                NoModule* pMod = loader()->findModule("bouncedcc");
                if (pMod) {
                    NoRegistry registry(pMod);
                    registry.setValue("UseClientIP", "1");
                }
            }
        }
    }
    if (pConfig->FindStringEntry("buffer", sValue)) setBufferCount(sValue.toUInt(), true);
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
        if (!setStatusPrefix(sValue)) {
            sError = "Invalid StatusPrefix [" + sValue + "] Must be 1-5 chars, no spaces.";
            No::printError(sError);
            return false;
        }
    }
    if (pConfig->FindStringEntry("timezone", sValue)) {
        setTimezone(sValue);
    }
    if (pConfig->FindStringEntry("timezoneoffset", sValue)) {
        if (fabs(sValue.toDouble()) > 0.1) {
            No::printError("WARNING: TimezoneOffset has been deprecated, now you can set your timezone by name");
        }
    }
    if (pConfig->FindStringEntry("timestamp", sValue)) {
        if (!sValue.trim_n().equals("true")) {
            if (sValue.trim_n().equals("append")) {
                setTimestampAppend(true);
                setTimestampPrepend(false);
            } else if (sValue.trim_n().equals("prepend")) {
                setTimestampAppend(false);
                setTimestampPrepend(true);
            } else if (sValue.trim_n().equals("false")) {
                setTimestampAppend(false);
                setTimestampPrepend(false);
            } else {
                setTimestampFormat(sValue);
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
        setPassword(sValue, NoUser::HashMd5);
    } else {
        NoString sMethod = No::token(sValue, 0, "#");
        NoString sPass = No::tokens(sValue, 1, "#");
        if (sMethod == "md5" || sMethod == "sha256") {
            NoUser::HashType type = NoUser::HashMd5;
            if (sMethod == "sha256") type = NoUser::HashSha256;

            NoString sSalt = No::token(sPass, 1, "#");
            sPass = No::token(sPass, 0, "#");
            setPassword(sPass, type, sSalt);
        } else if (sMethod == "plain") {
            setPassword(sPass, NoUser::HashNone);
        } else {
            setPassword(sValue, NoUser::HashNone);
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
        NoUser::HashType method;
        pSubConf->FindStringEntry("hash", sHash);
        pSubConf->FindStringEntry("method", sMethod);
        pSubConf->FindStringEntry("salt", sSalt);
        if (sMethod.empty() || sMethod.equals("plain"))
            method = NoUser::HashNone;
        else if (sMethod.equals("md5"))
            method = NoUser::HashMd5;
        else if (sMethod.equals("sha256"))
            method = NoUser::HashSha256;
        else {
            sError = "Invalid hash method";
            No::printError(sError);
            return false;
        }

        setPassword(sHash, method, sSalt);
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

        NoNetwork* pNetwork = findNetwork(sNetworkName);

        if (!pNetwork) {
            pNetwork = new NoNetwork(this, sNetworkName);
        }

        if (!pNetwork->parseConfig(subIt->second.m_subConfig, sError)) {
            return false;
        }
    }

    if (pConfig->FindStringVector("server", vsList, false) || pConfig->FindStringVector("chan", vsList, false) ||
        pConfig->FindSubConfig("chan", subConf, false)) {
        NoNetwork* pNetwork = findNetwork("default");
        if (!pNetwork) {
            NoString sErrorDummy;
            pNetwork = addNetwork("default", sErrorDummy);
        }

        if (pNetwork) {
            No::printMessage("NOTICE: Found deprecated config, upgrading to a network");

            if (!pNetwork->parseConfig(pConfig, sError, true)) {
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
            setClientEncoding(vsClient[0]);
            for (NoNetwork* pNetwork : d->networks) {
                pNetwork->setEncoding(vsServer[0]);
            }
            No::printStatus(true, "Using [" + vsClient[0] + "] for clients, and [" + vsServer[0] + "] for servers");
            continue;
        }

        NoString sModRet;
        NoString sArgs = No::tokens(sMod, 1);

        bool bModRet = loadModule(sModName, sArgs, sNotice, sModRet);

        No::printStatus(bModRet, sModRet);
        if (!bModRet) {
            // XXX The awaynick module was retired in 1.6 (still available as external module)
            if (sModName == "awaynick") {
                // load simple_away instead, unless it's already on the list
                if (std::find(vsList.begin(), vsList.end(), "simple_away") == vsList.end()) {
                    sNotice = "Loading [simple_away] module instead";
                    sModName = "simple_away";
                    // not a fatal error if simple_away is not available
                    loadModule(sModName, sArgs, sNotice, sModRet);
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
            pNetwork->setEnabled(sValue.toBool());
        }
    }

    return true;
}

NoNetwork* NoUser::addNetwork(const NoString& sNetwork, NoString& sErrorRet)
{
    if (!NoNetwork::isValidNetwork(sNetwork)) {
        sErrorRet = "Invalid network name. It should be alphanumeric. Not to be confused with server name";
        return nullptr;
    } else if (findNetwork(sNetwork)) {
        sErrorRet = "Network [" + No::token(sNetwork, 0) + "] already exists";
        return nullptr;
    }

    NoNetwork* pNetwork = new NoNetwork(this, sNetwork);

    bool bCancel = false;
    USERMODULECALL(onAddNetwork(*pNetwork, sErrorRet), this, nullptr, &bCancel);
    if (bCancel) {
        removeNetwork(pNetwork);
        delete pNetwork;
        return nullptr;
    }

    return pNetwork;
}

bool NoUser::addNetwork(NoNetwork* pNetwork)
{
    if (findNetwork(pNetwork->name())) {
        return false;
    }

    d->networks.push_back(pNetwork);

    return true;
}

void NoUser::removeNetwork(NoNetwork* pNetwork)
{
    auto it = std::find(d->networks.begin(), d->networks.end(), pNetwork);
    if (it != d->networks.end()) {
        d->networks.erase(it);
    }
}

bool NoUser::deleteNetwork(const NoString& sNetwork)
{
    NoNetwork* pNetwork = findNetwork(sNetwork);

    if (pNetwork) {
        bool bCancel = false;
        USERMODULECALL(onDeleteNetwork(*pNetwork), this, nullptr, &bCancel);
        if (!bCancel) {
            delete pNetwork;
            return true;
        }
    }

    return false;
}

NoNetwork* NoUser::findNetwork(const NoString& sNetwork) const
{
    for (NoNetwork* pNetwork : d->networks) {
        if (pNetwork->name().equals(sNetwork)) {
            return pNetwork;
        }
    }

    return nullptr;
}

std::vector<NoNetwork*> NoUser::networks() const { return d->networks; }

NoString NoUser::expandString(const NoString& sStr) const
{
    NoString sRet;
    return expandString(sStr, sRet);
}

NoString& NoUser::expandString(const NoString& sStr, NoString& sRet) const
{
    NoString sTime = No::cTime(time(nullptr), d->timezone);

    sRet = sStr;
    sRet.replace("%user%", userName());
    sRet.replace("%defnick%", nick());
    sRet.replace("%nick%", nick());
    sRet.replace("%altnick%", altNick());
    sRet.replace("%ident%", ident());
    sRet.replace("%realname%", realName());
    sRet.replace("%vhost%", bindHost());
    sRet.replace("%bindhost%", bindHost());
    sRet.replace("%version%", NoApp::GetVersion());
    sRet.replace("%time%", sTime);
    sRet.replace("%uptime%", NoApp::Get().GetUptime());
    // The following lines do not exist. You must be on DrUgS!
    sRet.replace("%znc%", "All your IRC are belong to ZNC");
    // Chosen by fair zocchihedron dice roll by SilverLeo
    sRet.replace("%rand%", "42");

    return sRet;
}

NoString NoUser::addTimestamp(const NoString& sStr) const
{
    time_t tm;
    return addTimestamp(time(&tm), sStr);
}

NoString NoUser::addTimestamp(time_t tm, const NoString& sStr) const
{
    NoString sRet = sStr;

    if (!timestampFormat().empty() && (d->appendTimestamp || d->prependTimestamp)) {
        NoString sTimestamp = No::formatTime(tm, timestampFormat(), d->timezone);
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

void NoUser::bounceAllClients()
{
    for (NoClient* pClient : d->clients) {
        pClient->bouncedOff();
    }

    d->clients.clear();
}

void NoUser::setKeepBuffer(bool b) { setAutoClearChanBuffer(!b); }

void NoUser::userConnected(NoClient* pClient)
{
    if (!multiClients()) {
        bounceAllClients();
    }

    pClient->putClient(":irc.znc.in 001 " + pClient->nick() + " :- Welcome to ZNC -");

    d->clients.push_back(pClient);
}

void NoUser::userDisconnected(NoClient* pClient)
{
    auto it = std::find(d->clients.begin(), d->clients.end(), pClient);
    if (it != d->clients.end()) {
        d->clients.erase(it);
    }
}

void NoUser::cloneNetworks(const NoUser& User)
{
    const std::vector<NoNetwork*>& vNetworks = User.networks();
    for (NoNetwork* pUserNetwork : vNetworks) {
        NoNetwork* pNetwork = findNetwork(pUserNetwork->name());

        if (pNetwork) {
            pNetwork->clone(*pUserNetwork);
        } else {
            new NoNetwork(this, *pUserNetwork);
        }
    }

    std::set<NoString> ssDeleteNetworks;
    for (NoNetwork* pNetwork : d->networks) {
        if (!(User.findNetwork(pNetwork->name()))) {
            ssDeleteNetworks.insert(pNetwork->name());
        }
    }

    for (const NoString& sNetwork : ssDeleteNetworks) {
        // The following will move all the clients to the user.
        // So the clients are not disconnected. The client could
        // have requested the rehash. Then when we do
        // client->putStatus("Rehashing succeeded!") we would
        // crash if there was no client anymore.
        const std::vector<NoClient*>& vClients = findNetwork(sNetwork)->clients();

        while (vClients.begin() != vClients.end()) {
            NoClient* pClient = vClients.front();
            // This line will remove pClient from vClients,
            // because it's a reference to the internal Network's vector.
            pClient->setNetwork(nullptr);
        }

        deleteNetwork(sNetwork);
    }
}

bool NoUser::clone(const NoUser& User, NoString& sErrorRet, bool bCloneNetworks)
{
    sErrorRet.clear();

    if (!User.isValid(sErrorRet, true)) {
        return false;
    }

    // user names can only specified for the constructor, changing it later
    // on breaks too much stuff (e.g. lots of paths depend on the user name)
    if (userName() != User.userName()) {
        NO_DEBUG("Ignoring username in NoUser::Clone(), old username [" << userName() << "]; New username ["
                                                                    << User.userName() << "]");
    }

    if (!User.password().empty()) {
        setPassword(User.password(), User.passwordHashType(), User.passwordSalt());
    }

    setNick(User.nick(false));
    setAltNick(User.altNick(false));
    setIdent(User.ident(false));
    setRealName(User.realName());
    setStatusPrefix(User.statusPrefix());
    setBindHost(User.bindHost());
    setDccBindHost(User.dccBindHost());
    setQuitMsg(User.quitMsg());
    setSkinName(User.skinName());
    setDefaultChanModes(User.defaultChanModes());
    setBufferCount(User.bufferCount(), true);
    setJoinTries(User.joinTries());
    setMaxNetworks(User.maxNetworks());
    setMaxQueryBuffers(User.maxQueryBuffers());
    setMaxJoins(User.maxJoins());
    setClientEncoding(User.clientEncoding());

    // Allowed Hosts
    d->allowedHosts.clear();
    const std::set<NoString>& ssHosts = User.allowedHosts();
    for (const NoString& sHost : ssHosts) {
        addAllowedHost(sHost);
    }

    for (NoClient* pClient : d->clients) {
        NoSocket* pSock = pClient->socket();
        if (!isHostAllowed(pSock->GetRemoteIP())) {
            pClient->putStatusNotice(
            "You are being disconnected because your IP is no longer allowed to connect to this user");
            pSock->Close();
        }
    }

    // !Allowed Hosts

    // Networks
    if (bCloneNetworks) {
        cloneNetworks(User);
    }
    // !Networks

    // CTCP Replies
    d->ctcpReplies.clear();
    const NoStringMap& msReplies = User.ctcpReplies();
    for (const auto& it : msReplies) {
        addCtcpReply(it.first, it.second);
    }
    // !CTCP Replies

    // Flags
    setAutoClearChanBuffer(User.autoClearChanBuffer());
    setAutoclearQueryBuffer(User.autoclearQueryBuffer());
    setMultiClients(User.multiClients());
    setDenyLoadMod(User.denyLoadMod());
    setAdmin(User.isAdmin());
    setDenysetBindHost(User.denysetBindHost());
    setTimestampAppend(User.timestampAppend());
    setTimestampPrepend(User.timestampPrepend());
    setTimestampFormat(User.timestampFormat());
    setTimezone(User.timezone());
    // !Flags

    // Modules
    std::set<NoString> ssUnloadMods;
    NoModuleLoader* vCurMods = loader();
    const NoModuleLoader* vNewMods = User.loader();

    for (NoModule* pNewMod : vNewMods->modules()) {
        NoString sModRet;
        NoModule* pCurMod = vCurMods->findModule(pNewMod->moduleName());

        if (!pCurMod) {
            vCurMods->loadModule(pNewMod->moduleName(), pNewMod->args(), No::UserModule, this, nullptr, sModRet);
        } else if (pNewMod->args() != pCurMod->args()) {
            vCurMods->reloadModule(pNewMod->moduleName(), pNewMod->args(), this, nullptr, sModRet);
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

    return true;
}

void NoUser::addBytesRead(ulonglong u) { d->bytesRead += u; }

void NoUser::addBytesWritten(ulonglong u) { d->bytesWritten += u; }

std::set<NoString> NoUser::allowedHosts() const { return d->allowedHosts; }
bool NoUser::addAllowedHost(const NoString& sHostMask)
{
    if (sHostMask.empty() || d->allowedHosts.find(sHostMask) != d->allowedHosts.end()) {
        return false;
    }

    d->allowedHosts.insert(sHostMask);
    return true;
}

bool NoUser::isHostAllowed(const NoString& sHostMask) const
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

NoString NoUser::timestampFormat() const { return d->timestampFormat; }
bool NoUser::timestampAppend() const { return d->appendTimestamp; }
bool NoUser::timestampPrepend() const { return d->prependTimestamp; }

bool NoUser::isValidUserName(const NoString& sUserName)
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

bool NoUser::isValid(NoString& sErrMsg, bool bSkipPass) const
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

    if (!NoUser::isValidUserName(d->userName)) {
        sErrMsg = "Username is invalid";
        return false;
    }

    return true;
}

NoSettings NoUser::toConfig() const
{
    NoSettings config;
    NoSettings passConfig;

    NoString sHash;
    switch (d->hashType) {
    case HashNone:
        sHash = "Plain";
        break;
    case HashMd5:
        sHash = "MD5";
        break;
    case HashSha256:
        sHash = "SHA256";
        break;
    }
    passConfig.AddKeyValuePair("Salt", d->passwordSalt);
    passConfig.AddKeyValuePair("Method", sHash);
    passConfig.AddKeyValuePair("Hash", password());
    config.AddSubConfig("Pass", "password", passConfig);

    config.AddKeyValuePair("Nick", nick());
    config.AddKeyValuePair("AltNick", altNick());
    config.AddKeyValuePair("Ident", ident());
    config.AddKeyValuePair("RealName", realName());
    config.AddKeyValuePair("BindHost", bindHost());
    config.AddKeyValuePair("DCCBindHost", dccBindHost());
    config.AddKeyValuePair("QuitMsg", quitMsg());
    if (NoApp::Get().GetStatusPrefix() != statusPrefix()) config.AddKeyValuePair("StatusPrefix", statusPrefix());
    config.AddKeyValuePair("Skin", skinName());
    config.AddKeyValuePair("ChanModes", defaultChanModes());
    config.AddKeyValuePair("Buffer", NoString(bufferCount()));
    config.AddKeyValuePair("AutoClearChanBuffer", NoString(autoClearChanBuffer()));
    config.AddKeyValuePair("autoclearQueryBuffer", NoString(autoclearQueryBuffer()));
    config.AddKeyValuePair("MultiClients", NoString(multiClients()));
    config.AddKeyValuePair("DenyLoadMod", NoString(denyLoadMod()));
    config.AddKeyValuePair("Admin", NoString(isAdmin()));
    config.AddKeyValuePair("DenysetBindHost", NoString(denysetBindHost()));
    config.AddKeyValuePair("TimestampFormat", timestampFormat());
    config.AddKeyValuePair("AppendTimestamp", NoString(timestampAppend()));
    config.AddKeyValuePair("PrependTimestamp", NoString(timestampPrepend()));
    config.AddKeyValuePair("Timezone", d->timezone);
    config.AddKeyValuePair("JoinTries", NoString(d->maxJoinTries));
    config.AddKeyValuePair("MaxNetworks", NoString(d->maxNetworks));
    config.AddKeyValuePair("MaxQueryBuffers", NoString(d->maxQueryBuffers));
    config.AddKeyValuePair("MaxJoins", NoString(d->maxJoins));
    config.AddKeyValuePair("ClientEncoding", clientEncoding());

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
    const NoModuleLoader* Mods = loader();

    for (NoModule* pMod : Mods->modules()) {
        NoString sArgs = pMod->args();

        if (!sArgs.empty()) {
            sArgs = " " + sArgs;
        }

        config.AddKeyValuePair("LoadModule", pMod->moduleName() + sArgs);
    }

    // Networks
    for (NoNetwork* pNetwork : d->networks) {
        config.AddSubConfig("Network", pNetwork->name(), pNetwork->toConfig());
    }

    return config;
}

bool NoUser::checkPass(const NoString& sPass) const
{
    switch (d->hashType) {
    case HashMd5:
        return d->password.equals(No::saltedMd5(sPass, d->passwordSalt));
    case HashSha256:
        return d->password.equals(No::saltedSha256(sPass, d->passwordSalt));
    case HashNone:
    default:
        return (sPass == d->password);
    }
}

/*NoClient* NoUser::client() {
    // Todo: optimize this by saving a pointer to the sock
    NoSocketManager& Manager = NoApp::Get().manager();
    NoString sSockName = "USR::" + d->sUserName;

    for (uint a = 0; a < Manager.size(); a++) {
        Csock* pSock = Manager[a];
        if (pSock->GetSockName().equals(sSockName)) {
            if (!pSock->IsClosed()) {
                return (NoClient*) pSock;
            }
        }
    }

    return (NoClient*) NoApp::Get().manager().FindSockByName(sSockName);
}*/

NoString NoUser::localDccIp() const
{
    if (!dccBindHost().empty()) return dccBindHost();

    for (NoNetwork* pNetwork : d->networks) {
        NoIrcSocket* pIRCSock = pNetwork->ircSocket();
        if (pIRCSock) {
            return pIRCSock->GetLocalIP();
        }
    }

    if (!allClients().empty()) {
        return allClients()[0]->socket()->GetLocalIP();
    }

    return "";
}

bool NoUser::putUser(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    for (NoClient* pEachClient : d->clients) {
        if ((!pClient || pClient == pEachClient) && pSkipClient != pEachClient) {
            pEachClient->putClient(sLine);

            if (pClient) {
                return true;
            }
        }
    }

    return (pClient == nullptr);
}

bool NoUser::putAllUser(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    putUser(sLine, pClient, pSkipClient);

    for (NoNetwork* pNetwork : d->networks) {
        if (pNetwork->putUser(sLine, pClient, pSkipClient)) {
            return true;
        }
    }

    return (pClient == nullptr);
}

bool NoUser::putStatus(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    std::vector<NoClient*> vClients = allClients();
    for (NoClient* pEachClient : vClients) {
        if ((!pClient || pClient == pEachClient) && pSkipClient != pEachClient) {
            pEachClient->putStatus(sLine);

            if (pClient) {
                return true;
            }
        }
    }

    return (pClient == nullptr);
}

bool NoUser::putStatusNotice(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    std::vector<NoClient*> vClients = allClients();
    for (NoClient* pEachClient : vClients) {
        if ((!pClient || pClient == pEachClient) && pSkipClient != pEachClient) {
            pEachClient->putStatusNotice(sLine);

            if (pClient) {
                return true;
            }
        }
    }

    return (pClient == nullptr);
}

bool NoUser::putModule(const NoString& sModule, const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    for (NoClient* pEachClient : d->clients) {
        if ((!pClient || pClient == pEachClient) && pSkipClient != pEachClient) {
            pEachClient->putModule(sModule, sLine);

            if (pClient) {
                return true;
            }
        }
    }

    return (pClient == nullptr);
}

bool NoUser::putModuleNotice(const NoString& sModule, const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    for (NoClient* pEachClient : d->clients) {
        if ((!pClient || pClient == pEachClient) && pSkipClient != pEachClient) {
            pEachClient->putModuleNotice(sModule, sLine);

            if (pClient) {
                return true;
            }
        }
    }

    return (pClient == nullptr);
}

NoString NoUser::makeCleanUserName(const NoString& sUserName) { return No::token(sUserName, 0, "@").replace_n(".", ""); }

NoModuleLoader* NoUser::loader() const { return d->modules; }

bool NoUser::isUserAttached() const
{
    if (!d->clients.empty()) {
        return true;
    }

    for (const NoNetwork* pNetwork : d->networks) {
        if (pNetwork->isUserAttached()) {
            return true;
        }
    }

    return false;
}

bool NoUser::loadModule(const NoString& sModName, const NoString& sArgs, const NoString& sNotice, NoString& sError)
{
    bool bModRet = true;
    NoString sModRet;

    NoModuleInfo ModInfo;
    if (!NoApp::Get().GetLoader()->moduleInfo(ModInfo, sModName, sModRet)) {
        sError = "Unable to find modinfo [" + sModName + "] [" + sModRet + "]";
        return false;
    }

    No::printAction(sNotice);

    if (!ModInfo.supportsType(No::UserModule) && ModInfo.supportsType(No::NetworkModule)) {
        No::printMessage("NOTICE: Module [" + sModName +
                             "] is a network module, loading module for all networks in user.");

        // Do they have old NV?
        NoFile fNVFile = NoFile(userPath() + "/moddata/" + sModName + "/.registry");

        for (NoNetwork* pNetwork : d->networks) {
            if (fNVFile.Exists()) {
                NoString sNetworkModPath = pNetwork->networkPath() + "/moddata/" + sModName;
                if (!NoFile::Exists(sNetworkModPath)) {
                    NoDir::MakeDir(sNetworkModPath);
                }

                fNVFile.Copy(sNetworkModPath + "/.registry");
            }

            bModRet = pNetwork->loader()->loadModule(sModName, sArgs, No::NetworkModule, this, pNetwork, sModRet);
            if (!bModRet) {
                break;
            }
        }
    } else {
        bModRet = loader()->loadModule(sModName, sArgs, No::UserModule, this, nullptr, sModRet);
    }

    if (!bModRet) {
        sError = sModRet;
    }
    return bModRet;
}

// Setters
void NoUser::setNick(const NoString& s) { d->nickName = s; }
void NoUser::setAltNick(const NoString& s) { d->altNick = s; }
void NoUser::setIdent(const NoString& s) { d->ident = s; }
void NoUser::setRealName(const NoString& s) { d->realName = s; }
void NoUser::setBindHost(const NoString& s) { d->bindHost = s; }
void NoUser::setDccBindHost(const NoString& s) { d->dccBindHost = s; }
void NoUser::setPassword(const NoString& s, HashType eHash, const NoString& sSalt)
{
    d->password = s;
    d->hashType = eHash;
    d->passwordSalt = sSalt;
}
void NoUser::setMultiClients(bool b) { d->multiClients = b; }
void NoUser::setDenyLoadMod(bool b) { d->denyLoadMod = b; }
void NoUser::setAdmin(bool b) { d->admin = b; }
void NoUser::setDenysetBindHost(bool b) { d->denysetBindHost = b; }
void NoUser::setDefaultChanModes(const NoString& s) { d->defaultChanModes = s; }
void NoUser::setClientEncoding(const NoString& s) { d->clientEncoding = s; }
void NoUser::setQuitMsg(const NoString& s) { d->quitMsg = s; }
void NoUser::setAutoClearChanBuffer(bool b)
{
    for (NoNetwork* pNetwork : d->networks) {
        for (NoChannel* pChan : pNetwork->channels()) {
            pChan->inheritAutoClearChanBuffer(b);
        }
    }
    d->autoClearChanBuffer = b;
}
void NoUser::setAutoclearQueryBuffer(bool b) { d->autoclearQueryBuffer = b; }

void NoUser::setBeingDeleted(bool b) { d->beingDeleted = b; }

void NoUser::setTimestampFormat(const NoString& s) { d->timestampFormat = s; }

void NoUser::setTimestampAppend(bool b) { d->appendTimestamp = b; }

void NoUser::setTimestampPrepend(bool b) { d->prependTimestamp = b; }

void NoUser::setTimezone(const NoString& s) { d->timezone = s; }

void NoUser::setJoinTries(uint i) { d->maxJoinTries = i; }

void NoUser::setMaxJoins(uint i) { d->maxJoins = i; }

void NoUser::setSkinName(const NoString& s) { d->skinName = s; }

void NoUser::setMaxNetworks(uint i) { d->maxNetworks = i; }

void NoUser::setMaxQueryBuffers(uint i) { d->maxQueryBuffers = i; }

std::vector<NoClient*> NoUser::userClients() const { return d->clients; }

bool NoUser::setBufferCount(uint u, bool bForce)
{
    if (!bForce && u > NoApp::Get().GetMaxBufferSize()) return false;
    for (NoNetwork* pNetwork : d->networks) {
        for (NoChannel* pChan : pNetwork->channels()) {
            pChan->inheritBufferCount(u, bForce);
        }
    }
    d->bufferCount = u;
    return true;
}

bool NoUser::addCtcpReply(const NoString& sCTCP, const NoString& sReply)
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

bool NoUser::removeCtcpReply(const NoString& sCTCP) { return d->ctcpReplies.erase(sCTCP) > 0; }

bool NoUser::setStatusPrefix(const NoString& s)
{
    if (!s.empty() && s.length() < 6 && !s.contains(' ')) {
        d->statusPrefix = (s.empty()) ? "*" : s;
        return true;
    }

    return false;
}
// !Setters

// Getters
std::vector<NoClient*> NoUser::allClients() const
{
    std::vector<NoClient*> vClients;

    for (NoNetwork* pNetwork : d->networks) {
        for (NoClient* pClient : pNetwork->clients()) {
            vClients.push_back(pClient);
        }
    }

    for (NoClient* pClient : d->clients) {
        vClients.push_back(pClient);
    }

    return vClients;
}

NoString NoUser::userName() const { return d->userName; }
NoString NoUser::cleanUserName() const { return d->cleanUserName; }
NoString NoUser::nick(bool bAllowDefault) const
{
    return (bAllowDefault && d->nickName.empty()) ? cleanUserName() : d->nickName;
}
NoString NoUser::altNick(bool bAllowDefault) const
{
    return (bAllowDefault && d->altNick.empty()) ? cleanUserName() : d->altNick;
}
NoString NoUser::ident(bool bAllowDefault) const
{
    return (bAllowDefault && d->ident.empty()) ? cleanUserName() : d->ident;
}
NoString NoUser::realName() const { return d->realName.empty() ? d->userName : d->realName; }
NoString NoUser::bindHost() const { return d->bindHost; }
NoString NoUser::dccBindHost() const { return d->dccBindHost; }
NoString NoUser::password() const { return d->password; }
NoUser::HashType NoUser::passwordHashType() const { return d->hashType; }
NoString NoUser::passwordSalt() const { return d->passwordSalt; }
bool NoUser::denyLoadMod() const { return d->denyLoadMod; }
bool NoUser::isAdmin() const { return d->admin; }
bool NoUser::denysetBindHost() const { return d->denysetBindHost; }
bool NoUser::multiClients() const { return d->multiClients; }
NoString NoUser::statusPrefix() const { return d->statusPrefix; }
NoString NoUser::defaultChanModes() const { return d->defaultChanModes; }
NoString NoUser::clientEncoding() const { return d->clientEncoding; }
bool NoUser::hasSpaceForNewNetwork() const { return networks().size() < maxNetworks(); }

NoString NoUser::quitMsg() const { return (!d->quitMsg.trim_n().empty()) ? d->quitMsg : NoApp::GetTag(false); }
NoStringMap NoUser::ctcpReplies() const { return d->ctcpReplies; }
uint NoUser::bufferCount() const { return d->bufferCount; }
bool NoUser::autoClearChanBuffer() const { return d->autoClearChanBuffer; }
bool NoUser::autoclearQueryBuffer() const { return d->autoclearQueryBuffer; }

bool NoUser::isBeingDeleted() const { return d->beingDeleted; }

NoString NoUser::timezone() const { return d->timezone; }

ulonglong NoUser::bytesRead() const { return d->bytesRead; }

ulonglong NoUser::bytesWritten() const { return d->bytesWritten; }

uint NoUser::joinTries() const { return d->maxJoinTries; }

uint NoUser::maxJoins() const { return d->maxJoins; }
// NoString NoUser::GetSkinName() const { return (!d->sSkinName.empty()) ? d->sSkinName : NoApp::Get().GetSkinName(); }
NoString NoUser::skinName() const { return d->skinName; }

uint NoUser::maxNetworks() const { return d->maxNetworks; }

uint NoUser::maxQueryBuffers() const { return d->maxQueryBuffers; }
NoString NoUser::userPath() const
{
    if (!NoFile::Exists(d->userPath)) {
        NoDir::MakeDir(d->userPath);
    }
    return d->userPath;
}
// !Getters
