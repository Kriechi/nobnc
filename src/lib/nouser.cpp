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
#include "nouser_p.h"
#include "nosettings.h"
#include "nofile.h"
#include "nodir.h"
#include "nonetwork.h"
#include "noircsocket.h"
#include "nochannel.h"
#include "noclient.h"
#include "nomodulecall.h"
#include "noapp_p.h"
#include "noregistry.h"
#include "Csocket/Csocket.h"
#include <math.h>
#include <algorithm>

class NoUserTimer : public CCron
{
public:
    NoUserTimer(NoUser* user) : CCron(), m_pUser(user)
    {
        SetName("NoUserTimer::" + m_pUser->userName());
        Start(NoNetwork::PingSlack);
    }

protected:
    void RunJob() override
    {
        const std::vector<NoClient*>& vUserClients = m_pUser->userClients();

        for (NoClient* pUserClient : vUserClients) {
            if (pUserClient->socket()->timeSinceLastDataTransaction() >= NoNetwork::PingFrequency) {
                pUserClient->putClient("PING :ZNC");
            }
        }
    }

    NoUser* m_pUser;
};

NoUser::NoUser(const NoString& userName) : d(new NoUserPrivate)
{
    d->userName = userName;
    d->cleanUserName = makeCleanUserName(userName);
    d->ident = d->cleanUserName;
    d->realName = userName;
    d->userPath = noApp->userPath() + "/" + userName;
    d->modules = new NoModuleLoader;
    d->userTimer = new NoUserTimer(this);
    noApp->manager()->addCron(d->userTimer);
}

NoUser::~NoUser()
{
    // Delete networks
    while (!d->networks.empty()) {
        delete *d->networks.begin();
    }

    // Delete clients
    while (!d->clients.empty()) {
        noApp->manager()->removeSocket(d->clients[0]->socket());
    }
    d->clients.clear();

    // Delete modules (unloads all modules!)
    delete d->modules;
    d->modules = nullptr;

    noApp->manager()->removeCron(d->userTimer);

    NoAppPrivate::get(noApp)->addBytesRead(bytesRead());
    NoAppPrivate::get(noApp)->addBytesWritten(bytesWritten());
}

template <class T>
struct TOption
{
    const char* name;
    void (NoUser::*pSetter)(T);
};

bool NoUser::parseConfig(NoSettings* settings, NoString& error)
{
    TOption<const NoString&> StringOptions[] = {
        { "nick", &NoUser::setNick },
        { "quitmsg", &NoUser::setQuitMessage },
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
        NoString value;
        if (settings->FindStringEntry(Option.name, value))
            (this->*Option.pSetter)(value);
    }
    for (const auto& Option : UIntOptions) {
        NoString value;
        if (settings->FindStringEntry(Option.name, value))
            (this->*Option.pSetter)(value.toUInt());
    }
    for (const auto& Option : BoolOptions) {
        NoString value;
        if (settings->FindStringEntry(Option.name, value))
            (this->*Option.pSetter)(value.toBool());
    }

    NoStringVector vsList;
    settings->FindStringVector("allow", vsList);
    for (const NoString& host : vsList) {
        addAllowedHost(host);
    }
    settings->FindStringVector("ctcpreply", vsList);
    for (const NoString& reply : vsList) {
        addCtcpReply(No::token(reply, 0), No::tokens(reply, 1));
    }

    NoString value;

    NoString sDCCLookupValue;
    settings->FindStringEntry("dcclookupmethod", sDCCLookupValue);
    if (settings->FindStringEntry("bouncedccs", value)) {
        if (value.toBool()) {
            No::printAction("Loading Module [bouncedcc]");
            NoString sModRet;
            bool bModRet = loader()->loadModule("bouncedcc", "", No::UserModule, this, nullptr, sModRet);

            No::printStatus(bModRet, sModRet);
            if (!bModRet) {
                error = sModRet;
                return false;
            }

            if (sDCCLookupValue.equals("client")) {
                NoModule* mod = loader()->findModule("bouncedcc");
                if (mod) {
                    NoRegistry registry(mod);
                    registry.setValue("UseClientIP", "1");
                }
            }
        }
    }
    if (settings->FindStringEntry("buffer", value))
        setBufferCount(value.toUInt(), true);
    if (settings->FindStringEntry("awaysuffix", value)) {
        No::printMessage("WARNING: AwaySuffix has been deprecated, instead try -> LoadModule = awaynick %nick%_" + value);
    }
    if (settings->FindStringEntry("autocycle", value)) {
        if (value.equals("true"))
            No::printError("WARNING: AutoCycle has been removed, instead try -> LoadModule = autocycle");
    }
    if (settings->FindStringEntry("keepnick", value)) {
        if (value.equals("true"))
            No::printError("WARNING: KeepNick has been deprecated, instead try -> LoadModule = keepnick");
    }
    if (settings->FindStringEntry("statusprefix", value)) {
        if (!setStatusPrefix(value)) {
            error = "Invalid StatusPrefix [" + value + "] Must be 1-5 chars, no spaces.";
            No::printError(error);
            return false;
        }
    }
    if (settings->FindStringEntry("timezone", value)) {
        setTimezone(value);
    }
    if (settings->FindStringEntry("timezoneoffset", value)) {
        if (fabs(value.toDouble()) > 0.1) {
            No::printError("WARNING: TimezoneOffset has been deprecated, now you can set your timezone by name");
        }
    }
    if (settings->FindStringEntry("timestamp", value)) {
        if (!value.trim_n().equals("true")) {
            if (value.trim_n().equals("append")) {
                setTimestampAppend(true);
                setTimestampPrepend(false);
            } else if (value.trim_n().equals("prepend")) {
                setTimestampAppend(false);
                setTimestampPrepend(true);
            } else if (value.trim_n().equals("false")) {
                setTimestampAppend(false);
                setTimestampPrepend(false);
            } else {
                setTimestampFormat(value);
            }
        }
    }
    settings->FindStringEntry("pass", value);
    // There are different formats for this available:
    // Pass = <plain text>
    // Pass = <md5 hash> -
    // Pass = plain#<plain text>
    // Pass = <hash name>#<hash>
    // Pass = <hash name>#<salted hash>#<salt>#
    // 'Salted hash' means hash of 'password' + 'salt'
    // Possible hashes are md5 and sha256
    if (value.right(1) == "-") {
        value.rightChomp(1);
        value.trim();
        setPassword(value, NoUser::HashMd5);
    } else {
        NoString sMethod = No::token(value, 0, "#");
        NoString pass = No::tokens(value, 1, "#");
        if (sMethod == "md5" || sMethod == "sha256") {
            NoUser::HashType type = NoUser::HashMd5;
            if (sMethod == "sha256")
                type = NoUser::HashSha256;

            NoString salt = No::token(pass, 1, "#");
            pass = No::token(pass, 0, "#");
            setPassword(pass, type, salt);
        } else if (sMethod == "plain") {
            setPassword(pass, NoUser::HashNone);
        } else {
            setPassword(value, NoUser::HashNone);
        }
    }
    NoSettings::SubConfig subConf;
    NoSettings::SubConfig::const_iterator subIt;
    settings->FindSubConfig("pass", subConf);
    if (!value.empty() && !subConf.empty()) {
        error = "Password defined more than once";
        No::printError(error);
        return false;
    }
    subIt = subConf.begin();
    if (subIt != subConf.end()) {
        NoSettings* pSubConf = subIt->second.m_subConfig;
        NoString sHash;
        NoString sMethod;
        NoString salt;
        NoUser::HashType method;
        pSubConf->FindStringEntry("hash", sHash);
        pSubConf->FindStringEntry("method", sMethod);
        pSubConf->FindStringEntry("salt", salt);
        if (sMethod.empty() || sMethod.equals("plain"))
            method = NoUser::HashNone;
        else if (sMethod.equals("md5"))
            method = NoUser::HashMd5;
        else if (sMethod.equals("sha256"))
            method = NoUser::HashSha256;
        else {
            error = "Invalid hash method";
            No::printError(error);
            return false;
        }

        setPassword(sHash, method, salt);
        if (!pSubConf->empty()) {
            error = "Unhandled lines in config!";
            No::printError(error);

            NoApp::dumpConfig(pSubConf);
            return false;
        }
        ++subIt;
    }
    if (subIt != subConf.end()) {
        error = "Password defined more than once";
        No::printError(error);
        return false;
    }

    settings->FindSubConfig("network", subConf);
    for (subIt = subConf.begin(); subIt != subConf.end(); ++subIt) {
        const NoString& sNetworkName = subIt->first;

        No::printMessage("Loading network [" + sNetworkName + "]");

        NoNetwork* network = findNetwork(sNetworkName);

        if (!network) {
            network = new NoNetwork(this, sNetworkName);
        }

        if (!network->parseConfig(subIt->second.m_subConfig, error)) {
            return false;
        }
    }

    if (settings->FindStringVector("server", vsList, false) || settings->FindStringVector("chan", vsList, false) ||
        settings->FindSubConfig("chan", subConf, false)) {
        NoNetwork* network = findNetwork("default");
        if (!network) {
            NoString sErrorDummy;
            network = addNetwork("default", sErrorDummy);
        }

        if (network) {
            No::printMessage("NOTICE: Found deprecated config, upgrading to a network");

            if (!network->parseConfig(settings, error, true)) {
                return false;
            }
        }
    }

    settings->FindStringVector("loadmodule", vsList);
    for (const NoString& sMod : vsList) {
        NoString name = No::token(sMod, 0);
        NoString notice = "Loading user module [" + name + "]";

        // XXX Legacy crap, added in ZNC 0.089
        if (name == "discon_kick") {
            notice = "NOTICE: [discon_kick] was renamed, loading [disconkick] instead";
            name = "disconkick";
        }

        // XXX Legacy crap, added in ZNC 0.099
        if (name == "fixfreenode") {
            notice = "NOTICE: [fixfreenode] doesn't do anything useful anymore, ignoring it";
            continue;
        }

        // XXX Legacy crap, added in ZNC 0.207
        if (name == "admin") {
            notice = "NOTICE: [admin] module was renamed, loading [controlpanel] instead";
            name = "controlpanel";
        }

        // XXX Legacy crap, should have been added ZNC 0.207, but added only in 1.1 :(
        if (name == "away") {
            notice = "NOTICE: [away] was renamed, loading [awaystore] instead";
            name = "awaystore";
        }

        // XXX Legacy crap, added in 1.1; fakeonline module was dropped in 1.0 and returned in 1.1
        if (name == "fakeonline") {
            notice = "NOTICE: [fakeonline] was renamed, loading [modules_online] instead";
            name = "modules_online";
        }

        // XXX Legacy crap, added in 1.3
        if (name == "charset") {
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
            for (NoNetwork* network : d->networks) {
                network->setEncoding(vsServer[0]);
            }
            No::printStatus(true, "Using [" + vsClient[0] + "] for clients, and [" + vsServer[0] + "] for servers");
            continue;
        }

        NoString sModRet;
        NoString args = No::tokens(sMod, 1);

        bool bModRet = loadModule(name, args, notice, sModRet);

        No::printStatus(bModRet, sModRet);
        if (!bModRet) {
            // XXX The awaynick module was retired in 1.6 (still available as external module)
            if (name == "awaynick") {
                // load simple_away instead, unless it's already on the list
                if (std::find(vsList.begin(), vsList.end(), "simple_away") == vsList.end()) {
                    notice = "Loading [simple_away] module instead";
                    name = "simple_away";
                    // not a fatal error if simple_away is not available
                    loadModule(name, args, notice, sModRet);
                }
            } else {
                error = sModRet;
                return false;
            }
        }
        continue;
    }

    // Move ircconnectenabled to the networks
    if (settings->FindStringEntry("ircconnectenabled", value)) {
        for (NoNetwork* network : d->networks) {
            network->setEnabled(value.toBool());
        }
    }

    return true;
}

NoNetwork* NoUser::addNetwork(const NoString& name, NoString& error)
{
    if (!NoNetwork::isValidNetwork(name)) {
        error = "Invalid network name. It should be alphanumeric. Not to be confused with server name";
        return nullptr;
    } else if (findNetwork(name)) {
        error = "network [" + No::token(name, 0) + "] already exists";
        return nullptr;
    }

    NoNetwork* network = new NoNetwork(this, name);

    bool bCancel = false;
    USERMODULECALL(onAddNetwork(*network, error), this, nullptr, &bCancel);
    if (bCancel) {
        removeNetwork(network);
        delete network;
        return nullptr;
    }

    return network;
}

bool NoUser::addNetwork(NoNetwork* network)
{
    if (findNetwork(network->name())) {
        return false;
    }

    d->networks.push_back(network);

    return true;
}

void NoUser::removeNetwork(NoNetwork* network)
{
    auto it = std::find(d->networks.begin(), d->networks.end(), network);
    if (it != d->networks.end()) {
        d->networks.erase(it);
    }
}

bool NoUser::deleteNetwork(const NoString& name)
{
    NoNetwork* network = findNetwork(name);

    if (network) {
        bool bCancel = false;
        USERMODULECALL(onDeleteNetwork(*network), this, nullptr, &bCancel);
        if (!bCancel) {
            delete network;
            return true;
        }
    }

    return false;
}

NoNetwork* NoUser::findNetwork(const NoString& name) const
{
    for (NoNetwork* network : d->networks) {
        if (network->name().equals(name)) {
            return network;
        }
    }

    return nullptr;
}

std::vector<NoNetwork*> NoUser::networks() const
{
    return d->networks;
}

NoString NoUser::expandString(const NoString& str) const
{
    NoString ret;
    return expandString(str, ret);
}

NoString& NoUser::expandString(const NoString& str, NoString& ret) const
{
    NoString sTime = No::cTime(time(nullptr), d->timezone);

    ret = str;
    ret.replace("%user%", userName());
    ret.replace("%defnick%", nick());
    ret.replace("%nick%", nick());
    ret.replace("%altnick%", altNick());
    ret.replace("%ident%", ident());
    ret.replace("%realname%", realName());
    ret.replace("%vhost%", bindHost());
    ret.replace("%bindhost%", bindHost());
    ret.replace("%version%", NoApp::version());
    ret.replace("%time%", sTime);
    ret.replace("%uptime%", noApp->uptime());
    // The following lines do not exist. You must be on DrUgS!
    ret.replace("%znc%", "All your IRC are belong to ZNC");
    // Chosen by fair zocchihedron dice roll by SilverLeo
    ret.replace("%rand%", "42");

    return ret;
}

NoString NoUser::addTimestamp(const NoString& str) const
{
    time_t tm;
    return addTimestamp(time(&tm), str);
}

NoString NoUser::addTimestamp(time_t tm, const NoString& str) const
{
    NoString ret = str;

    if (!timestampFormat().empty() && (d->appendTimestamp || d->prependTimestamp)) {
        NoString sTimestamp = No::formatTime(tm, timestampFormat(), d->timezone);
        if (sTimestamp.empty()) {
            return ret;
        }

        if (d->prependTimestamp) {
            ret = sTimestamp;
            ret += " " + str;
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
            if (NoString::npos != ret.find_first_of("\x02\x03\x04\x0F\x12\x16\x1D\x1F")) {
                ret += "\x0F";
            }

            ret += " " + sTimestamp;
        }
    }

    return ret;
}

void NoUser::bounceAllClients()
{
    for (NoClient* client : d->clients) {
        client->bouncedOff();
    }

    d->clients.clear();
}

void NoUser::setKeepBuffer(bool b)
{
    setAutoClearChanBuffer(!b);
}

void NoUser::userConnected(NoClient* client)
{
    if (!multiClients()) {
        bounceAllClients();
    }

    client->putClient(":irc.znc.in 001 " + client->nick() + " :- Welcome to ZNC -");

    d->clients.push_back(client);
}

void NoUser::userDisconnected(NoClient* client)
{
    auto it = std::find(d->clients.begin(), d->clients.end(), client);
    if (it != d->clients.end()) {
        d->clients.erase(it);
    }
}

void NoUser::cloneNetworks(const NoUser& User)
{
    const std::vector<NoNetwork*>& vNetworks = User.networks();
    for (NoNetwork* pUserNetwork : vNetworks) {
        NoNetwork* network = findNetwork(pUserNetwork->name());

        if (network) {
            network->clone(*pUserNetwork);
        } else {
            new NoNetwork(this, *pUserNetwork);
        }
    }

    std::set<NoString> ssDeleteNetworks;
    for (NoNetwork* network : d->networks) {
        if (!(User.findNetwork(network->name()))) {
            ssDeleteNetworks.insert(network->name());
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
            NoClient* client = vClients.front();
            // This line will remove client from vClients,
            // because it's a reference to the internal network's vector.
            client->setNetwork(nullptr);
        }

        deleteNetwork(sNetwork);
    }
}

bool NoUser::clone(const NoUser& User, NoString& error, bool cloneNetworks)
{
    error.clear();

    if (!User.isValid(error, true)) {
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
    setQuitMessage(User.quitMessage());
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
    for (const NoString& host : ssHosts) {
        addAllowedHost(host);
    }

    for (NoClient* client : d->clients) {
        NoSocket* socket = client->socket();
        if (!isHostAllowed(socket->remoteAddress())) {
            client->putStatusNotice(
            "You are being disconnected because your IP is no longer allowed to connect to this user");
            socket->close();
        }
    }

    // !Allowed Hosts

    // Networks
    if (cloneNetworks) {
        NoUser::cloneNetworks(User);
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

void NoUserPrivate::addBytesRead(ulonglong bytes)
{
    bytesRead += bytes;
}

void NoUserPrivate::addBytesWritten(ulonglong bytes)
{
    bytesWritten += bytes;
}

std::set<NoString> NoUser::allowedHosts() const
{
    return d->allowedHosts;
}
bool NoUser::addAllowedHost(const NoString& hostMask)
{
    if (hostMask.empty() || d->allowedHosts.find(hostMask) != d->allowedHosts.end()) {
        return false;
    }

    d->allowedHosts.insert(hostMask);
    return true;
}

bool NoUser::isHostAllowed(const NoString& hostMask) const
{
    if (d->allowedHosts.empty()) {
        return true;
    }

    for (const NoString& host : d->allowedHosts) {
        if (No::wildCmp(hostMask, host)) {
            return true;
        }
    }

    return false;
}

NoString NoUser::timestampFormat() const
{
    return d->timestampFormat;
}
bool NoUser::timestampAppend() const
{
    return d->appendTimestamp;
}
bool NoUser::timestampPrepend() const
{
    return d->prependTimestamp;
}

bool NoUser::isValidUserName(const NoString& userName)
{
    // /^[a-zA-Z][a-zA-Z@._\-]*$/
    const char* p = userName.c_str();

    if (userName.empty()) {
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

bool NoUser::isValid(NoString& error, bool skipPass) const
{
    error.clear();

    if (!skipPass && d->password.empty()) {
        error = "Pass is empty";
        return false;
    }

    if (d->userName.empty()) {
        error = "Username is empty";
        return false;
    }

    if (!NoUser::isValidUserName(d->userName)) {
        error = "Username is invalid";
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
    config.AddKeyValuePair("QuitMsg", quitMessage());
    if (noApp->statusPrefix() != statusPrefix())
        config.AddKeyValuePair("StatusPrefix", statusPrefix());
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
        for (const NoString& host : d->allowedHosts) {
            config.AddKeyValuePair("Allow", host);
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

    for (NoModule* mod : Mods->modules()) {
        NoString args = mod->args();

        if (!args.empty()) {
            args = " " + args;
        }

        config.AddKeyValuePair("LoadModule", mod->moduleName() + args);
    }

    // Networks
    for (NoNetwork* network : d->networks) {
        config.AddSubConfig("network", network->name(), network->toConfig());
    }

    return config;
}

bool NoUser::checkPass(const NoString& pass) const
{
    switch (d->hashType) {
    case HashMd5:
        return d->password.equals(No::saltedMd5(pass, d->passwordSalt));
    case HashSha256:
        return d->password.equals(No::saltedSha256(pass, d->passwordSalt));
    case HashNone:
    default:
        return (pass == d->password);
    }
}

/*NoClient* NoUser::client() {
    // Todo: optimize this by saving a pointer to the sock
    NoSocketManager& Manager = noApp->manager();
    NoString name = "USR::" + d->userName;

    for (uint a = 0; a < Manager.size(); a++) {
        Csock* socket = Manager[a];
        if (socket->GetSockName().equals(name)) {
            if (!socket->IsClosed()) {
                return (NoClient*) socket;
            }
        }
    }

    return (NoClient*) noApp->manager()->FindSockByName(name);
}*/

NoString NoUser::localDccIp() const
{
    if (!dccBindHost().empty())
        return dccBindHost();

    for (NoNetwork* network : d->networks) {
        NoIrcSocket* socket = network->ircSocket();
        if (socket) {
            return socket->localAddress();
        }
    }

    if (!allClients().empty()) {
        return allClients()[0]->socket()->localAddress();
    }

    return "";
}

bool NoUser::putUser(const NoString& line, NoClient* client, NoClient* skipClient)
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

bool NoUser::putAllUser(const NoString& line, NoClient* client, NoClient* skipClient)
{
    putUser(line, client, skipClient);

    for (NoNetwork* network : d->networks) {
        if (network->putUser(line, client, skipClient)) {
            return true;
        }
    }

    return (client == nullptr);
}

bool NoUser::putStatus(const NoString& line, NoClient* client, NoClient* skipClient)
{
    std::vector<NoClient*> vClients = allClients();
    for (NoClient* pEachClient : vClients) {
        if ((!client || client == pEachClient) && skipClient != pEachClient) {
            pEachClient->putStatus(line);

            if (client) {
                return true;
            }
        }
    }

    return (client == nullptr);
}

bool NoUser::putStatusNotice(const NoString& line, NoClient* client, NoClient* skipClient)
{
    std::vector<NoClient*> vClients = allClients();
    for (NoClient* pEachClient : vClients) {
        if ((!client || client == pEachClient) && skipClient != pEachClient) {
            pEachClient->putStatusNotice(line);

            if (client) {
                return true;
            }
        }
    }

    return (client == nullptr);
}

bool NoUser::putModule(const NoString& module, const NoString& line, NoClient* client, NoClient* skipClient)
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

bool NoUser::putModuleNotice(const NoString& module, const NoString& line, NoClient* client, NoClient* skipClient)
{
    for (NoClient* pEachClient : d->clients) {
        if ((!client || client == pEachClient) && skipClient != pEachClient) {
            pEachClient->putModuleNotice(module, line);

            if (client) {
                return true;
            }
        }
    }

    return (client == nullptr);
}

NoString NoUser::makeCleanUserName(const NoString& userName)
{
    return No::token(userName, 0, "@").replace_n(".", "");
}

NoModuleLoader* NoUser::loader() const
{
    return d->modules;
}

bool NoUser::isUserAttached() const
{
    if (!d->clients.empty()) {
        return true;
    }

    for (const NoNetwork* network : d->networks) {
        if (network->isUserAttached()) {
            return true;
        }
    }

    return false;
}

bool NoUser::loadModule(const NoString& name, const NoString& args, const NoString& notice, NoString& error)
{
    bool bModRet = true;
    NoString sModRet;

    NoModuleInfo info;
    if (!noApp->loader()->moduleInfo(info, name, sModRet)) {
        error = "Unable to find modinfo [" + name + "] [" + sModRet + "]";
        return false;
    }

    No::printAction(notice);

    if (!info.supportsType(No::UserModule) && info.supportsType(No::NetworkModule)) {
        No::printMessage("NOTICE: Module [" + name +
                         "] is a network module, loading module for all networks in user.");

        // Do they have old NV?
        NoFile fNVFile = NoFile(userPath() + "/moddata/" + name + "/.registry");

        for (NoNetwork* network : d->networks) {
            if (fNVFile.Exists()) {
                NoString sNetworkModPath = network->networkPath() + "/moddata/" + name;
                if (!NoFile::Exists(sNetworkModPath)) {
                    NoDir::mkpath(sNetworkModPath);
                }

                fNVFile.Copy(sNetworkModPath + "/.registry");
            }

            bModRet = network->loader()->loadModule(name, args, No::NetworkModule, this, network, sModRet);
            if (!bModRet) {
                break;
            }
        }
    } else {
        bModRet = loader()->loadModule(name, args, No::UserModule, this, nullptr, sModRet);
    }

    if (!bModRet) {
        error = sModRet;
    }
    return bModRet;
}

// Setters
void NoUser::setNick(const NoString& s)
{
    d->nickName = s;
}
void NoUser::setAltNick(const NoString& s)
{
    d->altNick = s;
}
void NoUser::setIdent(const NoString& s)
{
    d->ident = s;
}
void NoUser::setRealName(const NoString& s)
{
    d->realName = s;
}
void NoUser::setBindHost(const NoString& s)
{
    d->bindHost = s;
}
void NoUser::setDccBindHost(const NoString& s)
{
    d->dccBindHost = s;
}
void NoUser::setPassword(const NoString& s, HashType hash, const NoString& salt)
{
    d->password = s;
    d->hashType = hash;
    d->passwordSalt = salt;
}
void NoUser::setMultiClients(bool b)
{
    d->multiClients = b;
}
void NoUser::setDenyLoadMod(bool b)
{
    d->denyLoadMod = b;
}
void NoUser::setAdmin(bool b)
{
    d->admin = b;
}
void NoUser::setDenysetBindHost(bool b)
{
    d->denysetBindHost = b;
}
void NoUser::setDefaultChanModes(const NoString& s)
{
    d->defaultChanModes = s;
}
void NoUser::setClientEncoding(const NoString& s)
{
    d->clientEncoding = s;
}
void NoUser::setQuitMessage(const NoString& s)
{
    d->quitMessage = s;
}
void NoUser::setAutoClearChanBuffer(bool b)
{
    for (NoNetwork* network : d->networks) {
        for (NoChannel* channel : network->channels()) {
            channel->inheritAutoClearChanBuffer(b);
        }
    }
    d->autoClearChanBuffer = b;
}
void NoUser::setAutoclearQueryBuffer(bool b)
{
    d->autoclearQueryBuffer = b;
}

void NoUser::setBeingDeleted(bool b)
{
    d->beingDeleted = b;
}

void NoUser::setTimestampFormat(const NoString& s)
{
    d->timestampFormat = s;
}

void NoUser::setTimestampAppend(bool b)
{
    d->appendTimestamp = b;
}

void NoUser::setTimestampPrepend(bool b)
{
    d->prependTimestamp = b;
}

void NoUser::setTimezone(const NoString& s)
{
    d->timezone = s;
}

void NoUser::setJoinTries(uint i)
{
    d->maxJoinTries = i;
}

void NoUser::setMaxJoins(uint i)
{
    d->maxJoins = i;
}

void NoUser::setSkinName(const NoString& s)
{
    d->skinName = s;
}

void NoUser::setMaxNetworks(uint i)
{
    d->maxNetworks = i;
}

void NoUser::setMaxQueryBuffers(uint i)
{
    d->maxQueryBuffers = i;
}

std::vector<NoClient*> NoUser::userClients() const
{
    return d->clients;
}

bool NoUser::setBufferCount(uint u, bool force)
{
    if (!force && u > noApp->maxBufferSize())
        return false;
    for (NoNetwork* network : d->networks) {
        for (NoChannel* channel : network->channels()) {
            channel->inheritBufferCount(u, force);
        }
    }
    d->bufferCount = u;
    return true;
}

bool NoUser::addCtcpReply(const NoString& ctcp, const NoString& reply)
{
    // Reject CTCP requests containing spaces
    if (ctcp.find_first_of(' ') != NoString::npos) {
        return false;
    }
    // Reject empty CTCP requests
    if (ctcp.empty()) {
        return false;
    }
    d->ctcpReplies[ctcp.toUpper()] = reply;
    return true;
}

bool NoUser::removeCtcpReply(const NoString& ctcp)
{
    return d->ctcpReplies.erase(ctcp) > 0;
}

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

    for (NoNetwork* network : d->networks) {
        for (NoClient* client : network->clients()) {
            vClients.push_back(client);
        }
    }

    for (NoClient* client : d->clients) {
        vClients.push_back(client);
    }

    return vClients;
}

NoString NoUser::userName() const
{
    return d->userName;
}
NoString NoUser::cleanUserName() const
{
    return d->cleanUserName;
}
NoString NoUser::nick(bool allowDefault) const
{
    return (allowDefault && d->nickName.empty()) ? cleanUserName() : d->nickName;
}
NoString NoUser::altNick(bool allowDefault) const
{
    return (allowDefault && d->altNick.empty()) ? cleanUserName() : d->altNick;
}
NoString NoUser::ident(bool allowDefault) const
{
    return (allowDefault && d->ident.empty()) ? cleanUserName() : d->ident;
}
NoString NoUser::realName() const
{
    return d->realName.empty() ? d->userName : d->realName;
}
NoString NoUser::bindHost() const
{
    return d->bindHost;
}
NoString NoUser::dccBindHost() const
{
    return d->dccBindHost;
}
NoString NoUser::password() const
{
    return d->password;
}
NoUser::HashType NoUser::passwordHashType() const
{
    return d->hashType;
}
NoString NoUser::passwordSalt() const
{
    return d->passwordSalt;
}
bool NoUser::denyLoadMod() const
{
    return d->denyLoadMod;
}
bool NoUser::isAdmin() const
{
    return d->admin;
}
bool NoUser::denysetBindHost() const
{
    return d->denysetBindHost;
}
bool NoUser::multiClients() const
{
    return d->multiClients;
}
NoString NoUser::statusPrefix() const
{
    return d->statusPrefix;
}
NoString NoUser::defaultChanModes() const
{
    return d->defaultChanModes;
}
NoString NoUser::clientEncoding() const
{
    return d->clientEncoding;
}
bool NoUser::hasSpaceForNewNetwork() const
{
    return networks().size() < maxNetworks();
}

NoString NoUser::quitMessage() const
{
    return (!d->quitMessage.trim_n().empty()) ? d->quitMessage : NoApp::tag(false);
}
NoStringMap NoUser::ctcpReplies() const
{
    return d->ctcpReplies;
}
uint NoUser::bufferCount() const
{
    return d->bufferCount;
}
bool NoUser::autoClearChanBuffer() const
{
    return d->autoClearChanBuffer;
}
bool NoUser::autoclearQueryBuffer() const
{
    return d->autoclearQueryBuffer;
}

bool NoUser::isBeingDeleted() const
{
    return d->beingDeleted;
}

NoString NoUser::timezone() const
{
    return d->timezone;
}

ulonglong NoUser::bytesRead() const
{
    return d->bytesRead;
}

ulonglong NoUser::bytesWritten() const
{
    return d->bytesWritten;
}

uint NoUser::joinTries() const
{
    return d->maxJoinTries;
}

uint NoUser::maxJoins() const
{
    return d->maxJoins;
}
// NoString NoUser::GetSkinName() const { return (!d->sSkinName.empty()) ? d->sSkinName : noApp->GetSkinName(); }
NoString NoUser::skinName() const
{
    return d->skinName;
}

uint NoUser::maxNetworks() const
{
    return d->maxNetworks;
}

uint NoUser::maxQueryBuffers() const
{
    return d->maxQueryBuffers;
}
NoString NoUser::userPath() const
{
    if (!NoFile::Exists(d->userPath)) {
        NoDir::mkpath(d->userPath);
    }
    return d->userPath;
}
// !Getters