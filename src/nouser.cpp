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

#include "nouser.h"
#include "nosettings.h"
#include "nofile.h"
#include "nodir.h"
#include "nonetwork.h"
#include "noircsock.h"
#include "nochannel.h"
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
    virtual ~NoUserTimer() {}

    NoUserTimer(const NoUserTimer&) = delete;
    NoUserTimer& operator=(const NoUserTimer&) = delete;

private:
protected:
    void RunJob() override
    {
        const std::vector<NoClient*>& vUserClients = m_pUser->GetUserClients();

        for (NoClient* pUserClient : vUserClients) {
            if (pUserClient->GetTimeSinceLastDataTransaction() >= NoNetwork::PING_FREQUENCY) {
                pUserClient->PutClient("PING :ZNC");
            }
        }
    }

    NoUser* m_pUser;
};

NoUser::NoUser(const NoString& sUserName)
    : m_sUserName(sUserName), m_sCleanUserName(MakeCleanUserName(sUserName)), m_sNick(m_sCleanUserName), m_sAltNick(""),
      m_sIdent(m_sCleanUserName), m_sRealName(sUserName), m_sBindHost(""), m_sDCCBindHost(""), m_sPass(""),
      m_sPassSalt(""), m_sStatusPrefix("*"), m_sDefaultChanModes(""), m_sClientEncoding(""), m_sQuitMsg(""),
      m_mssCTCPReplies(), m_sTimestampFormat("[%H:%M:%S]"), m_sTimezone(""), m_eHashType(HASH_NONE),
      m_sUserPath(NoApp::Get().GetUserPath() + "/" + sUserName), m_bMultiClients(true), m_bDenyLoadMod(false),
      m_bAdmin(false), m_bDenySetBindHost(false), m_bAutoClearChanBuffer(true), m_bAutoClearQueryBuffer(true),
      m_bBeingDeleted(false), m_bAppendTimestamp(false), m_bPrependTimestamp(true), m_pUserTimer(nullptr), m_vIRNoNetworks(),
      m_vClients(), m_ssAllowedHosts(), m_uBufferCount(50), m_uBytesRead(0), m_uBytesWritten(0), m_uMaxJoinTries(10),
      m_uMaxNetworks(1), m_uMaxQueryBuffers(50), m_uMaxJoins(0), m_sSkinName(""), m_pModules(new NoModules)
{
    m_pUserTimer = new NoUserTimer(this);
    NoApp::Get().GetManager().AddCron(m_pUserTimer);
}

NoUser::~NoUser()
{
    // Delete networks
    while (!m_vIRNoNetworks.empty()) {
        delete *m_vIRNoNetworks.begin();
    }

    // Delete clients
    while (!m_vClients.empty()) {
        NoApp::Get().GetManager().DelSockByAddr(m_vClients[0]);
    }
    m_vClients.clear();

    // Delete modules (unloads all modules!)
    delete m_pModules;
    m_pModules = nullptr;

    NoApp::Get().GetManager().DelCronByAddr(m_pUserTimer);

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
        if (pConfig->FindStringEntry(Option.name, sValue)) (this->*Option.pSetter)(sValue.ToUInt());
    }
    for (const auto& Option : BoolOptions) {
        NoString sValue;
        if (pConfig->FindStringEntry(Option.name, sValue)) (this->*Option.pSetter)(sValue.ToBool());
    }

    NoStringVector vsList;
    pConfig->FindStringVector("allow", vsList);
    for (const NoString& sHost : vsList) {
        AddAllowedHost(sHost);
    }
    pConfig->FindStringVector("ctcpreply", vsList);
    for (const NoString& sReply : vsList) {
        AddCTCPReply(sReply.Token(0), sReply.Token(1, true));
    }

    NoString sValue;

    NoString sDCCLookupValue;
    pConfig->FindStringEntry("dcclookupmethod", sDCCLookupValue);
    if (pConfig->FindStringEntry("bouncedccs", sValue)) {
        if (sValue.ToBool()) {
            NoUtils::PrintAction("Loading Module [bouncedcc]");
            NoString sModRet;
            bool bModRet = GetModules().LoadModule("bouncedcc", "", NoModInfo::UserModule, this, nullptr, sModRet);

            NoUtils::PrintStatus(bModRet, sModRet);
            if (!bModRet) {
                sError = sModRet;
                return false;
            }

            if (sDCCLookupValue.Equals("Client")) {
                GetModules().FindModule("bouncedcc")->SetNV("UseClientIP", "1");
            }
        }
    }
    if (pConfig->FindStringEntry("buffer", sValue)) SetBufferCount(sValue.ToUInt(), true);
    if (pConfig->FindStringEntry("awaysuffix", sValue)) {
        NoUtils::PrintMessage("WARNING: AwaySuffix has been deprecated, instead try -> LoadModule = awaynick %nick%_" + sValue);
    }
    if (pConfig->FindStringEntry("autocycle", sValue)) {
        if (sValue.Equals("true"))
            NoUtils::PrintError("WARNING: AutoCycle has been removed, instead try -> LoadModule = autocycle");
    }
    if (pConfig->FindStringEntry("keepnick", sValue)) {
        if (sValue.Equals("true"))
            NoUtils::PrintError("WARNING: KeepNick has been deprecated, instead try -> LoadModule = keepnick");
    }
    if (pConfig->FindStringEntry("statusprefix", sValue)) {
        if (!SetStatusPrefix(sValue)) {
            sError = "Invalid StatusPrefix [" + sValue + "] Must be 1-5 chars, no spaces.";
            NoUtils::PrintError(sError);
            return false;
        }
    }
    if (pConfig->FindStringEntry("timezone", sValue)) {
        SetTimezone(sValue);
    }
    if (pConfig->FindStringEntry("timezoneoffset", sValue)) {
        if (fabs(sValue.ToDouble()) > 0.1) {
            NoUtils::PrintError("WARNING: TimezoneOffset has been deprecated, now you can set your timezone by name");
        }
    }
    if (pConfig->FindStringEntry("timestamp", sValue)) {
        if (!sValue.Trim_n().Equals("true")) {
            if (sValue.Trim_n().Equals("append")) {
                SetTimestampAppend(true);
                SetTimestampPrepend(false);
            } else if (sValue.Trim_n().Equals("prepend")) {
                SetTimestampAppend(false);
                SetTimestampPrepend(true);
            } else if (sValue.Trim_n().Equals("false")) {
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
    if (sValue.Right(1) == "-") {
        sValue.RightChomp(1);
        sValue.Trim();
        SetPass(sValue, NoUser::HASH_MD5);
    } else {
        NoString sMethod = sValue.Token(0, false, "#");
        NoString sPass = sValue.Token(1, true, "#");
        if (sMethod == "md5" || sMethod == "sha256") {
            NoUser::eHashType type = NoUser::HASH_MD5;
            if (sMethod == "sha256") type = NoUser::HASH_SHA256;

            NoString sSalt = sPass.Token(1, false, "#");
            sPass = sPass.Token(0, false, "#");
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
        NoUtils::PrintError(sError);
        return false;
    }
    subIt = subConf.begin();
    if (subIt != subConf.end()) {
        NoSettings* pSubConf = subIt->second.m_pSubConfig;
        NoString sHash;
        NoString sMethod;
        NoString sSalt;
        NoUser::eHashType method;
        pSubConf->FindStringEntry("hash", sHash);
        pSubConf->FindStringEntry("method", sMethod);
        pSubConf->FindStringEntry("salt", sSalt);
        if (sMethod.empty() || sMethod.Equals("plain"))
            method = NoUser::HASH_NONE;
        else if (sMethod.Equals("md5"))
            method = NoUser::HASH_MD5;
        else if (sMethod.Equals("sha256"))
            method = NoUser::HASH_SHA256;
        else {
            sError = "Invalid hash method";
            NoUtils::PrintError(sError);
            return false;
        }

        SetPass(sHash, method, sSalt);
        if (!pSubConf->empty()) {
            sError = "Unhandled lines in config!";
            NoUtils::PrintError(sError);

            NoApp::DumpConfig(pSubConf);
            return false;
        }
        ++subIt;
    }
    if (subIt != subConf.end()) {
        sError = "Password defined more than once";
        NoUtils::PrintError(sError);
        return false;
    }

    pConfig->FindSubConfig("network", subConf);
    for (subIt = subConf.begin(); subIt != subConf.end(); ++subIt) {
        const NoString& sNetworkName = subIt->first;

        NoUtils::PrintMessage("Loading network [" + sNetworkName + "]");

        NoNetwork* pNetwork = FindNetwork(sNetworkName);

        if (!pNetwork) {
            pNetwork = new NoNetwork(this, sNetworkName);
        }

        if (!pNetwork->ParseConfig(subIt->second.m_pSubConfig, sError)) {
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
            NoUtils::PrintMessage("NOTICE: Found deprecated config, upgrading to a network");

            if (!pNetwork->ParseConfig(pConfig, sError, true)) {
                return false;
            }
        }
    }

    pConfig->FindStringVector("loadmodule", vsList);
    for (const NoString& sMod : vsList) {
        NoString sModName = sMod.Token(0);
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
            NoUtils::PrintAction("NOTICE: Charset support was moved to core, importing old charset module settings");
            size_t uIndex = 1;
            if (sMod.Token(uIndex).Equals("-force")) {
                uIndex++;
            }
            NoStringVector vsClient = sMod.Token(uIndex).Split(",");
            NoStringVector vsServer = sMod.Token(uIndex + 1).Split(",");
            if (vsClient.empty() || vsServer.empty()) {
                NoUtils::PrintStatus(false, "charset module was loaded with wrong parameters.");
                continue;
            }
            SetClientEncoding(vsClient[0]);
            for (NoNetwork* pNetwork : m_vIRNoNetworks) {
                pNetwork->SetEncoding(vsServer[0]);
            }
            NoUtils::PrintStatus(true, "Using [" + vsClient[0] + "] for clients, and [" + vsServer[0] + "] for servers");
            continue;
        }

        NoString sModRet;
        NoString sArgs = sMod.Token(1, true);

        bool bModRet = LoadModule(sModName, sArgs, sNotice, sModRet);

        NoUtils::PrintStatus(bModRet, sModRet);
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
        for (NoNetwork* pNetwork : m_vIRNoNetworks) {
            pNetwork->SetIRCConnectEnabled(sValue.ToBool());
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
        sErrorRet = "Network [" + sNetwork.Token(0) + "] already exists";
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

    m_vIRNoNetworks.push_back(pNetwork);

    return true;
}

void NoUser::RemoveNetwork(NoNetwork* pNetwork)
{
    auto it = std::find(m_vIRNoNetworks.begin(), m_vIRNoNetworks.end(), pNetwork);
    if (it != m_vIRNoNetworks.end()) {
        m_vIRNoNetworks.erase(it);
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
    for (NoNetwork* pNetwork : m_vIRNoNetworks) {
        if (pNetwork->GetName().Equals(sNetwork)) {
            return pNetwork;
        }
    }

    return nullptr;
}

const std::vector<NoNetwork*>& NoUser::GetNetworks() const { return m_vIRNoNetworks; }

NoString NoUser::ExpandString(const NoString& sStr) const
{
    NoString sRet;
    return ExpandString(sStr, sRet);
}

NoString& NoUser::ExpandString(const NoString& sStr, NoString& sRet) const
{
    NoString sTime = NoUtils::CTime(time(nullptr), m_sTimezone);

    sRet = sStr;
    sRet.Replace("%user%", GetUserName());
    sRet.Replace("%defnick%", GetNick());
    sRet.Replace("%nick%", GetNick());
    sRet.Replace("%altnick%", GetAltNick());
    sRet.Replace("%ident%", GetIdent());
    sRet.Replace("%realname%", GetRealName());
    sRet.Replace("%vhost%", GetBindHost());
    sRet.Replace("%bindhost%", GetBindHost());
    sRet.Replace("%version%", NoApp::GetVersion());
    sRet.Replace("%time%", sTime);
    sRet.Replace("%uptime%", NoApp::Get().GetUptime());
    // The following lines do not exist. You must be on DrUgS!
    sRet.Replace("%znc%", "All your IRC are belong to ZNC");
    // Chosen by fair zocchihedron dice roll by SilverLeo
    sRet.Replace("%rand%", "42");

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

    if (!GetTimestampFormat().empty() && (m_bAppendTimestamp || m_bPrependTimestamp)) {
        NoString sTimestamp = NoUtils::FormatTime(tm, GetTimestampFormat(), m_sTimezone);
        if (sTimestamp.empty()) {
            return sRet;
        }

        if (m_bPrependTimestamp) {
            sRet = sTimestamp;
            sRet += " " + sStr;
        }
        if (m_bAppendTimestamp) {
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
            // Keep in sync with NoIrcSocket::IcuExt__UCallback
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
    for (NoClient* pClient : m_vClients) {
        pClient->BouncedOff();
    }

    m_vClients.clear();
}

void NoUser::UserConnected(NoClient* pClient)
{
    if (!MultiClients()) {
        BounceAllClients();
    }

    pClient->PutClient(":irc.znc.in 001 " + pClient->GetNick() + " :- Welcome to ZNC -");

    m_vClients.push_back(pClient);
}

void NoUser::UserDisconnected(NoClient* pClient)
{
    auto it = std::find(m_vClients.begin(), m_vClients.end(), pClient);
    if (it != m_vClients.end()) {
        m_vClients.erase(it);
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
    for (NoNetwork* pNetwork : m_vIRNoNetworks) {
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
        DEBUG("Ignoring username in NoUser::Clone(), old username [" << GetUserName() << "]; New username ["
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
    m_ssAllowedHosts.clear();
    const std::set<NoString>& ssHosts = User.GetAllowedHosts();
    for (const NoString& sHost : ssHosts) {
        AddAllowedHost(sHost);
    }

    for (NoClient* pSock : m_vClients) {
        if (!IsHostAllowed(pSock->GetRemoteIP())) {
            pSock->PutStatusNotice(
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
    m_mssCTCPReplies.clear();
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
            vCurMods.LoadModule(pNewMod->GetModName(), pNewMod->GetArgs(), NoModInfo::UserModule, this, nullptr, sModRet);
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

const std::set<NoString>& NoUser::GetAllowedHosts() const { return m_ssAllowedHosts; }
bool NoUser::AddAllowedHost(const NoString& sHostMask)
{
    if (sHostMask.empty() || m_ssAllowedHosts.find(sHostMask) != m_ssAllowedHosts.end()) {
        return false;
    }

    m_ssAllowedHosts.insert(sHostMask);
    return true;
}

bool NoUser::IsHostAllowed(const NoString& sHostMask) const
{
    if (m_ssAllowedHosts.empty()) {
        return true;
    }

    for (const NoString& sHost : m_ssAllowedHosts) {
        if (sHostMask.WildCmp(sHost)) {
            return true;
        }
    }

    return false;
}

const NoString& NoUser::GetTimestampFormat() const { return m_sTimestampFormat; }
bool NoUser::GetTimestampAppend() const { return m_bAppendTimestamp; }
bool NoUser::GetTimestampPrepend() const { return m_bPrependTimestamp; }

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

    if (!bSkipPass && m_sPass.empty()) {
        sErrMsg = "Pass is empty";
        return false;
    }

    if (m_sUserName.empty()) {
        sErrMsg = "Username is empty";
        return false;
    }

    if (!NoUser::IsValidUserName(m_sUserName)) {
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
    switch (m_eHashType) {
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
    passConfig.AddKeyValuePair("Salt", m_sPassSalt);
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
    config.AddKeyValuePair("Timezone", m_sTimezone);
    config.AddKeyValuePair("JoinTries", NoString(m_uMaxJoinTries));
    config.AddKeyValuePair("MaxNetworks", NoString(m_uMaxNetworks));
    config.AddKeyValuePair("MaxQueryBuffers", NoString(m_uMaxQueryBuffers));
    config.AddKeyValuePair("MaxJoins", NoString(m_uMaxJoins));
    config.AddKeyValuePair("ClientEncoding", GetClientEncoding());

    // Allow Hosts
    if (!m_ssAllowedHosts.empty()) {
        for (const NoString& sHost : m_ssAllowedHosts) {
            config.AddKeyValuePair("Allow", sHost);
        }
    }

    // CTCP Replies
    if (!m_mssCTCPReplies.empty()) {
        for (const auto& itb : m_mssCTCPReplies) {
            config.AddKeyValuePair("CTCPReply", itb.first.AsUpper() + " " + itb.second);
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
    for (NoNetwork* pNetwork : m_vIRNoNetworks) {
        config.AddSubConfig("Network", pNetwork->GetName(), pNetwork->ToConfig());
    }

    return config;
}

bool NoUser::CheckPass(const NoString& sPass) const
{
    switch (m_eHashType) {
    case HASH_MD5:
        return m_sPass.Equals(NoUtils::SaltedMD5Hash(sPass, m_sPassSalt));
    case HASH_SHA256:
        return m_sPass.Equals(NoUtils::SaltedSHA256Hash(sPass, m_sPassSalt));
    case HASH_NONE:
    default:
        return (sPass == m_sPass);
    }
}

/*NoClient* NoUser::GetClient() {
    // Todo: optimize this by saving a pointer to the sock
    NoSocketManager& Manager = NoApp::Get().GetManager();
    NoString sSockName = "USR::" + m_sUserName;

    for (uint a = 0; a < Manager.size(); a++) {
        Csock* pSock = Manager[a];
        if (pSock->GetSockName().Equals(sSockName)) {
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

    for (NoNetwork* pNetwork : m_vIRNoNetworks) {
        NoIrcSock* pIRCSock = pNetwork->GetIRCSock();
        if (pIRCSock) {
            return pIRCSock->GetLocalIP();
        }
    }

    if (!GetAllClients().empty()) {
        return GetAllClients()[0]->GetLocalIP();
    }

    return "";
}

bool NoUser::PutUser(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
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

bool NoUser::PutAllUser(const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    PutUser(sLine, pClient, pSkipClient);

    for (NoNetwork* pNetwork : m_vIRNoNetworks) {
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

bool NoUser::PutModNotice(const NoString& sModule, const NoString& sLine, NoClient* pClient, NoClient* pSkipClient)
{
    for (NoClient* pEachClient : m_vClients) {
        if ((!pClient || pClient == pEachClient) && pSkipClient != pEachClient) {
            pEachClient->PutModNotice(sModule, sLine);

            if (pClient) {
                return true;
            }
        }
    }

    return (pClient == nullptr);
}

NoString NoUser::MakeCleanUserName(const NoString& sUserName) { return sUserName.Token(0, false, "@").Replace_n(".", ""); }

bool NoUser::IsUserAttached() const
{
    if (!m_vClients.empty()) {
        return true;
    }

    for (const NoNetwork* pNetwork : m_vIRNoNetworks) {
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

    NoModInfo ModInfo;
    if (!NoApp::Get().GetModules().GetModInfo(ModInfo, sModName, sModRet)) {
        sError = "Unable to find modinfo [" + sModName + "] [" + sModRet + "]";
        return false;
    }

    NoUtils::PrintAction(sNotice);

    if (!ModInfo.SupportsType(NoModInfo::UserModule) && ModInfo.SupportsType(NoModInfo::NetworkModule)) {
        NoUtils::PrintMessage("NOTICE: Module [" + sModName +
                             "] is a network module, loading module for all networks in user.");

        // Do they have old NV?
        NoFile fNVFile = NoFile(GetUserPath() + "/moddata/" + sModName + "/.registry");

        for (NoNetwork* pNetwork : m_vIRNoNetworks) {
            if (fNVFile.Exists()) {
                NoString sNetworkModPath = pNetwork->GetNetworkPath() + "/moddata/" + sModName;
                if (!NoFile::Exists(sNetworkModPath)) {
                    NoDir::MakeDir(sNetworkModPath);
                }

                fNVFile.Copy(sNetworkModPath + "/.registry");
            }

            bModRet = pNetwork->GetModules().LoadModule(sModName, sArgs, NoModInfo::NetworkModule, this, pNetwork, sModRet);
            if (!bModRet) {
                break;
            }
        }
    } else {
        bModRet = GetModules().LoadModule(sModName, sArgs, NoModInfo::UserModule, this, nullptr, sModRet);
    }

    if (!bModRet) {
        sError = sModRet;
    }
    return bModRet;
}

// Setters
void NoUser::SetNick(const NoString& s) { m_sNick = s; }
void NoUser::SetAltNick(const NoString& s) { m_sAltNick = s; }
void NoUser::SetIdent(const NoString& s) { m_sIdent = s; }
void NoUser::SetRealName(const NoString& s) { m_sRealName = s; }
void NoUser::SetBindHost(const NoString& s) { m_sBindHost = s; }
void NoUser::SetDCCBindHost(const NoString& s) { m_sDCCBindHost = s; }
void NoUser::SetPass(const NoString& s, eHashType eHash, const NoString& sSalt)
{
    m_sPass = s;
    m_eHashType = eHash;
    m_sPassSalt = sSalt;
}
void NoUser::SetMultiClients(bool b) { m_bMultiClients = b; }
void NoUser::SetDenyLoadMod(bool b) { m_bDenyLoadMod = b; }
void NoUser::SetAdmin(bool b) { m_bAdmin = b; }
void NoUser::SetDenySetBindHost(bool b) { m_bDenySetBindHost = b; }
void NoUser::SetDefaultChanModes(const NoString& s) { m_sDefaultChanModes = s; }
void NoUser::SetClientEncoding(const NoString& s) { m_sClientEncoding = s; }
void NoUser::SetQuitMsg(const NoString& s) { m_sQuitMsg = s; }
void NoUser::SetAutoClearChanBuffer(bool b)
{
    for (NoNetwork* pNetwork : m_vIRNoNetworks) {
        for (NoChannel* pChan : pNetwork->GetChans()) {
            pChan->inheritAutoClearChanBuffer(b);
        }
    }
    m_bAutoClearChanBuffer = b;
}
void NoUser::SetAutoClearQueryBuffer(bool b) { m_bAutoClearQueryBuffer = b; }

bool NoUser::SetBufferCount(uint u, bool bForce)
{
    if (!bForce && u > NoApp::Get().GetMaxBufferSize()) return false;
    for (NoNetwork* pNetwork : m_vIRNoNetworks) {
        for (NoChannel* pChan : pNetwork->GetChans()) {
            pChan->inheritBufferCount(u, bForce);
        }
    }
    m_uBufferCount = u;
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
    m_mssCTCPReplies[sCTCP.AsUpper()] = sReply;
    return true;
}

bool NoUser::DelCTCPReply(const NoString& sCTCP) { return m_mssCTCPReplies.erase(sCTCP) > 0; }

bool NoUser::SetStatusPrefix(const NoString& s)
{
    if ((!s.empty()) && (s.length() < 6) && (s.find(' ') == NoString::npos)) {
        m_sStatusPrefix = (s.empty()) ? "*" : s;
        return true;
    }

    return false;
}
// !Setters

// Getters
std::vector<NoClient*> NoUser::GetAllClients() const
{
    std::vector<NoClient*> vClients;

    for (NoNetwork* pNetwork : m_vIRNoNetworks) {
        for (NoClient* pClient : pNetwork->GetClients()) {
            vClients.push_back(pClient);
        }
    }

    for (NoClient* pClient : m_vClients) {
        vClients.push_back(pClient);
    }

    return vClients;
}

const NoString& NoUser::GetUserName() const { return m_sUserName; }
const NoString& NoUser::GetCleanUserName() const { return m_sCleanUserName; }
const NoString& NoUser::GetNick(bool bAllowDefault) const
{
    return (bAllowDefault && m_sNick.empty()) ? GetCleanUserName() : m_sNick;
}
const NoString& NoUser::GetAltNick(bool bAllowDefault) const
{
    return (bAllowDefault && m_sAltNick.empty()) ? GetCleanUserName() : m_sAltNick;
}
const NoString& NoUser::GetIdent(bool bAllowDefault) const
{
    return (bAllowDefault && m_sIdent.empty()) ? GetCleanUserName() : m_sIdent;
}
const NoString& NoUser::GetRealName() const { return m_sRealName.empty() ? m_sUserName : m_sRealName; }
const NoString& NoUser::GetBindHost() const { return m_sBindHost; }
const NoString& NoUser::GetDCCBindHost() const { return m_sDCCBindHost; }
const NoString& NoUser::GetPass() const { return m_sPass; }
NoUser::eHashType NoUser::GetPassHashType() const { return m_eHashType; }
const NoString& NoUser::GetPassSalt() const { return m_sPassSalt; }
bool NoUser::DenyLoadMod() const { return m_bDenyLoadMod; }
bool NoUser::IsAdmin() const { return m_bAdmin; }
bool NoUser::DenySetBindHost() const { return m_bDenySetBindHost; }
bool NoUser::MultiClients() const { return m_bMultiClients; }
const NoString& NoUser::GetStatusPrefix() const { return m_sStatusPrefix; }
const NoString& NoUser::GetDefaultChanModes() const { return m_sDefaultChanModes; }
const NoString& NoUser::GetClientEncoding() const { return m_sClientEncoding; }
bool NoUser::HasSpaceForNewNetwork() const { return GetNetworks().size() < MaxNetworks(); }

NoString NoUser::GetQuitMsg() const { return (!m_sQuitMsg.Trim_n().empty()) ? m_sQuitMsg : NoApp::GetTag(false); }
const NoStringMap& NoUser::GetCTCPReplies() const { return m_mssCTCPReplies; }
uint NoUser::GetBufferCount() const { return m_uBufferCount; }
bool NoUser::AutoClearChanBuffer() const { return m_bAutoClearChanBuffer; }
bool NoUser::AutoClearQueryBuffer() const { return m_bAutoClearQueryBuffer; }
// NoString NoUser::GetSkinName() const { return (!m_sSkinName.empty()) ? m_sSkinName : NoApp::Get().GetSkinName(); }
NoString NoUser::GetSkinName() const { return m_sSkinName; }
const NoString& NoUser::GetUserPath() const
{
    if (!NoFile::Exists(m_sUserPath)) {
        NoDir::MakeDir(m_sUserPath);
    }
    return m_sUserPath;
}
// !Getters
