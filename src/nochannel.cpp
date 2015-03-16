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

#include "nochannel.h"
#include "noircsock.h"
#include "nouser.h"
#include "nonetwork.h"
#include "nosettings.h"
#include "noznc.h"

using std::set;
using std::vector;
using std::map;

NoChannel::NoChannel(const NoString& sName, NoNetwork* pNetwork, bool bInConfig, NoSettings* pConfig)
    : m_bDetached(false), m_bIsOn(false), m_bAutoClearChanBuffer(pNetwork->GetUser()->AutoClearChanBuffer()),
      m_bInConfig(bInConfig), m_bDisabled(false), m_bHasBufferCountSet(false), m_bHasAutoClearChanBufferSet(false),
      m_sName(sName.Token(0)), m_sKey(sName.Token(1)), m_sTopic(""), m_sTopicOwner(""), m_ulTopicDate(0),
      m_ulCreationDate(0), m_pNetwork(pNetwork), m_Nick(), m_uJoinTries(0), m_sDefaultModes(""), m_msNicks(),
      m_Buffer(), m_bModeKnown(false), m_musModes()
{
    if (!m_pNetwork->IsChan(m_sName)) {
        m_sName = "#" + m_sName;
    }

    m_Nick.SetNetwork(m_pNetwork);
    m_Buffer.SetLimit(m_pNetwork->GetUser()->GetBufferCount(), true);

    if (pConfig) {
        NoString sValue;
        if (pConfig->FindStringEntry("buffer", sValue)) SetBufferCount(sValue.ToUInt(), true);
        if (pConfig->FindStringEntry("autoclearchanbuffer", sValue)) SetAutoClearChanBuffer(sValue.ToBool());
        if (pConfig->FindStringEntry("keepbuffer", sValue))
            SetAutoClearChanBuffer(!sValue.ToBool()); // XXX Compatibility crap, added in 0.207
        if (pConfig->FindStringEntry("detached", sValue)) SetDetached(sValue.ToBool());
        if (pConfig->FindStringEntry("disabled", sValue))
            if (sValue.ToBool()) Disable();
        if (pConfig->FindStringEntry("autocycle", sValue))
            if (sValue.Equals("true"))
                NoUtils::PrintError("WARNING: AutoCycle has been removed, instead try -> LoadModule = autocycle " + sName);
        if (pConfig->FindStringEntry("key", sValue)) SetKey(sValue);
        if (pConfig->FindStringEntry("modes", sValue)) SetDefaultModes(sValue);
    }
}

NoChannel::~NoChannel() { ClearNicks(); }

void NoChannel::Reset()
{
    m_bIsOn = false;
    m_bModeKnown = false;
    m_musModes.clear();
    m_sTopic = "";
    m_sTopicOwner = "";
    m_ulTopicDate = 0;
    m_ulCreationDate = 0;
    m_Nick.Reset();
    ClearNicks();
    ResetJoinTries();
}

NoSettings NoChannel::ToConfig() const
{
    NoSettings config;

    if (m_bHasBufferCountSet) config.AddKeyValuePair("Buffer", NoString(GetBufferCount()));
    if (m_bHasAutoClearChanBufferSet) config.AddKeyValuePair("AutoClearChanBuffer", NoString(AutoClearChanBuffer()));
    if (IsDetached()) config.AddKeyValuePair("Detached", "true");
    if (IsDisabled()) config.AddKeyValuePair("Disabled", "true");
    if (!GetKey().empty()) config.AddKeyValuePair("Key", GetKey());
    if (!GetDefaultModes().empty()) config.AddKeyValuePair("Modes", GetDefaultModes());

    return config;
}

void NoChannel::Clone(NoChannel& chan)
{
    // We assume that m_sName and m_pNetwork are equal
    SetBufferCount(chan.GetBufferCount(), true);
    SetAutoClearChanBuffer(chan.AutoClearChanBuffer());
    SetKey(chan.GetKey());
    SetDefaultModes(chan.GetDefaultModes());

    if (IsDetached() != chan.IsDetached()) {
        // Only send something if it makes sense
        // (= Only detach if client is on the channel
        //    and only attach if we are on the channel)
        if (IsOn()) {
            if (IsDetached()) {
                AttachUser();
            } else {
                DetachUser();
            }
        }
        SetDetached(chan.IsDetached());
    }
}

void NoChannel::Cycle() const { m_pNetwork->PutIRC("PART " + GetName() + "\r\nJOIN " + GetName() + " " + GetKey()); }

void NoChannel::JoinUser(const NoString& sKey)
{
    if (!sKey.empty()) {
        SetKey(sKey);
    }
    m_pNetwork->PutIRC("JOIN " + GetName() + " " + GetKey());
}

void NoChannel::AttachUser(NoClient* pClient)
{
    m_pNetwork->PutUser(":" + m_pNetwork->GetIRNoNick().GetNickMask() + " JOIN :" + GetName(), pClient);

    if (!GetTopic().empty()) {
        m_pNetwork->PutUser(":" + m_pNetwork->GetIRNoServer() + " 332 " + m_pNetwork->GetIRNoNick().GetNick() + " " +
                            GetName() + " :" + GetTopic(),
                            pClient);
        m_pNetwork->PutUser(":" + m_pNetwork->GetIRNoServer() + " 333 " + m_pNetwork->GetIRNoNick().GetNick() + " " +
                            GetName() + " " + GetTopicOwner() + " " + NoString(GetTopicDate()),
                            pClient);
    }

    NoString sPre = ":" + m_pNetwork->GetIRNoServer() + " 353 " + m_pNetwork->GetIRNoNick().GetNick() + " " +
                   GetModeForNames() + " " + GetName() + " :";
    NoString sLine = sPre;
    NoString sPerm, sNick;

    const vector<NoClient*>& vpClients = m_pNetwork->GetClients();
    for (NoClient* pEachClient : vpClients) {
        NoClient* pThisClient;
        if (!pClient)
            pThisClient = pEachClient;
        else
            pThisClient = pClient;

        for (map<NoString, NoNick>::iterator a = m_msNicks.begin(); a != m_msNicks.end(); ++a) {
            if (pThisClient->HasNamesx()) {
                sPerm = a->second.GetPermStr();
            } else {
                char c = a->second.GetPermChar();
                sPerm = "";
                if (c != '\0') {
                    sPerm += c;
                }
            }
            if (pThisClient->HasUHNames() && !a->second.GetIdent().empty() && !a->second.GetHost().empty()) {
                sNick = a->first + "!" + a->second.GetIdent() + "@" + a->second.GetHost();
            } else {
                sNick = a->first;
            }

            sLine += sPerm + sNick;

            if (sLine.size() >= 490 || a == (--m_msNicks.end())) {
                m_pNetwork->PutUser(sLine, pThisClient);
                sLine = sPre;
            } else {
                sLine += " ";
            }
        }

        if (pClient) // We only want to do this for one client
            break;
    }

    m_pNetwork->PutUser(":" + m_pNetwork->GetIRNoServer() + " 366 " + m_pNetwork->GetIRNoNick().GetNick() + " " + GetName() + " :End of /NAMES list.",
                        pClient);
    m_bDetached = false;

    // Send Buffer
    SendBuffer(pClient);
}

void NoChannel::DetachUser()
{
    if (!m_bDetached) {
        m_pNetwork->PutUser(":" + m_pNetwork->GetIRNoNick().GetNickMask() + " PART " + GetName());
        m_bDetached = true;
    }
}

NoString NoChannel::GetModeString() const
{
    NoString sModes, sArgs;

    for (const auto& it : m_musModes) {
        sModes += it.first;
        if (it.second.size()) {
            sArgs += " " + it.second;
        }
    }

    return sModes.empty() ? sModes : NoString("+" + sModes + sArgs);
}

NoString NoChannel::GetModeForNames() const
{
    NoString sMode;

    for (const auto& it : m_musModes) {
        if (it.first == 's') {
            sMode = "@";
        } else if ((it.first == 'p') && sMode.empty()) {
            sMode = "*";
        }
    }

    return (sMode.empty() ? "=" : sMode);
}

void NoChannel::SetModes(const NoString& sModes)
{
    m_musModes.clear();
    ModeChange(sModes);
}

void NoChannel::SetAutoClearChanBuffer(bool b)
{
    m_bHasAutoClearChanBufferSet = true;
    m_bAutoClearChanBuffer = b;

    if (m_bAutoClearChanBuffer && !IsDetached() && m_pNetwork->IsUserOnline()) {
        ClearBuffer();
    }
}

void NoChannel::InheritAutoClearChanBuffer(bool b)
{
    if (!m_bHasAutoClearChanBufferSet) {
        m_bAutoClearChanBuffer = b;

        if (m_bAutoClearChanBuffer && !IsDetached() && m_pNetwork->IsUserOnline()) {
            ClearBuffer();
        }
    }
}

void NoChannel::OnWho(const NoString& sNick, const NoString& sIdent, const NoString& sHost)
{
    NoNick* pNick = FindNick(sNick);

    if (pNick) {
        pNick->SetIdent(sIdent);
        pNick->SetHost(sHost);
    }
}

void NoChannel::ModeChange(const NoString& sModes, const NoNick* pOpNick)
{
    NoString sModeArg = sModes.Token(0);
    NoString sArgs = sModes.Token(1, true);
    bool bAdd = true;

    /* Try to find a NoNick* from this channel so that pOpNick->HasPerm()
     * works as expected. */
    if (pOpNick) {
        NoNick* OpNick = FindNick(pOpNick->GetNick());
        /* If nothing was found, use the original pOpNick, else use the
         * NoNick* from FindNick() */
        if (OpNick) pOpNick = OpNick;
    }

    NETWORKMODULECALL(OnRawMode2(pOpNick, *this, sModeArg, sArgs), m_pNetwork->GetUser(), m_pNetwork, nullptr, NOTHING);

    for (unsigned int a = 0; a < sModeArg.size(); a++) {
        const unsigned char& uMode = sModeArg[a];

        if (uMode == '+') {
            bAdd = true;
        } else if (uMode == '-') {
            bAdd = false;
        } else if (m_pNetwork->GetIRCSock()->IsPermMode(uMode)) {
            NoString sArg = GetModeArg(sArgs);
            NoNick* pNick = FindNick(sArg);
            if (pNick) {
                unsigned char uPerm = m_pNetwork->GetIRCSock()->GetPermFromMode(uMode);

                if (uPerm) {
                    bool bNoChange = (pNick->HasPerm(uPerm) == bAdd);

                    if (bAdd) {
                        pNick->AddPerm(uPerm);

                        if (pNick->NickEquals(m_pNetwork->GetCurNick())) {
                            AddPerm(uPerm);
                        }
                    } else {
                        pNick->RemPerm(uPerm);

                        if (pNick->NickEquals(m_pNetwork->GetCurNick())) {
                            RemPerm(uPerm);
                        }
                    }

                    NETWORKMODULECALL(OnChanPermission2(pOpNick, *pNick, *this, uMode, bAdd, bNoChange),
                                      m_pNetwork->GetUser(),
                                      m_pNetwork,
                                      nullptr,
                                      NOTHING);

                    if (uMode == NoChannel::M_Op) {
                        if (bAdd) {
                            NETWORKMODULECALL(OnOp2(pOpNick, *pNick, *this, bNoChange), m_pNetwork->GetUser(), m_pNetwork, nullptr, NOTHING);
                        } else {
                            NETWORKMODULECALL(OnDeop2(pOpNick, *pNick, *this, bNoChange), m_pNetwork->GetUser(), m_pNetwork, nullptr, NOTHING);
                        }
                    } else if (uMode == NoChannel::M_Voice) {
                        if (bAdd) {
                            NETWORKMODULECALL(OnVoice2(pOpNick, *pNick, *this, bNoChange), m_pNetwork->GetUser(), m_pNetwork, nullptr, NOTHING);
                        } else {
                            NETWORKMODULECALL(OnDevoice2(pOpNick, *pNick, *this, bNoChange), m_pNetwork->GetUser(), m_pNetwork, nullptr, NOTHING);
                        }
                    }
                }
            }
        } else {
            bool bList = false;
            NoString sArg;

            switch (m_pNetwork->GetIRCSock()->GetModeType(uMode)) {
            case NoIrcSock::ListArg:
                bList = true;
                sArg = GetModeArg(sArgs);
                break;
            case NoIrcSock::HasArg:
                sArg = GetModeArg(sArgs);
                break;
            case NoIrcSock::NoArg:
                break;
            case NoIrcSock::ArgWhenSet:
                if (bAdd) {
                    sArg = GetModeArg(sArgs);
                }

                break;
            }

            bool bNoChange;
            if (bList) {
                bNoChange = false;
            } else if (bAdd) {
                bNoChange = HasMode(uMode) && GetModeArg(uMode) == sArg;
            } else {
                bNoChange = !HasMode(uMode);
            }
            NETWORKMODULECALL(OnMode2(pOpNick, *this, uMode, sArg, bAdd, bNoChange), m_pNetwork->GetUser(), m_pNetwork, nullptr, NOTHING);

            if (!bList) {
                (bAdd) ? AddMode(uMode, sArg) : RemMode(uMode);
            }

            // This is called when we join (ZNC requests the channel modes
            // on join) *and* when someone changes the channel keys.
            // We ignore channel key "*" because of some broken nets.
            if (uMode == M_Key && !bNoChange && bAdd && sArg != "*") {
                SetKey(sArg);
            }
        }
    }
}

NoString NoChannel::GetOptions() const
{
    NoStringVector vsRet;

    if (IsDetached()) {
        vsRet.push_back("Detached");
    }

    if (AutoClearChanBuffer()) {
        if (HasAutoClearChanBufferSet()) {
            vsRet.push_back("AutoClearChanBuffer");
        } else {
            vsRet.push_back("AutoClearChanBuffer (default)");
        }
    }

    return NoString(", ").Join(vsRet.begin(), vsRet.end());
}

NoString NoChannel::GetModeArg(unsigned char uMode) const
{
    if (uMode) {
        map<unsigned char, NoString>::const_iterator it = m_musModes.find(uMode);

        if (it != m_musModes.end()) {
            return it->second;
        }
    }

    return "";
}

bool NoChannel::HasMode(unsigned char uMode) const { return (uMode && m_musModes.find(uMode) != m_musModes.end()); }

bool NoChannel::AddMode(unsigned char uMode, const NoString& sArg)
{
    m_musModes[uMode] = sArg;
    return true;
}

bool NoChannel::RemMode(unsigned char uMode)
{
    if (!HasMode(uMode)) {
        return false;
    }

    m_musModes.erase(uMode);
    return true;
}

NoString NoChannel::GetModeArg(NoString& sArgs) const
{
    NoString sRet = sArgs.substr(0, sArgs.find(' '));
    sArgs = (sRet.size() < sArgs.size()) ? sArgs.substr(sRet.size() + 1) : "";
    return sRet;
}

void NoChannel::ClearNicks() { m_msNicks.clear(); }

int NoChannel::AddNicks(const NoString& sNicks)
{
    int iRet = 0;
    NoStringVector vsNicks;

    sNicks.Split(" ", vsNicks, false);

    for (const NoString& sNick : vsNicks) {
        if (AddNick(sNick)) {
            iRet++;
        }
    }

    return iRet;
}

bool NoChannel::AddNick(const NoString& sNick)
{
    const char* p = sNick.c_str();
    NoString sPrefix, sTmp, sIdent, sHost;

    while (m_pNetwork->GetIRCSock()->IsPermChar(*p)) {
        sPrefix += *p;

        if (!*++p) {
            return false;
        }
    }

    sTmp = p;

    // The UHNames extension gets us nick!ident@host instead of just plain nick
    sIdent = sTmp.Token(1, true, "!");
    sHost = sIdent.Token(1, true, "@");
    sIdent = sIdent.Token(0, false, "@");
    // Get the nick
    sTmp = sTmp.Token(0, false, "!");

    NoNick tmpNick(sTmp);
    NoNick* pNick = FindNick(sTmp);
    if (!pNick) {
        pNick = &tmpNick;
        pNick->SetNetwork(m_pNetwork);
    }

    if (!sIdent.empty()) pNick->SetIdent(sIdent);
    if (!sHost.empty()) pNick->SetHost(sHost);

    for (NoString::size_type i = 0; i < sPrefix.length(); i++) {
        pNick->AddPerm(sPrefix[i]);
    }

    if (pNick->NickEquals(m_pNetwork->GetCurNick())) {
        for (NoString::size_type i = 0; i < sPrefix.length(); i++) {
            AddPerm(sPrefix[i]);
        }
    }

    m_msNicks[pNick->GetNick()] = *pNick;

    return true;
}

map<char, unsigned int> NoChannel::GetPermCounts() const
{
    map<char, unsigned int> mRet;

    for (const auto& it : m_msNicks) {
        NoString sPerms = it.second.GetPermStr();

        for (unsigned int p = 0; p < sPerms.size(); p++) {
            mRet[sPerms[p]]++;
        }
    }

    return mRet;
}

bool NoChannel::RemNick(const NoString& sNick)
{
    map<NoString, NoNick>::iterator it;
    set<unsigned char>::iterator it2;

    it = m_msNicks.find(sNick);
    if (it == m_msNicks.end()) {
        return false;
    }

    m_msNicks.erase(it);

    return true;
}

bool NoChannel::ChangeNick(const NoString& sOldNick, const NoString& sNewNick)
{
    map<NoString, NoNick>::iterator it = m_msNicks.find(sOldNick);

    if (it == m_msNicks.end()) {
        return false;
    }

    // Rename this nick
    it->second.SetNick(sNewNick);

    // Insert a new element into the map then erase the old one, do this to change the key to the new nick
    m_msNicks[sNewNick] = it->second;
    m_msNicks.erase(it);

    return true;
}

const NoNick* NoChannel::FindNick(const NoString& sNick) const
{
    map<NoString, NoNick>::const_iterator it = m_msNicks.find(sNick);
    return (it != m_msNicks.end()) ? &it->second : nullptr;
}

NoNick* NoChannel::FindNick(const NoString& sNick)
{
    map<NoString, NoNick>::iterator it = m_msNicks.find(sNick);
    return (it != m_msNicks.end()) ? &it->second : nullptr;
}

void NoChannel::SendBuffer(NoClient* pClient)
{
    SendBuffer(pClient, m_Buffer);
    if (AutoClearChanBuffer()) {
        ClearBuffer();
    }
}

void NoChannel::SendBuffer(NoClient* pClient, const NoBuffer& Buffer)
{
    if (m_pNetwork && m_pNetwork->IsUserAttached()) {
        // in the event that pClient is nullptr, need to send this to all clients for the user
        // I'm presuming here that pClient is listed inside vClients thus vClients at this
        // point can't be empty.
        //
        // This loop has to be cycled twice to maintain the existing behavior which is
        // 1. OnChanBufferStarting
        // 2. OnChanBufferPlayLine
        // 3. ClearBuffer() if not keeping the buffer
        // 4. OnChanBufferEnding
        //
        // With the exception of ClearBuffer(), this needs to happen per client, and
        // if pClient is not nullptr, the loops break after the first iteration.
        //
        // Rework this if you like ...
        if (!Buffer.IsEmpty()) {
            const vector<NoClient*>& vClients = m_pNetwork->GetClients();
            for (NoClient* pEachClient : vClients) {
                NoClient* pUseClient = (pClient ? pClient : pEachClient);

                bool bWasPlaybackActive = pUseClient->IsPlaybackActive();
                pUseClient->SetPlaybackActive(true);

                bool bSkipStatusMsg = pUseClient->HasServerTime();
                NETWORKMODULECALL(OnChanBufferStarting(*this, *pUseClient), m_pNetwork->GetUser(), m_pNetwork, nullptr, &bSkipStatusMsg);

                if (!bSkipStatusMsg) {
                    m_pNetwork->PutUser(":***!znc@znc.in PRIVMSG " + GetName() + " :Buffer Playback...", pUseClient);
                }

                bool bBatch = pUseClient->HasBatch();
                NoString sBatchName = GetName().MD5();

                if (bBatch) {
                    m_pNetwork->PutUser(":znc.in BATCH +" + sBatchName + " znc.in/playback " + GetName(), pUseClient);
                }

                size_t uSize = Buffer.Size();
                for (size_t uIdx = 0; uIdx < uSize; uIdx++) {
                    const NoMessage& BufLine = Buffer.GetMessage(uIdx);
                    NoString sLine = BufLine.GetLine(*pUseClient, NoStringMap::EmptyMap);
                    if (bBatch) {
                        NoStringMap msBatchTags = NoUtils::GetMessageTags(sLine);
                        msBatchTags["batch"] = sBatchName;
                        NoUtils::SetMessageTags(sLine, msBatchTags);
                    }
                    bool bNotShowThisLine = false;
                    NETWORKMODULECALL(OnChanBufferPlayLine2(*this, *pUseClient, sLine, BufLine.GetTime()),
                                      m_pNetwork->GetUser(),
                                      m_pNetwork,
                                      nullptr,
                                      &bNotShowThisLine);
                    if (bNotShowThisLine) continue;
                    m_pNetwork->PutUser(sLine, pUseClient);
                }

                bSkipStatusMsg = pUseClient->HasServerTime();
                NETWORKMODULECALL(OnChanBufferEnding(*this, *pUseClient), m_pNetwork->GetUser(), m_pNetwork, nullptr, &bSkipStatusMsg);
                if (!bSkipStatusMsg) {
                    m_pNetwork->PutUser(":***!znc@znc.in PRIVMSG " + GetName() + " :Playback Complete.", pUseClient);
                }

                if (bBatch) {
                    m_pNetwork->PutUser(":znc.in BATCH -" + sBatchName, pUseClient);
                }

                pUseClient->SetPlaybackActive(bWasPlaybackActive);

                if (pClient) break;
            }
        }
    }
}

void NoChannel::Enable()
{
    ResetJoinTries();
    m_bDisabled = false;
}

void NoChannel::SetKey(const NoString& s)
{
    if (m_sKey != s) {
        m_sKey = s;
        if (m_bInConfig) {
            CZNC::Get().SetConfigState(CZNC::ECONFIG_NEED_WRITE);
        }
    }
}

void NoChannel::SetInConfig(bool b)
{
    if (m_bInConfig != b) {
        m_bInConfig = b;
        if (m_bInConfig) {
            CZNC::Get().SetConfigState(CZNC::ECONFIG_NEED_WRITE);
        }
    }
}
