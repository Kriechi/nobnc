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
#include "noircconnection.h"
#include "nouser.h"
#include "nonetwork.h"
#include "nosettings.h"
#include "noclient.h"
#include "noapp.h"

NoChannel::NoChannel(const NoString& sName, NoNetwork* pNetwork, bool bInConfig, NoSettings* pConfig)
    : m_detached(false), m_isOn(false), m_autoClearChanBuffer(pNetwork->GetUser()->AutoClearChanBuffer()),
      m_inConfig(bInConfig), m_disabled(false), m_hasBufferCountSet(false), m_hasAutoClearChanBufferSet(false),
      m_name(sName.token(0)), m_key(sName.token(1)), m_topic(""), m_topicOwner(""), m_topicDate(0),
      m_creationDate(0), m_network(pNetwork), m_nick(), m_joinTries(0), m_defaultModes(""), m_nicks(),
      m_buffer(), m_modeKnown(false), m_modes()
{
    if (!m_network->IsChan(m_name)) {
        m_name = "#" + m_name;
    }

    m_nick.setNetwork(m_network);
    m_buffer.setLimit(m_network->GetUser()->GetBufferCount(), true);

    if (pConfig) {
        NoString sValue;
        if (pConfig->FindStringEntry("buffer", sValue)) setBufferCount(sValue.toUInt(), true);
        if (pConfig->FindStringEntry("autoclearchanbuffer", sValue)) setAutoClearChanBuffer(sValue.toBool());
        if (pConfig->FindStringEntry("keepbuffer", sValue))
            setAutoClearChanBuffer(!sValue.toBool()); // XXX Compatibility crap, added in 0.207
        if (pConfig->FindStringEntry("detached", sValue)) setDetached(sValue.toBool());
        if (pConfig->FindStringEntry("disabled", sValue))
            if (sValue.toBool()) disable();
        if (pConfig->FindStringEntry("autocycle", sValue))
            if (sValue.equals("true"))
                No::printError("WARNING: AutoCycle has been removed, instead try -> LoadModule = autocycle " + sName);
        if (pConfig->FindStringEntry("key", sValue)) setKey(sValue);
        if (pConfig->FindStringEntry("modes", sValue)) setDefaultModes(sValue);
    }
}

NoChannel::~NoChannel() { clearNicks(); }

void NoChannel::reset()
{
    m_isOn = false;
    m_modeKnown = false;
    m_modes.clear();
    m_topic = "";
    m_topicOwner = "";
    m_topicDate = 0;
    m_creationDate = 0;
    m_nick.reset();
    clearNicks();
    resetJoinTries();
}

NoSettings NoChannel::toConfig() const
{
    NoSettings config;

    if (m_hasBufferCountSet) config.AddKeyValuePair("Buffer", NoString(getBufferCount()));
    if (m_hasAutoClearChanBufferSet) config.AddKeyValuePair("AutoClearChanBuffer", NoString(autoClearChanBuffer()));
    if (isDetached()) config.AddKeyValuePair("Detached", "true");
    if (isDisabled()) config.AddKeyValuePair("Disabled", "true");
    if (!getKey().empty()) config.AddKeyValuePair("Key", getKey());
    if (!getDefaultModes().empty()) config.AddKeyValuePair("Modes", getDefaultModes());

    return config;
}

void NoChannel::clone(NoChannel& chan)
{
    // We assume that m_sName and m_pNetwork are equal
    setBufferCount(chan.getBufferCount(), true);
    setAutoClearChanBuffer(chan.autoClearChanBuffer());
    setKey(chan.getKey());
    setDefaultModes(chan.getDefaultModes());

    if (isDetached() != chan.isDetached()) {
        // Only send something if it makes sense
        // (= Only detach if client is on the channel
        //    and only attach if we are on the channel)
        if (isOn()) {
            if (isDetached()) {
                attachUser();
            } else {
                detachUser();
            }
        }
        setDetached(chan.isDetached());
    }
}

void NoChannel::cycle() const { m_network->PutIRC("PART " + getName() + "\r\nJOIN " + getName() + " " + getKey()); }

void NoChannel::joinUser(const NoString& sKey)
{
    if (!sKey.empty()) {
        setKey(sKey);
    }
    m_network->PutIRC("JOIN " + getName() + " " + getKey());
}

void NoChannel::attachUser(NoClient* pClient)
{
    m_network->PutUser(":" + m_network->GetIRCNick().nickMask() + " JOIN :" + getName(), pClient);

    if (!getTopic().empty()) {
        m_network->PutUser(":" + m_network->GetIRCServer() + " 332 " + m_network->GetIRCNick().nick() + " " +
                            getName() + " :" + getTopic(),
                            pClient);
        m_network->PutUser(":" + m_network->GetIRCServer() + " 333 " + m_network->GetIRCNick().nick() + " " +
                            getName() + " " + getTopicOwner() + " " + NoString(getTopicDate()),
                            pClient);
    }

    NoString sPre = ":" + m_network->GetIRCServer() + " 353 " + m_network->GetIRCNick().nick() + " " +
                   getModeForNames() + " " + getName() + " :";
    NoString sLine = sPre;
    NoString sPerm, sNick;

    const std::vector<NoClient*>& vpClients = m_network->GetClients();
    for (NoClient* pEachClient : vpClients) {
        NoClient* pThisClient;
        if (!pClient)
            pThisClient = pEachClient;
        else
            pThisClient = pClient;

        for (std::map<NoString, NoNick>::iterator a = m_nicks.begin(); a != m_nicks.end(); ++a) {
            if (pThisClient->HasNamesx()) {
                sPerm = a->second.perms();
            } else {
                char c = a->second.perm();
                sPerm = "";
                if (c != '\0') {
                    sPerm += c;
                }
            }
            if (pThisClient->HasUHNames() && !a->second.ident().empty() && !a->second.host().empty()) {
                sNick = a->first + "!" + a->second.ident() + "@" + a->second.host();
            } else {
                sNick = a->first;
            }

            sLine += sPerm + sNick;

            if (sLine.size() >= 490 || a == (--m_nicks.end())) {
                m_network->PutUser(sLine, pThisClient);
                sLine = sPre;
            } else {
                sLine += " ";
            }
        }

        if (pClient) // We only want to do this for one client
            break;
    }

    m_network->PutUser(":" + m_network->GetIRCServer() + " 366 " + m_network->GetIRCNick().nick() + " " + getName() + " :End of /NAMES list.",
                        pClient);
    m_detached = false;

    // Send Buffer
    sendBuffer(pClient);
}

void NoChannel::detachUser()
{
    if (!m_detached) {
        m_network->PutUser(":" + m_network->GetIRCNick().nickMask() + " PART " + getName());
        m_detached = true;
    }
}

NoString NoChannel::getModeString() const
{
    NoString sModes, sArgs;

    for (const auto& it : m_modes) {
        sModes += it.first;
        if (it.second.size()) {
            sArgs += " " + it.second;
        }
    }

    return sModes.empty() ? sModes : NoString("+" + sModes + sArgs);
}

NoString NoChannel::getModeForNames() const
{
    NoString sMode;

    for (const auto& it : m_modes) {
        if (it.first == 's') {
            sMode = "@";
        } else if ((it.first == 'p') && sMode.empty()) {
            sMode = "*";
        }
    }

    return (sMode.empty() ? "=" : sMode);
}

void NoChannel::setModes(const NoString& sModes)
{
    m_modes.clear();
    modeChange(sModes);
}

void NoChannel::setAutoClearChanBuffer(bool b)
{
    m_hasAutoClearChanBufferSet = true;
    m_autoClearChanBuffer = b;

    if (m_autoClearChanBuffer && !isDetached() && m_network->IsUserOnline()) {
        clearBuffer();
    }
}

void NoChannel::inheritAutoClearChanBuffer(bool b)
{
    if (!m_hasAutoClearChanBufferSet) {
        m_autoClearChanBuffer = b;

        if (m_autoClearChanBuffer && !isDetached() && m_network->IsUserOnline()) {
            clearBuffer();
        }
    }
}

void NoChannel::onWho(const NoString& sNick, const NoString& sIdent, const NoString& sHost)
{
    NoNick* pNick = findNick(sNick);

    if (pNick) {
        pNick->setIdent(sIdent);
        pNick->setHost(sHost);
    }
}

void NoChannel::modeChange(const NoString& sModes, const NoNick* pOpNick)
{
    NoString sModeArg = sModes.token(0);
    NoString sArgs = sModes.tokens(1);
    bool bAdd = true;

    /* Try to find a NoNick* from this channel so that pOpNick->HasPerm()
     * works as expected. */
    if (pOpNick) {
        NoNick* OpNick = findNick(pOpNick->nick());
        /* If nothing was found, use the original pOpNick, else use the
         * NoNick* from FindNick() */
        if (OpNick) pOpNick = OpNick;
    }

    NETWORKMODULECALL(OnRawMode2(pOpNick, *this, sModeArg, sArgs), m_network->GetUser(), m_network, nullptr, NOTHING);

    for (uint a = 0; a < sModeArg.size(); a++) {
        const uchar& uMode = sModeArg[a];

        if (uMode == '+') {
            bAdd = true;
        } else if (uMode == '-') {
            bAdd = false;
        } else if (m_network->GetIRCSock()->IsPermMode(uMode)) {
            NoString sArg = getModeArg(sArgs);
            NoNick* pNick = findNick(sArg);
            if (pNick) {
                uchar uPerm = m_network->GetIRCSock()->GetPermFromMode(uMode);

                if (uPerm) {
                    bool bNoChange = (pNick->hasPerm(uPerm) == bAdd);

                    if (bAdd) {
                        pNick->addPerm(uPerm);

                        if (pNick->equals(m_network->GetCurNick())) {
                            addPerm(uPerm);
                        }
                    } else {
                        pNick->removePerm(uPerm);

                        if (pNick->equals(m_network->GetCurNick())) {
                            remPerm(uPerm);
                        }
                    }

                    NETWORKMODULECALL(OnChanPermission2(pOpNick, *pNick, *this, uMode, bAdd, bNoChange),
                                      m_network->GetUser(),
                                      m_network,
                                      nullptr,
                                      NOTHING);

                    if (uMode == NoChannel::M_Op) {
                        if (bAdd) {
                            NETWORKMODULECALL(OnOp2(pOpNick, *pNick, *this, bNoChange), m_network->GetUser(), m_network, nullptr, NOTHING);
                        } else {
                            NETWORKMODULECALL(OnDeop2(pOpNick, *pNick, *this, bNoChange), m_network->GetUser(), m_network, nullptr, NOTHING);
                        }
                    } else if (uMode == NoChannel::M_Voice) {
                        if (bAdd) {
                            NETWORKMODULECALL(OnVoice2(pOpNick, *pNick, *this, bNoChange), m_network->GetUser(), m_network, nullptr, NOTHING);
                        } else {
                            NETWORKMODULECALL(OnDevoice2(pOpNick, *pNick, *this, bNoChange), m_network->GetUser(), m_network, nullptr, NOTHING);
                        }
                    }
                }
            }
        } else {
            bool bList = false;
            NoString sArg;

            switch (m_network->GetIRCSock()->GetModeType(uMode)) {
            case NoIrcConnection::ListArg:
                bList = true;
                sArg = getModeArg(sArgs);
                break;
            case NoIrcConnection::HasArg:
                sArg = getModeArg(sArgs);
                break;
            case NoIrcConnection::NoArg:
                break;
            case NoIrcConnection::ArgWhenSet:
                if (bAdd) {
                    sArg = getModeArg(sArgs);
                }

                break;
            }

            bool bNoChange;
            if (bList) {
                bNoChange = false;
            } else if (bAdd) {
                bNoChange = hasMode(uMode) && getModeArg(uMode) == sArg;
            } else {
                bNoChange = !hasMode(uMode);
            }
            NETWORKMODULECALL(OnMode2(pOpNick, *this, uMode, sArg, bAdd, bNoChange), m_network->GetUser(), m_network, nullptr, NOTHING);

            if (!bList) {
                (bAdd) ? addMode(uMode, sArg) : remMode(uMode);
            }

            // This is called when we join (ZNC requests the channel modes
            // on join) *and* when someone changes the channel keys.
            // We ignore channel key "*" because of some broken nets.
            if (uMode == M_Key && !bNoChange && bAdd && sArg != "*") {
                setKey(sArg);
            }
        }
    }
}

NoString NoChannel::getOptions() const
{
    NoStringVector vsRet;

    if (isDetached()) {
        vsRet.push_back("Detached");
    }

    if (autoClearChanBuffer()) {
        if (hasAutoClearChanBufferSet()) {
            vsRet.push_back("AutoClearChanBuffer");
        } else {
            vsRet.push_back("AutoClearChanBuffer (default)");
        }
    }

    return NoString(", ").join(vsRet.begin(), vsRet.end());
}

NoString NoChannel::getModeArg(uchar uMode) const
{
    if (uMode) {
        std::map<uchar, NoString>::const_iterator it = m_modes.find(uMode);

        if (it != m_modes.end()) {
            return it->second;
        }
    }

    return "";
}

bool NoChannel::hasMode(uchar uMode) const { return (uMode && m_modes.find(uMode) != m_modes.end()); }

bool NoChannel::addMode(uchar uMode, const NoString& sArg)
{
    m_modes[uMode] = sArg;
    return true;
}

bool NoChannel::remMode(uchar uMode)
{
    if (!hasMode(uMode)) {
        return false;
    }

    m_modes.erase(uMode);
    return true;
}

NoString NoChannel::getModeArg(NoString& sArgs) const
{
    NoString sRet = sArgs.substr(0, sArgs.find(' '));
    sArgs = (sRet.size() < sArgs.size()) ? sArgs.substr(sRet.size() + 1) : "";
    return sRet;
}

void NoChannel::clearNicks() { m_nicks.clear(); }

int NoChannel::addNicks(const NoString& sNicks)
{
    int iRet = 0;
    NoStringVector vsNicks = sNicks.split(" ", No::SkipEmptyParts);

    for (const NoString& sNick : vsNicks) {
        if (addNick(sNick)) {
            iRet++;
        }
    }

    return iRet;
}

bool NoChannel::addNick(const NoString& sNick)
{
    const char* p = sNick.c_str();
    NoString sPrefix, sTmp, sIdent, sHost;

    while (m_network->GetIRCSock()->IsPermChar(*p)) {
        sPrefix += *p;

        if (!*++p) {
            return false;
        }
    }

    sTmp = p;

    // The UHNames extension gets us nick!ident@host instead of just plain nick
    sIdent = sTmp.tokens(1, "!");
    sHost = sIdent.tokens(1, "@");
    sIdent = sIdent.token(0, "@");
    // Get the nick
    sTmp = sTmp.token(0, "!");

    NoNick tmpNick(sTmp);
    NoNick* pNick = findNick(sTmp);
    if (!pNick) {
        pNick = &tmpNick;
        pNick->setNetwork(m_network);
    }

    if (!sIdent.empty()) pNick->setIdent(sIdent);
    if (!sHost.empty()) pNick->setHost(sHost);

    for (NoString::size_type i = 0; i < sPrefix.length(); i++) {
        pNick->addPerm(sPrefix[i]);
    }

    if (pNick->equals(m_network->GetCurNick())) {
        for (NoString::size_type i = 0; i < sPrefix.length(); i++) {
            addPerm(sPrefix[i]);
        }
    }

    m_nicks[pNick->nick()] = *pNick;

    return true;
}

std::map<char, uint> NoChannel::getPermCounts() const
{
    std::map<char, uint> mRet;

    for (const auto& it : m_nicks) {
        NoString sPerms = it.second.perms();

        for (uint p = 0; p < sPerms.size(); p++) {
            mRet[sPerms[p]]++;
        }
    }

    return mRet;
}

bool NoChannel::remNick(const NoString& sNick)
{
    std::map<NoString, NoNick>::iterator it;
    std::set<uchar>::iterator it2;

    it = m_nicks.find(sNick);
    if (it == m_nicks.end()) {
        return false;
    }

    m_nicks.erase(it);

    return true;
}

bool NoChannel::changeNick(const NoString& sOldNick, const NoString& sNewNick)
{
    std::map<NoString, NoNick>::iterator it = m_nicks.find(sOldNick);

    if (it == m_nicks.end()) {
        return false;
    }

    // Rename this nick
    it->second.setNick(sNewNick);

    // Insert a new element into the map then erase the old one, do this to change the key to the new nick
    m_nicks[sNewNick] = it->second;
    m_nicks.erase(it);

    return true;
}

const NoNick* NoChannel::findNick(const NoString& sNick) const
{
    std::map<NoString, NoNick>::const_iterator it = m_nicks.find(sNick);
    return (it != m_nicks.end()) ? &it->second : nullptr;
}

NoNick* NoChannel::findNick(const NoString& sNick)
{
    std::map<NoString, NoNick>::iterator it = m_nicks.find(sNick);
    return (it != m_nicks.end()) ? &it->second : nullptr;
}

const NoBuffer& NoChannel::getBuffer() const { return m_buffer; }
uint NoChannel::getBufferCount() const { return m_buffer.getLimit(); }
bool NoChannel::setBufferCount(uint u, bool bForce)
{
    m_hasBufferCountSet = true;
    return m_buffer.setLimit(u, bForce);
}
void NoChannel::inheritBufferCount(uint u, bool bForce)
{
    if (!m_hasBufferCountSet) m_buffer.setLimit(u, bForce);
}
size_t NoChannel::addBuffer(const NoString& sFormat, const NoString& sText, const timeval* ts)
{
    return m_buffer.addMessage(sFormat, sText, ts);
}
void NoChannel::clearBuffer() { m_buffer.clear(); }

void NoChannel::sendBuffer(NoClient* pClient)
{
    sendBuffer(pClient, m_buffer);
    if (autoClearChanBuffer()) {
        clearBuffer();
    }
}

void NoChannel::sendBuffer(NoClient* pClient, const NoBuffer& Buffer)
{
    if (m_network && m_network->IsUserAttached()) {
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
        if (!Buffer.isEmpty()) {
            const std::vector<NoClient*>& vClients = m_network->GetClients();
            for (NoClient* pEachClient : vClients) {
                NoClient* pUseClient = (pClient ? pClient : pEachClient);

                bool bWasPlaybackActive = pUseClient->IsPlaybackActive();
                pUseClient->SetPlaybackActive(true);

                bool bSkipStatusMsg = pUseClient->HasServerTime();
                NETWORKMODULECALL(OnChanBufferStarting(*this, *pUseClient), m_network->GetUser(), m_network, nullptr, &bSkipStatusMsg);

                if (!bSkipStatusMsg) {
                    m_network->PutUser(":***!znc@znc.in PRIVMSG " + getName() + " :Buffer Playback...", pUseClient);
                }

                bool bBatch = pUseClient->HasBatch();
                NoString sBatchName = No::md5(getName());

                if (bBatch) {
                    m_network->PutUser(":znc.in BATCH +" + sBatchName + " znc.in/playback " + getName(), pUseClient);
                }

                size_t uSize = Buffer.size();
                for (size_t uIdx = 0; uIdx < uSize; uIdx++) {
                    const NoMessage& BufLine = Buffer.getMessage(uIdx);
                    NoString sLine = BufLine.GetLine(*pUseClient, NoStringMap());
                    if (bBatch) {
                        NoStringMap msBatchTags = No::messageTags(sLine);
                        msBatchTags["batch"] = sBatchName;
                        No::setMessageTags(sLine, msBatchTags);
                    }
                    bool bNotShowThisLine = false;
                    NETWORKMODULECALL(OnChanBufferPlayLine2(*this, *pUseClient, sLine, BufLine.GetTime()),
                                      m_network->GetUser(),
                                      m_network,
                                      nullptr,
                                      &bNotShowThisLine);
                    if (bNotShowThisLine) continue;
                    m_network->PutUser(sLine, pUseClient);
                }

                bSkipStatusMsg = pUseClient->HasServerTime();
                NETWORKMODULECALL(OnChanBufferEnding(*this, *pUseClient), m_network->GetUser(), m_network, nullptr, &bSkipStatusMsg);
                if (!bSkipStatusMsg) {
                    m_network->PutUser(":***!znc@znc.in PRIVMSG " + getName() + " :Playback Complete.", pUseClient);
                }

                if (bBatch) {
                    m_network->PutUser(":znc.in BATCH -" + sBatchName, pUseClient);
                }

                pUseClient->SetPlaybackActive(bWasPlaybackActive);

                if (pClient) break;
            }
        }
    }
}

NoString NoChannel::getPermStr() const { return m_nick.perms(); }
bool NoChannel::hasPerm(uchar uPerm) const { return m_nick.hasPerm(uPerm); }
void NoChannel::addPerm(uchar uPerm) { m_nick.addPerm(uPerm); }
void NoChannel::remPerm(uchar uPerm) { m_nick.removePerm(uPerm); }

bool NoChannel::isModeKnown() const { return m_modeKnown; }
void NoChannel::setModeKnown(bool b) { m_modeKnown = b; }
void NoChannel::setIsOn(bool b)
{
    m_isOn = b;
    if (!b) {
        reset();
    }
}

void NoChannel::setKey(const NoString& s)
{
    if (m_key != s) {
        m_key = s;
        if (m_inConfig) {
            NoApp::Get().SetConfigState(NoApp::ConfigNeedWrite);
        }
    }
}

void NoChannel::setTopic(const NoString& s) { m_topic = s; }
void NoChannel::setTopicOwner(const NoString& s) { m_topicOwner = s; }
void NoChannel::setTopicDate(ulong u) { m_topicDate = u; }
void NoChannel::setDefaultModes(const NoString& s) { m_defaultModes = s; }
void NoChannel::setDetached(bool b) { m_detached = b; }

void NoChannel::setCreationDate(ulong u) { m_creationDate = u; }
void NoChannel::disable() { m_disabled = true; }

void NoChannel::enable()
{
    resetJoinTries();
    m_disabled = false;
}

void NoChannel::incJoinTries() { m_joinTries++; }
void NoChannel::resetJoinTries() { m_joinTries = 0; }

void NoChannel::setInConfig(bool b)
{
    if (m_inConfig != b) {
        m_inConfig = b;
        if (m_inConfig) {
            NoApp::Get().SetConfigState(NoApp::ConfigNeedWrite);
        }
    }
}

bool NoChannel::isOn() const { return m_isOn; }
NoString NoChannel::getName() const { return m_name; }
std::map<uchar, NoString> NoChannel::getModes() const { return m_modes; }
NoString NoChannel::getKey() const { return m_key; }
NoString NoChannel::getTopic() const { return m_topic; }
NoString NoChannel::getTopicOwner() const { return m_topicOwner; }
ulong NoChannel::getTopicDate() const { return m_topicDate; }
NoString NoChannel::getDefaultModes() const { return m_defaultModes; }
std::map<NoString, NoNick> NoChannel::getNicks() const { return m_nicks; }
size_t NoChannel::getNickCount() const { return m_nicks.size(); }
bool NoChannel::autoClearChanBuffer() const { return m_autoClearChanBuffer; }
bool NoChannel::isDetached() const { return m_detached; }
bool NoChannel::inConfig() const { return m_inConfig; }
ulong NoChannel::getCreationDate() const { return m_creationDate; }
bool NoChannel::isDisabled() const { return m_disabled; }
uint NoChannel::getJoinTries() const { return m_joinTries; }
bool NoChannel::hasBufferCountSet() const { return m_hasBufferCountSet; }
bool NoChannel::hasAutoClearChanBufferSet() const { return m_hasAutoClearChanBufferSet; }
