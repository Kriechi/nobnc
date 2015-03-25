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

#include "nochannel.h"
#include "noircsocket.h"
#include "nomessage.h"
#include "nouser.h"
#include "nonetwork.h"
#include "nosettings.h"
#include "noclient.h"
#include "nobuffer.h"
#include "nonick.h"
#include "noapp.h"

class NoChannelPrivate
{
public:
    bool detached = false;
    bool isOn = false;
    bool autoClearChanBuffer = false;
    bool inConfig = false;
    bool disabled = false;
    bool hasBufferCountSet = false;
    bool hasAutoClearChanBufferSet = false;
    bool modeKnown = false;
    NoString name = "";
    NoString key = "";
    NoString topic = "";
    NoString topicOwner = "";
    ulong topicDate = 0;
    ulong creationDate = 0;
    NoNetwork* network = nullptr;
    NoNick nick;
    uint joinTries = 0;
    NoString defaultModes = "";
    std::map<NoString, NoNick> nicks; // Todo: make this caseless (irc style)
    NoBuffer buffer;
    std::map<uchar, NoString> modes;
};

NoChannel::NoChannel(const NoString& sName, NoNetwork* pNetwork, bool bInConfig, NoSettings* pConfig)
    : d(new NoChannelPrivate)
{
    d->network = pNetwork;
    d->autoClearChanBuffer = pNetwork->GetUser()->AutoClearChanBuffer();
    d->inConfig = bInConfig;

    d->name = No::token(sName, 0);
    d->key = No::token(sName, 1);

    if (!pNetwork->IsChan(d->name)) {
        d->name = "#" + d->name;
    }

    d->nick.setNetwork(d->network);
    d->buffer.setLimit(d->network->GetUser()->GetBufferCount(), true);

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
    d->isOn = false;
    d->modeKnown = false;
    d->modes.clear();
    d->topic = "";
    d->topicOwner = "";
    d->topicDate = 0;
    d->creationDate = 0;
    d->nick.reset();
    clearNicks();
    resetJoinTries();
}

NoSettings NoChannel::toConfig() const
{
    NoSettings config;

    if (d->hasBufferCountSet) config.AddKeyValuePair("Buffer", NoString(getBufferCount()));
    if (d->hasAutoClearChanBufferSet) config.AddKeyValuePair("AutoClearChanBuffer", NoString(autoClearChanBuffer()));
    if (isDetached()) config.AddKeyValuePair("Detached", "true");
    if (isDisabled()) config.AddKeyValuePair("Disabled", "true");
    if (!getKey().empty()) config.AddKeyValuePair("Key", getKey());
    if (!getDefaultModes().empty()) config.AddKeyValuePair("Modes", getDefaultModes());

    return config;
}

void NoChannel::clone(NoChannel& chan)
{
    // We assume that d->sName and d->pNetwork are equal
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

void NoChannel::cycle() const { d->network->PutIRC("PART " + getName() + "\r\nJOIN " + getName() + " " + getKey()); }

void NoChannel::joinUser(const NoString& sKey)
{
    if (!sKey.empty()) {
        setKey(sKey);
    }
    d->network->PutIRC("JOIN " + getName() + " " + getKey());
}

void NoChannel::attachUser(NoClient* pClient)
{
    d->network->PutUser(":" + d->network->GetIRCNick().nickMask() + " JOIN :" + getName(), pClient);

    if (!getTopic().empty()) {
        d->network->PutUser(":" + d->network->GetIRCServer() + " 332 " + d->network->GetIRCNick().nick() + " " +
                            getName() + " :" + getTopic(),
                            pClient);
        d->network->PutUser(":" + d->network->GetIRCServer() + " 333 " + d->network->GetIRCNick().nick() + " " +
                            getName() + " " + getTopicOwner() + " " + NoString(getTopicDate()),
                            pClient);
    }

    NoString sPre = ":" + d->network->GetIRCServer() + " 353 " + d->network->GetIRCNick().nick() + " " +
                   getModeForNames() + " " + getName() + " :";
    NoString sLine = sPre;
    NoString sPerm, sNick;

    const std::vector<NoClient*>& vpClients = d->network->GetClients();
    for (NoClient* pEachClient : vpClients) {
        NoClient* pThisClient;
        if (!pClient)
            pThisClient = pEachClient;
        else
            pThisClient = pClient;

        for (std::map<NoString, NoNick>::iterator a = d->nicks.begin(); a != d->nicks.end(); ++a) {
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

            if (sLine.size() >= 490 || a == (--d->nicks.end())) {
                d->network->PutUser(sLine, pThisClient);
                sLine = sPre;
            } else {
                sLine += " ";
            }
        }

        if (pClient) // We only want to do this for one client
            break;
    }

    d->network->PutUser(":" + d->network->GetIRCServer() + " 366 " + d->network->GetIRCNick().nick() + " " + getName() + " :End of /NAMES list.",
                        pClient);
    d->detached = false;

    // Send Buffer
    sendBuffer(pClient);
}

void NoChannel::detachUser()
{
    if (!d->detached) {
        d->network->PutUser(":" + d->network->GetIRCNick().nickMask() + " PART " + getName());
        d->detached = true;
    }
}

NoString NoChannel::getModeString() const
{
    NoString sModes, sArgs;

    for (const auto& it : d->modes) {
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

    for (const auto& it : d->modes) {
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
    d->modes.clear();
    modeChange(sModes);
}

void NoChannel::setAutoClearChanBuffer(bool b)
{
    d->hasAutoClearChanBufferSet = true;
    d->autoClearChanBuffer = b;

    if (d->autoClearChanBuffer && !isDetached() && d->network->IsUserOnline()) {
        clearBuffer();
    }
}

void NoChannel::inheritAutoClearChanBuffer(bool b)
{
    if (!d->hasAutoClearChanBufferSet) {
        d->autoClearChanBuffer = b;

        if (d->autoClearChanBuffer && !isDetached() && d->network->IsUserOnline()) {
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
    NoString sModeArg = No::token(sModes, 0);
    NoString sArgs = No::tokens(sModes, 1);
    bool bAdd = true;

    /* Try to find a NoNick* from this channel so that pOpNick->HasPerm()
     * works as expected. */
    if (pOpNick) {
        NoNick* OpNick = findNick(pOpNick->nick());
        /* If nothing was found, use the original pOpNick, else use the
         * NoNick* from FindNick() */
        if (OpNick) pOpNick = OpNick;
    }

    NETWORKMODULECALL(onRawMode2(pOpNick, *this, sModeArg, sArgs), d->network->GetUser(), d->network, nullptr, NOTHING);

    for (uint a = 0; a < sModeArg.size(); a++) {
        const uchar& uMode = sModeArg[a];

        if (uMode == '+') {
            bAdd = true;
        } else if (uMode == '-') {
            bAdd = false;
        } else if (d->network->GetIRCSock()->IsPermMode(uMode)) {
            NoString sArg = getModeArg(sArgs);
            NoNick* pNick = findNick(sArg);
            if (pNick) {
                uchar uPerm = d->network->GetIRCSock()->GetPermFromMode(uMode);

                if (uPerm) {
                    bool bNoChange = (pNick->hasPerm(uPerm) == bAdd);

                    if (bAdd) {
                        pNick->addPerm(uPerm);

                        if (pNick->equals(d->network->GetCurNick())) {
                            addPerm(uPerm);
                        }
                    } else {
                        pNick->removePerm(uPerm);

                        if (pNick->equals(d->network->GetCurNick())) {
                            remPerm(uPerm);
                        }
                    }

                    NETWORKMODULECALL(onChanPermission2(pOpNick, *pNick, *this, uMode, bAdd, bNoChange),
                                      d->network->GetUser(),
                                      d->network,
                                      nullptr,
                                      NOTHING);

                    if (uMode == NoChannel::M_Op) {
                        if (bAdd) {
                            NETWORKMODULECALL(onOp2(pOpNick, *pNick, *this, bNoChange), d->network->GetUser(), d->network, nullptr, NOTHING);
                        } else {
                            NETWORKMODULECALL(onDeop2(pOpNick, *pNick, *this, bNoChange), d->network->GetUser(), d->network, nullptr, NOTHING);
                        }
                    } else if (uMode == NoChannel::M_Voice) {
                        if (bAdd) {
                            NETWORKMODULECALL(onVoice2(pOpNick, *pNick, *this, bNoChange), d->network->GetUser(), d->network, nullptr, NOTHING);
                        } else {
                            NETWORKMODULECALL(onDevoice2(pOpNick, *pNick, *this, bNoChange), d->network->GetUser(), d->network, nullptr, NOTHING);
                        }
                    }
                }
            }
        } else {
            bool bList = false;
            NoString sArg;

            switch (d->network->GetIRCSock()->GetModeType(uMode)) {
            case NoIrcSocket::ListArg:
                bList = true;
                sArg = getModeArg(sArgs);
                break;
            case NoIrcSocket::HasArg:
                sArg = getModeArg(sArgs);
                break;
            case NoIrcSocket::NoArg:
                break;
            case NoIrcSocket::ArgWhenSet:
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
            NETWORKMODULECALL(onMode2(pOpNick, *this, uMode, sArg, bAdd, bNoChange), d->network->GetUser(), d->network, nullptr, NOTHING);

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
        std::map<uchar, NoString>::const_iterator it = d->modes.find(uMode);

        if (it != d->modes.end()) {
            return it->second;
        }
    }

    return "";
}

bool NoChannel::hasMode(uchar uMode) const { return (uMode && d->modes.find(uMode) != d->modes.end()); }

bool NoChannel::addMode(uchar uMode, const NoString& sArg)
{
    d->modes[uMode] = sArg;
    return true;
}

bool NoChannel::remMode(uchar uMode)
{
    if (!hasMode(uMode)) {
        return false;
    }

    d->modes.erase(uMode);
    return true;
}

NoString NoChannel::getModeArg(NoString& sArgs) const
{
    NoString sRet = sArgs.substr(0, sArgs.find(' '));
    sArgs = (sRet.size() < sArgs.size()) ? sArgs.substr(sRet.size() + 1) : "";
    return sRet;
}

void NoChannel::clearNicks() { d->nicks.clear(); }

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

    while (d->network->GetIRCSock()->IsPermChar(*p)) {
        sPrefix += *p;

        if (!*++p) {
            return false;
        }
    }

    sTmp = p;

    // The UHNames extension gets us nick!ident@host instead of just plain nick
    sIdent = No::tokens(sTmp, 1, "!");
    sHost = No::tokens(sIdent, 1, "@");
    sIdent = No::token(sIdent, 0, "@");
    // Get the nick
    sTmp = No::token(sTmp, 0, "!");

    NoNick tmpNick(sTmp);
    NoNick* pNick = findNick(sTmp);
    if (!pNick) {
        pNick = &tmpNick;
        pNick->setNetwork(d->network);
    }

    if (!sIdent.empty()) pNick->setIdent(sIdent);
    if (!sHost.empty()) pNick->setHost(sHost);

    for (NoString::size_type i = 0; i < sPrefix.length(); i++) {
        pNick->addPerm(sPrefix[i]);
    }

    if (pNick->equals(d->network->GetCurNick())) {
        for (NoString::size_type i = 0; i < sPrefix.length(); i++) {
            addPerm(sPrefix[i]);
        }
    }

    d->nicks[pNick->nick()] = *pNick;

    return true;
}

std::map<char, uint> NoChannel::getPermCounts() const
{
    std::map<char, uint> mRet;

    for (const auto& it : d->nicks) {
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

    it = d->nicks.find(sNick);
    if (it == d->nicks.end()) {
        return false;
    }

    d->nicks.erase(it);

    return true;
}

bool NoChannel::changeNick(const NoString& sOldNick, const NoString& sNewNick)
{
    std::map<NoString, NoNick>::iterator it = d->nicks.find(sOldNick);

    if (it == d->nicks.end()) {
        return false;
    }

    // Rename this nick
    it->second.setNick(sNewNick);

    // Insert a new element into the map then erase the old one, do this to change the key to the new nick
    d->nicks[sNewNick] = it->second;
    d->nicks.erase(it);

    return true;
}

const NoNick* NoChannel::findNick(const NoString& sNick) const
{
    std::map<NoString, NoNick>::const_iterator it = d->nicks.find(sNick);
    return (it != d->nicks.end()) ? &it->second : nullptr;
}

NoNick* NoChannel::findNick(const NoString& sNick)
{
    std::map<NoString, NoNick>::iterator it = d->nicks.find(sNick);
    return (it != d->nicks.end()) ? &it->second : nullptr;
}

const NoBuffer& NoChannel::getBuffer() const { return d->buffer; }
uint NoChannel::getBufferCount() const { return d->buffer.getLimit(); }
bool NoChannel::setBufferCount(uint u, bool bForce)
{
    d->hasBufferCountSet = true;
    return d->buffer.setLimit(u, bForce);
}
void NoChannel::inheritBufferCount(uint u, bool bForce)
{
    if (!d->hasBufferCountSet) d->buffer.setLimit(u, bForce);
}
size_t NoChannel::addBuffer(const NoString& sFormat, const NoString& sText, const timeval* ts)
{
    return d->buffer.addMessage(sFormat, sText, ts);
}
void NoChannel::clearBuffer() { d->buffer.clear(); }

void NoChannel::sendBuffer(NoClient* pClient)
{
    sendBuffer(pClient, d->buffer);
    if (autoClearChanBuffer()) {
        clearBuffer();
    }
}

void NoChannel::sendBuffer(NoClient* pClient, const NoBuffer& Buffer)
{
    if (d->network && d->network->IsUserAttached()) {
        // in the event that pClient is nullptr, need to send this to all clients for the user
        // I'm presuming here that pClient is listed inside vClients thus vClients at this
        // point can't be empty.
        //
        // This loop has to be cycled twice to maintain the existing behavior which is
        // 1. onChanBufferStarting
        // 2. onChanBufferPlayLine
        // 3. ClearBuffer() if not keeping the buffer
        // 4. onChanBufferEnding
        //
        // With the exception of ClearBuffer(), this needs to happen per client, and
        // if pClient is not nullptr, the loops break after the first iteration.
        //
        // Rework this if you like ...
        if (!Buffer.isEmpty()) {
            const std::vector<NoClient*>& vClients = d->network->GetClients();
            for (NoClient* pEachClient : vClients) {
                NoClient* pUseClient = (pClient ? pClient : pEachClient);

                bool bWasPlaybackActive = pUseClient->IsPlaybackActive();
                pUseClient->SetPlaybackActive(true);

                bool bSkipStatusMsg = pUseClient->HasServerTime();
                NETWORKMODULECALL(onChanBufferStarting(*this, *pUseClient), d->network->GetUser(), d->network, nullptr, &bSkipStatusMsg);

                if (!bSkipStatusMsg) {
                    d->network->PutUser(":***!znc@znc.in PRIVMSG " + getName() + " :Buffer Playback...", pUseClient);
                }

                bool bBatch = pUseClient->HasBatch();
                NoString sBatchName = No::md5(getName());

                if (bBatch) {
                    d->network->PutUser(":znc.in BATCH +" + sBatchName + " znc.in/playback " + getName(), pUseClient);
                }

                size_t uSize = Buffer.size();
                for (size_t uIdx = 0; uIdx < uSize; uIdx++) {
                    const NoMessage& BufLine = Buffer.getMessage(uIdx);
                    NoString sLine = BufLine.formatted(*pUseClient, NoStringMap());
                    if (bBatch) {
                        NoStringMap msBatchTags = No::messageTags(sLine);
                        msBatchTags["batch"] = sBatchName;
                        No::setMessageTags(sLine, msBatchTags);
                    }
                    bool bNotShowThisLine = false;
                    NETWORKMODULECALL(onChanBufferPlayLine2(*this, *pUseClient, sLine, BufLine.timestamp()),
                                      d->network->GetUser(),
                                      d->network,
                                      nullptr,
                                      &bNotShowThisLine);
                    if (bNotShowThisLine) continue;
                    d->network->PutUser(sLine, pUseClient);
                }

                bSkipStatusMsg = pUseClient->HasServerTime();
                NETWORKMODULECALL(onChanBufferEnding(*this, *pUseClient), d->network->GetUser(), d->network, nullptr, &bSkipStatusMsg);
                if (!bSkipStatusMsg) {
                    d->network->PutUser(":***!znc@znc.in PRIVMSG " + getName() + " :Playback Complete.", pUseClient);
                }

                if (bBatch) {
                    d->network->PutUser(":znc.in BATCH -" + sBatchName, pUseClient);
                }

                pUseClient->SetPlaybackActive(bWasPlaybackActive);

                if (pClient) break;
            }
        }
    }
}

NoString NoChannel::getPermStr() const { return d->nick.perms(); }
bool NoChannel::hasPerm(uchar uPerm) const { return d->nick.hasPerm(uPerm); }
void NoChannel::addPerm(uchar uPerm) { d->nick.addPerm(uPerm); }
void NoChannel::remPerm(uchar uPerm) { d->nick.removePerm(uPerm); }

bool NoChannel::isModeKnown() const { return d->modeKnown; }
void NoChannel::setModeKnown(bool b) { d->modeKnown = b; }
void NoChannel::setIsOn(bool b)
{
    d->isOn = b;
    if (!b) {
        reset();
    }
}

void NoChannel::setKey(const NoString& s)
{
    if (d->key != s) {
        d->key = s;
        if (d->inConfig) {
            NoApp::Get().SetConfigState(NoApp::ConfigNeedWrite);
        }
    }
}

void NoChannel::setTopic(const NoString& s) { d->topic = s; }
void NoChannel::setTopicOwner(const NoString& s) { d->topicOwner = s; }
void NoChannel::setTopicDate(ulong u) { d->topicDate = u; }
void NoChannel::setDefaultModes(const NoString& s) { d->defaultModes = s; }
void NoChannel::setDetached(bool b) { d->detached = b; }

void NoChannel::setCreationDate(ulong u) { d->creationDate = u; }
void NoChannel::disable() { d->disabled = true; }

void NoChannel::enable()
{
    resetJoinTries();
    d->disabled = false;
}

void NoChannel::incJoinTries() { d->joinTries++; }
void NoChannel::resetJoinTries() { d->joinTries = 0; }

void NoChannel::setInConfig(bool b)
{
    if (d->inConfig != b) {
        d->inConfig = b;
        if (d->inConfig) {
            NoApp::Get().SetConfigState(NoApp::ConfigNeedWrite);
        }
    }
}

bool NoChannel::isOn() const { return d->isOn; }
NoString NoChannel::getName() const { return d->name; }
std::map<uchar, NoString> NoChannel::getModes() const { return d->modes; }
NoString NoChannel::getKey() const { return d->key; }
NoString NoChannel::getTopic() const { return d->topic; }
NoString NoChannel::getTopicOwner() const { return d->topicOwner; }
ulong NoChannel::getTopicDate() const { return d->topicDate; }
NoString NoChannel::getDefaultModes() const { return d->defaultModes; }
std::map<NoString, NoNick> NoChannel::getNicks() const { return d->nicks; }
size_t NoChannel::getNickCount() const { return d->nicks.size(); }
bool NoChannel::autoClearChanBuffer() const { return d->autoClearChanBuffer; }
bool NoChannel::isDetached() const { return d->detached; }
bool NoChannel::inConfig() const { return d->inConfig; }
ulong NoChannel::getCreationDate() const { return d->creationDate; }
bool NoChannel::isDisabled() const { return d->disabled; }
uint NoChannel::getJoinTries() const { return d->joinTries; }
bool NoChannel::hasBufferCountSet() const { return d->hasBufferCountSet; }
bool NoChannel::hasAutoClearChanBufferSet() const { return d->hasAutoClearChanBufferSet; }
