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

NoChannel::NoChannel(const NoString& name, NoNetwork* network, bool bInConfig, NoSettings* settings)
    : d(new NoChannelPrivate)
{
    d->network = network;
    d->autoClearChanBuffer = network->user()->autoClearChanBuffer();
    d->inConfig = bInConfig;

    d->name = No::token(name, 0);
    d->key = No::token(name, 1);

    if (!network->isChannel(d->name)) {
        d->name = "#" + d->name;
    }

    d->nick.setNetwork(d->network);
    d->buffer.setLimit(d->network->user()->bufferCount(), true);

    if (settings) {
        NoString value;
        if (settings->FindStringEntry("buffer", value))
            setBufferCount(value.toUInt(), true);
        if (settings->FindStringEntry("autoclearchanbuffer", value))
            setAutoClearChanBuffer(value.toBool());
        if (settings->FindStringEntry("detached", value))
            setDetached(value.toBool());
        if (settings->FindStringEntry("disabled", value))
            if (value.toBool())
                disable();
        if (settings->FindStringEntry("autocycle", value))
            if (value.equals("true"))
                No::printError("WARNING: AutoCycle has been removed, instead try -> LoadModule = autocycle " + name);
        if (settings->FindStringEntry("key", value))
            setKey(value);
        if (settings->FindStringEntry("modes", value))
            setDefaultModes(value);
    }
}

NoChannel::~NoChannel()
{
    clearNicks();
}

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

    if (d->hasBufferCountSet)
        config.AddKeyValuePair("Buffer", NoString(bufferCount()));
    if (d->hasAutoClearChanBufferSet)
        config.AddKeyValuePair("AutoClearChanBuffer", NoString(autoClearChanBuffer()));
    if (isDetached())
        config.AddKeyValuePair("Detached", "true");
    if (isDisabled())
        config.AddKeyValuePair("Disabled", "true");
    if (!key().empty())
        config.AddKeyValuePair("Key", key());
    if (!defaultModes().empty())
        config.AddKeyValuePair("Modes", defaultModes());

    return config;
}

void NoChannel::clone(NoChannel& chan)
{
    // We assume that d->name and d->network are equal
    setBufferCount(chan.bufferCount(), true);
    setAutoClearChanBuffer(chan.autoClearChanBuffer());
    setKey(chan.key());
    setDefaultModes(chan.defaultModes());

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

void NoChannel::cycle() const
{
    d->network->putIrc("PART " + name() + "\r\nJOIN " + name() + " " + key());
}

void NoChannel::joinUser(const NoString& key)
{
    if (!key.empty()) {
        setKey(key);
    }
    d->network->putIrc("JOIN " + name() + " " + d->key);
}

void NoChannel::attachUser(NoClient* client)
{
    d->network->putUser(":" + d->network->ircNick().nickMask() + " JOIN :" + name(), client);

    if (!topic().empty()) {
        d->network->putUser(":" + d->network->ircServer() + " 332 " + d->network->ircNick().nick() + " " + name() +
                            " :" + topic(),
                            client);
        d->network->putUser(":" + d->network->ircServer() + " 333 " + d->network->ircNick().nick() + " " + name() +
                            " " + topicOwner() + " " + NoString(topicDate()),
                            client);
    }

    NoString sPre =
    ":" + d->network->ircServer() + " 353 " + d->network->ircNick().nick() + " " + modeForNames() + " " + name() + " :";
    NoString line = sPre;
    NoString sPerm, nick;

    const std::vector<NoClient*>& vpClients = d->network->clients();
    for (NoClient* pEachClient : vpClients) {
        NoClient* pThisClient;
        if (!client)
            pThisClient = pEachClient;
        else
            pThisClient = client;

        for (std::map<NoString, NoNick>::iterator a = d->nicks.begin(); a != d->nicks.end(); ++a) {
            if (pThisClient->hasNamesX()) {
                sPerm = a->second.perms();
            } else {
                char c = a->second.perm();
                sPerm = "";
                if (c != '\0') {
                    sPerm += c;
                }
            }
            if (pThisClient->hasUhNames() && !a->second.ident().empty() && !a->second.host().empty()) {
                nick = a->first + "!" + a->second.ident() + "@" + a->second.host();
            } else {
                nick = a->first;
            }

            line += sPerm + nick;

            if (line.size() >= 490 || a == (--d->nicks.end())) {
                d->network->putUser(line, pThisClient);
                line = sPre;
            } else {
                line += " ";
            }
        }

        if (client) // We only want to do this for one client
            break;
    }

    d->network->putUser(":" + d->network->ircServer() + " 366 " + d->network->ircNick().nick() + " " + name() +
                        " :End of /NAMES list.",
                        client);
    d->detached = false;

    // Send Buffer
    sendBuffer(client);
}

void NoChannel::detachUser()
{
    if (!d->detached) {
        d->network->putUser(":" + d->network->ircNick().nickMask() + " PART " + name());
        d->detached = true;
    }
}

NoString NoChannel::modeString() const
{
    NoString modes, args;

    for (const auto& it : d->modes) {
        modes += it.first;
        if (it.second.size()) {
            args += " " + it.second;
        }
    }

    return modes.empty() ? modes : NoString("+" + modes + args);
}

NoString NoChannel::modeForNames() const
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

void NoChannel::setModes(const NoString& modes)
{
    d->modes.clear();
    modeChange(modes);
}

void NoChannel::setAutoClearChanBuffer(bool b)
{
    d->hasAutoClearChanBufferSet = true;
    d->autoClearChanBuffer = b;

    if (d->autoClearChanBuffer && !isDetached() && d->network->isUserOnline()) {
        clearBuffer();
    }
}

void NoChannel::inheritAutoClearChanBuffer(bool b)
{
    if (!d->hasAutoClearChanBufferSet) {
        d->autoClearChanBuffer = b;

        if (d->autoClearChanBuffer && !isDetached() && d->network->isUserOnline()) {
            clearBuffer();
        }
    }
}

void NoChannel::onWho(const NoString& nick, const NoString& ident, const NoString& host)
{
    NoNick* pNick = findNick(nick);

    if (pNick) {
        pNick->setIdent(ident);
        pNick->setHost(host);
    }
}

void NoChannel::modeChange(const NoString& modes, const NoNick* opNick)
{
    NoString sModeArg = No::token(modes, 0);
    NoString args = No::tokens(modes, 1);
    bool bAdd = true;

    /* Try to find a NoNick* from this channel so that opNick->HasPerm()
     * works as expected. */
    if (opNick) {
        NoNick* opNick = findNick(opNick->nick());
        /* If nothing was found, use the original opNick, else use the
         * NoNick* from FindNick() */
        if (opNick)
            opNick = opNick;
    }

    NETWORKMODULECALL(onRawMode2(opNick, *this, sModeArg, args), d->network->user(), d->network, nullptr, NOTHING);

    for (uint a = 0; a < sModeArg.size(); a++) {
        const uchar& mode = sModeArg[a];

        if (mode == '+') {
            bAdd = true;
        } else if (mode == '-') {
            bAdd = false;
        } else if (d->network->ircSocket()->isPermMode(mode)) {
            NoString arg = modeArg(args);
            NoNick* pNick = findNick(arg);
            if (pNick) {
                uchar uPerm = d->network->ircSocket()->permFromMode(mode);

                if (uPerm) {
                    bool noChange = (pNick->hasPerm(uPerm) == bAdd);

                    if (bAdd) {
                        pNick->addPerm(uPerm);

                        if (pNick->equals(d->network->currentNick())) {
                            addPerm(uPerm);
                        }
                    } else {
                        pNick->removePerm(uPerm);

                        if (pNick->equals(d->network->currentNick())) {
                            removePerm(uPerm);
                        }
                    }

                    NETWORKMODULECALL(onChanPermission2(opNick, *pNick, *this, mode, bAdd, noChange),
                                      d->network->user(),
                                      d->network,
                                      nullptr,
                                      NOTHING);

                    if (mode == NoChannel::M_Op) {
                        if (bAdd) {
                            NETWORKMODULECALL(onOp2(opNick, *pNick, *this, noChange), d->network->user(), d->network, nullptr, NOTHING);
                        } else {
                            NETWORKMODULECALL(onDeop2(opNick, *pNick, *this, noChange), d->network->user(), d->network, nullptr, NOTHING);
                        }
                    } else if (mode == NoChannel::M_Voice) {
                        if (bAdd) {
                            NETWORKMODULECALL(onVoice2(opNick, *pNick, *this, noChange), d->network->user(), d->network, nullptr, NOTHING);
                        } else {
                            NETWORKMODULECALL(onDevoice2(opNick, *pNick, *this, noChange), d->network->user(), d->network, nullptr, NOTHING);
                        }
                    }
                }
            }
        } else {
            bool bList = false;
            NoString arg;

            switch (d->network->ircSocket()->modeType(mode)) {
            case NoIrcSocket::ListArg:
                bList = true;
                arg = modeArg(args);
                break;
            case NoIrcSocket::HasArg:
                arg = modeArg(args);
                break;
            case NoIrcSocket::NoArg:
                break;
            case NoIrcSocket::ArgWhenSet:
                if (bAdd) {
                    arg = modeArg(args);
                }

                break;
            }

            bool noChange;
            if (bList) {
                noChange = false;
            } else if (bAdd) {
                noChange = hasMode(mode) && modeArg(mode) == arg;
            } else {
                noChange = !hasMode(mode);
            }
            NETWORKMODULECALL(onMode2(opNick, *this, mode, arg, bAdd, noChange), d->network->user(), d->network, nullptr, NOTHING);

            if (!bList) {
                (bAdd) ? addMode(mode, arg) : removeMode(mode);
            }

            // This is called when we join (ZNC requests the channel modes
            // on join) *and* when someone changes the channel keys.
            // We ignore channel key "*" because of some broken nets.
            if (mode == M_Key && !noChange && bAdd && arg != "*") {
                setKey(arg);
            }
        }
    }
}

NoString NoChannel::options() const
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

NoString NoChannel::modeArg(uchar mode) const
{
    if (mode) {
        std::map<uchar, NoString>::const_iterator it = d->modes.find(mode);

        if (it != d->modes.end()) {
            return it->second;
        }
    }

    return "";
}

bool NoChannel::hasMode(uchar mode) const
{
    return (mode && d->modes.find(mode) != d->modes.end());
}

bool NoChannel::addMode(uchar mode, const NoString& arg)
{
    d->modes[mode] = arg;
    return true;
}

bool NoChannel::removeMode(uchar mode)
{
    if (!hasMode(mode)) {
        return false;
    }

    d->modes.erase(mode);
    return true;
}

NoString NoChannel::modeArg(NoString& args) const
{
    NoString ret = args.substr(0, args.find(' '));
    args = (ret.size() < args.size()) ? args.substr(ret.size() + 1) : "";
    return ret;
}

void NoChannel::clearNicks()
{
    d->nicks.clear();
}

int NoChannel::addNicks(const NoString& sNicks)
{
    int iRet = 0;
    NoStringVector vsNicks = sNicks.split(" ", No::SkipEmptyParts);

    for (const NoString& nick : vsNicks) {
        if (addNick(nick)) {
            iRet++;
        }
    }

    return iRet;
}

bool NoChannel::addNick(const NoString& nick)
{
    const char* p = nick.c_str();
    NoString prefix, sTmp, ident, host;

    while (d->network->ircSocket()->isPermChar(*p)) {
        prefix += *p;

        if (!*++p) {
            return false;
        }
    }

    sTmp = p;

    // The UHNames extension gets us nick!ident@host instead of just plain nick
    ident = No::tokens(sTmp, 1, "!");
    host = No::tokens(ident, 1, "@");
    ident = No::token(ident, 0, "@");
    // Get the nick
    sTmp = No::token(sTmp, 0, "!");

    NoNick tmpNick(sTmp);
    NoNick* pNick = findNick(sTmp);
    if (!pNick) {
        pNick = &tmpNick;
        pNick->setNetwork(d->network);
    }

    if (!ident.empty())
        pNick->setIdent(ident);
    if (!host.empty())
        pNick->setHost(host);

    for (NoString::size_type i = 0; i < prefix.length(); i++) {
        pNick->addPerm(prefix[i]);
    }

    if (pNick->equals(d->network->currentNick())) {
        for (NoString::size_type i = 0; i < prefix.length(); i++) {
            addPerm(prefix[i]);
        }
    }

    d->nicks[pNick->nick()] = *pNick;

    return true;
}

std::map<char, uint> NoChannel::permCounts() const
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

bool NoChannel::removeNick(const NoString& nick)
{
    std::map<NoString, NoNick>::iterator it;
    std::set<uchar>::iterator it2;

    it = d->nicks.find(nick);
    if (it == d->nicks.end()) {
        return false;
    }

    d->nicks.erase(it);

    return true;
}

bool NoChannel::changeNick(const NoString& sOldNick, const NoString& newNick)
{
    std::map<NoString, NoNick>::iterator it = d->nicks.find(sOldNick);

    if (it == d->nicks.end()) {
        return false;
    }

    // Rename this nick
    it->second.setNick(newNick);

    // Insert a new element into the map then erase the old one, do this to change the key to the new nick
    d->nicks[newNick] = it->second;
    d->nicks.erase(it);

    return true;
}

const NoNick* NoChannel::findNick(const NoString& nick) const
{
    std::map<NoString, NoNick>::const_iterator it = d->nicks.find(nick);
    return (it != d->nicks.end()) ? &it->second : nullptr;
}

NoNick* NoChannel::findNick(const NoString& nick)
{
    std::map<NoString, NoNick>::iterator it = d->nicks.find(nick);
    return (it != d->nicks.end()) ? &it->second : nullptr;
}

const NoBuffer& NoChannel::buffer() const
{
    return d->buffer;
}
uint NoChannel::bufferCount() const
{
    return d->buffer.limit();
}
bool NoChannel::setBufferCount(uint u, bool force)
{
    d->hasBufferCountSet = true;
    return d->buffer.setLimit(u, force);
}
void NoChannel::inheritBufferCount(uint u, bool force)
{
    if (!d->hasBufferCountSet)
        d->buffer.setLimit(u, force);
}
size_t NoChannel::addBuffer(const NoString& format, const NoString& text, const timeval* ts)
{
    return d->buffer.addMessage(format, text, ts);
}
void NoChannel::clearBuffer()
{
    d->buffer.clear();
}

void NoChannel::sendBuffer(NoClient* client)
{
    sendBuffer(client, d->buffer);
    if (autoClearChanBuffer()) {
        clearBuffer();
    }
}

void NoChannel::sendBuffer(NoClient* client, const NoBuffer& Buffer)
{
    if (d->network && d->network->isUserAttached()) {
        // in the event that client is nullptr, need to send this to all clients for the user
        // I'm presuming here that client is listed inside vClients thus vClients at this
        // point can't be empty.
        //
        // This loop has to be cycled twice to maintain the existing behavior which is
        // 1. onChanBufferStarting
        // 2. onChanBufferPlayLine
        // 3. ClearBuffer() if not keeping the buffer
        // 4. onChanBufferEnding
        //
        // With the exception of ClearBuffer(), this needs to happen per client, and
        // if client is not nullptr, the loops break after the first iteration.
        //
        // Rework this if you like ...
        if (!Buffer.isEmpty()) {
            const std::vector<NoClient*>& vClients = d->network->clients();
            for (NoClient* pEachClient : vClients) {
                NoClient* pUseClient = (client ? client : pEachClient);

                bool bWasPlaybackActive = pUseClient->isPlaybackActive();
                pUseClient->setPlaybackActive(true);

                bool skipStatusMsg = pUseClient->hasServerTime();
                NETWORKMODULECALL(onChanBufferStarting(*this, *pUseClient), d->network->user(), d->network, nullptr, &skipStatusMsg);

                if (!skipStatusMsg) {
                    d->network->putUser(":***!znc@znc.in PRIVMSG " + name() + " :Buffer Playback...", pUseClient);
                }

                bool bBatch = pUseClient->hasBatch();
                NoString sBatchName = No::md5(name());

                if (bBatch) {
                    d->network->putUser(":znc.in BATCH +" + sBatchName + " znc.in/playback " + name(), pUseClient);
                }

                size_t uSize = Buffer.size();
                for (size_t uIdx = 0; uIdx < uSize; uIdx++) {
                    const NoMessage& BufLine = Buffer.message(uIdx);
                    NoString line = BufLine.formatted(*pUseClient, NoStringMap());
                    if (bBatch) {
                        NoStringMap msBatchTags = No::messageTags(line);
                        msBatchTags["batch"] = sBatchName;
                        No::setMessageTags(line, msBatchTags);
                    }
                    bool bNotShowThisLine = false;
                    NETWORKMODULECALL(onChanBufferPlayLine2(*this, *pUseClient, line, BufLine.timestamp()),
                                      d->network->user(),
                                      d->network,
                                      nullptr,
                                      &bNotShowThisLine);
                    if (bNotShowThisLine)
                        continue;
                    d->network->putUser(line, pUseClient);
                }

                skipStatusMsg = pUseClient->hasServerTime();
                NETWORKMODULECALL(onChanBufferEnding(*this, *pUseClient), d->network->user(), d->network, nullptr, &skipStatusMsg);
                if (!skipStatusMsg) {
                    d->network->putUser(":***!znc@znc.in PRIVMSG " + name() + " :Playback Complete.", pUseClient);
                }

                if (bBatch) {
                    d->network->putUser(":znc.in BATCH -" + sBatchName, pUseClient);
                }

                pUseClient->setPlaybackActive(bWasPlaybackActive);

                if (client)
                    break;
            }
        }
    }
}

NoString NoChannel::permStr() const
{
    return d->nick.perms();
}
bool NoChannel::hasPerm(uchar uPerm) const
{
    return d->nick.hasPerm(uPerm);
}
void NoChannel::addPerm(uchar uPerm)
{
    d->nick.addPerm(uPerm);
}
void NoChannel::removePerm(uchar uPerm)
{
    d->nick.removePerm(uPerm);
}

bool NoChannel::isModeKnown() const
{
    return d->modeKnown;
}
void NoChannel::setModeKnown(bool b)
{
    d->modeKnown = b;
}
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
            noApp->setConfigState(NoApp::ConfigNeedWrite);
        }
    }
}

void NoChannel::setTopic(const NoString& s)
{
    d->topic = s;
}
void NoChannel::setTopicOwner(const NoString& s)
{
    d->topicOwner = s;
}
void NoChannel::setTopicDate(ulong u)
{
    d->topicDate = u;
}
void NoChannel::setDefaultModes(const NoString& s)
{
    d->defaultModes = s;
}
void NoChannel::setDetached(bool b)
{
    d->detached = b;
}

void NoChannel::setCreationDate(ulong u)
{
    d->creationDate = u;
}
void NoChannel::disable()
{
    d->disabled = true;
}

void NoChannel::enable()
{
    resetJoinTries();
    d->disabled = false;
}

void NoChannel::incJoinTries()
{
    d->joinTries++;
}
void NoChannel::resetJoinTries()
{
    d->joinTries = 0;
}

void NoChannel::setInConfig(bool b)
{
    if (d->inConfig != b) {
        d->inConfig = b;
        noApp->setConfigState(NoApp::ConfigNeedWrite);
    }
}

bool NoChannel::isOn() const
{
    return d->isOn;
}
NoString NoChannel::name() const
{
    return d->name;
}
std::map<uchar, NoString> NoChannel::modes() const
{
    return d->modes;
}
NoString NoChannel::key() const
{
    return d->key;
}
NoString NoChannel::topic() const
{
    return d->topic;
}
NoString NoChannel::topicOwner() const
{
    return d->topicOwner;
}
ulong NoChannel::topicDate() const
{
    return d->topicDate;
}
NoString NoChannel::defaultModes() const
{
    return d->defaultModes;
}
std::map<NoString, NoNick> NoChannel::nicks() const
{
    return d->nicks;
}
size_t NoChannel::nickCount() const
{
    return d->nicks.size();
}
bool NoChannel::autoClearChanBuffer() const
{
    return d->autoClearChanBuffer;
}
bool NoChannel::isDetached() const
{
    return d->detached;
}
bool NoChannel::inConfig() const
{
    return d->inConfig;
}
ulong NoChannel::creationDate() const
{
    return d->creationDate;
}
bool NoChannel::isDisabled() const
{
    return d->disabled;
}
uint NoChannel::joinTries() const
{
    return d->joinTries;
}
bool NoChannel::hasBufferCountSet() const
{
    return d->hasBufferCountSet;
}
bool NoChannel::hasAutoClearChanBufferSet() const
{
    return d->hasAutoClearChanBufferSet;
}
