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

#include "noircsocket.h"
#include "nosocket_p.h"
#include "nochannel.h"
#include "nouser_p.h"
#include "nonetwork.h"
#include "noserverinfo.h"
#include "nomodulecall.h"
#include "noclient.h"
#include "noapp.h"
#include "noquery.h"
#include "noescape.h"
#include "nonick.h"
#include "Csocket/Csocket.h"

#define IRCSOCKMODULECALL(macFUNC, macEXITER) \
    NETWORKMODULECALL(macFUNC, d->network->user(), d->network, nullptr, macEXITER)

// It will be bad if user sets it to 0.00000000000001
// If you want no flood protection, set network's flood rate to -1
// TODO move this constant to NoNetwork?
static const double FLOOD_MINIMAL_RATE = 0.3;

class NoIrcSocketPrivate
{
public:
    bool authed = false;
    bool hasNamesX = false;
    bool hasUhNames = false;
    NoString perms = "*!@%+";
    NoString permModes = "qaohv";
    std::set<uchar> userModes;
    std::map<uchar, NoIrcSocket::ChanModeArgs> chanModes;
    NoNetwork* network = nullptr;
    NoNick nick;
    NoString password = "";
    std::map<NoString, NoChannel*> chans;
    uint maxNickLen = 9;
    uint capPaused = 0;
    NoStringSet acceptedCaps;
    NoStringSet pendingCaps;
    time_t lastCtcp = 0;
    uint numCtcp = 0;
    static const time_t ctcpFloodTime;
    static const uint ctcpFloodCount;
    NoStringMap iSupport;
    std::deque<NoString> sendQueue;
    short int sendsAllowed = 0;
    ushort floodBurst = 0;
    double floodRate = 0;
    bool floodProtection = false;
};

// These are used in OnGeneralCTCP()
const time_t NoIrcSocketPrivate::ctcpFloodTime = 5;
const uint NoIrcSocketPrivate::ctcpFloodCount = 5;

class NoIrcFloodTimer : public CCron
{
    NoIrcSocket* m_socket;

public:
    NoIrcFloodTimer(NoIrcSocket* socket) : m_socket(socket)
    {
        StartMaxCycles(socket->d->floodRate, 0);
    }
    NoIrcFloodTimer(const NoIrcFloodTimer&) = delete;
    NoIrcFloodTimer& operator=(const NoIrcFloodTimer&) = delete;
    void RunJob() override
    {
        if (m_socket->d->sendsAllowed < m_socket->d->floodBurst) {
            m_socket->d->sendsAllowed++;
        }
        m_socket->trySend();
    }
};

bool NoIrcSocket::isFloodProtected(double fRate)
{
    return fRate > FLOOD_MINIMAL_RATE;
}

NoIrcSocket::NoIrcSocket(NoNetwork* network) : d(new NoIrcSocketPrivate)
{
    d->network = network;
    d->sendsAllowed = network->floodBurst();
    d->floodBurst = network->floodBurst();
    d->floodRate = network->floodRate();
    d->floodProtection = isFloodProtected(network->floodRate());

    NoSocketPrivate::get(this)->allowControlCodes = true;
    enableReadLine();
    d->nick.setIdent(d->network->ident());
    d->nick.setHost(d->network->bindHost());
    setEncoding(d->network->encoding());

    d->chanModes['b'] = ListArg;
    d->chanModes['e'] = ListArg;
    d->chanModes['I'] = ListArg;
    d->chanModes['k'] = HasArg;
    d->chanModes['l'] = ArgWhenSet;
    d->chanModes['p'] = NoArg;
    d->chanModes['s'] = NoArg;
    d->chanModes['t'] = NoArg;
    d->chanModes['i'] = NoArg;
    d->chanModes['n'] = NoArg;

    network->setIrcSocket(this);

    // RFC says a line can have 512 chars max, but we don't care ;)
    setMaxBufferThreshold(1024);
    if (d->floodProtection) {
        NoSocketPrivate::get(this)->AddCron(new NoIrcFloodTimer(this));
    }
}

NoIrcSocket::~NoIrcSocket()
{
    if (!d->authed) {
        IRCSOCKMODULECALL(onIrcConnectionError(this), NOTHING);
    }

    const std::vector<NoChannel*>& channels = d->network->channels();
    for (NoChannel* channel : channels) {
        channel->reset();
    }

    d->network->ircDisconnected();

    for (const auto& it : d->chans) {
        delete it.second;
    }

    quit();
    d->chans.clear();
    NoUserPrivate::get(d->network->user())->addBytesRead(bytesRead());
    NoUserPrivate::get(d->network->user())->addBytesWritten(bytesWritten());
}

void NoIrcSocket::quit(const NoString& message)
{
    if (!d->authed) {
        close(CloseImmediately);
        return;
    }
    if (!message.empty()) {
        putIrc("QUIT :" + message);
    } else {
        putIrc("QUIT :" + d->network->expandString(d->network->quitMessage()));
    }
    close(CloseAfterWrite);
}

void NoIrcSocket::readLine(const NoString& data)
{
    NoString line = data;

    line.trimRight("\n\r");

    NO_DEBUG("(" << d->network->user()->userName() << "/" << d->network->name() << ") IRC -> ZNC [" << line << "]");

    bool bReturn = false;
    IRCSOCKMODULECALL(onRaw(line), &bReturn);
    if (bReturn)
        return;

    if (line.startsWith("PING ")) {
        // Generate a reply and don't forward this to any user,
        // we don't want any PING forwarded
        putIrcQuick("PONG " + line.substr(5));
        return;
    } else if (No::token(line, 1).equals("PONG")) {
        // Block PONGs, we already responded to the pings
        return;
    } else if (line.startsWith("ERROR ")) {
        // ERROR :Closing Link: nick[24.24.24.24] (Excess Flood)
        NoString error(line.substr(6));
        error.trimPrefix();
        d->network->putStatus("Error from Server [" + error + "]");
        return;
    }

    NoString cmd = No::token(line, 1);

    if ((cmd.length() == 3) && (isdigit(cmd[0])) && (isdigit(cmd[1])) && (isdigit(cmd[2]))) {
        NoString sServer = No::token(line, 0).leftChomp_n(1);
        uint uRaw = cmd.toUInt();
        NoString nick = No::token(line, 2);
        NoString sRest = No::tokens(line, 3);
        NoString sTmp;

        switch (uRaw) {
        case 1: { // :irc.server.com 001 nick :Welcome to the Internet Relay network nick
            if (d->authed && sServer == "irc.znc.in") {
                // d->bAuthed == true => we already received another 001 => we might be in a traffic loop
                d->network->putStatus("ZNC seems to be connected to itself, disconnecting...");
                quit();
                return;
            }

            d->network->setIrcServer(sServer);
            setTimeout(NoNetwork::NoTrafficTimeout, ReadTimeout); // Now that we are connected, let nature take its course
            putIrc("WHO " + nick);

            d->authed = true;
            d->network->putStatus("Connected!");

            const std::vector<NoClient*>& vClients = d->network->clients();

            for (NoClient* client : vClients) {
                NoString sClientNick = client->nick(false);

                if (!sClientNick.equals(nick)) {
                    // If they connected with a nick that doesn't match the one we got on irc, then we need to update
                    // them
                    client->putClient(":" + sClientNick + "!" + d->nick.ident() + "@" + d->nick.host() + " NICK :" + nick);
                }
            }

            setNick(nick);

            IRCSOCKMODULECALL(onIrcConnected(), NOTHING);

            d->network->clearRawBuffer();
            d->network->addRawBuffer(":" + _NAMEDFMT(sServer) + " " + cmd + " {target} " + _NAMEDFMT(sRest));

            d->network->ircConnected();

            break;
        }
        case 5:
            parseISupport(sRest);
            d->network->updateExactRawBuffer(":" + _NAMEDFMT(sServer) + " " + cmd + " {target} " + _NAMEDFMT(sRest));
            break;
        case 10: { // :irc.server.com 010 nick <hostname> <port> :<info>
            NoString host = No::token(sRest, 0);
            NoString sPort = No::token(sRest, 1);
            NoString sInfo = No::tokens(sRest, 2).trimPrefix_n();
            NoServerInfo server = NoServerInfo(*d->network->currentServer()); // TODO: store NoServerInfo by value
            server.setPassword("");
            d->network->putStatus("Server [" + server.toString() + "] redirects us to [" + host + ":" + sPort +
                                  "] with reason [" + sInfo + "]");
            d->network->putStatus("Perhaps you want to add it as a new server.");
            // Don't send server redirects to the client
            return;
        }
        case 2:
        case 3:
        case 4:
        case 250: // highest connection count
        case 251: // user count
        case 252: // oper count
        case 254: // channel count
        case 255: // client count
        case 265: // local users
        case 266: // global users
            sTmp = ":" + _NAMEDFMT(sServer) + " " + cmd;
            d->network->updateRawBuffer(sTmp, sTmp + " {target} " + _NAMEDFMT(sRest));
            break;
        case 305:
            d->network->setIrcAway(false);
            break;
        case 306:
            d->network->setIrcAway(true);
            break;
        case 324: { // MODE
            sRest.trim();
            NoChannel* channel = d->network->findChannel(No::token(sRest, 0));

            if (channel) {
                channel->setModes(No::tokens(sRest, 1));

                // We don't SetModeKnown(true) here,
                // because a 329 will follow
                if (!channel->isModeKnown()) {
                    // When we JOIN, we send a MODE
                    // request. This makes sure the
                    // reply isn't forwarded.
                    return;
                }
                if (channel->isDetached()) {
                    return;
                }
            }
        } break;
        case 329: {
            sRest.trim();
            NoChannel* channel = d->network->findChannel(No::token(sRest, 0));

            if (channel) {
                ulong ulDate = No::token(line, 4).toULong();
                channel->setCreationDate(ulDate);

                if (!channel->isModeKnown()) {
                    channel->setModeKnown(true);
                    // When we JOIN, we send a MODE
                    // request. This makes sure the
                    // reply isn't forwarded.
                    return;
                }
                if (channel->isDetached()) {
                    return;
                }
            }
        } break;
        case 331: {
            // :irc.server.com 331 yournick #chan :No topic is set.
            NoChannel* channel = d->network->findChannel(No::token(line, 3));

            if (channel) {
                channel->setTopic("");
                if (channel->isDetached()) {
                    return;
                }
            }

            break;
        }
        case 332: {
            // :irc.server.com 332 yournick #chan :This is a topic
            NoChannel* channel = d->network->findChannel(No::token(line, 3));

            if (channel) {
                NoString topic = No::tokens(line, 4);
                topic.leftChomp(1);
                channel->setTopic(topic);
                if (channel->isDetached()) {
                    return;
                }
            }

            break;
        }
        case 333: {
            // :irc.server.com 333 yournick #chan setternick 1112320796
            NoChannel* channel = d->network->findChannel(No::token(line, 3));

            if (channel) {
                nick = No::token(line, 4);
                ulong ulDate = No::token(line, 5).toULong();

                channel->setTopicOwner(nick);
                channel->setTopicDate(ulDate);

                if (channel->isDetached()) {
                    return;
                }
            }

            break;
        }
        case 352: { // WHO
            // :irc.yourserver.com 352 yournick #chan ident theirhost.com irc.theirserver.com theirnick H :0 Real Name
            sServer = No::token(line, 0);
            nick = No::token(line, 7);
            NoString sChan = No::token(line, 3);
            NoString ident = No::token(line, 4);
            NoString host = No::token(line, 5);

            sServer.leftChomp(1);

            if (nick.equals(d->nick.nick())) {
                d->nick.setIdent(ident);
                d->nick.setHost(host);
            }

            d->network->setIrcNick(d->nick);
            d->network->setIrcServer(sServer);

            const std::vector<NoChannel*>& channels = d->network->channels();

            for (NoChannel* channel : channels) {
                channel->onWho(nick, ident, host);
            }

            if (d->hasNamesX && (nick.size() > 1) && isPermChar(nick[1])) {
                // line uses multi-prefix

                const std::vector<NoClient*>& vClients = d->network->clients();
                for (NoClient* client : vClients) {
                    if (client->hasNamesX()) {
                        d->network->putUser(line, client);
                    } else {
                        // The client doesn't support multi-prefix so we need to remove
                        // the other prefixes.

                        NoString newNick = nick;
                        size_t pos = nick.find_first_not_of(perms());
                        if (pos >= 2 && pos != NoString::npos) {
                            newNick = nick[0] + nick.substr(pos);
                        }
                        NoString sNewLine = sServer + " 352 " + No::token(line, 2) + " " + sChan + " " + ident + " " +
                                            host + " " + No::token(line, 6) + " " + newNick + " " + No::tokens(line, 8);
                        d->network->putUser(sNewLine, client);
                    }
                }

                return;
            }

            NoChannel* channel = d->network->findChannel(sChan);
            if (channel && channel->isDetached()) {
                return;
            }

            break;
        }
        case 353: { // NAMES
            sRest.trim();
            // Todo: allow for non @+= server msgs
            NoChannel* channel = d->network->findChannel(No::token(sRest, 1));
            // If we don't know that channel, some client might have
            // requested a /names for it and we really should forward this.
            if (channel) {
                NoString sNicks = No::tokens(sRest, 2).trimPrefix_n();
                channel->addNicks(sNicks);
                if (channel->isDetached()) {
                    return;
                }
            }

            forwardRaw353(line);

            // We forwarded it already, so return
            return;
        }
        case 366: { // end of names list
            // :irc.server.com 366 nick #chan :End of /NAMES list.
            NoChannel* channel = d->network->findChannel(No::token(sRest, 0));

            if (channel) {
                if (channel->isOn()) {
                    // If we are the only one in the chan, set our default modes
                    if (channel->nickCount() == 1) {
                        NoString modes = channel->defaultModes();

                        if (modes.empty()) {
                            modes = d->network->user()->defaultChanModes();
                        }

                        if (!modes.empty()) {
                            putIrc("MODE " + channel->name() + " " + modes);
                        }
                    }
                }
                if (channel->isDetached()) {
                    // don't put it to clients
                    return;
                }
            }

            break;
        }
        case 375: // begin motd
        case 422: // MOTD File is missing
            if (d->network->ircServer().equals(sServer)) {
                d->network->clearMotdBuffer();
            }
        case 372: // motd
        case 376: // end motd
            if (d->network->ircServer().equals(sServer)) {
                d->network->addMotdBuffer(":" + _NAMEDFMT(sServer) + " " + cmd + " {target} " + _NAMEDFMT(sRest));
            }
            break;
        case 437:
            // :irc.server.net 437 * badnick :nick/channel is temporarily unavailable
            // :irc.server.net 437 mynick badnick :nick/channel is temporarily unavailable
            // :irc.server.net 437 mynick badnick :Cannot change nickname while banned on channel
            if (d->network->isChannel(No::token(sRest, 0)) || nick != "*")
                break;
        case 432: // :irc.server.com 432 * nick :Erroneous Nickname: Illegal characters
        case 433: {
            NoString sBadNick = No::token(sRest, 0);

            if (!d->authed) {
                sendAltNick(sBadNick);
                return;
            }
            break;
        }
        case 451:
            // :irc.server.com 451 CAP :You have not registered
            // Servers that dont support CAP will give us this error, dont send it to the client
            if (nick.equals("CAP"))
                return;
        case 470: {
            // :irc.unreal.net 470 mynick [Link] #chan1 has become full, so you are automatically being transferred to
            // the linked channel #chan2
            // :mccaffrey.freenode.net 470 mynick #electronics ##electronics :Forwarding to another channel

            // freenode style numeric
            NoChannel* channel = d->network->findChannel(No::token(sRest, 0));
            if (!channel) {
                // unreal style numeric
                channel = d->network->findChannel(No::token(sRest, 1));
            }
            if (channel) {
                channel->disable();
                d->network->putStatus("channel [" + channel->name() + "] is linked to "
                                                                    "another channel and was thus disabled.");
            }
            break;
        }
        case 670:
            // :hydra.sector5d.org 670 kylef :STARTTLS successful, go ahead with TLS handshake
            // 670 is a response to `STARTTLS` telling the client to switch to TLS

            if (!isSsl()) {
                startTls();
                d->network->putStatus("Switched to SSL (STARTTLS)");
            }

            return;
        }
    } else {
        NoNick nick(No::token(line, 0).trimPrefix_n());
        cmd = No::token(line, 1);
        NoString sRest = No::tokens(line, 2);

        if (cmd.equals("NICK")) {
            NoString newNick = sRest.trimPrefix_n();
            bool bIsVisible = false;

            std::vector<NoChannel*> vFoundChans;
            const std::vector<NoChannel*>& channels = d->network->channels();

            for (NoChannel* channel : channels) {
                if (channel->changeNick(nick.nick(), newNick)) {
                    vFoundChans.push_back(channel);

                    if (!channel->isDetached()) {
                        bIsVisible = true;
                    }
                }
            }

            if (nick.equals(d->nick.nick())) {
                // We are changing our own nick, the clients always must see this!
                bIsVisible = false;
                setNick(newNick);
                d->network->putUser(line);
            }

            IRCSOCKMODULECALL(onNick(nick, newNick, vFoundChans), NOTHING);

            if (!bIsVisible) {
                return;
            }
        } else if (cmd.equals("QUIT")) {
            NoString message = sRest.trimPrefix_n();
            bool bIsVisible = false;

            // :nick!ident@host.com QUIT :message

            if (nick.equals(d->nick.nick())) {
                d->network->putStatus("You quit [" + message + "]");
                // We don't call module hooks and we don't
                // forward this quit to clients (Some clients
                // disconnect if they receive such a QUIT)
                return;
            }

            std::vector<NoChannel*> vFoundChans;
            const std::vector<NoChannel*>& channels = d->network->channels();

            for (NoChannel* channel : channels) {
                if (channel->removeNick(nick.nick())) {
                    vFoundChans.push_back(channel);

                    if (!channel->isDetached()) {
                        bIsVisible = true;
                    }
                }
            }

            IRCSOCKMODULECALL(onQuit(nick, message, vFoundChans), NOTHING);

            if (!bIsVisible) {
                return;
            }
        } else if (cmd.equals("JOIN")) {
            NoString sChan = No::token(sRest, 0).trimPrefix_n();
            NoChannel* channel;

            if (nick.equals(d->nick.nick())) {
                d->network->addChannel(sChan, false);
                channel = d->network->findChannel(sChan);
                if (channel) {
                    channel->enable();
                    channel->setIsOn(true);
                    putIrc("MODE " + sChan);
                }
            } else {
                channel = d->network->findChannel(sChan);
            }

            if (channel) {
                channel->addNick(nick.nickMask());
                IRCSOCKMODULECALL(onJoin(nick.nickMask(), channel), NOTHING);

                if (channel->isDetached()) {
                    return;
                }
            }
        } else if (cmd.equals("PART")) {
            NoString sChan = No::token(sRest, 0).trimPrefix_n();
            NoString msg = No::tokens(sRest, 1).trimPrefix_n();

            NoChannel* channel = d->network->findChannel(sChan);
            bool bDetached = false;
            if (channel) {
                channel->removeNick(nick.nick());
                IRCSOCKMODULECALL(onPart(nick.nickMask(), channel, msg), NOTHING);

                if (channel->isDetached())
                    bDetached = true;
            }

            if (nick.equals(d->nick.nick())) {
                d->network->removeChannel(sChan);
            }

            /*
             * We use this boolean because
             * d->network->removeChannel() will delete this channel
             * and thus we would dereference an
             * already-freed pointer!
             */
            if (bDetached) {
                return;
            }
        } else if (cmd.equals("MODE")) {
            NoString target = No::token(sRest, 0);
            NoString modes = No::tokens(sRest, 1);
            if (modes.left(1) == ":")
                modes = modes.substr(1);

            NoChannel* channel = d->network->findChannel(target);
            if (channel) {
                channel->modeChange(modes, &nick);

                if (channel->isDetached()) {
                    return;
                }
            } else if (target == d->nick.nick()) {
                NoString sModeArg = No::token(modes, 0);
                bool bAdd = true;
                /* no module call defined (yet?)
                                MODULECALL(onRawUserMode(*opNick, *this, sModeArg, args), d->network->user(),
                   nullptr, );
                */
                for (uint a = 0; a < sModeArg.size(); a++) {
                    const uchar& mode = sModeArg[a];

                    if (mode == '+') {
                        bAdd = true;
                    } else if (mode == '-') {
                        bAdd = false;
                    } else {
                        if (bAdd) {
                            d->userModes.insert(mode);
                        } else {
                            d->userModes.erase(mode);
                        }
                    }
                }
            }
        } else if (cmd.equals("KICK")) {
            // :opnick!ident@host.com KICK #chan nick :msg
            NoString sChan = No::token(sRest, 0);
            NoString sKickedNick = No::token(sRest, 1);
            NoString msg = No::tokens(sRest, 2);
            msg.leftChomp(1);

            NoChannel* channel = d->network->findChannel(sChan);

            if (channel) {
                IRCSOCKMODULECALL(onKick(nick, sKickedNick, channel, msg), NOTHING);
                // do not remove the nick till after the onKick call, so modules
                // can do channel.FindNick or something to get more info.
                channel->removeNick(sKickedNick);
            }

            if (d->nick.nick().equals(sKickedNick) && channel) {
                channel->setIsOn(false);

                // Don't try to rejoin!
                channel->disable();
            }

            if ((channel) && (channel->isDetached())) {
                return;
            }
        } else if (cmd.equals("NOTICE")) {
            // :nick!ident@host.com NOTICE #chan :Message
            NoString target = No::token(sRest, 0);
            NoString msg = No::tokens(sRest, 1);
            msg.leftChomp(1);

            if (No::wildCmp(msg, "\001*\001")) {
                msg.leftChomp(1);
                msg.rightChomp(1);

                if (target.equals(d->nick.nick())) {
                    if (onCtcpReply(nick, msg)) {
                        return;
                    }
                }

                d->network->putUser(":" + nick.nickMask() + " NOTICE " + target + " :\001" + msg + "\001");
                return;
            } else {
                if (target.equals(d->nick.nick())) {
                    if (onPrivNotice(nick, msg)) {
                        return;
                    }
                } else {
                    if (onChanNotice(nick, target, msg)) {
                        return;
                    }
                }
            }

            if (nick.equals(d->network->ircServer())) {
                d->network->putUser(":" + nick.nick() + " NOTICE " + target + " :" + msg);
            } else {
                d->network->putUser(":" + nick.nickMask() + " NOTICE " + target + " :" + msg);
            }

            return;
        } else if (cmd.equals("TOPIC")) {
            // :nick!ident@host.com TOPIC #chan :This is a topic
            NoChannel* channel = d->network->findChannel(No::token(line, 2));

            if (channel) {
                NoString topic = No::tokens(line, 3);
                topic.leftChomp(1);

                IRCSOCKMODULECALL(onTopic(nick, channel, topic), &bReturn);
                if (bReturn)
                    return;

                channel->setTopicOwner(nick.nick());
                channel->setTopicDate((ulong)time(nullptr));
                channel->setTopic(topic);

                if (channel->isDetached()) {
                    return; // Don't forward this
                }

                line = ":" + nick.nickMask() + " TOPIC " + channel->name() + " :" + topic;
            }
        } else if (cmd.equals("PRIVMSG")) {
            // :nick!ident@host.com PRIVMSG #chan :Message
            NoString target = No::token(sRest, 0);
            NoString msg = No::tokens(sRest, 1).trimPrefix_n();

            if (No::wildCmp(msg, "\001*\001")) {
                msg.leftChomp(1);
                msg.rightChomp(1);

                if (target.equals(d->nick.nick())) {
                    if (onPrivCtcp(nick, msg)) {
                        return;
                    }
                } else {
                    if (onChanCtcp(nick, target, msg)) {
                        return;
                    }
                }

                d->network->putUser(":" + nick.nickMask() + " PRIVMSG " + target + " :\001" + msg + "\001");
                return;
            } else {
                if (target.equals(d->nick.nick())) {
                    if (onPrivMsg(nick, msg)) {
                        return;
                    }
                } else {
                    if (onChanMsg(nick, target, msg)) {
                        return;
                    }
                }

                d->network->putUser(":" + nick.nickMask() + " PRIVMSG " + target + " :" + msg);
                return;
            }
        } else if (cmd.equals("WALLOPS")) {
            // :blub!dummy@rox-8DBEFE92 WALLOPS :this is a test
            NoString msg = No::tokens(sRest, 0).trimPrefix_n();

            if (!d->network->isUserOnline()) {
                d->network->addNoticeBuffer(":" + _NAMEDFMT(nick.nickMask()) + " WALLOPS :{text}", msg);
            }
        } else if (cmd.equals("CAP")) {
            // CAPs are supported only before authorization.
            if (!d->authed) {
                // No::token(sRest, 0) is most likely "*". No idea why, the
                // CAP spec don't mention this, but all implementations
                // I've seen add this extra asterisk
                NoString sSubCmd = No::token(sRest, 1);

                // If the caplist of a reply is too long, it's split
                // into multiple replies. A "*" is prepended to show
                // that the list was split into multiple replies.
                // This is useful mainly for LS. For ACK and NAK
                // replies, there's no real need for this, because
                // we request only 1 capability per line.
                // If we will need to support broken servers or will
                // send several requests per line, need to delay ACK
                // actions until all ACK lines are received and
                // to recognize past request of NAK by 100 chars
                // of this reply.
                NoString args;
                if (No::token(sRest, 2) == "*") {
                    args = No::tokens(sRest, 3).trimPrefix_n();
                } else {
                    args = No::tokens(sRest, 2).trimPrefix_n();
                }

                if (sSubCmd == "LS") {
                    NoStringVector vsTokens = args.split(" ", No::SkipEmptyParts);

                    for (const NoString& cap : vsTokens) {
                        if (onServerCapAvailable(cap) || cap == "multi-prefix" || cap == "userhost-in-names") {
                            d->pendingCaps.insert(cap);
                        }
                    }
                } else if (sSubCmd == "ACK") {
                    args.trim();
                    IRCSOCKMODULECALL(onServerCapResult(args, true), NOTHING);
                    if ("multi-prefix" == args) {
                        d->hasNamesX = true;
                    } else if ("userhost-in-names" == args) {
                        d->hasUhNames = true;
                    }
                    d->acceptedCaps.insert(args);
                } else if (sSubCmd == "NAK") {
                    // This should work because there's no [known]
                    // capability with length of name more than 100 characters.
                    args.trim();
                    IRCSOCKMODULECALL(onServerCapResult(args, false), NOTHING);
                }

                sendNextCap();
            }
            // Don't forward any CAP stuff to the client
            return;
        } else if (cmd.equals("INVITE")) {
            IRCSOCKMODULECALL(onInvite(nick, No::token(line, 3).trimPrefix_n(":")), &bReturn);
            if (bReturn)
                return;
        }
    }

    d->network->putUser(line);
}

void NoIrcSocket::sendNextCap()
{
    if (!d->capPaused) {
        if (d->pendingCaps.empty()) {
            // We already got all needed ACK/NAK replies.
            putIrc("CAP END");
        } else {
            NoString cap = *d->pendingCaps.begin();
            d->pendingCaps.erase(d->pendingCaps.begin());
            putIrc("CAP REQ :" + cap);
        }
    }
}

void NoIrcSocket::pauseCap()
{
    ++d->capPaused;
}

void NoIrcSocket::resumeCap()
{
    --d->capPaused;
    sendNextCap();
}

void NoIrcSocket::setPassword(const NoString& s)
{
    d->password = s;
}

uint NoIrcSocket::maxNickLen() const
{
    return d->maxNickLen;
}

bool NoIrcSocket::onServerCapAvailable(const NoString& cap)
{
    bool bResult = false;
    IRCSOCKMODULECALL(onServerCapAvailable(cap), &bResult);
    return bResult;
}

bool NoIrcSocket::onCtcpReply(NoNick& nick, NoString& message)
{
    bool bResult = false;
    IRCSOCKMODULECALL(onCtcpReply(nick, message), &bResult);

    return bResult;
}

bool NoIrcSocket::onPrivCtcp(NoNick& nick, NoString& message)
{
    bool bResult = false;
    IRCSOCKMODULECALL(onPrivCtcp(nick, message), &bResult);
    if (bResult)
        return true;

    if (message.trimPrefix("ACTION ")) {
        bResult = false;
        IRCSOCKMODULECALL(onPrivAction(nick, message), &bResult);
        if (bResult)
            return true;

        if (!d->network->isUserOnline() || !d->network->user()->autoclearQueryBuffer()) {
            NoQuery* query = d->network->addQuery(nick.nick());
            if (query) {
                query->addBuffer(":" + _NAMEDFMT(nick.nickMask()) + " PRIVMSG {target} :\001ACTION {text}\001", message);
            }
        }

        message = "ACTION " + message;
    }

    // This handles everything which wasn't handled yet
    return OnGeneralCTCP(nick, message);
}

bool NoIrcSocket::OnGeneralCTCP(NoNick& nick, NoString& message)
{
    const NoStringMap& mssCTCPReplies = d->network->user()->ctcpReplies();
    NoString sQuery = No::token(message, 0).toUpper();
    NoStringMap::const_iterator it = mssCTCPReplies.find(sQuery);
    bool bHaveReply = false;
    NoString reply;

    if (it != mssCTCPReplies.end()) {
        reply = d->network->expandString(it->second);
        bHaveReply = true;

        if (reply.empty()) {
            return true;
        }
    }

    if (!bHaveReply && !d->network->isUserAttached()) {
        if (sQuery == "VERSION") {
            reply = NoApp::tag(false);
        } else if (sQuery == "PING") {
            reply = No::tokens(message, 1);
        }
    }

    if (!reply.empty()) {
        time_t now = time(nullptr);
        // If the last CTCP is older than d->uCTCPFloodTime, reset the counter
        if (d->lastCtcp + d->ctcpFloodTime < now)
            d->numCtcp = 0;
        d->lastCtcp = now;
        // If we are over the limit, don't reply to this CTCP
        if (d->numCtcp >= d->ctcpFloodCount) {
            NO_DEBUG("CTCP flood detected - not replying to query");
            return true;
        }
        d->numCtcp++;

        putIrc("NOTICE " + nick.nick() + " :\001" + sQuery + " " + reply + "\001");
        return true;
    }

    return false;
}

bool NoIrcSocket::onPrivNotice(NoNick& nick, NoString& message)
{
    bool bResult = false;
    IRCSOCKMODULECALL(onPrivNotice(nick, message), &bResult);
    if (bResult)
        return true;

    if (!d->network->isUserOnline()) {
        // If the user is detached, add to the buffer
        d->network->addNoticeBuffer(":" + _NAMEDFMT(nick.nickMask()) + " NOTICE {target} :{text}", message);
    }

    return false;
}

bool NoIrcSocket::onPrivMsg(NoNick& nick, NoString& message)
{
    bool bResult = false;
    IRCSOCKMODULECALL(onPrivMsg(nick, message), &bResult);
    if (bResult)
        return true;

    if (!d->network->isUserOnline() || !d->network->user()->autoclearQueryBuffer()) {
        NoQuery* query = d->network->addQuery(nick.nick());
        if (query) {
            query->addBuffer(":" + _NAMEDFMT(nick.nickMask()) + " PRIVMSG {target} :{text}", message);
        }
    }

    return false;
}

bool NoIrcSocket::onChanCtcp(NoNick& nick, const NoString& sChan, NoString& message)
{
    NoChannel* channel = d->network->findChannel(sChan);
    if (channel) {
        bool bResult = false;
        IRCSOCKMODULECALL(onChanCtcp(nick, channel, message), &bResult);
        if (bResult)
            return true;

        // Record a /me
        if (message.trimPrefix("ACTION ")) {
            bResult = false;
            IRCSOCKMODULECALL(onChanAction(nick, channel, message), &bResult);
            if (bResult)
                return true;
            if (!channel->autoClearChanBuffer() || !d->network->isUserOnline() || channel->isDetached()) {
                channel->addBuffer(":" + _NAMEDFMT(nick.nickMask()) + " PRIVMSG " + _NAMEDFMT(sChan) +
                                 " :\001ACTION {text}\001",
                                 message);
            }
            message = "ACTION " + message;
        }
    }

    if (OnGeneralCTCP(nick, message))
        return true;

    return (channel && channel->isDetached());
}

bool NoIrcSocket::onChanNotice(NoNick& nick, const NoString& sChan, NoString& message)
{
    NoChannel* channel = d->network->findChannel(sChan);
    if (channel) {
        bool bResult = false;
        IRCSOCKMODULECALL(onChanNotice(nick, channel, message), &bResult);
        if (bResult)
            return true;

        if (!channel->autoClearChanBuffer() || !d->network->isUserOnline() || channel->isDetached()) {
            channel->addBuffer(":" + _NAMEDFMT(nick.nickMask()) + " NOTICE " + _NAMEDFMT(sChan) + " :{text}", message);
        }
    }

    return ((channel) && (channel->isDetached()));
}

bool NoIrcSocket::onChanMsg(NoNick& nick, const NoString& sChan, NoString& message)
{
    NoChannel* channel = d->network->findChannel(sChan);
    if (channel) {
        bool bResult = false;
        IRCSOCKMODULECALL(onChanMsg(nick, channel, message), &bResult);
        if (bResult)
            return true;

        if (!channel->autoClearChanBuffer() || !d->network->isUserOnline() || channel->isDetached()) {
            channel->addBuffer(":" + _NAMEDFMT(nick.nickMask()) + " PRIVMSG " + _NAMEDFMT(sChan) + " :{text}", message);
        }
    }

    return ((channel) && (channel->isDetached()));
}

void NoIrcSocket::putIrc(const NoString& line)
{
    // Only print if the line won't get sent immediately (same condition as in TrySend()!)
    if (d->floodProtection && d->sendsAllowed <= 0) {
        NO_DEBUG("(" << d->network->user()->userName() << "/" << d->network->name() << ") ZNC -> IRC [" << line
                     << "] (queued)");
    }
    d->sendQueue.push_back(line);
    trySend();
}

void NoIrcSocket::putIrcQuick(const NoString& line)
{
    // Only print if the line won't get sent immediately (same condition as in TrySend()!)
    if (d->floodProtection && d->sendsAllowed <= 0) {
        NO_DEBUG("(" << d->network->user()->userName() << "/" << d->network->name() << ") ZNC -> IRC [" << line
                     << "] (queued to front)");
    }
    d->sendQueue.push_front(line);
    trySend();
}

void NoIrcSocket::trySend()
{
    // This condition must be the same as in putIrc() and putIrcQuick()!
    while (!d->sendQueue.empty() && (!d->floodProtection || d->sendsAllowed > 0)) {
        d->sendsAllowed--;
        bool skip = false;
        NoString& line = d->sendQueue.front();
        IRCSOCKMODULECALL(onSendToIrc(line), &skip);
        if (!skip) {
            ;
            NO_DEBUG("(" << d->network->user()->userName() << "/" << d->network->name() << ") ZNC -> IRC [" << line << "]");
            write(line + "\r\n");
        }
        d->sendQueue.pop_front();
    }
}

void NoIrcSocket::setNick(const NoString& nick)
{
    d->nick.setNick(nick);
    d->network->setIrcNick(d->nick);
}

void NoIrcSocket::onConnected()
{
    NO_DEBUG(name() << " == Connected()");

    NoString pass = d->password;
    NoString nick = d->network->nick();
    NoString ident = d->network->ident();
    NoString realName = d->network->realName();

    bool bReturn = false;
    IRCSOCKMODULECALL(onIrcRegistration(pass, nick, ident, realName), &bReturn);
    if (bReturn)
        return;

    putIrc("CAP LS");

    if (!pass.empty()) {
        putIrc("PASS " + pass);
    }

    putIrc("NICK " + nick);
    putIrc("USER " + ident + " \"" + ident + "\" \"" + ident + "\" :" + realName);

    // SendAltNick() needs this
    d->nick.setNick(nick);
}

void NoIrcSocket::onDisconnected()
{
    IRCSOCKMODULECALL(onIrcDisconnected(), NOTHING);

    NO_DEBUG(name() << " == Disconnected()");
    if (!NoUserPrivate::get(d->network->user())->beingDeleted && d->network->isEnabled() && d->network->servers().size() != 0) {
        d->network->putStatus("Disconnected from IRC. Reconnecting...");
    }
    d->network->clearRawBuffer();
    d->network->clearMotdBuffer();

    resetChans();

    // send a "reset user modes" cmd to the client.
    // otherwise, on reconnect, it might think it still
    // had user modes that it actually doesn't have.
    NoString sUserMode;
    for (uchar cMode : d->userModes) {
        sUserMode += cMode;
    }
    if (!sUserMode.empty()) {
        d->network->putUser(":" + d->network->ircNick().nickMask() + " MODE " + d->network->ircNick().nick() + " :-" + sUserMode);
    }

    // also clear the user modes in our space:
    d->userModes.clear();
}

void NoIrcSocket::onSocketError(int iErrno, const NoString& description)
{
    NoString error = description;

    NO_DEBUG(name() << " == SockError(" << iErrno << " " << error << ")");
    if (!NoUserPrivate::get(d->network->user())->beingDeleted) {
        if (isReady()) {
            d->network->putStatus("Cannot connect to IRC (" + error + "). Retrying...");
        } else {
            d->network->putStatus("Disconnected from IRC (" + error + "). Reconnecting...");
        }
#ifdef HAVE_LIBSSL
        if (iErrno == errnoBadSSLCert) {
            // Stringify bad cert
            X509* pCert = NoSocketPrivate::get(this)->GetX509();
            if (pCert) {
                BIO* mem = BIO_new(BIO_s_mem());
                X509_print(mem, pCert);
                X509_free(pCert);
                char* pCertStr = nullptr;
                long iLen = BIO_get_mem_data(mem, &pCertStr);
                NoString sCert(pCertStr, iLen);
                BIO_free(mem);

                NoStringVector vsCert = sCert.split("\n");
                for (const NoString& s : vsCert) {
                    // It shouldn't contain any bad characters, but let's be safe...
                    d->network->putStatus("|" + No::escape(s, No::DebugFormat));
                }
                NoString sSHA1;
                if (peerFingerprint(sSHA1))
                    d->network->putStatus("SHA1: " + No::escape(sSHA1, No::HexColonFormat, No::HexColonFormat));
                NoString sSHA256 = fingerprint();
                d->network->putStatus("SHA-256: " + sSHA256);
                d->network->putStatus("If you trust this certificate, do /znc AddTrustedServerFingerprint " + sSHA256);
            }
        }
#endif
    }
    d->network->clearRawBuffer();
    d->network->clearMotdBuffer();

    resetChans();
    d->userModes.clear();
}

void NoIrcSocket::onTimeout()
{
    NO_DEBUG(name() << " == Timeout()");
    if (!NoUserPrivate::get(d->network->user())->beingDeleted) {
        d->network->putStatus("IRC connection timed out.  Reconnecting...");
    }
    d->network->clearRawBuffer();
    d->network->clearMotdBuffer();

    resetChans();
    d->userModes.clear();
}

void NoIrcSocket::onConnectionRefused()
{
    NO_DEBUG(name() << " == ConnectionRefused()");
    if (!NoUserPrivate::get(d->network->user())->beingDeleted) {
        d->network->putStatus("Connection Refused.  Reconnecting...");
    }
    d->network->clearRawBuffer();
    d->network->clearMotdBuffer();
}

void NoIrcSocket::onReachedMaxBuffer()
{
    NO_DEBUG(name() << " == ReachedMaxBuffer()");
    d->network->putStatus("Received a too long line from the IRC server!");
    quit();
}

void NoIrcSocket::parseISupport(const NoString& line)
{
    NoStringVector vsTokens = line.split(" ", No::SkipEmptyParts);

    for (const NoString& sToken : vsTokens) {
        NoString name = No::token(sToken, 0, "=");
        NoString value = No::tokens(sToken, 1, "=");

        if (0 < name.length() && ':' == name[0]) {
            break;
        }

        d->iSupport[name] = value;

        if (name.equals("PREFIX")) {
            NoString sPrefixes = No::token(value, 1, ")");
            NoString sPermModes = No::token(value, 0, ")");
            sPermModes.trimLeft("(");

            if (!sPrefixes.empty() && sPermModes.size() == sPrefixes.size()) {
                d->perms = sPrefixes;
                d->permModes = sPermModes;
            }
        } else if (name.equals("CHANTYPES")) {
            d->network->setChannelPrefixes(value);
        } else if (name.equals("NICKLEN")) {
            uint uMax = value.toUInt();

            if (uMax) {
                d->maxNickLen = uMax;
            }
        } else if (name.equals("CHANMODES")) {
            if (!value.empty()) {
                d->chanModes.clear();

                for (uint a = 0; a < 4; a++) {
                    NoString modes = No::token(value, a, ",");

                    for (uint b = 0; b < modes.size(); b++) {
                        d->chanModes[modes[b]] = (ChanModeArgs)a;
                    }
                }
            }
        } else if (name.equals("NAMESX")) {
            if (d->hasNamesX)
                continue;
            d->hasNamesX = true;
            putIrc("PROTOCTL NAMESX");
        } else if (name.equals("UHNAMES")) {
            if (d->hasUhNames)
                continue;
            d->hasUhNames = true;
            putIrc("PROTOCTL UHNAMES");
        }
    }
}

NoString NoIrcSocket::isupport(const NoString& key, const NoString& sDefault) const
{
    NoStringMap::const_iterator i = d->iSupport.find(key.toUpper());
    if (i == d->iSupport.end()) {
        return sDefault;
    } else {
        return i->second;
    }
}

void NoIrcSocket::forwardRaw353(const NoString& line) const
{
    const std::vector<NoClient*>& vClients = d->network->clients();

    for (NoClient* client : vClients) {
        forwardRaw353(line, client);
    }
}

void NoIrcSocket::forwardRaw353(const NoString& line, NoClient* client) const
{
    NoString sNicks = No::tokens(line, 5).trimPrefix_n();

    if ((!d->hasNamesX || client->hasNamesX()) && (!d->hasUhNames || client->hasUhNames())) {
        // client and server have both the same UHNames and Namesx stuff enabled
        d->network->putUser(line, client);
    } else {
        // Get everything except the actual user list
        NoString sTmp = No::token(line, 0, " :") + " :";

        // This loop runs once for every nick on the channel
        NoStringVector vsNicks = sNicks.split(" ", No::SkipEmptyParts);
        for (NoString nick : vsNicks) {
            if (nick.empty())
                break;

            if (d->hasNamesX && !client->hasNamesX() && isPermChar(nick[0])) {
                // Server has, client doesn't have NAMESX, so we just use the first perm char
                size_t pos = nick.find_first_not_of(perms());
                if (pos >= 2 && pos != NoString::npos) {
                    nick = nick[0] + nick.substr(pos);
                }
            }

            if (d->hasUhNames && !client->hasUhNames()) {
                // Server has, client hasnt UHNAMES,
                // so we strip away ident and host.
                nick = No::token(nick, 0, "!");
            }

            sTmp += nick + " ";
        }
        // Strip away the spaces we inserted at the end
        sTmp.trimRight(" ");
        d->network->putUser(sTmp, client);
    }
}

void NoIrcSocket::sendAltNick(const NoString& sBadNick)
{
    const NoString& sLastNick = d->nick.nick();

    // We don't know the maximum allowed nick length yet, but we know which
    // nick we sent last. If sBadNick is shorter than that, we assume the
    // server truncated our nick.
    if (sBadNick.length() < sLastNick.length())
        d->maxNickLen = (uint)sBadNick.length();

    uint uMax = d->maxNickLen;

    const NoString& sConfNick = d->network->nick();
    const NoString& sAltNick = d->network->altNick();
    NoString newNick = sConfNick.left(uMax - 1);

    if (sLastNick.equals(sConfNick)) {
        if ((!sAltNick.empty()) && (!sConfNick.equals(sAltNick))) {
            newNick = sAltNick;
        } else {
            newNick += "-";
        }
    } else if (sLastNick.equals(sAltNick) && !sAltNick.equals(newNick + "-")) {
        newNick += "-";
    } else if (sLastNick.equals(newNick + "-") && !sAltNick.equals(newNick + "|")) {
        newNick += "|";
    } else if (sLastNick.equals(newNick + "|") && !sAltNick.equals(newNick + "^")) {
        newNick += "^";
    } else if (sLastNick.equals(newNick + "^") && !sAltNick.equals(newNick + "a")) {
        newNick += "a";
    } else {
        char cLetter = 0;
        if (sBadNick.empty()) {
            d->network->putUser("No free nick available");
            quit();
            return;
        }

        cLetter = sBadNick.right(1)[0];

        if (cLetter == 'z') {
            d->network->putUser("No free nick found");
            quit();
            return;
        }

        newNick = sConfNick.left(uMax - 1) + ++cLetter;
        if (newNick.equals(sAltNick))
            newNick = sConfNick.left(uMax - 1) + ++cLetter;
    }
    putIrc("NICK " + newNick);
    d->nick.setNick(newNick);
}

uchar NoIrcSocket::permFromMode(uchar mode) const
{
    if (d->permModes.size() == d->perms.size()) {
        for (uint a = 0; a < d->permModes.size(); a++) {
            if (d->permModes[a] == mode) {
                return d->perms[a];
            }
        }
    }

    return 0;
}

std::map<uchar, NoIrcSocket::ChanModeArgs> NoIrcSocket::chanModes() const
{
    return d->chanModes;
}

bool NoIrcSocket::isPermChar(const char c) const
{
    return (c != '\0' && perms().contains(c));
}

bool NoIrcSocket::isPermMode(const char c) const
{
    return (c != '\0' && permModes().contains(c));
}

NoString NoIrcSocket::perms() const
{
    return d->perms;
}

NoString NoIrcSocket::permModes() const
{
    return d->permModes;
}

NoString NoIrcSocket::nickMask() const
{
    return d->nick.nickMask();
}

NoString NoIrcSocket::nick() const
{
    return d->nick.nick();
}

NoString NoIrcSocket::password() const
{
    return d->password;
}

NoNetwork* NoIrcSocket::network() const
{
    return d->network;
}

bool NoIrcSocket::hasNamesX() const
{
    return d->hasNamesX;
}

bool NoIrcSocket::hasUhNames() const
{
    return d->hasUhNames;
}

std::set<uchar> NoIrcSocket::userModes() const
{
    return d->userModes;
}

bool NoIrcSocket::isAuthed() const
{
    return d->authed;
}

bool NoIrcSocket::isCapAccepted(const NoString& cap)
{
    return 1 == d->acceptedCaps.count(cap);
}

NoStringMap NoIrcSocket::isupport() const
{
    return d->iSupport;
}

NoIrcSocket::ChanModeArgs NoIrcSocket::modeType(uchar mode) const
{
    std::map<uchar, ChanModeArgs>::const_iterator it = d->chanModes.find(mode);

    if (it == d->chanModes.end()) {
        return NoArg;
    }

    return it->second;
}

void NoIrcSocket::resetChans()
{
    for (const auto& it : d->chans) {
        it.second->reset();
    }
}
