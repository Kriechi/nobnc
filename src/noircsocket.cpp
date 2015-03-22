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

#include "noircsocket.h"
#include "nosocket_p.h"
#include "nochannel.h"
#include "nouser.h"
#include "nonetwork.h"
#include "noserverinfo.h"
#include "nomodulecall.h"
#include "noclient.h"
#include "noapp.h"
#include "noquery.h"
#include "noescape.h"
#include "Csocket/Csocket.h"

#define IRCSOCKMODULECALL(macFUNC, macEXITER) \
    NETWORKMODULECALL(macFUNC, d->network->GetUser(), d->network, nullptr, macEXITER)

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
    NoIrcFloodTimer(NoIrcSocket* socket) : m_socket(socket) { StartMaxCycles(socket->d->floodRate, 0); }
    NoIrcFloodTimer(const NoIrcFloodTimer&) = delete;
    NoIrcFloodTimer& operator=(const NoIrcFloodTimer&) = delete;
    void RunJob() override
    {
        if (m_socket->d->sendsAllowed < m_socket->d->floodBurst) {
            m_socket->d->sendsAllowed++;
        }
        m_socket->TrySend();
    }
};

bool NoIrcSocket::IsFloodProtected(double fRate) { return fRate > FLOOD_MINIMAL_RATE; }

NoIrcSocket::NoIrcSocket(NoNetwork* pNetwork) : d(new NoIrcSocketPrivate)
{
    d->network = pNetwork;
    d->sendsAllowed = pNetwork->GetFloodBurst();
    d->floodBurst = pNetwork->GetFloodBurst();
    d->floodRate = pNetwork->GetFloodRate();
    d->floodProtection = IsFloodProtected(pNetwork->GetFloodRate());

    NoSocketPrivate::get(this)->allowControlCodes = true;
    EnableReadLine();
    d->nick.setIdent(d->network->GetIdent());
    d->nick.setHost(d->network->GetBindHost());
    SetEncoding(d->network->GetEncoding());

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

    pNetwork->SetIRCSocket(this);

    // RFC says a line can have 512 chars max, but we don't care ;)
    SetMaxBufferThreshold(1024);
    if (d->floodProtection) {
        NoSocketPrivate::get(this)->AddCron(new NoIrcFloodTimer(this));
    }
}

NoIrcSocket::~NoIrcSocket()
{
    if (!d->authed) {
        IRCSOCKMODULECALL(OnIRCConnectionError(this), NOTHING);
    }

    const std::vector<NoChannel*>& vChans = d->network->GetChans();
    for (NoChannel* pChan : vChans) {
        pChan->reset();
    }

    d->network->IRCDisconnected();

    for (const auto& it : d->chans) {
        delete it.second;
    }

    Quit();
    d->chans.clear();
    d->network->GetUser()->AddBytesRead(GetBytesRead());
    d->network->GetUser()->AddBytesWritten(GetBytesWritten());
}

void NoIrcSocket::Quit(const NoString& sQuitMsg)
{
    if (!d->authed) {
        Close(CLT_NOW);
        return;
    }
    if (!sQuitMsg.empty()) {
        PutIRC("QUIT :" + sQuitMsg);
    } else {
        PutIRC("QUIT :" + d->network->ExpandString(d->network->GetQuitMsg()));
    }
    Close(CLT_AFTERWRITE);
}

void NoIrcSocket::ReadLineImpl(const NoString& sData)
{
    NoString sLine = sData;

    sLine.trimRight("\n\r");

    NO_DEBUG("(" << d->network->GetUser()->GetUserName() << "/" << d->network->GetName() << ") IRC -> ZNC [" << sLine << "]");

    bool bReturn = false;
    IRCSOCKMODULECALL(OnRaw(sLine), &bReturn);
    if (bReturn) return;

    if (sLine.startsWith("PING ")) {
        // Generate a reply and don't forward this to any user,
        // we don't want any PING forwarded
        PutIRCQuick("PONG " + sLine.substr(5));
        return;
    } else if (No::token(sLine, 1).equals("PONG")) {
        // Block PONGs, we already responded to the pings
        return;
    } else if (sLine.startsWith("ERROR ")) {
        // ERROR :Closing Link: nick[24.24.24.24] (Excess Flood)
        NoString sError(sLine.substr(6));
        sError.trimPrefix();
        d->network->PutStatus("Error from Server [" + sError + "]");
        return;
    }

    NoString sCmd = No::token(sLine, 1);

    if ((sCmd.length() == 3) && (isdigit(sCmd[0])) && (isdigit(sCmd[1])) && (isdigit(sCmd[2]))) {
        NoString sServer = No::token(sLine, 0).leftChomp_n(1);
        uint uRaw = sCmd.toUInt();
        NoString sNick = No::token(sLine, 2);
        NoString sRest = No::tokens(sLine, 3);
        NoString sTmp;

        switch (uRaw) {
        case 1: { // :irc.server.com 001 nick :Welcome to the Internet Relay Network nick
            if (d->authed && sServer == "irc.znc.in") {
                // d->bAuthed == true => we already received another 001 => we might be in a traffic loop
                d->network->PutStatus("ZNC seems to be connected to itself, disconnecting...");
                Quit();
                return;
            }

            d->network->SetIRCServer(sServer);
            SetTimeout(NoNetwork::NO_TRAFFIC_TIMEOUT,
                       TMO_READ); // Now that we are connected, let nature take its course
            PutIRC("WHO " + sNick);

            d->authed = true;
            d->network->PutStatus("Connected!");

            const std::vector<NoClient*>& vClients = d->network->GetClients();

            for (NoClient* pClient : vClients) {
                NoString sClientNick = pClient->GetNick(false);

                if (!sClientNick.equals(sNick)) {
                    // If they connected with a nick that doesn't match the one we got on irc, then we need to update
                    // them
                    pClient->PutClient(":" + sClientNick + "!" + d->nick.ident() + "@" + d->nick.host() +
                                       " NICK :" + sNick);
                }
            }

            SetNick(sNick);

            IRCSOCKMODULECALL(OnIRCConnected(), NOTHING);

            d->network->ClearRawBuffer();
            d->network->AddRawBuffer(":" + _NAMEDFMT(sServer) + " " + sCmd + " {target} " + _NAMEDFMT(sRest));

            d->network->IRCConnected();

            break;
        }
        case 5:
            ParseISupport(sRest);
            d->network->UpdateExactRawBuffer(":" + _NAMEDFMT(sServer) + " " + sCmd + " {target} " + _NAMEDFMT(sRest));
            break;
        case 10: { // :irc.server.com 010 nick <hostname> <port> :<info>
            NoString sHost = No::token(sRest, 0);
            NoString sPort = No::token(sRest, 1);
            NoString sInfo = No::tokens(sRest, 2).trimPrefix_n();
            NoServerInfo server = NoServerInfo(*d->network->GetCurrentServer()); // TODO: store NoServerInfo by value
            server.setPassword("");
            d->network->PutStatus("Server [" + server.toString() +
                                  "] redirects us to [" + sHost + ":" + sPort + "] with reason [" + sInfo + "]");
            d->network->PutStatus("Perhaps you want to add it as a new server.");
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
            sTmp = ":" + _NAMEDFMT(sServer) + " " + sCmd;
            d->network->UpdateRawBuffer(sTmp, sTmp + " {target} " + _NAMEDFMT(sRest));
            break;
        case 305:
            d->network->SetIRCAway(false);
            break;
        case 306:
            d->network->SetIRCAway(true);
            break;
        case 324: { // MODE
            sRest.trim();
            NoChannel* pChan = d->network->FindChan(No::token(sRest, 0));

            if (pChan) {
                pChan->setModes(No::tokens(sRest, 1));

                // We don't SetModeKnown(true) here,
                // because a 329 will follow
                if (!pChan->isModeKnown()) {
                    // When we JOIN, we send a MODE
                    // request. This makes sure the
                    // reply isn't forwarded.
                    return;
                }
                if (pChan->isDetached()) {
                    return;
                }
            }
        } break;
        case 329: {
            sRest.trim();
            NoChannel* pChan = d->network->FindChan(No::token(sRest, 0));

            if (pChan) {
                ulong ulDate = No::token(sLine, 4).toULong();
                pChan->setCreationDate(ulDate);

                if (!pChan->isModeKnown()) {
                    pChan->setModeKnown(true);
                    // When we JOIN, we send a MODE
                    // request. This makes sure the
                    // reply isn't forwarded.
                    return;
                }
                if (pChan->isDetached()) {
                    return;
                }
            }
        } break;
        case 331: {
            // :irc.server.com 331 yournick #chan :No topic is set.
            NoChannel* pChan = d->network->FindChan(No::token(sLine, 3));

            if (pChan) {
                pChan->setTopic("");
                if (pChan->isDetached()) {
                    return;
                }
            }

            break;
        }
        case 332: {
            // :irc.server.com 332 yournick #chan :This is a topic
            NoChannel* pChan = d->network->FindChan(No::token(sLine, 3));

            if (pChan) {
                NoString sTopic = No::tokens(sLine, 4);
                sTopic.leftChomp(1);
                pChan->setTopic(sTopic);
                if (pChan->isDetached()) {
                    return;
                }
            }

            break;
        }
        case 333: {
            // :irc.server.com 333 yournick #chan setternick 1112320796
            NoChannel* pChan = d->network->FindChan(No::token(sLine, 3));

            if (pChan) {
                sNick = No::token(sLine, 4);
                ulong ulDate = No::token(sLine, 5).toULong();

                pChan->setTopicOwner(sNick);
                pChan->setTopicDate(ulDate);

                if (pChan->isDetached()) {
                    return;
                }
            }

            break;
        }
        case 352: { // WHO
            // :irc.yourserver.com 352 yournick #chan ident theirhost.com irc.theirserver.com theirnick H :0 Real Name
            sServer = No::token(sLine, 0);
            sNick = No::token(sLine, 7);
            NoString sChan = No::token(sLine, 3);
            NoString sIdent = No::token(sLine, 4);
            NoString sHost = No::token(sLine, 5);

            sServer.leftChomp(1);

            if (sNick.equals(GetNick())) {
                d->nick.setIdent(sIdent);
                d->nick.setHost(sHost);
            }

            d->network->SetIRCNick(d->nick);
            d->network->SetIRCServer(sServer);

            const std::vector<NoChannel*>& vChans = d->network->GetChans();

            for (NoChannel* pChan : vChans) {
                pChan->onWho(sNick, sIdent, sHost);
            }

            if (d->hasNamesX && (sNick.size() > 1) && IsPermChar(sNick[1])) {
                // sLine uses multi-prefix

                const std::vector<NoClient*>& vClients = d->network->GetClients();
                for (NoClient* pClient : vClients) {
                    if (pClient->HasNamesx()) {
                        d->network->PutUser(sLine, pClient);
                    } else {
                        // The client doesn't support multi-prefix so we need to remove
                        // the other prefixes.

                        NoString sNewNick = sNick;
                        size_t pos = sNick.find_first_not_of(GetPerms());
                        if (pos >= 2 && pos != NoString::npos) {
                            sNewNick = sNick[0] + sNick.substr(pos);
                        }
                        NoString sNewLine = sServer + " 352 " + No::token(sLine, 2) + " " + sChan + " " + sIdent + " " +
                                           sHost + " " + No::token(sLine, 6) + " " + sNewNick + " " + No::tokens(sLine, 8);
                        d->network->PutUser(sNewLine, pClient);
                    }
                }

                return;
            }

            NoChannel* pChan = d->network->FindChan(sChan);
            if (pChan && pChan->isDetached()) {
                return;
            }

            break;
        }
        case 353: { // NAMES
            sRest.trim();
            // Todo: allow for non @+= server msgs
            NoChannel* pChan = d->network->FindChan(No::token(sRest, 1));
            // If we don't know that channel, some client might have
            // requested a /names for it and we really should forward this.
            if (pChan) {
                NoString sNicks = No::tokens(sRest, 2).trimPrefix_n();
                pChan->addNicks(sNicks);
                if (pChan->isDetached()) {
                    return;
                }
            }

            ForwardRaw353(sLine);

            // We forwarded it already, so return
            return;
        }
        case 366: { // end of names list
            // :irc.server.com 366 nick #chan :End of /NAMES list.
            NoChannel* pChan = d->network->FindChan(No::token(sRest, 0));

            if (pChan) {
                if (pChan->isOn()) {
                    // If we are the only one in the chan, set our default modes
                    if (pChan->getNickCount() == 1) {
                        NoString sModes = pChan->getDefaultModes();

                        if (sModes.empty()) {
                            sModes = d->network->GetUser()->GetDefaultChanModes();
                        }

                        if (!sModes.empty()) {
                            PutIRC("MODE " + pChan->getName() + " " + sModes);
                        }
                    }
                }
                if (pChan->isDetached()) {
                    // don't put it to clients
                    return;
                }
            }

            break;
        }
        case 375: // begin motd
        case 422: // MOTD File is missing
            if (d->network->GetIRCServer().equals(sServer)) {
                d->network->ClearMotdBuffer();
            }
        case 372: // motd
        case 376: // end motd
            if (d->network->GetIRCServer().equals(sServer)) {
                d->network->AddMotdBuffer(":" + _NAMEDFMT(sServer) + " " + sCmd + " {target} " + _NAMEDFMT(sRest));
            }
            break;
        case 437:
            // :irc.server.net 437 * badnick :Nick/channel is temporarily unavailable
            // :irc.server.net 437 mynick badnick :Nick/channel is temporarily unavailable
            // :irc.server.net 437 mynick badnick :Cannot change nickname while banned on channel
            if (d->network->IsChan(No::token(sRest, 0)) || sNick != "*") break;
        case 432: // :irc.server.com 432 * nick :Erroneous Nickname: Illegal characters
        case 433: {
            NoString sBadNick = No::token(sRest, 0);

            if (!d->authed) {
                SendAltNick(sBadNick);
                return;
            }
            break;
        }
        case 451:
            // :irc.server.com 451 CAP :You have not registered
            // Servers that dont support CAP will give us this error, dont send it to the client
            if (sNick.equals("CAP")) return;
        case 470: {
            // :irc.unreal.net 470 mynick [Link] #chan1 has become full, so you are automatically being transferred to
            // the linked channel #chan2
            // :mccaffrey.freenode.net 470 mynick #electronics ##electronics :Forwarding to another channel

            // freenode style numeric
            NoChannel* pChan = d->network->FindChan(No::token(sRest, 0));
            if (!pChan) {
                // unreal style numeric
                pChan = d->network->FindChan(No::token(sRest, 1));
            }
            if (pChan) {
                pChan->disable();
                d->network->PutStatus("Channel [" + pChan->getName() + "] is linked to "
                                                                       "another channel and was thus disabled.");
            }
            break;
        }
        case 670:
            // :hydra.sector5d.org 670 kylef :STARTTLS successful, go ahead with TLS handshake
            // 670 is a response to `STARTTLS` telling the client to switch to TLS

            if (!GetSSL()) {
                StartTLS();
                d->network->PutStatus("Switched to SSL (STARTTLS)");
            }

            return;
        }
    } else {
        NoNick Nick(No::token(sLine, 0).trimPrefix_n());
        sCmd = No::token(sLine, 1);
        NoString sRest = No::tokens(sLine, 2);

        if (sCmd.equals("NICK")) {
            NoString sNewNick = sRest.trimPrefix_n();
            bool bIsVisible = false;

            std::vector<NoChannel*> vFoundChans;
            const std::vector<NoChannel*>& vChans = d->network->GetChans();

            for (NoChannel* pChan : vChans) {
                if (pChan->changeNick(Nick.nick(), sNewNick)) {
                    vFoundChans.push_back(pChan);

                    if (!pChan->isDetached()) {
                        bIsVisible = true;
                    }
                }
            }

            if (Nick.equals(GetNick())) {
                // We are changing our own nick, the clients always must see this!
                bIsVisible = false;
                SetNick(sNewNick);
                d->network->PutUser(sLine);
            }

            IRCSOCKMODULECALL(OnNick(Nick, sNewNick, vFoundChans), NOTHING);

            if (!bIsVisible) {
                return;
            }
        } else if (sCmd.equals("QUIT")) {
            NoString sMessage = sRest.trimPrefix_n();
            bool bIsVisible = false;

            // :nick!ident@host.com QUIT :message

            if (Nick.equals(GetNick())) {
                d->network->PutStatus("You quit [" + sMessage + "]");
                // We don't call module hooks and we don't
                // forward this quit to clients (Some clients
                // disconnect if they receive such a QUIT)
                return;
            }

            std::vector<NoChannel*> vFoundChans;
            const std::vector<NoChannel*>& vChans = d->network->GetChans();

            for (NoChannel* pChan : vChans) {
                if (pChan->remNick(Nick.nick())) {
                    vFoundChans.push_back(pChan);

                    if (!pChan->isDetached()) {
                        bIsVisible = true;
                    }
                }
            }

            IRCSOCKMODULECALL(OnQuit(Nick, sMessage, vFoundChans), NOTHING);

            if (!bIsVisible) {
                return;
            }
        } else if (sCmd.equals("JOIN")) {
            NoString sChan = No::token(sRest, 0).trimPrefix_n();
            NoChannel* pChan;

            if (Nick.equals(GetNick())) {
                d->network->AddChan(sChan, false);
                pChan = d->network->FindChan(sChan);
                if (pChan) {
                    pChan->enable();
                    pChan->setIsOn(true);
                    PutIRC("MODE " + sChan);
                }
            } else {
                pChan = d->network->FindChan(sChan);
            }

            if (pChan) {
                pChan->addNick(Nick.nickMask());
                IRCSOCKMODULECALL(OnJoin(Nick.nickMask(), *pChan), NOTHING);

                if (pChan->isDetached()) {
                    return;
                }
            }
        } else if (sCmd.equals("PART")) {
            NoString sChan = No::token(sRest, 0).trimPrefix_n();
            NoString sMsg = No::tokens(sRest, 1).trimPrefix_n();

            NoChannel* pChan = d->network->FindChan(sChan);
            bool bDetached = false;
            if (pChan) {
                pChan->remNick(Nick.nick());
                IRCSOCKMODULECALL(OnPart(Nick.nickMask(), *pChan, sMsg), NOTHING);

                if (pChan->isDetached()) bDetached = true;
            }

            if (Nick.equals(GetNick())) {
                d->network->DelChan(sChan);
            }

            /*
             * We use this boolean because
             * d->pNetwork->DelChan() will delete this channel
             * and thus we would dereference an
             * already-freed pointer!
             */
            if (bDetached) {
                return;
            }
        } else if (sCmd.equals("MODE")) {
            NoString sTarget = No::token(sRest, 0);
            NoString sModes = No::tokens(sRest, 1);
            if (sModes.left(1) == ":") sModes = sModes.substr(1);

            NoChannel* pChan = d->network->FindChan(sTarget);
            if (pChan) {
                pChan->modeChange(sModes, &Nick);

                if (pChan->isDetached()) {
                    return;
                }
            } else if (sTarget == d->nick.nick()) {
                NoString sModeArg = No::token(sModes, 0);
                bool bAdd = true;
                /* no module call defined (yet?)
                                MODULECALL(OnRawUserMode(*pOpNick, *this, sModeArg, sArgs), d->pNetwork->GetUser(),
                   nullptr, );
                */
                for (uint a = 0; a < sModeArg.size(); a++) {
                    const uchar& uMode = sModeArg[a];

                    if (uMode == '+') {
                        bAdd = true;
                    } else if (uMode == '-') {
                        bAdd = false;
                    } else {
                        if (bAdd) {
                            d->userModes.insert(uMode);
                        } else {
                            d->userModes.erase(uMode);
                        }
                    }
                }
            }
        } else if (sCmd.equals("KICK")) {
            // :opnick!ident@host.com KICK #chan nick :msg
            NoString sChan = No::token(sRest, 0);
            NoString sKickedNick = No::token(sRest, 1);
            NoString sMsg = No::tokens(sRest, 2);
            sMsg.leftChomp(1);

            NoChannel* pChan = d->network->FindChan(sChan);

            if (pChan) {
                IRCSOCKMODULECALL(OnKick(Nick, sKickedNick, *pChan, sMsg), NOTHING);
                // do not remove the nick till after the OnKick call, so modules
                // can do Chan.FindNick or something to get more info.
                pChan->remNick(sKickedNick);
            }

            if (GetNick().equals(sKickedNick) && pChan) {
                pChan->setIsOn(false);

                // Don't try to rejoin!
                pChan->disable();
            }

            if ((pChan) && (pChan->isDetached())) {
                return;
            }
        } else if (sCmd.equals("NOTICE")) {
            // :nick!ident@host.com NOTICE #chan :Message
            NoString sTarget = No::token(sRest, 0);
            NoString sMsg = No::tokens(sRest, 1);
            sMsg.leftChomp(1);

            if (No::wildCmp(sMsg, "\001*\001")) {
                sMsg.leftChomp(1);
                sMsg.rightChomp(1);

                if (sTarget.equals(GetNick())) {
                    if (OnCTCPReply(Nick, sMsg)) {
                        return;
                    }
                }

                d->network->PutUser(":" + Nick.nickMask() + " NOTICE " + sTarget + " :\001" + sMsg + "\001");
                return;
            } else {
                if (sTarget.equals(GetNick())) {
                    if (OnPrivNotice(Nick, sMsg)) {
                        return;
                    }
                } else {
                    if (OnChanNotice(Nick, sTarget, sMsg)) {
                        return;
                    }
                }
            }

            if (Nick.equals(d->network->GetIRCServer())) {
                d->network->PutUser(":" + Nick.nick() + " NOTICE " + sTarget + " :" + sMsg);
            } else {
                d->network->PutUser(":" + Nick.nickMask() + " NOTICE " + sTarget + " :" + sMsg);
            }

            return;
        } else if (sCmd.equals("TOPIC")) {
            // :nick!ident@host.com TOPIC #chan :This is a topic
            NoChannel* pChan = d->network->FindChan(No::token(sLine, 2));

            if (pChan) {
                NoString sTopic = No::tokens(sLine, 3);
                sTopic.leftChomp(1);

                IRCSOCKMODULECALL(OnTopic(Nick, *pChan, sTopic), &bReturn);
                if (bReturn) return;

                pChan->setTopicOwner(Nick.nick());
                pChan->setTopicDate((ulong)time(nullptr));
                pChan->setTopic(sTopic);

                if (pChan->isDetached()) {
                    return; // Don't forward this
                }

                sLine = ":" + Nick.nickMask() + " TOPIC " + pChan->getName() + " :" + sTopic;
            }
        } else if (sCmd.equals("PRIVMSG")) {
            // :nick!ident@host.com PRIVMSG #chan :Message
            NoString sTarget = No::token(sRest, 0);
            NoString sMsg = No::tokens(sRest, 1).trimPrefix_n();

            if (No::wildCmp(sMsg, "\001*\001")) {
                sMsg.leftChomp(1);
                sMsg.rightChomp(1);

                if (sTarget.equals(GetNick())) {
                    if (OnPrivCTCP(Nick, sMsg)) {
                        return;
                    }
                } else {
                    if (OnChanCTCP(Nick, sTarget, sMsg)) {
                        return;
                    }
                }

                d->network->PutUser(":" + Nick.nickMask() + " PRIVMSG " + sTarget + " :\001" + sMsg + "\001");
                return;
            } else {
                if (sTarget.equals(GetNick())) {
                    if (OnPrivMsg(Nick, sMsg)) {
                        return;
                    }
                } else {
                    if (OnChanMsg(Nick, sTarget, sMsg)) {
                        return;
                    }
                }

                d->network->PutUser(":" + Nick.nickMask() + " PRIVMSG " + sTarget + " :" + sMsg);
                return;
            }
        } else if (sCmd.equals("WALLOPS")) {
            // :blub!dummy@rox-8DBEFE92 WALLOPS :this is a test
            NoString sMsg = No::tokens(sRest, 0).trimPrefix_n();

            if (!d->network->IsUserOnline()) {
                d->network->AddNoticeBuffer(":" + _NAMEDFMT(Nick.nickMask()) + " WALLOPS :{text}", sMsg);
            }
        } else if (sCmd.equals("CAP")) {
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
                NoString sArgs;
                if (No::token(sRest, 2) == "*") {
                    sArgs = No::tokens(sRest, 3).trimPrefix_n();
                } else {
                    sArgs = No::tokens(sRest, 2).trimPrefix_n();
                }

                if (sSubCmd == "LS") {
                    NoStringVector vsTokens = sArgs.split(" ", No::SkipEmptyParts);

                    for (const NoString& sCap : vsTokens) {
                        if (OnServerCapAvailable(sCap) || sCap == "multi-prefix" || sCap == "userhost-in-names") {
                            d->pendingCaps.insert(sCap);
                        }
                    }
                } else if (sSubCmd == "ACK") {
                    sArgs.trim();
                    IRCSOCKMODULECALL(OnServerCapResult(sArgs, true), NOTHING);
                    if ("multi-prefix" == sArgs) {
                        d->hasNamesX = true;
                    } else if ("userhost-in-names" == sArgs) {
                        d->hasUhNames = true;
                    }
                    d->acceptedCaps.insert(sArgs);
                } else if (sSubCmd == "NAK") {
                    // This should work because there's no [known]
                    // capability with length of name more than 100 characters.
                    sArgs.trim();
                    IRCSOCKMODULECALL(OnServerCapResult(sArgs, false), NOTHING);
                }

                SendNextCap();
            }
            // Don't forward any CAP stuff to the client
            return;
        } else if (sCmd.equals("INVITE")) {
            IRCSOCKMODULECALL(OnInvite(Nick, No::token(sLine, 3).trimPrefix_n(":")), &bReturn);
            if (bReturn) return;
        }
    }

    d->network->PutUser(sLine);
}

void NoIrcSocket::SendNextCap()
{
    if (!d->capPaused) {
        if (d->pendingCaps.empty()) {
            // We already got all needed ACK/NAK replies.
            PutIRC("CAP END");
        } else {
            NoString sCap = *d->pendingCaps.begin();
            d->pendingCaps.erase(d->pendingCaps.begin());
            PutIRC("CAP REQ :" + sCap);
        }
    }
}

void NoIrcSocket::PauseCap() { ++d->capPaused; }

void NoIrcSocket::ResumeCap()
{
    --d->capPaused;
    SendNextCap();
}

void NoIrcSocket::SetPass(const NoString& s) { d->password = s; }

uint NoIrcSocket::GetMaxNickLen() const { return d->maxNickLen; }

bool NoIrcSocket::OnServerCapAvailable(const NoString& sCap)
{
    bool bResult = false;
    IRCSOCKMODULECALL(OnServerCapAvailable(sCap), &bResult);
    return bResult;
}

bool NoIrcSocket::OnCTCPReply(NoNick& Nick, NoString& sMessage)
{
    bool bResult = false;
    IRCSOCKMODULECALL(OnCTCPReply(Nick, sMessage), &bResult);

    return bResult;
}

bool NoIrcSocket::OnPrivCTCP(NoNick& Nick, NoString& sMessage)
{
    bool bResult = false;
    IRCSOCKMODULECALL(OnPrivCTCP(Nick, sMessage), &bResult);
    if (bResult) return true;

    if (sMessage.trimPrefix("ACTION ")) {
        bResult = false;
        IRCSOCKMODULECALL(OnPrivAction(Nick, sMessage), &bResult);
        if (bResult) return true;

        if (!d->network->IsUserOnline() || !d->network->GetUser()->AutoClearQueryBuffer()) {
            NoQuery* pQuery = d->network->AddQuery(Nick.nick());
            if (pQuery) {
                pQuery->addBuffer(":" + _NAMEDFMT(Nick.nickMask()) + " PRIVMSG {target} :\001ACTION {text}\001", sMessage);
            }
        }

        sMessage = "ACTION " + sMessage;
    }

    // This handles everything which wasn't handled yet
    return OnGeneralCTCP(Nick, sMessage);
}

bool NoIrcSocket::OnGeneralCTCP(NoNick& Nick, NoString& sMessage)
{
    const NoStringMap& mssCTCPReplies = d->network->GetUser()->GetCTCPReplies();
    NoString sQuery = No::token(sMessage, 0).toUpper();
    NoStringMap::const_iterator it = mssCTCPReplies.find(sQuery);
    bool bHaveReply = false;
    NoString sReply;

    if (it != mssCTCPReplies.end()) {
        sReply = d->network->ExpandString(it->second);
        bHaveReply = true;

        if (sReply.empty()) {
            return true;
        }
    }

    if (!bHaveReply && !d->network->IsUserAttached()) {
        if (sQuery == "VERSION") {
            sReply = NoApp::GetTag(false);
        } else if (sQuery == "PING") {
            sReply = No::tokens(sMessage, 1);
        }
    }

    if (!sReply.empty()) {
        time_t now = time(nullptr);
        // If the last CTCP is older than d->uCTCPFloodTime, reset the counter
        if (d->lastCtcp + d->ctcpFloodTime < now) d->numCtcp = 0;
        d->lastCtcp = now;
        // If we are over the limit, don't reply to this CTCP
        if (d->numCtcp >= d->ctcpFloodCount) {
            NO_DEBUG("CTCP flood detected - not replying to query");
            return true;
        }
        d->numCtcp++;

        PutIRC("NOTICE " + Nick.nick() + " :\001" + sQuery + " " + sReply + "\001");
        return true;
    }

    return false;
}

bool NoIrcSocket::OnPrivNotice(NoNick& Nick, NoString& sMessage)
{
    bool bResult = false;
    IRCSOCKMODULECALL(OnPrivNotice(Nick, sMessage), &bResult);
    if (bResult) return true;

    if (!d->network->IsUserOnline()) {
        // If the user is detached, add to the buffer
        d->network->AddNoticeBuffer(":" + _NAMEDFMT(Nick.nickMask()) + " NOTICE {target} :{text}", sMessage);
    }

    return false;
}

bool NoIrcSocket::OnPrivMsg(NoNick& Nick, NoString& sMessage)
{
    bool bResult = false;
    IRCSOCKMODULECALL(OnPrivMsg(Nick, sMessage), &bResult);
    if (bResult) return true;

    if (!d->network->IsUserOnline() || !d->network->GetUser()->AutoClearQueryBuffer()) {
        NoQuery* pQuery = d->network->AddQuery(Nick.nick());
        if (pQuery) {
            pQuery->addBuffer(":" + _NAMEDFMT(Nick.nickMask()) + " PRIVMSG {target} :{text}", sMessage);
        }
    }

    return false;
}

bool NoIrcSocket::OnChanCTCP(NoNick& Nick, const NoString& sChan, NoString& sMessage)
{
    NoChannel* pChan = d->network->FindChan(sChan);
    if (pChan) {
        bool bResult = false;
        IRCSOCKMODULECALL(OnChanCTCP(Nick, *pChan, sMessage), &bResult);
        if (bResult) return true;

        // Record a /me
        if (sMessage.trimPrefix("ACTION ")) {
            bResult = false;
            IRCSOCKMODULECALL(OnChanAction(Nick, *pChan, sMessage), &bResult);
            if (bResult) return true;
            if (!pChan->autoClearChanBuffer() || !d->network->IsUserOnline() || pChan->isDetached()) {
                pChan->addBuffer(":" + _NAMEDFMT(Nick.nickMask()) + " PRIVMSG " + _NAMEDFMT(sChan) +
                                 " :\001ACTION {text}\001",
                                 sMessage);
            }
            sMessage = "ACTION " + sMessage;
        }
    }

    if (OnGeneralCTCP(Nick, sMessage)) return true;

    return (pChan && pChan->isDetached());
}

bool NoIrcSocket::OnChanNotice(NoNick& Nick, const NoString& sChan, NoString& sMessage)
{
    NoChannel* pChan = d->network->FindChan(sChan);
    if (pChan) {
        bool bResult = false;
        IRCSOCKMODULECALL(OnChanNotice(Nick, *pChan, sMessage), &bResult);
        if (bResult) return true;

        if (!pChan->autoClearChanBuffer() || !d->network->IsUserOnline() || pChan->isDetached()) {
            pChan->addBuffer(":" + _NAMEDFMT(Nick.nickMask()) + " NOTICE " + _NAMEDFMT(sChan) + " :{text}", sMessage);
        }
    }

    return ((pChan) && (pChan->isDetached()));
}

bool NoIrcSocket::OnChanMsg(NoNick& Nick, const NoString& sChan, NoString& sMessage)
{
    NoChannel* pChan = d->network->FindChan(sChan);
    if (pChan) {
        bool bResult = false;
        IRCSOCKMODULECALL(OnChanMsg(Nick, *pChan, sMessage), &bResult);
        if (bResult) return true;

        if (!pChan->autoClearChanBuffer() || !d->network->IsUserOnline() || pChan->isDetached()) {
            pChan->addBuffer(":" + _NAMEDFMT(Nick.nickMask()) + " PRIVMSG " + _NAMEDFMT(sChan) + " :{text}", sMessage);
        }
    }

    return ((pChan) && (pChan->isDetached()));
}

void NoIrcSocket::PutIRC(const NoString& sLine)
{
    // Only print if the line won't get sent immediately (same condition as in TrySend()!)
    if (d->floodProtection && d->sendsAllowed <= 0) {
        NO_DEBUG("(" << d->network->GetUser()->GetUserName() << "/" << d->network->GetName() << ") ZNC -> IRC [" << sLine << "] (queued)");
    }
    d->sendQueue.push_back(sLine);
    TrySend();
}

void NoIrcSocket::PutIRCQuick(const NoString& sLine)
{
    // Only print if the line won't get sent immediately (same condition as in TrySend()!)
    if (d->floodProtection && d->sendsAllowed <= 0) {
        NO_DEBUG("(" << d->network->GetUser()->GetUserName() << "/" << d->network->GetName() << ") ZNC -> IRC [" << sLine
                  << "] (queued to front)");
    }
    d->sendQueue.push_front(sLine);
    TrySend();
}

void NoIrcSocket::TrySend()
{
    // This condition must be the same as in PutIRC() and PutIRCQuick()!
    while (!d->sendQueue.empty() && (!d->floodProtection || d->sendsAllowed > 0)) {
        d->sendsAllowed--;
        bool bSkip = false;
        NoString& sLine = d->sendQueue.front();
        IRCSOCKMODULECALL(OnSendToIRC(sLine), &bSkip);
        if (!bSkip) {
            ;
            NO_DEBUG("(" << d->network->GetUser()->GetUserName() << "/" << d->network->GetName() << ") ZNC -> IRC [" << sLine << "]");
            Write(sLine + "\r\n");
        }
        d->sendQueue.pop_front();
    }
}

void NoIrcSocket::SetNick(const NoString& sNick)
{
    d->nick.setNick(sNick);
    d->network->SetIRCNick(d->nick);
}

void NoIrcSocket::ConnectedImpl()
{
    NO_DEBUG(GetSockName() << " == Connected()");

    NoString sPass = d->password;
    NoString sNick = d->network->GetNick();
    NoString sIdent = d->network->GetIdent();
    NoString sRealName = d->network->GetRealName();

    bool bReturn = false;
    IRCSOCKMODULECALL(OnIRCRegistration(sPass, sNick, sIdent, sRealName), &bReturn);
    if (bReturn) return;

    PutIRC("CAP LS");

    if (!sPass.empty()) {
        PutIRC("PASS " + sPass);
    }

    PutIRC("NICK " + sNick);
    PutIRC("USER " + sIdent + " \"" + sIdent + "\" \"" + sIdent + "\" :" + sRealName);

    // SendAltNick() needs this
    d->nick.setNick(sNick);
}

void NoIrcSocket::DisconnectedImpl()
{
    IRCSOCKMODULECALL(OnIRCDisconnected(), NOTHING);

    NO_DEBUG(GetSockName() << " == Disconnected()");
    if (!d->network->GetUser()->IsBeingDeleted() && d->network->GetIRCConnectEnabled() && d->network->GetServers().size() != 0) {
        d->network->PutStatus("Disconnected from IRC. Reconnecting...");
    }
    d->network->ClearRawBuffer();
    d->network->ClearMotdBuffer();

    ResetChans();

    // send a "reset user modes" cmd to the client.
    // otherwise, on reconnect, it might think it still
    // had user modes that it actually doesn't have.
    NoString sUserMode;
    for (uchar cMode : d->userModes) {
        sUserMode += cMode;
    }
    if (!sUserMode.empty()) {
        d->network->PutUser(":" + d->network->GetIRCNick().nickMask() + " MODE " +
                            d->network->GetIRCNick().nick() + " :-" + sUserMode);
    }

    // also clear the user modes in our space:
    d->userModes.clear();
}

void NoIrcSocket::SockErrorImpl(int iErrno, const NoString& sDescription)
{
    NoString sError = sDescription;

    NO_DEBUG(GetSockName() << " == SockError(" << iErrno << " " << sError << ")");
    if (!d->network->GetUser()->IsBeingDeleted()) {
        if (IsConOK()) {
            d->network->PutStatus("Cannot connect to IRC (" + sError + "). Retrying...");
        } else {
            d->network->PutStatus("Disconnected from IRC (" + sError + "). Reconnecting...");
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
                    d->network->PutStatus("|" + No::escape(s, No::DebugFormat));
                }
                NoString sSHA1;
                if (GetPeerFingerprint(sSHA1))
                    d->network->PutStatus("SHA1: " + No::escape(sSHA1, No::HexColonFormat, No::HexColonFormat));
                NoString sSHA256 = GetSSLPeerFingerprint();
                d->network->PutStatus("SHA-256: " + sSHA256);
                d->network->PutStatus("If you trust this certificate, do /znc AddTrustedServerFingerprint " + sSHA256);
            }
        }
#endif
    }
    d->network->ClearRawBuffer();
    d->network->ClearMotdBuffer();

    ResetChans();
    d->userModes.clear();
}

void NoIrcSocket::TimeoutImpl()
{
    NO_DEBUG(GetSockName() << " == Timeout()");
    if (!d->network->GetUser()->IsBeingDeleted()) {
        d->network->PutStatus("IRC connection timed out.  Reconnecting...");
    }
    d->network->ClearRawBuffer();
    d->network->ClearMotdBuffer();

    ResetChans();
    d->userModes.clear();
}

void NoIrcSocket::ConnectionRefusedImpl()
{
    NO_DEBUG(GetSockName() << " == ConnectionRefused()");
    if (!d->network->GetUser()->IsBeingDeleted()) {
        d->network->PutStatus("Connection Refused.  Reconnecting...");
    }
    d->network->ClearRawBuffer();
    d->network->ClearMotdBuffer();
}

void NoIrcSocket::ReachedMaxBufferImpl()
{
    NO_DEBUG(GetSockName() << " == ReachedMaxBuffer()");
    d->network->PutStatus("Received a too long line from the IRC server!");
    Quit();
}

void NoIrcSocket::ParseISupport(const NoString& sLine)
{
    NoStringVector vsTokens = sLine.split(" ", No::SkipEmptyParts);

    for (const NoString& sToken : vsTokens) {
        NoString sName = No::token(sToken, 0, "=");
        NoString sValue = No::tokens(sToken, 1, "=");

        if (0 < sName.length() && ':' == sName[0]) {
            break;
        }

        d->iSupport[sName] = sValue;

        if (sName.equals("PREFIX")) {
            NoString sPrefixes = No::token(sValue, 1, ")");
            NoString sPermModes = No::token(sValue, 0, ")");
            sPermModes.trimLeft("(");

            if (!sPrefixes.empty() && sPermModes.size() == sPrefixes.size()) {
                d->perms = sPrefixes;
                d->permModes = sPermModes;
            }
        } else if (sName.equals("CHANTYPES")) {
            d->network->SetChanPrefixes(sValue);
        } else if (sName.equals("NICKLEN")) {
            uint uMax = sValue.toUInt();

            if (uMax) {
                d->maxNickLen = uMax;
            }
        } else if (sName.equals("CHANMODES")) {
            if (!sValue.empty()) {
                d->chanModes.clear();

                for (uint a = 0; a < 4; a++) {
                    NoString sModes = No::token(sValue, a, ",");

                    for (uint b = 0; b < sModes.size(); b++) {
                        d->chanModes[sModes[b]] = (ChanModeArgs)a;
                    }
                }
            }
        } else if (sName.equals("NAMESX")) {
            if (d->hasNamesX) continue;
            d->hasNamesX = true;
            PutIRC("PROTOCTL NAMESX");
        } else if (sName.equals("UHNAMES")) {
            if (d->hasUhNames) continue;
            d->hasUhNames = true;
            PutIRC("PROTOCTL UHNAMES");
        }
    }
}

NoString NoIrcSocket::GetISupport(const NoString& sKey, const NoString& sDefault) const
{
    NoStringMap::const_iterator i = d->iSupport.find(sKey.toUpper());
    if (i == d->iSupport.end()) {
        return sDefault;
    } else {
        return i->second;
    }
}

void NoIrcSocket::ForwardRaw353(const NoString& sLine) const
{
    const std::vector<NoClient*>& vClients = d->network->GetClients();

    for (NoClient* pClient : vClients) {
        ForwardRaw353(sLine, pClient);
    }
}

void NoIrcSocket::ForwardRaw353(const NoString& sLine, NoClient* pClient) const
{
    NoString sNicks = No::tokens(sLine, 5).trimPrefix_n();

    if ((!d->hasNamesX || pClient->HasNamesx()) && (!d->hasUhNames || pClient->HasUHNames())) {
        // Client and server have both the same UHNames and Namesx stuff enabled
        d->network->PutUser(sLine, pClient);
    } else {
        // Get everything except the actual user list
        NoString sTmp = No::token(sLine, 0, " :") + " :";

        // This loop runs once for every nick on the channel
        NoStringVector vsNicks = sNicks.split(" ", No::SkipEmptyParts);
        for (NoString sNick : vsNicks) {
            if (sNick.empty()) break;

            if (d->hasNamesX && !pClient->HasNamesx() && IsPermChar(sNick[0])) {
                // Server has, client doesn't have NAMESX, so we just use the first perm char
                size_t pos = sNick.find_first_not_of(GetPerms());
                if (pos >= 2 && pos != NoString::npos) {
                    sNick = sNick[0] + sNick.substr(pos);
                }
            }

            if (d->hasUhNames && !pClient->HasUHNames()) {
                // Server has, client hasnt UHNAMES,
                // so we strip away ident and host.
                sNick = No::token(sNick, 0, "!");
            }

            sTmp += sNick + " ";
        }
        // Strip away the spaces we inserted at the end
        sTmp.trimRight(" ");
        d->network->PutUser(sTmp, pClient);
    }
}

void NoIrcSocket::SendAltNick(const NoString& sBadNick)
{
    const NoString& sLastNick = d->nick.nick();

    // We don't know the maximum allowed nick length yet, but we know which
    // nick we sent last. If sBadNick is shorter than that, we assume the
    // server truncated our nick.
    if (sBadNick.length() < sLastNick.length()) d->maxNickLen = (uint)sBadNick.length();

    uint uMax = d->maxNickLen;

    const NoString& sConfNick = d->network->GetNick();
    const NoString& sAltNick = d->network->GetAltNick();
    NoString sNewNick = sConfNick.left(uMax - 1);

    if (sLastNick.equals(sConfNick)) {
        if ((!sAltNick.empty()) && (!sConfNick.equals(sAltNick))) {
            sNewNick = sAltNick;
        } else {
            sNewNick += "-";
        }
    } else if (sLastNick.equals(sAltNick) && !sAltNick.equals(sNewNick + "-")) {
        sNewNick += "-";
    } else if (sLastNick.equals(sNewNick + "-") && !sAltNick.equals(sNewNick + "|")) {
        sNewNick += "|";
    } else if (sLastNick.equals(sNewNick + "|") && !sAltNick.equals(sNewNick + "^")) {
        sNewNick += "^";
    } else if (sLastNick.equals(sNewNick + "^") && !sAltNick.equals(sNewNick + "a")) {
        sNewNick += "a";
    } else {
        char cLetter = 0;
        if (sBadNick.empty()) {
            d->network->PutUser("No free nick available");
            Quit();
            return;
        }

        cLetter = sBadNick.right(1)[0];

        if (cLetter == 'z') {
            d->network->PutUser("No free nick found");
            Quit();
            return;
        }

        sNewNick = sConfNick.left(uMax - 1) + ++cLetter;
        if (sNewNick.equals(sAltNick)) sNewNick = sConfNick.left(uMax - 1) + ++cLetter;
    }
    PutIRC("NICK " + sNewNick);
    d->nick.setNick(sNewNick);
}

uchar NoIrcSocket::GetPermFromMode(uchar uMode) const
{
    if (d->permModes.size() == d->perms.size()) {
        for (uint a = 0; a < d->permModes.size(); a++) {
            if (d->permModes[a] == uMode) {
                return d->perms[a];
            }
        }
    }

    return 0;
}

const std::map<uchar, NoIrcSocket::ChanModeArgs>&NoIrcSocket::GetChanModes() const { return d->chanModes; }

bool NoIrcSocket::IsPermChar(const char c) const { return (c != '\0' && GetPerms().contains(c)); }

bool NoIrcSocket::IsPermMode(const char c) const { return (c != '\0' && GetPermModes().contains(c)); }

const NoString& NoIrcSocket::GetPerms() const { return d->perms; }

const NoString& NoIrcSocket::GetPermModes() const { return d->permModes; }

NoString NoIrcSocket::GetNickMask() const { return d->nick.nickMask(); }

NoString NoIrcSocket::GetNick() const { return d->nick.nick(); }

const NoString& NoIrcSocket::GetPass() const { return d->password; }

NoNetwork*NoIrcSocket::GetNetwork() const { return d->network; }

bool NoIrcSocket::HasNamesx() const { return d->hasNamesX; }

bool NoIrcSocket::HasUHNames() const { return d->hasUhNames; }

const std::set<uchar>&NoIrcSocket::GetUserModes() const { return d->userModes; }

bool NoIrcSocket::IsAuthed() const { return d->authed; }

bool NoIrcSocket::IsCapAccepted(const NoString& sCap) { return 1 == d->acceptedCaps.count(sCap); }

const NoStringMap&NoIrcSocket::GetISupport() const { return d->iSupport; }

NoIrcSocket::ChanModeArgs NoIrcSocket::GetModeType(uchar uMode) const
{
    std::map<uchar, ChanModeArgs>::const_iterator it = d->chanModes.find(uMode);

    if (it == d->chanModes.end()) {
        return NoArg;
    }

    return it->second;
}

void NoIrcSocket::ResetChans()
{
    for (const auto& it : d->chans) {
        it.second->reset();
    }
}
