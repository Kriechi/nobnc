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

#include "noircconnection.h"
#include "nosocket_p.h"
#include "nochannel.h"
#include "nouser.h"
#include "nonetwork.h"
#include "noserver.h"
#include "nomodulecall.h"
#include "noclient.h"
#include "noapp.h"
#include "noquery.h"
#include "noescape.h"
#include "Csocket/Csocket.h"

#define IRCSOCKMODULECALL(macFUNC, macEXITER) \
    NETWORKMODULECALL(macFUNC, m_pNetwork->GetUser(), m_pNetwork, nullptr, macEXITER)
// These are used in OnGeneralCTCP()
const time_t NoIrcConnection::m_uCTCPFloodTime = 5;
const uint NoIrcConnection::m_uCTCPFloodCount = 5;

// It will be bad if user sets it to 0.00000000000001
// If you want no flood protection, set network's flood rate to -1
// TODO move this constant to NoNetwork?
static const double FLOOD_MINIMAL_RATE = 0.3;

class NoIrcFloodTimer : public CCron
{
    NoIrcConnection* m_pSock;

public:
    NoIrcFloodTimer(NoIrcConnection* pSock) : m_pSock(pSock) { StartMaxCycles(m_pSock->m_fFloodRate, 0); }
    NoIrcFloodTimer(const NoIrcFloodTimer&) = delete;
    NoIrcFloodTimer& operator=(const NoIrcFloodTimer&) = delete;
    void RunJob() override
    {
        if (m_pSock->m_iSendsAllowed < m_pSock->m_uFloodBurst) {
            m_pSock->m_iSendsAllowed++;
        }
        m_pSock->TrySend();
    }
};

bool NoIrcConnection::IsFloodProtected(double fRate) { return fRate > FLOOD_MINIMAL_RATE; }

NoIrcConnection::NoIrcConnection(NoNetwork* pNetwork)
    : m_bAuthed(false), m_bNamesx(false), m_bUHNames(false), m_sPerms("*!@%+"), m_sPermModes("qaohv"),
      m_scUserModes(), m_mueChanModes(), m_pNetwork(pNetwork), m_Nick(), m_sPass(""), m_msChans(), m_uMaxNickLen(9),
      m_uCapPaused(0), m_ssAcceptedCaps(), m_ssPendingCaps(), m_lastCTCP(0), m_uNumCTCP(0), m_mISupport(),
      m_vsSendQueue(), m_iSendsAllowed(pNetwork->GetFloodBurst()), m_uFloodBurst(pNetwork->GetFloodBurst()),
      m_fFloodRate(pNetwork->GetFloodRate()), m_bFloodProtection(IsFloodProtected(pNetwork->GetFloodRate()))
{
    NoSocketPrivate::get(this)->allowControlCodes = true;
    EnableReadLine();
    m_Nick.setIdent(m_pNetwork->GetIdent());
    m_Nick.setHost(m_pNetwork->GetBindHost());
    SetEncoding(m_pNetwork->GetEncoding());

    m_mueChanModes['b'] = ListArg;
    m_mueChanModes['e'] = ListArg;
    m_mueChanModes['I'] = ListArg;
    m_mueChanModes['k'] = HasArg;
    m_mueChanModes['l'] = ArgWhenSet;
    m_mueChanModes['p'] = NoArg;
    m_mueChanModes['s'] = NoArg;
    m_mueChanModes['t'] = NoArg;
    m_mueChanModes['i'] = NoArg;
    m_mueChanModes['n'] = NoArg;

    pNetwork->SetIRCSocket(this);

    // RFC says a line can have 512 chars max, but we don't care ;)
    SetMaxBufferThreshold(1024);
    if (m_bFloodProtection) {
        AddCron(new NoIrcFloodTimer(this));
    }
}

NoIrcConnection::~NoIrcConnection()
{
    if (!m_bAuthed) {
        IRCSOCKMODULECALL(OnIRCConnectionError(this), NOTHING);
    }

    const std::vector<NoChannel*>& vChans = m_pNetwork->GetChans();
    for (NoChannel* pChan : vChans) {
        pChan->reset();
    }

    m_pNetwork->IRCDisconnected();

    for (const auto& it : m_msChans) {
        delete it.second;
    }

    Quit();
    m_msChans.clear();
    m_pNetwork->GetUser()->AddBytesRead(GetBytesRead());
    m_pNetwork->GetUser()->AddBytesWritten(GetBytesWritten());
}

void NoIrcConnection::Quit(const NoString& sQuitMsg)
{
    if (!m_bAuthed) {
        Close(CLT_NOW);
        return;
    }
    if (!sQuitMsg.empty()) {
        PutIRC("QUIT :" + sQuitMsg);
    } else {
        PutIRC("QUIT :" + m_pNetwork->ExpandString(m_pNetwork->GetQuitMsg()));
    }
    Close(CLT_AFTERWRITE);
}

void NoIrcConnection::ReadLineImpl(const NoString& sData)
{
    NoString sLine = sData;

    sLine.trimRight("\n\r");

    NO_DEBUG("(" << m_pNetwork->GetUser()->GetUserName() << "/" << m_pNetwork->GetName() << ") IRC -> ZNC [" << sLine << "]");

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
        m_pNetwork->PutStatus("Error from Server [" + sError + "]");
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
            if (m_bAuthed && sServer == "irc.znc.in") {
                // m_bAuthed == true => we already received another 001 => we might be in a traffic loop
                m_pNetwork->PutStatus("ZNC seems to be connected to itself, disconnecting...");
                Quit();
                return;
            }

            m_pNetwork->SetIRCServer(sServer);
            SetTimeout(NoNetwork::NO_TRAFFIC_TIMEOUT,
                       TMO_READ); // Now that we are connected, let nature take its course
            PutIRC("WHO " + sNick);

            m_bAuthed = true;
            m_pNetwork->PutStatus("Connected!");

            const std::vector<NoClient*>& vClients = m_pNetwork->GetClients();

            for (NoClient* pClient : vClients) {
                NoString sClientNick = pClient->GetNick(false);

                if (!sClientNick.equals(sNick)) {
                    // If they connected with a nick that doesn't match the one we got on irc, then we need to update
                    // them
                    pClient->PutClient(":" + sClientNick + "!" + m_Nick.ident() + "@" + m_Nick.host() +
                                       " NICK :" + sNick);
                }
            }

            SetNick(sNick);

            IRCSOCKMODULECALL(OnIRCConnected(), NOTHING);

            m_pNetwork->ClearRawBuffer();
            m_pNetwork->AddRawBuffer(":" + _NAMEDFMT(sServer) + " " + sCmd + " {target} " + _NAMEDFMT(sRest));

            m_pNetwork->IRCConnected();

            break;
        }
        case 5:
            ParseISupport(sRest);
            m_pNetwork->UpdateExactRawBuffer(":" + _NAMEDFMT(sServer) + " " + sCmd + " {target} " + _NAMEDFMT(sRest));
            break;
        case 10: { // :irc.server.com 010 nick <hostname> <port> :<info>
            NoString sHost = No::token(sRest, 0);
            NoString sPort = No::token(sRest, 1);
            NoString sInfo = No::tokens(sRest, 2).trimPrefix_n();
            m_pNetwork->PutStatus("Server [" + m_pNetwork->GetCurrentServer()->GetString(false) +
                                  "] redirects us to [" + sHost + ":" + sPort + "] with reason [" + sInfo + "]");
            m_pNetwork->PutStatus("Perhaps you want to add it as a new server.");
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
            m_pNetwork->UpdateRawBuffer(sTmp, sTmp + " {target} " + _NAMEDFMT(sRest));
            break;
        case 305:
            m_pNetwork->SetIRCAway(false);
            break;
        case 306:
            m_pNetwork->SetIRCAway(true);
            break;
        case 324: { // MODE
            sRest.trim();
            NoChannel* pChan = m_pNetwork->FindChan(No::token(sRest, 0));

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
            NoChannel* pChan = m_pNetwork->FindChan(No::token(sRest, 0));

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
            NoChannel* pChan = m_pNetwork->FindChan(No::token(sLine, 3));

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
            NoChannel* pChan = m_pNetwork->FindChan(No::token(sLine, 3));

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
            NoChannel* pChan = m_pNetwork->FindChan(No::token(sLine, 3));

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
                m_Nick.setIdent(sIdent);
                m_Nick.setHost(sHost);
            }

            m_pNetwork->SetIRCNick(m_Nick);
            m_pNetwork->SetIRCServer(sServer);

            const std::vector<NoChannel*>& vChans = m_pNetwork->GetChans();

            for (NoChannel* pChan : vChans) {
                pChan->onWho(sNick, sIdent, sHost);
            }

            if (m_bNamesx && (sNick.size() > 1) && IsPermChar(sNick[1])) {
                // sLine uses multi-prefix

                const std::vector<NoClient*>& vClients = m_pNetwork->GetClients();
                for (NoClient* pClient : vClients) {
                    if (pClient->HasNamesx()) {
                        m_pNetwork->PutUser(sLine, pClient);
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
                        m_pNetwork->PutUser(sNewLine, pClient);
                    }
                }

                return;
            }

            NoChannel* pChan = m_pNetwork->FindChan(sChan);
            if (pChan && pChan->isDetached()) {
                return;
            }

            break;
        }
        case 353: { // NAMES
            sRest.trim();
            // Todo: allow for non @+= server msgs
            NoChannel* pChan = m_pNetwork->FindChan(No::token(sRest, 1));
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
            NoChannel* pChan = m_pNetwork->FindChan(No::token(sRest, 0));

            if (pChan) {
                if (pChan->isOn()) {
                    // If we are the only one in the chan, set our default modes
                    if (pChan->getNickCount() == 1) {
                        NoString sModes = pChan->getDefaultModes();

                        if (sModes.empty()) {
                            sModes = m_pNetwork->GetUser()->GetDefaultChanModes();
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
            if (m_pNetwork->GetIRCServer().equals(sServer)) {
                m_pNetwork->ClearMotdBuffer();
            }
        case 372: // motd
        case 376: // end motd
            if (m_pNetwork->GetIRCServer().equals(sServer)) {
                m_pNetwork->AddMotdBuffer(":" + _NAMEDFMT(sServer) + " " + sCmd + " {target} " + _NAMEDFMT(sRest));
            }
            break;
        case 437:
            // :irc.server.net 437 * badnick :Nick/channel is temporarily unavailable
            // :irc.server.net 437 mynick badnick :Nick/channel is temporarily unavailable
            // :irc.server.net 437 mynick badnick :Cannot change nickname while banned on channel
            if (m_pNetwork->IsChan(No::token(sRest, 0)) || sNick != "*") break;
        case 432: // :irc.server.com 432 * nick :Erroneous Nickname: Illegal characters
        case 433: {
            NoString sBadNick = No::token(sRest, 0);

            if (!m_bAuthed) {
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
            NoChannel* pChan = m_pNetwork->FindChan(No::token(sRest, 0));
            if (!pChan) {
                // unreal style numeric
                pChan = m_pNetwork->FindChan(No::token(sRest, 1));
            }
            if (pChan) {
                pChan->disable();
                m_pNetwork->PutStatus("Channel [" + pChan->getName() + "] is linked to "
                                                                       "another channel and was thus disabled.");
            }
            break;
        }
        case 670:
            // :hydra.sector5d.org 670 kylef :STARTTLS successful, go ahead with TLS handshake
            // 670 is a response to `STARTTLS` telling the client to switch to TLS

            if (!GetSSL()) {
                StartTLS();
                m_pNetwork->PutStatus("Switched to SSL (STARTTLS)");
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
            const std::vector<NoChannel*>& vChans = m_pNetwork->GetChans();

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
                m_pNetwork->PutUser(sLine);
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
                m_pNetwork->PutStatus("You quit [" + sMessage + "]");
                // We don't call module hooks and we don't
                // forward this quit to clients (Some clients
                // disconnect if they receive such a QUIT)
                return;
            }

            std::vector<NoChannel*> vFoundChans;
            const std::vector<NoChannel*>& vChans = m_pNetwork->GetChans();

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
                m_pNetwork->AddChan(sChan, false);
                pChan = m_pNetwork->FindChan(sChan);
                if (pChan) {
                    pChan->enable();
                    pChan->setIsOn(true);
                    PutIRC("MODE " + sChan);
                }
            } else {
                pChan = m_pNetwork->FindChan(sChan);
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

            NoChannel* pChan = m_pNetwork->FindChan(sChan);
            bool bDetached = false;
            if (pChan) {
                pChan->remNick(Nick.nick());
                IRCSOCKMODULECALL(OnPart(Nick.nickMask(), *pChan, sMsg), NOTHING);

                if (pChan->isDetached()) bDetached = true;
            }

            if (Nick.equals(GetNick())) {
                m_pNetwork->DelChan(sChan);
            }

            /*
             * We use this boolean because
             * m_pNetwork->DelChan() will delete this channel
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

            NoChannel* pChan = m_pNetwork->FindChan(sTarget);
            if (pChan) {
                pChan->modeChange(sModes, &Nick);

                if (pChan->isDetached()) {
                    return;
                }
            } else if (sTarget == m_Nick.nick()) {
                NoString sModeArg = No::token(sModes, 0);
                bool bAdd = true;
                /* no module call defined (yet?)
                                MODULECALL(OnRawUserMode(*pOpNick, *this, sModeArg, sArgs), m_pNetwork->GetUser(),
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
                            m_scUserModes.insert(uMode);
                        } else {
                            m_scUserModes.erase(uMode);
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

            NoChannel* pChan = m_pNetwork->FindChan(sChan);

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

                m_pNetwork->PutUser(":" + Nick.nickMask() + " NOTICE " + sTarget + " :\001" + sMsg + "\001");
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

            if (Nick.equals(m_pNetwork->GetIRCServer())) {
                m_pNetwork->PutUser(":" + Nick.nick() + " NOTICE " + sTarget + " :" + sMsg);
            } else {
                m_pNetwork->PutUser(":" + Nick.nickMask() + " NOTICE " + sTarget + " :" + sMsg);
            }

            return;
        } else if (sCmd.equals("TOPIC")) {
            // :nick!ident@host.com TOPIC #chan :This is a topic
            NoChannel* pChan = m_pNetwork->FindChan(No::token(sLine, 2));

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

                m_pNetwork->PutUser(":" + Nick.nickMask() + " PRIVMSG " + sTarget + " :\001" + sMsg + "\001");
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

                m_pNetwork->PutUser(":" + Nick.nickMask() + " PRIVMSG " + sTarget + " :" + sMsg);
                return;
            }
        } else if (sCmd.equals("WALLOPS")) {
            // :blub!dummy@rox-8DBEFE92 WALLOPS :this is a test
            NoString sMsg = No::tokens(sRest, 0).trimPrefix_n();

            if (!m_pNetwork->IsUserOnline()) {
                m_pNetwork->AddNoticeBuffer(":" + _NAMEDFMT(Nick.nickMask()) + " WALLOPS :{text}", sMsg);
            }
        } else if (sCmd.equals("CAP")) {
            // CAPs are supported only before authorization.
            if (!m_bAuthed) {
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
                            m_ssPendingCaps.insert(sCap);
                        }
                    }
                } else if (sSubCmd == "ACK") {
                    sArgs.trim();
                    IRCSOCKMODULECALL(OnServerCapResult(sArgs, true), NOTHING);
                    if ("multi-prefix" == sArgs) {
                        m_bNamesx = true;
                    } else if ("userhost-in-names" == sArgs) {
                        m_bUHNames = true;
                    }
                    m_ssAcceptedCaps.insert(sArgs);
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

    m_pNetwork->PutUser(sLine);
}

void NoIrcConnection::SendNextCap()
{
    if (!m_uCapPaused) {
        if (m_ssPendingCaps.empty()) {
            // We already got all needed ACK/NAK replies.
            PutIRC("CAP END");
        } else {
            NoString sCap = *m_ssPendingCaps.begin();
            m_ssPendingCaps.erase(m_ssPendingCaps.begin());
            PutIRC("CAP REQ :" + sCap);
        }
    }
}

void NoIrcConnection::PauseCap() { ++m_uCapPaused; }

void NoIrcConnection::ResumeCap()
{
    --m_uCapPaused;
    SendNextCap();
}

void NoIrcConnection::SetPass(const NoString& s) { m_sPass = s; }

uint NoIrcConnection::GetMaxNickLen() const { return m_uMaxNickLen; }

bool NoIrcConnection::OnServerCapAvailable(const NoString& sCap)
{
    bool bResult = false;
    IRCSOCKMODULECALL(OnServerCapAvailable(sCap), &bResult);
    return bResult;
}

bool NoIrcConnection::OnCTCPReply(NoNick& Nick, NoString& sMessage)
{
    bool bResult = false;
    IRCSOCKMODULECALL(OnCTCPReply(Nick, sMessage), &bResult);

    return bResult;
}

bool NoIrcConnection::OnPrivCTCP(NoNick& Nick, NoString& sMessage)
{
    bool bResult = false;
    IRCSOCKMODULECALL(OnPrivCTCP(Nick, sMessage), &bResult);
    if (bResult) return true;

    if (sMessage.trimPrefix("ACTION ")) {
        bResult = false;
        IRCSOCKMODULECALL(OnPrivAction(Nick, sMessage), &bResult);
        if (bResult) return true;

        if (!m_pNetwork->IsUserOnline() || !m_pNetwork->GetUser()->AutoClearQueryBuffer()) {
            NoQuery* pQuery = m_pNetwork->AddQuery(Nick.nick());
            if (pQuery) {
                pQuery->addBuffer(":" + _NAMEDFMT(Nick.nickMask()) + " PRIVMSG {target} :\001ACTION {text}\001", sMessage);
            }
        }

        sMessage = "ACTION " + sMessage;
    }

    // This handles everything which wasn't handled yet
    return OnGeneralCTCP(Nick, sMessage);
}

bool NoIrcConnection::OnGeneralCTCP(NoNick& Nick, NoString& sMessage)
{
    const NoStringMap& mssCTCPReplies = m_pNetwork->GetUser()->GetCTCPReplies();
    NoString sQuery = No::token(sMessage, 0).toUpper();
    NoStringMap::const_iterator it = mssCTCPReplies.find(sQuery);
    bool bHaveReply = false;
    NoString sReply;

    if (it != mssCTCPReplies.end()) {
        sReply = m_pNetwork->ExpandString(it->second);
        bHaveReply = true;

        if (sReply.empty()) {
            return true;
        }
    }

    if (!bHaveReply && !m_pNetwork->IsUserAttached()) {
        if (sQuery == "VERSION") {
            sReply = NoApp::GetTag(false);
        } else if (sQuery == "PING") {
            sReply = No::tokens(sMessage, 1);
        }
    }

    if (!sReply.empty()) {
        time_t now = time(nullptr);
        // If the last CTCP is older than m_uCTCPFloodTime, reset the counter
        if (m_lastCTCP + m_uCTCPFloodTime < now) m_uNumCTCP = 0;
        m_lastCTCP = now;
        // If we are over the limit, don't reply to this CTCP
        if (m_uNumCTCP >= m_uCTCPFloodCount) {
            NO_DEBUG("CTCP flood detected - not replying to query");
            return true;
        }
        m_uNumCTCP++;

        PutIRC("NOTICE " + Nick.nick() + " :\001" + sQuery + " " + sReply + "\001");
        return true;
    }

    return false;
}

bool NoIrcConnection::OnPrivNotice(NoNick& Nick, NoString& sMessage)
{
    bool bResult = false;
    IRCSOCKMODULECALL(OnPrivNotice(Nick, sMessage), &bResult);
    if (bResult) return true;

    if (!m_pNetwork->IsUserOnline()) {
        // If the user is detached, add to the buffer
        m_pNetwork->AddNoticeBuffer(":" + _NAMEDFMT(Nick.nickMask()) + " NOTICE {target} :{text}", sMessage);
    }

    return false;
}

bool NoIrcConnection::OnPrivMsg(NoNick& Nick, NoString& sMessage)
{
    bool bResult = false;
    IRCSOCKMODULECALL(OnPrivMsg(Nick, sMessage), &bResult);
    if (bResult) return true;

    if (!m_pNetwork->IsUserOnline() || !m_pNetwork->GetUser()->AutoClearQueryBuffer()) {
        NoQuery* pQuery = m_pNetwork->AddQuery(Nick.nick());
        if (pQuery) {
            pQuery->addBuffer(":" + _NAMEDFMT(Nick.nickMask()) + " PRIVMSG {target} :{text}", sMessage);
        }
    }

    return false;
}

bool NoIrcConnection::OnChanCTCP(NoNick& Nick, const NoString& sChan, NoString& sMessage)
{
    NoChannel* pChan = m_pNetwork->FindChan(sChan);
    if (pChan) {
        bool bResult = false;
        IRCSOCKMODULECALL(OnChanCTCP(Nick, *pChan, sMessage), &bResult);
        if (bResult) return true;

        // Record a /me
        if (sMessage.trimPrefix("ACTION ")) {
            bResult = false;
            IRCSOCKMODULECALL(OnChanAction(Nick, *pChan, sMessage), &bResult);
            if (bResult) return true;
            if (!pChan->autoClearChanBuffer() || !m_pNetwork->IsUserOnline() || pChan->isDetached()) {
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

bool NoIrcConnection::OnChanNotice(NoNick& Nick, const NoString& sChan, NoString& sMessage)
{
    NoChannel* pChan = m_pNetwork->FindChan(sChan);
    if (pChan) {
        bool bResult = false;
        IRCSOCKMODULECALL(OnChanNotice(Nick, *pChan, sMessage), &bResult);
        if (bResult) return true;

        if (!pChan->autoClearChanBuffer() || !m_pNetwork->IsUserOnline() || pChan->isDetached()) {
            pChan->addBuffer(":" + _NAMEDFMT(Nick.nickMask()) + " NOTICE " + _NAMEDFMT(sChan) + " :{text}", sMessage);
        }
    }

    return ((pChan) && (pChan->isDetached()));
}

bool NoIrcConnection::OnChanMsg(NoNick& Nick, const NoString& sChan, NoString& sMessage)
{
    NoChannel* pChan = m_pNetwork->FindChan(sChan);
    if (pChan) {
        bool bResult = false;
        IRCSOCKMODULECALL(OnChanMsg(Nick, *pChan, sMessage), &bResult);
        if (bResult) return true;

        if (!pChan->autoClearChanBuffer() || !m_pNetwork->IsUserOnline() || pChan->isDetached()) {
            pChan->addBuffer(":" + _NAMEDFMT(Nick.nickMask()) + " PRIVMSG " + _NAMEDFMT(sChan) + " :{text}", sMessage);
        }
    }

    return ((pChan) && (pChan->isDetached()));
}

void NoIrcConnection::PutIRC(const NoString& sLine)
{
    // Only print if the line won't get sent immediately (same condition as in TrySend()!)
    if (m_bFloodProtection && m_iSendsAllowed <= 0) {
        NO_DEBUG("(" << m_pNetwork->GetUser()->GetUserName() << "/" << m_pNetwork->GetName() << ") ZNC -> IRC [" << sLine << "] (queued)");
    }
    m_vsSendQueue.push_back(sLine);
    TrySend();
}

void NoIrcConnection::PutIRCQuick(const NoString& sLine)
{
    // Only print if the line won't get sent immediately (same condition as in TrySend()!)
    if (m_bFloodProtection && m_iSendsAllowed <= 0) {
        NO_DEBUG("(" << m_pNetwork->GetUser()->GetUserName() << "/" << m_pNetwork->GetName() << ") ZNC -> IRC [" << sLine
                  << "] (queued to front)");
    }
    m_vsSendQueue.push_front(sLine);
    TrySend();
}

void NoIrcConnection::TrySend()
{
    // This condition must be the same as in PutIRC() and PutIRCQuick()!
    while (!m_vsSendQueue.empty() && (!m_bFloodProtection || m_iSendsAllowed > 0)) {
        m_iSendsAllowed--;
        bool bSkip = false;
        NoString& sLine = m_vsSendQueue.front();
        IRCSOCKMODULECALL(OnSendToIRC(sLine), &bSkip);
        if (!bSkip) {
            ;
            NO_DEBUG("(" << m_pNetwork->GetUser()->GetUserName() << "/" << m_pNetwork->GetName() << ") ZNC -> IRC [" << sLine << "]");
            Write(sLine + "\r\n");
        }
        m_vsSendQueue.pop_front();
    }
}

void NoIrcConnection::SetNick(const NoString& sNick)
{
    m_Nick.setNick(sNick);
    m_pNetwork->SetIRCNick(m_Nick);
}

void NoIrcConnection::ConnectedImpl()
{
    NO_DEBUG(GetSockName() << " == Connected()");

    NoString sPass = m_sPass;
    NoString sNick = m_pNetwork->GetNick();
    NoString sIdent = m_pNetwork->GetIdent();
    NoString sRealName = m_pNetwork->GetRealName();

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
    m_Nick.setNick(sNick);
}

void NoIrcConnection::DisconnectedImpl()
{
    IRCSOCKMODULECALL(OnIRCDisconnected(), NOTHING);

    NO_DEBUG(GetSockName() << " == Disconnected()");
    if (!m_pNetwork->GetUser()->IsBeingDeleted() && m_pNetwork->GetIRCConnectEnabled() && m_pNetwork->GetServers().size() != 0) {
        m_pNetwork->PutStatus("Disconnected from IRC. Reconnecting...");
    }
    m_pNetwork->ClearRawBuffer();
    m_pNetwork->ClearMotdBuffer();

    ResetChans();

    // send a "reset user modes" cmd to the client.
    // otherwise, on reconnect, it might think it still
    // had user modes that it actually doesn't have.
    NoString sUserMode;
    for (uchar cMode : m_scUserModes) {
        sUserMode += cMode;
    }
    if (!sUserMode.empty()) {
        m_pNetwork->PutUser(":" + m_pNetwork->GetIRCNick().nickMask() + " MODE " +
                            m_pNetwork->GetIRCNick().nick() + " :-" + sUserMode);
    }

    // also clear the user modes in our space:
    m_scUserModes.clear();
}

void NoIrcConnection::SockErrorImpl(int iErrno, const NoString& sDescription)
{
    NoString sError = sDescription;

    NO_DEBUG(GetSockName() << " == SockError(" << iErrno << " " << sError << ")");
    if (!m_pNetwork->GetUser()->IsBeingDeleted()) {
        if (IsConOK()) {
            m_pNetwork->PutStatus("Cannot connect to IRC (" + sError + "). Retrying...");
        } else {
            m_pNetwork->PutStatus("Disconnected from IRC (" + sError + "). Reconnecting...");
        }
#ifdef HAVE_LIBSSL
        if (iErrno == errnoBadSSLCert) {
            // Stringify bad cert
            X509* pCert = GetX509();
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
                    m_pNetwork->PutStatus("|" + No::escape(s, No::DebugFormat));
                }
                NoString sSHA1;
                if (GetPeerFingerprint(sSHA1))
                    m_pNetwork->PutStatus("SHA1: " + No::escape(sSHA1, No::HexColonFormat, No::HexColonFormat));
                NoString sSHA256 = GetSSLPeerFingerprint();
                m_pNetwork->PutStatus("SHA-256: " + sSHA256);
                m_pNetwork->PutStatus("If you trust this certificate, do /znc AddTrustedServerFingerprint " + sSHA256);
            }
        }
#endif
    }
    m_pNetwork->ClearRawBuffer();
    m_pNetwork->ClearMotdBuffer();

    ResetChans();
    m_scUserModes.clear();
}

void NoIrcConnection::TimeoutImpl()
{
    NO_DEBUG(GetSockName() << " == Timeout()");
    if (!m_pNetwork->GetUser()->IsBeingDeleted()) {
        m_pNetwork->PutStatus("IRC connection timed out.  Reconnecting...");
    }
    m_pNetwork->ClearRawBuffer();
    m_pNetwork->ClearMotdBuffer();

    ResetChans();
    m_scUserModes.clear();
}

void NoIrcConnection::ConnectionRefusedImpl()
{
    NO_DEBUG(GetSockName() << " == ConnectionRefused()");
    if (!m_pNetwork->GetUser()->IsBeingDeleted()) {
        m_pNetwork->PutStatus("Connection Refused.  Reconnecting...");
    }
    m_pNetwork->ClearRawBuffer();
    m_pNetwork->ClearMotdBuffer();
}

void NoIrcConnection::ReachedMaxBufferImpl()
{
    NO_DEBUG(GetSockName() << " == ReachedMaxBuffer()");
    m_pNetwork->PutStatus("Received a too long line from the IRC server!");
    Quit();
}

void NoIrcConnection::ParseISupport(const NoString& sLine)
{
    NoStringVector vsTokens = sLine.split(" ", No::SkipEmptyParts);

    for (const NoString& sToken : vsTokens) {
        NoString sName = No::token(sToken, 0, "=");
        NoString sValue = No::tokens(sToken, 1, "=");

        if (0 < sName.length() && ':' == sName[0]) {
            break;
        }

        m_mISupport[sName] = sValue;

        if (sName.equals("PREFIX")) {
            NoString sPrefixes = No::token(sValue, 1, ")");
            NoString sPermModes = No::token(sValue, 0, ")");
            sPermModes.trimLeft("(");

            if (!sPrefixes.empty() && sPermModes.size() == sPrefixes.size()) {
                m_sPerms = sPrefixes;
                m_sPermModes = sPermModes;
            }
        } else if (sName.equals("CHANTYPES")) {
            m_pNetwork->SetChanPrefixes(sValue);
        } else if (sName.equals("NICKLEN")) {
            uint uMax = sValue.toUInt();

            if (uMax) {
                m_uMaxNickLen = uMax;
            }
        } else if (sName.equals("CHANMODES")) {
            if (!sValue.empty()) {
                m_mueChanModes.clear();

                for (uint a = 0; a < 4; a++) {
                    NoString sModes = No::token(sValue, a, ",");

                    for (uint b = 0; b < sModes.size(); b++) {
                        m_mueChanModes[sModes[b]] = (ChanModeArgs)a;
                    }
                }
            }
        } else if (sName.equals("NAMESX")) {
            if (m_bNamesx) continue;
            m_bNamesx = true;
            PutIRC("PROTOCTL NAMESX");
        } else if (sName.equals("UHNAMES")) {
            if (m_bUHNames) continue;
            m_bUHNames = true;
            PutIRC("PROTOCTL UHNAMES");
        }
    }
}

NoString NoIrcConnection::GetISupport(const NoString& sKey, const NoString& sDefault) const
{
    NoStringMap::const_iterator i = m_mISupport.find(sKey.toUpper());
    if (i == m_mISupport.end()) {
        return sDefault;
    } else {
        return i->second;
    }
}

void NoIrcConnection::ForwardRaw353(const NoString& sLine) const
{
    const std::vector<NoClient*>& vClients = m_pNetwork->GetClients();

    for (NoClient* pClient : vClients) {
        ForwardRaw353(sLine, pClient);
    }
}

void NoIrcConnection::ForwardRaw353(const NoString& sLine, NoClient* pClient) const
{
    NoString sNicks = No::tokens(sLine, 5).trimPrefix_n();

    if ((!m_bNamesx || pClient->HasNamesx()) && (!m_bUHNames || pClient->HasUHNames())) {
        // Client and server have both the same UHNames and Namesx stuff enabled
        m_pNetwork->PutUser(sLine, pClient);
    } else {
        // Get everything except the actual user list
        NoString sTmp = No::token(sLine, 0, " :") + " :";

        // This loop runs once for every nick on the channel
        NoStringVector vsNicks = sNicks.split(" ", No::SkipEmptyParts);
        for (NoString sNick : vsNicks) {
            if (sNick.empty()) break;

            if (m_bNamesx && !pClient->HasNamesx() && IsPermChar(sNick[0])) {
                // Server has, client doesn't have NAMESX, so we just use the first perm char
                size_t pos = sNick.find_first_not_of(GetPerms());
                if (pos >= 2 && pos != NoString::npos) {
                    sNick = sNick[0] + sNick.substr(pos);
                }
            }

            if (m_bUHNames && !pClient->HasUHNames()) {
                // Server has, client hasnt UHNAMES,
                // so we strip away ident and host.
                sNick = No::token(sNick, 0, "!");
            }

            sTmp += sNick + " ";
        }
        // Strip away the spaces we inserted at the end
        sTmp.trimRight(" ");
        m_pNetwork->PutUser(sTmp, pClient);
    }
}

void NoIrcConnection::SendAltNick(const NoString& sBadNick)
{
    const NoString& sLastNick = m_Nick.nick();

    // We don't know the maximum allowed nick length yet, but we know which
    // nick we sent last. If sBadNick is shorter than that, we assume the
    // server truncated our nick.
    if (sBadNick.length() < sLastNick.length()) m_uMaxNickLen = (uint)sBadNick.length();

    uint uMax = m_uMaxNickLen;

    const NoString& sConfNick = m_pNetwork->GetNick();
    const NoString& sAltNick = m_pNetwork->GetAltNick();
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
            m_pNetwork->PutUser("No free nick available");
            Quit();
            return;
        }

        cLetter = sBadNick.right(1)[0];

        if (cLetter == 'z') {
            m_pNetwork->PutUser("No free nick found");
            Quit();
            return;
        }

        sNewNick = sConfNick.left(uMax - 1) + ++cLetter;
        if (sNewNick.equals(sAltNick)) sNewNick = sConfNick.left(uMax - 1) + ++cLetter;
    }
    PutIRC("NICK " + sNewNick);
    m_Nick.setNick(sNewNick);
}

uchar NoIrcConnection::GetPermFromMode(uchar uMode) const
{
    if (m_sPermModes.size() == m_sPerms.size()) {
        for (uint a = 0; a < m_sPermModes.size(); a++) {
            if (m_sPermModes[a] == uMode) {
                return m_sPerms[a];
            }
        }
    }

    return 0;
}

const std::map<uchar, NoIrcConnection::ChanModeArgs>&NoIrcConnection::GetChanModes() const { return m_mueChanModes; }

bool NoIrcConnection::IsPermChar(const char c) const { return (c != '\0' && GetPerms().find(c) != NoString::npos); }

bool NoIrcConnection::IsPermMode(const char c) const { return (c != '\0' && GetPermModes().find(c) != NoString::npos); }

const NoString& NoIrcConnection::GetPerms() const { return m_sPerms; }

const NoString& NoIrcConnection::GetPermModes() const { return m_sPermModes; }

NoString NoIrcConnection::GetNickMask() const { return m_Nick.nickMask(); }

NoString NoIrcConnection::GetNick() const { return m_Nick.nick(); }

const NoString& NoIrcConnection::GetPass() const { return m_sPass; }

NoNetwork*NoIrcConnection::GetNetwork() const { return m_pNetwork; }

bool NoIrcConnection::HasNamesx() const { return m_bNamesx; }

bool NoIrcConnection::HasUHNames() const { return m_bUHNames; }

const std::set<uchar>&NoIrcConnection::GetUserModes() const { return m_scUserModes; }

bool NoIrcConnection::IsAuthed() const { return m_bAuthed; }

bool NoIrcConnection::IsCapAccepted(const NoString& sCap) { return 1 == m_ssAcceptedCaps.count(sCap); }

const NoStringMap&NoIrcConnection::GetISupport() const { return m_mISupport; }

NoIrcConnection::ChanModeArgs NoIrcConnection::GetModeType(uchar uMode) const
{
    std::map<uchar, ChanModeArgs>::const_iterator it = m_mueChanModes.find(uMode);

    if (it == m_mueChanModes.end()) {
        return NoArg;
    }

    return it->second;
}

void NoIrcConnection::ResetChans()
{
    for (const auto& it : m_msChans) {
        it.second->reset();
    }
}
