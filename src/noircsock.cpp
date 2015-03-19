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

#include "noircsock.h"
#include "nochannel.h"
#include "nouser.h"
#include "nonetwork.h"
#include "noserver.h"
#include "noquery.h"
#include "Csocket/Csocket.h"

#define IRCSOCKMODULECALL(macFUNC, macEXITER) \
    NETWORKMODULECALL(macFUNC, m_pNetwork->GetUser(), m_pNetwork, nullptr, macEXITER)
// These are used in OnGeneralCTCP()
const time_t NoIrcSock::m_uCTCPFloodTime = 5;
const uint NoIrcSock::m_uCTCPFloodCount = 5;

// It will be bad if user sets it to 0.00000000000001
// If you want no flood protection, set network's flood rate to -1
// TODO move this constant to NoNetwork?
static const double FLOOD_MINIMAL_RATE = 0.3;

class NoIrcFloodTimer : public CCron
{
    NoIrcSock* m_pSock;

public:
    NoIrcFloodTimer(NoIrcSock* pSock) : m_pSock(pSock) { StartMaxCycles(m_pSock->m_fFloodRate, 0); }
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

bool NoIrcSock::IsFloodProtected(double fRate) { return fRate > FLOOD_MINIMAL_RATE; }

NoIrcSock::NoIrcSock(NoNetwork* pNetwork)
    : NoIrcSocket(), m_bAuthed(false), m_bNamesx(false), m_bUHNames(false), m_sPerms("*!@%+"), m_sPermModes("qaohv"),
      m_scUserModes(), m_mueChanModes(), m_pNetwork(pNetwork), m_Nick(), m_sPass(""), m_msChans(), m_uMaxNickLen(9),
      m_uCapPaused(0), m_ssAcceptedCaps(), m_ssPendingCaps(), m_lastCTCP(0), m_uNumCTCP(0), m_mISupport(),
      m_vsSendQueue(), m_iSendsAllowed(pNetwork->GetFloodBurst()), m_uFloodBurst(pNetwork->GetFloodBurst()),
      m_fFloodRate(pNetwork->GetFloodRate()), m_bFloodProtection(IsFloodProtected(pNetwork->GetFloodRate()))
{
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

    pNetwork->SetIRNoSocket(this);

    // RFC says a line can have 512 chars max, but we don't care ;)
    SetMaxBufferThreshold(1024);
    if (m_bFloodProtection) {
        AddCron(new NoIrcFloodTimer(this));
    }
}

NoIrcSock::~NoIrcSock()
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

void NoIrcSock::Quit(const NoString& sQuitMsg)
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

void NoIrcSock::ReadLineImpl(const NoString& sData)
{
    NoString sLine = sData;

    sLine.TrimRight("\n\r");

    DEBUG("(" << m_pNetwork->GetUser()->GetUserName() << "/" << m_pNetwork->GetName() << ") IRC -> ZNC [" << sLine << "]");

    bool bReturn = false;
    IRCSOCKMODULECALL(OnRaw(sLine), &bReturn);
    if (bReturn) return;

    if (sLine.StartsWith("PING ")) {
        // Generate a reply and don't forward this to any user,
        // we don't want any PING forwarded
        PutIRCQuick("PONG " + sLine.substr(5));
        return;
    } else if (sLine.Token(1).Equals("PONG")) {
        // Block PONGs, we already responded to the pings
        return;
    } else if (sLine.StartsWith("ERROR ")) {
        // ERROR :Closing Link: nick[24.24.24.24] (Excess Flood)
        NoString sError(sLine.substr(6));
        sError.TrimPrefix();
        m_pNetwork->PutStatus("Error from Server [" + sError + "]");
        return;
    }

    NoString sCmd = sLine.Token(1);

    if ((sCmd.length() == 3) && (isdigit(sCmd[0])) && (isdigit(sCmd[1])) && (isdigit(sCmd[2]))) {
        NoString sServer = sLine.Token(0).LeftChomp_n(1);
        uint uRaw = sCmd.ToUInt();
        NoString sNick = sLine.Token(2);
        NoString sRest = sLine.Token(3, true);
        NoString sTmp;

        switch (uRaw) {
        case 1: { // :irc.server.com 001 nick :Welcome to the Internet Relay Network nick
            if (m_bAuthed && sServer == "irc.znc.in") {
                // m_bAuthed == true => we already received another 001 => we might be in a traffic loop
                m_pNetwork->PutStatus("ZNC seems to be connected to itself, disconnecting...");
                Quit();
                return;
            }

            m_pNetwork->SetIRNoServer(sServer);
            SetTimeout(NoNetwork::NO_TRAFFIC_TIMEOUT,
                       TMO_READ); // Now that we are connected, let nature take its course
            PutIRC("WHO " + sNick);

            m_bAuthed = true;
            m_pNetwork->PutStatus("Connected!");

            const std::vector<NoClient*>& vClients = m_pNetwork->GetClients();

            for (NoClient* pClient : vClients) {
                NoString sClientNick = pClient->GetNick(false);

                if (!sClientNick.Equals(sNick)) {
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
            NoString sHost = sRest.Token(0);
            NoString sPort = sRest.Token(1);
            NoString sInfo = sRest.Token(2, true).TrimPrefix_n();
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
            m_pNetwork->SetIRNoAway(false);
            break;
        case 306:
            m_pNetwork->SetIRNoAway(true);
            break;
        case 324: { // MODE
            sRest.Trim();
            NoChannel* pChan = m_pNetwork->FindChan(sRest.Token(0));

            if (pChan) {
                pChan->setModes(sRest.Token(1, true));

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
            sRest.Trim();
            NoChannel* pChan = m_pNetwork->FindChan(sRest.Token(0));

            if (pChan) {
                ulong ulDate = sLine.Token(4).ToULong();
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
            NoChannel* pChan = m_pNetwork->FindChan(sLine.Token(3));

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
            NoChannel* pChan = m_pNetwork->FindChan(sLine.Token(3));

            if (pChan) {
                NoString sTopic = sLine.Token(4, true);
                sTopic.LeftChomp(1);
                pChan->setTopic(sTopic);
                if (pChan->isDetached()) {
                    return;
                }
            }

            break;
        }
        case 333: {
            // :irc.server.com 333 yournick #chan setternick 1112320796
            NoChannel* pChan = m_pNetwork->FindChan(sLine.Token(3));

            if (pChan) {
                sNick = sLine.Token(4);
                ulong ulDate = sLine.Token(5).ToULong();

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
            sServer = sLine.Token(0);
            sNick = sLine.Token(7);
            NoString sChan = sLine.Token(3);
            NoString sIdent = sLine.Token(4);
            NoString sHost = sLine.Token(5);

            sServer.LeftChomp(1);

            if (sNick.Equals(GetNick())) {
                m_Nick.setIdent(sIdent);
                m_Nick.setHost(sHost);
            }

            m_pNetwork->SetIRNoNick(m_Nick);
            m_pNetwork->SetIRNoServer(sServer);

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
                        NoString sNewLine = sServer + " 352 " + sLine.Token(2) + " " + sChan + " " + sIdent + " " +
                                           sHost + " " + sLine.Token(6) + " " + sNewNick + " " + sLine.Token(8, true);
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
            sRest.Trim();
            // Todo: allow for non @+= server msgs
            NoChannel* pChan = m_pNetwork->FindChan(sRest.Token(1));
            // If we don't know that channel, some client might have
            // requested a /names for it and we really should forward this.
            if (pChan) {
                NoString sNicks = sRest.Token(2, true).TrimPrefix_n();
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
            NoChannel* pChan = m_pNetwork->FindChan(sRest.Token(0));

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
            if (m_pNetwork->GetIRNoServer().Equals(sServer)) {
                m_pNetwork->ClearMotdBuffer();
            }
        case 372: // motd
        case 376: // end motd
            if (m_pNetwork->GetIRNoServer().Equals(sServer)) {
                m_pNetwork->AddMotdBuffer(":" + _NAMEDFMT(sServer) + " " + sCmd + " {target} " + _NAMEDFMT(sRest));
            }
            break;
        case 437:
            // :irc.server.net 437 * badnick :Nick/channel is temporarily unavailable
            // :irc.server.net 437 mynick badnick :Nick/channel is temporarily unavailable
            // :irc.server.net 437 mynick badnick :Cannot change nickname while banned on channel
            if (m_pNetwork->IsChan(sRest.Token(0)) || sNick != "*") break;
        case 432: // :irc.server.com 432 * nick :Erroneous Nickname: Illegal characters
        case 433: {
            NoString sBadNick = sRest.Token(0);

            if (!m_bAuthed) {
                SendAltNick(sBadNick);
                return;
            }
            break;
        }
        case 451:
            // :irc.server.com 451 CAP :You have not registered
            // Servers that dont support CAP will give us this error, dont send it to the client
            if (sNick.Equals("CAP")) return;
        case 470: {
            // :irc.unreal.net 470 mynick [Link] #chan1 has become full, so you are automatically being transferred to
            // the linked channel #chan2
            // :mccaffrey.freenode.net 470 mynick #electronics ##electronics :Forwarding to another channel

            // freenode style numeric
            NoChannel* pChan = m_pNetwork->FindChan(sRest.Token(0));
            if (!pChan) {
                // unreal style numeric
                pChan = m_pNetwork->FindChan(sRest.Token(1));
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
        NoNick Nick(sLine.Token(0).TrimPrefix_n());
        sCmd = sLine.Token(1);
        NoString sRest = sLine.Token(2, true);

        if (sCmd.Equals("NICK")) {
            NoString sNewNick = sRest.TrimPrefix_n();
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
        } else if (sCmd.Equals("QUIT")) {
            NoString sMessage = sRest.TrimPrefix_n();
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
        } else if (sCmd.Equals("JOIN")) {
            NoString sChan = sRest.Token(0).TrimPrefix_n();
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
        } else if (sCmd.Equals("PART")) {
            NoString sChan = sRest.Token(0).TrimPrefix_n();
            NoString sMsg = sRest.Token(1, true).TrimPrefix_n();

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
        } else if (sCmd.Equals("MODE")) {
            NoString sTarget = sRest.Token(0);
            NoString sModes = sRest.Token(1, true);
            if (sModes.Left(1) == ":") sModes = sModes.substr(1);

            NoChannel* pChan = m_pNetwork->FindChan(sTarget);
            if (pChan) {
                pChan->modeChange(sModes, &Nick);

                if (pChan->isDetached()) {
                    return;
                }
            } else if (sTarget == m_Nick.nick()) {
                NoString sModeArg = sModes.Token(0);
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
        } else if (sCmd.Equals("KICK")) {
            // :opnick!ident@host.com KICK #chan nick :msg
            NoString sChan = sRest.Token(0);
            NoString sKickedNick = sRest.Token(1);
            NoString sMsg = sRest.Token(2, true);
            sMsg.LeftChomp(1);

            NoChannel* pChan = m_pNetwork->FindChan(sChan);

            if (pChan) {
                IRCSOCKMODULECALL(OnKick(Nick, sKickedNick, *pChan, sMsg), NOTHING);
                // do not remove the nick till after the OnKick call, so modules
                // can do Chan.FindNick or something to get more info.
                pChan->remNick(sKickedNick);
            }

            if (GetNick().Equals(sKickedNick) && pChan) {
                pChan->setIsOn(false);

                // Don't try to rejoin!
                pChan->disable();
            }

            if ((pChan) && (pChan->isDetached())) {
                return;
            }
        } else if (sCmd.Equals("NOTICE")) {
            // :nick!ident@host.com NOTICE #chan :Message
            NoString sTarget = sRest.Token(0);
            NoString sMsg = sRest.Token(1, true);
            sMsg.LeftChomp(1);

            if (sMsg.WildCmp("\001*\001")) {
                sMsg.LeftChomp(1);
                sMsg.RightChomp(1);

                if (sTarget.Equals(GetNick())) {
                    if (OnCTCPReply(Nick, sMsg)) {
                        return;
                    }
                }

                m_pNetwork->PutUser(":" + Nick.nickMask() + " NOTICE " + sTarget + " :\001" + sMsg + "\001");
                return;
            } else {
                if (sTarget.Equals(GetNick())) {
                    if (OnPrivNotice(Nick, sMsg)) {
                        return;
                    }
                } else {
                    if (OnChanNotice(Nick, sTarget, sMsg)) {
                        return;
                    }
                }
            }

            if (Nick.equals(m_pNetwork->GetIRNoServer())) {
                m_pNetwork->PutUser(":" + Nick.nick() + " NOTICE " + sTarget + " :" + sMsg);
            } else {
                m_pNetwork->PutUser(":" + Nick.nickMask() + " NOTICE " + sTarget + " :" + sMsg);
            }

            return;
        } else if (sCmd.Equals("TOPIC")) {
            // :nick!ident@host.com TOPIC #chan :This is a topic
            NoChannel* pChan = m_pNetwork->FindChan(sLine.Token(2));

            if (pChan) {
                NoString sTopic = sLine.Token(3, true);
                sTopic.LeftChomp(1);

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
        } else if (sCmd.Equals("PRIVMSG")) {
            // :nick!ident@host.com PRIVMSG #chan :Message
            NoString sTarget = sRest.Token(0);
            NoString sMsg = sRest.Token(1, true).TrimPrefix_n();

            if (sMsg.WildCmp("\001*\001")) {
                sMsg.LeftChomp(1);
                sMsg.RightChomp(1);

                if (sTarget.Equals(GetNick())) {
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
                if (sTarget.Equals(GetNick())) {
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
        } else if (sCmd.Equals("WALLOPS")) {
            // :blub!dummy@rox-8DBEFE92 WALLOPS :this is a test
            NoString sMsg = sRest.Token(0, true).TrimPrefix_n();

            if (!m_pNetwork->IsUserOnline()) {
                m_pNetwork->AddNoticeBuffer(":" + _NAMEDFMT(Nick.nickMask()) + " WALLOPS :{text}", sMsg);
            }
        } else if (sCmd.Equals("CAP")) {
            // CAPs are supported only before authorization.
            if (!m_bAuthed) {
                // sRest.Token(0) is most likely "*". No idea why, the
                // CAP spec don't mention this, but all implementations
                // I've seen add this extra asterisk
                NoString sSubCmd = sRest.Token(1);

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
                if (sRest.Token(2) == "*") {
                    sArgs = sRest.Token(3, true).TrimPrefix_n();
                } else {
                    sArgs = sRest.Token(2, true).TrimPrefix_n();
                }

                if (sSubCmd == "LS") {
                    NoStringVector vsTokens = sArgs.Split(" ", false);

                    for (const NoString& sCap : vsTokens) {
                        if (OnServerCapAvailable(sCap) || sCap == "multi-prefix" || sCap == "userhost-in-names") {
                            m_ssPendingCaps.insert(sCap);
                        }
                    }
                } else if (sSubCmd == "ACK") {
                    sArgs.Trim();
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
                    sArgs.Trim();
                    IRCSOCKMODULECALL(OnServerCapResult(sArgs, false), NOTHING);
                }

                SendNextCap();
            }
            // Don't forward any CAP stuff to the client
            return;
        } else if (sCmd.Equals("INVITE")) {
            IRCSOCKMODULECALL(OnInvite(Nick, sLine.Token(3).TrimPrefix_n(":")), &bReturn);
            if (bReturn) return;
        }
    }

    m_pNetwork->PutUser(sLine);
}

void NoIrcSock::SendNextCap()
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

void NoIrcSock::PauseCap() { ++m_uCapPaused; }

void NoIrcSock::ResumeCap()
{
    --m_uCapPaused;
    SendNextCap();
}

bool NoIrcSock::OnServerCapAvailable(const NoString& sCap)
{
    bool bResult = false;
    IRCSOCKMODULECALL(OnServerCapAvailable(sCap), &bResult);
    return bResult;
}

bool NoIrcSock::OnCTCPReply(NoNick& Nick, NoString& sMessage)
{
    bool bResult = false;
    IRCSOCKMODULECALL(OnCTCPReply(Nick, sMessage), &bResult);

    return bResult;
}

bool NoIrcSock::OnPrivCTCP(NoNick& Nick, NoString& sMessage)
{
    bool bResult = false;
    IRCSOCKMODULECALL(OnPrivCTCP(Nick, sMessage), &bResult);
    if (bResult) return true;

    if (sMessage.TrimPrefix("ACTION ")) {
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

bool NoIrcSock::OnGeneralCTCP(NoNick& Nick, NoString& sMessage)
{
    const NoStringMap& mssCTCPReplies = m_pNetwork->GetUser()->GetCTCPReplies();
    NoString sQuery = sMessage.Token(0).AsUpper();
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
            sReply = sMessage.Token(1, true);
        }
    }

    if (!sReply.empty()) {
        time_t now = time(nullptr);
        // If the last CTCP is older than m_uCTCPFloodTime, reset the counter
        if (m_lastCTCP + m_uCTCPFloodTime < now) m_uNumCTCP = 0;
        m_lastCTCP = now;
        // If we are over the limit, don't reply to this CTCP
        if (m_uNumCTCP >= m_uCTCPFloodCount) {
            DEBUG("CTCP flood detected - not replying to query");
            return true;
        }
        m_uNumCTCP++;

        PutIRC("NOTICE " + Nick.nick() + " :\001" + sQuery + " " + sReply + "\001");
        return true;
    }

    return false;
}

bool NoIrcSock::OnPrivNotice(NoNick& Nick, NoString& sMessage)
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

bool NoIrcSock::OnPrivMsg(NoNick& Nick, NoString& sMessage)
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

bool NoIrcSock::OnChanCTCP(NoNick& Nick, const NoString& sChan, NoString& sMessage)
{
    NoChannel* pChan = m_pNetwork->FindChan(sChan);
    if (pChan) {
        bool bResult = false;
        IRCSOCKMODULECALL(OnChanCTCP(Nick, *pChan, sMessage), &bResult);
        if (bResult) return true;

        // Record a /me
        if (sMessage.TrimPrefix("ACTION ")) {
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

bool NoIrcSock::OnChanNotice(NoNick& Nick, const NoString& sChan, NoString& sMessage)
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

bool NoIrcSock::OnChanMsg(NoNick& Nick, const NoString& sChan, NoString& sMessage)
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

void NoIrcSock::PutIRC(const NoString& sLine)
{
    // Only print if the line won't get sent immediately (same condition as in TrySend()!)
    if (m_bFloodProtection && m_iSendsAllowed <= 0) {
        DEBUG("(" << m_pNetwork->GetUser()->GetUserName() << "/" << m_pNetwork->GetName() << ") ZNC -> IRC [" << sLine << "] (queued)");
    }
    m_vsSendQueue.push_back(sLine);
    TrySend();
}

void NoIrcSock::PutIRCQuick(const NoString& sLine)
{
    // Only print if the line won't get sent immediately (same condition as in TrySend()!)
    if (m_bFloodProtection && m_iSendsAllowed <= 0) {
        DEBUG("(" << m_pNetwork->GetUser()->GetUserName() << "/" << m_pNetwork->GetName() << ") ZNC -> IRC [" << sLine
                  << "] (queued to front)");
    }
    m_vsSendQueue.push_front(sLine);
    TrySend();
}

void NoIrcSock::TrySend()
{
    // This condition must be the same as in PutIRC() and PutIRCQuick()!
    while (!m_vsSendQueue.empty() && (!m_bFloodProtection || m_iSendsAllowed > 0)) {
        m_iSendsAllowed--;
        bool bSkip = false;
        NoString& sLine = m_vsSendQueue.front();
        IRCSOCKMODULECALL(OnSendToIRC(sLine), &bSkip);
        if (!bSkip) {
            ;
            DEBUG("(" << m_pNetwork->GetUser()->GetUserName() << "/" << m_pNetwork->GetName() << ") ZNC -> IRC [" << sLine << "]");
            Write(sLine + "\r\n");
        }
        m_vsSendQueue.pop_front();
    }
}

void NoIrcSock::SetNick(const NoString& sNick)
{
    m_Nick.setNick(sNick);
    m_pNetwork->SetIRNoNick(m_Nick);
}

void NoIrcSock::ConnectedImpl()
{
    DEBUG(GetSockName() << " == Connected()");

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

void NoIrcSock::DisconnectedImpl()
{
    IRCSOCKMODULECALL(OnIRCDisconnected(), NOTHING);

    DEBUG(GetSockName() << " == Disconnected()");
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
        m_pNetwork->PutUser(":" + m_pNetwork->GetIRNoNick().nickMask() + " MODE " +
                            m_pNetwork->GetIRNoNick().nick() + " :-" + sUserMode);
    }

    // also clear the user modes in our space:
    m_scUserModes.clear();
}

void NoIrcSock::SockErrorImpl(int iErrno, const NoString& sDescription)
{
    NoString sError = sDescription;

    DEBUG(GetSockName() << " == SockError(" << iErrno << " " << sError << ")");
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

                NoStringVector vsCert = sCert.Split("\n");
                for (const NoString& s : vsCert) {
                    // It shouldn't contain any bad characters, but let's be safe...
                    m_pNetwork->PutStatus("|" + s.Escape_n(NoString::EDEBUG));
                }
                NoString sSHA1;
                if (GetPeerFingerprint(sSHA1))
                    m_pNetwork->PutStatus("SHA1: " + sSHA1.Escape_n(NoString::EHEXCOLON, NoString::EHEXCOLON));
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

void NoIrcSock::TimeoutImpl()
{
    DEBUG(GetSockName() << " == Timeout()");
    if (!m_pNetwork->GetUser()->IsBeingDeleted()) {
        m_pNetwork->PutStatus("IRC connection timed out.  Reconnecting...");
    }
    m_pNetwork->ClearRawBuffer();
    m_pNetwork->ClearMotdBuffer();

    ResetChans();
    m_scUserModes.clear();
}

void NoIrcSock::ConnectionRefusedImpl()
{
    DEBUG(GetSockName() << " == ConnectionRefused()");
    if (!m_pNetwork->GetUser()->IsBeingDeleted()) {
        m_pNetwork->PutStatus("Connection Refused.  Reconnecting...");
    }
    m_pNetwork->ClearRawBuffer();
    m_pNetwork->ClearMotdBuffer();
}

void NoIrcSock::ReachedMaxBufferImpl()
{
    DEBUG(GetSockName() << " == ReachedMaxBuffer()");
    m_pNetwork->PutStatus("Received a too long line from the IRC server!");
    Quit();
}

void NoIrcSock::ParseISupport(const NoString& sLine)
{
    NoStringVector vsTokens = sLine.Split(" ", false);

    for (const NoString& sToken : vsTokens) {
        NoString sName = sToken.Token(0, false, "=");
        NoString sValue = sToken.Token(1, true, "=");

        if (0 < sName.length() && ':' == sName[0]) {
            break;
        }

        m_mISupport[sName] = sValue;

        if (sName.Equals("PREFIX")) {
            NoString sPrefixes = sValue.Token(1, false, ")");
            NoString sPermModes = sValue.Token(0, false, ")");
            sPermModes.TrimLeft("(");

            if (!sPrefixes.empty() && sPermModes.size() == sPrefixes.size()) {
                m_sPerms = sPrefixes;
                m_sPermModes = sPermModes;
            }
        } else if (sName.Equals("CHANTYPES")) {
            m_pNetwork->SetChanPrefixes(sValue);
        } else if (sName.Equals("NICKLEN")) {
            uint uMax = sValue.ToUInt();

            if (uMax) {
                m_uMaxNickLen = uMax;
            }
        } else if (sName.Equals("CHANMODES")) {
            if (!sValue.empty()) {
                m_mueChanModes.clear();

                for (uint a = 0; a < 4; a++) {
                    NoString sModes = sValue.Token(a, false, ",");

                    for (uint b = 0; b < sModes.size(); b++) {
                        m_mueChanModes[sModes[b]] = (EChanModeArgs)a;
                    }
                }
            }
        } else if (sName.Equals("NAMESX")) {
            if (m_bNamesx) continue;
            m_bNamesx = true;
            PutIRC("PROTOCTL NAMESX");
        } else if (sName.Equals("UHNAMES")) {
            if (m_bUHNames) continue;
            m_bUHNames = true;
            PutIRC("PROTOCTL UHNAMES");
        }
    }
}

NoString NoIrcSock::GetISupport(const NoString& sKey, const NoString& sDefault) const
{
    NoStringMap::const_iterator i = m_mISupport.find(sKey.AsUpper());
    if (i == m_mISupport.end()) {
        return sDefault;
    } else {
        return i->second;
    }
}

void NoIrcSock::ForwardRaw353(const NoString& sLine) const
{
    const std::vector<NoClient*>& vClients = m_pNetwork->GetClients();

    for (NoClient* pClient : vClients) {
        ForwardRaw353(sLine, pClient);
    }
}

void NoIrcSock::ForwardRaw353(const NoString& sLine, NoClient* pClient) const
{
    NoString sNicks = sLine.Token(5, true).TrimPrefix_n();

    if ((!m_bNamesx || pClient->HasNamesx()) && (!m_bUHNames || pClient->HasUHNames())) {
        // Client and server have both the same UHNames and Namesx stuff enabled
        m_pNetwork->PutUser(sLine, pClient);
    } else {
        // Get everything except the actual user list
        NoString sTmp = sLine.Token(0, false, " :") + " :";

        // This loop runs once for every nick on the channel
        NoStringVector vsNicks = sNicks.Split(" ", false);
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
                sNick = sNick.Token(0, false, "!");
            }

            sTmp += sNick + " ";
        }
        // Strip away the spaces we inserted at the end
        sTmp.TrimRight(" ");
        m_pNetwork->PutUser(sTmp, pClient);
    }
}

void NoIrcSock::SendAltNick(const NoString& sBadNick)
{
    const NoString& sLastNick = m_Nick.nick();

    // We don't know the maximum allowed nick length yet, but we know which
    // nick we sent last. If sBadNick is shorter than that, we assume the
    // server truncated our nick.
    if (sBadNick.length() < sLastNick.length()) m_uMaxNickLen = (uint)sBadNick.length();

    uint uMax = m_uMaxNickLen;

    const NoString& sConfNick = m_pNetwork->GetNick();
    const NoString& sAltNick = m_pNetwork->GetAltNick();
    NoString sNewNick = sConfNick.Left(uMax - 1);

    if (sLastNick.Equals(sConfNick)) {
        if ((!sAltNick.empty()) && (!sConfNick.Equals(sAltNick))) {
            sNewNick = sAltNick;
        } else {
            sNewNick += "-";
        }
    } else if (sLastNick.Equals(sAltNick) && !sAltNick.Equals(sNewNick + "-")) {
        sNewNick += "-";
    } else if (sLastNick.Equals(sNewNick + "-") && !sAltNick.Equals(sNewNick + "|")) {
        sNewNick += "|";
    } else if (sLastNick.Equals(sNewNick + "|") && !sAltNick.Equals(sNewNick + "^")) {
        sNewNick += "^";
    } else if (sLastNick.Equals(sNewNick + "^") && !sAltNick.Equals(sNewNick + "a")) {
        sNewNick += "a";
    } else {
        char cLetter = 0;
        if (sBadNick.empty()) {
            m_pNetwork->PutUser("No free nick available");
            Quit();
            return;
        }

        cLetter = sBadNick.Right(1)[0];

        if (cLetter == 'z') {
            m_pNetwork->PutUser("No free nick found");
            Quit();
            return;
        }

        sNewNick = sConfNick.Left(uMax - 1) + ++cLetter;
        if (sNewNick.Equals(sAltNick)) sNewNick = sConfNick.Left(uMax - 1) + ++cLetter;
    }
    PutIRC("NICK " + sNewNick);
    m_Nick.setNick(sNewNick);
}

uchar NoIrcSock::GetPermFromMode(uchar uMode) const
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

NoIrcSock::EChanModeArgs NoIrcSock::GetModeType(uchar uMode) const
{
    std::map<uchar, EChanModeArgs>::const_iterator it = m_mueChanModes.find(uMode);

    if (it == m_mueChanModes.end()) {
        return NoArg;
    }

    return it->second;
}

void NoIrcSock::ResetChans()
{
    for (const auto& it : m_msChans) {
        it.second->reset();
    }
}
