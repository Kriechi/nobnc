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

#include "noclient.h"
#include "nochannel.h"
#include "noircsock.h"
#include "nouser.h"
#include "nonetwork.h"
#include "noquery.h"

#define CALLMOD(MOD, CLIENT, USER, NETWORK, FUNC)                             \
    {                                                                         \
        NoModule* pModule = nullptr;                                           \
        if (NETWORK && (pModule = (NETWORK)->GetModules().FindModule(MOD))) { \
            try {                                                             \
                pModule->SetClient(CLIENT);                                   \
                pModule->FUNC;                                                \
                pModule->SetClient(nullptr);                                  \
            } catch (const NoModule::EModException& e) {                       \
                if (e == NoModule::UNLOAD) {                                   \
                    (NETWORK)->GetModules().UnloadModule(MOD);                \
                }                                                             \
            }                                                                 \
        } else if ((pModule = (USER)->GetModules().FindModule(MOD))) {        \
            try {                                                             \
                pModule->SetClient(CLIENT);                                   \
                pModule->SetNetwork(NETWORK);                                 \
                pModule->FUNC;                                                \
                pModule->SetClient(nullptr);                                  \
                pModule->SetNetwork(nullptr);                                 \
            } catch (const NoModule::EModException& e) {                       \
                if (e == NoModule::UNLOAD) {                                   \
                    (USER)->GetModules().UnloadModule(MOD);                   \
                }                                                             \
            }                                                                 \
        } else if ((pModule = NoApp::Get().GetModules().FindModule(MOD))) {    \
            try {                                                             \
                pModule->SetClient(CLIENT);                                   \
                pModule->SetNetwork(NETWORK);                                 \
                pModule->SetUser(USER);                                       \
                pModule->FUNC;                                                \
                pModule->SetClient(nullptr);                                  \
                pModule->SetNetwork(nullptr);                                 \
                pModule->SetUser(nullptr);                                    \
            } catch (const NoModule::EModException& e) {                       \
                if (e == NoModule::UNLOAD) {                                   \
                    NoApp::Get().GetModules().UnloadModule(MOD);               \
                }                                                             \
            }                                                                 \
        } else {                                                              \
            PutStatus("No such module [" + MOD + "]");                        \
        }                                                                     \
    }

NoClient::~NoClient()
{
    if (m_spAuth) {
        NoClientAuth* pAuth = (NoClientAuth*)&(*m_spAuth);
        pAuth->Invalidate();
    }
    if (m_pUser != nullptr) {
        m_pUser->AddBytesRead(GetBytesRead());
        m_pUser->AddBytesWritten(GetBytesWritten());
    }
}

void NoClient::SendRequiredPasswordNotice()
{
    PutClient(":irc.znc.in 464 " + GetNick() + " :Password required");
    PutClient(":irc.znc.in NOTICE AUTH :*** "
              "You need to send your password. "
              "Configure your client to send a server password.");
    PutClient(":irc.znc.in NOTICE AUTH :*** "
              "To connect now, you can use /quote PASS <username>:<password>, "
              "or /quote PASS <username>/<network>:<password> to connect to a specific network.");
}

void NoClient::ReadLine(const NoString& sData)
{
    NoString sLine = sData;

    sLine.TrimRight("\n\r");

    DEBUG("(" << GetFullName() << ") CLI -> ZNC [" << sLine << "]");

    if (sLine.Left(1) == "@") {
        // TODO support message-tags properly
        sLine = sLine.Token(1, true);
    }

    bool bReturn = false;
    if (IsAttached()) {
        NETWORKMODULECALL(OnUserRaw(sLine), m_pUser, m_pNetwork, this, &bReturn);
    } else {
        GLOBALMODULECALL(OnUnknownUserRaw(this, sLine), &bReturn);
    }
    if (bReturn) return;

    NoString sCommand = sLine.Token(0);
    if (sCommand.Left(1) == ":") {
        // Evil client! Sending a nickmask prefix on client's command
        // is bad, bad, bad, bad, bad, bad, bad, bad, BAD, B A D!
        sLine = sLine.Token(1, true);
        sCommand = sLine.Token(0);
    }

    if (!IsAttached()) { // The following commands happen before authentication with ZNC
        if (sCommand.Equals("PASS")) {
            m_bGotPass = true;

            NoString sAuthLine = sLine.Token(1, true).TrimPrefix_n();
            ParsePass(sAuthLine);

            AuthUser();
            return; // Don't forward this msg.  ZNC has already registered us.
        } else if (sCommand.Equals("NICK")) {
            NoString sNick = sLine.Token(1).TrimPrefix_n();

            m_sNick = sNick;
            m_bGotNick = true;

            AuthUser();
            return; // Don't forward this msg.  ZNC will handle nick changes until auth is complete
        } else if (sCommand.Equals("USER")) {
            NoString sAuthLine = sLine.Token(1);

            if (m_sUser.empty() && !sAuthLine.empty()) {
                ParseUser(sAuthLine);
            }

            m_bGotUser = true;
            if (m_bGotPass) {
                AuthUser();
            } else if (!m_bInCap) {
                SendRequiredPasswordNotice();
            }

            return; // Don't forward this msg.  ZNC has already registered us.
        }
    }

    if (sCommand.Equals("CAP")) {
        HandleCap(sLine);

        // Don't let the client talk to the server directly about CAP,
        // we don't want anything enabled that ZNC does not support.
        return;
    }

    if (!m_pUser) {
        // Only CAP, NICK, USER and PASS are allowed before login
        return;
    }

    if (sCommand.Equals("ZNC")) {
        NoString sTarget = sLine.Token(1);
        NoString sModCommand;

        if (sTarget.TrimPrefix(m_pUser->GetStatusPrefix())) {
            sModCommand = sLine.Token(2, true);
        } else {
            sTarget = "status";
            sModCommand = sLine.Token(1, true);
        }

        if (sTarget.Equals("status")) {
            if (sModCommand.empty())
                PutStatus("Hello. How may I help you?");
            else
                UserCommand(sModCommand);
        } else {
            if (sModCommand.empty())
                CALLMOD(sTarget, this, m_pUser, m_pNetwork, PutModule("Hello. How may I help you?"))
            else
                CALLMOD(sTarget, this, m_pUser, m_pNetwork, OnModCommand(sModCommand))
        }
        return;
    } else if (sCommand.Equals("PING")) {
        // All PONGs are generated by ZNC. We will still forward this to
        // the ircd, but all PONGs from irc will be blocked.
        if (sLine.length() >= 5)
            PutClient(":irc.znc.in PONG irc.znc.in " + sLine.substr(5));
        else
            PutClient(":irc.znc.in PONG irc.znc.in");
    } else if (sCommand.Equals("PONG")) {
        // Block PONGs, we already responded to the pings
        return;
    } else if (sCommand.Equals("QUIT")) {
        NoString sMsg = sLine.Token(1, true).TrimPrefix_n();
        NETWORKMODULECALL(OnUserQuit(sMsg), m_pUser, m_pNetwork, this, &bReturn);
        if (bReturn) return;
        Close(Csock::CLT_AFTERWRITE); // Treat a client quit as a detach
        return; // Don't forward this msg.  We don't want the client getting us disconnected.
    } else if (sCommand.Equals("PROTOCTL")) {
        NoStringVector vsTokens;
        sLine.Token(1, true).Split(" ", vsTokens, false);

        for (const NoString& sToken : vsTokens) {
            if (sToken == "NAMESX") {
                m_bNamesx = true;
            } else if (sToken == "UHNAMES") {
                m_bUHNames = true;
            }
        }
        return; // If the server understands it, we already enabled namesx / uhnames
    } else if (sCommand.Equals("NOTICE")) {
        NoString sTargets = sLine.Token(1).TrimPrefix_n();
        NoString sMsg = sLine.Token(2, true).TrimPrefix_n();

        NoStringVector vTargets;
        sTargets.Split(",", vTargets, false);

        for (NoString& sTarget : vTargets) {
            if (sTarget.TrimPrefix(m_pUser->GetStatusPrefix())) {
                if (!sTarget.Equals("status")) {
                    CALLMOD(sTarget, this, m_pUser, m_pNetwork, OnModNotice(sMsg));
                }
                continue;
            }

            bool bContinue = false;
            if (sMsg.WildCmp("\001*\001")) {
                NoString sCTCP = sMsg;
                sCTCP.LeftChomp();
                sCTCP.RightChomp();

                if (sCTCP.Token(0) == "VERSION") {
                    sCTCP += " via " + NoApp::GetTag(false);
                }

                NETWORKMODULECALL(OnUserCTCPReply(sTarget, sCTCP), m_pUser, m_pNetwork, this, &bContinue);
                if (bContinue) continue;

                sMsg = "\001" + sCTCP + "\001";
            } else {
                NETWORKMODULECALL(OnUserNotice(sTarget, sMsg), m_pUser, m_pNetwork, this, &bContinue);
                if (bContinue) continue;
            }

            if (!GetIRCSock()) {
                // Some lagmeters do a NOTICE to their own nick, ignore those.
                if (!sTarget.Equals(m_sNick))
                    PutStatus("Your notice to [" + sTarget + "] got lost, "
                                                             "you are not connected to IRC!");
                continue;
            }

            if (m_pNetwork) {
                NoChannel* pChan = m_pNetwork->FindChan(sTarget);

                if ((pChan) && (!pChan->autoClearChanBuffer())) {
                    pChan->addBuffer(":" + _NAMEDFMT(GetNickMask()) + " NOTICE " + _NAMEDFMT(sTarget) + " :{text}", sMsg);
                }

                // Relay to the rest of the clients that may be connected to this user
                const std::vector<NoClient*>& vClients = GetClients();

                for (NoClient* pClient : vClients) {
                    if (pClient != this && (m_pNetwork->IsChan(sTarget) || pClient->HasSelfMessage())) {
                        pClient->PutClient(":" + GetNickMask() + " NOTICE " + sTarget + " :" + sMsg);
                    }
                }

                PutIRC("NOTICE " + sTarget + " :" + sMsg);
            }
        }

        return;
    } else if (sCommand.Equals("PRIVMSG")) {
        NoString sTargets = sLine.Token(1);
        NoString sMsg = sLine.Token(2, true).TrimPrefix_n();

        NoStringVector vTargets;
        sTargets.Split(",", vTargets, false);

        for (NoString& sTarget : vTargets) {
            bool bContinue = false;
            if (sMsg.WildCmp("\001*\001")) {
                NoString sCTCP = sMsg;
                sCTCP.LeftChomp();
                sCTCP.RightChomp();

                if (sTarget.TrimPrefix(m_pUser->GetStatusPrefix())) {
                    if (sTarget.Equals("status")) {
                        StatusCTCP(sCTCP);
                    } else {
                        CALLMOD(sTarget, this, m_pUser, m_pNetwork, OnModCTCP(sCTCP));
                    }
                    continue;
                }

                if (m_pNetwork) {
                    if (sCTCP.Token(0).Equals("ACTION")) {
                        NoString sMessage = sCTCP.Token(1, true);
                        NETWORKMODULECALL(OnUserAction(sTarget, sMessage), m_pUser, m_pNetwork, this, &bContinue);
                        if (bContinue) continue;
                        sCTCP = "ACTION " + sMessage;

                        if (m_pNetwork->IsChan(sTarget)) {
                            NoChannel* pChan = m_pNetwork->FindChan(sTarget);

                            if (pChan && (!pChan->autoClearChanBuffer() || !m_pNetwork->IsUserOnline())) {
                                pChan->addBuffer(":" + _NAMEDFMT(GetNickMask()) + " PRIVMSG " + _NAMEDFMT(sTarget) +
                                                 " :\001ACTION {text}\001",
                                                 sMessage);
                            }
                        } else {
                            if (!m_pUser->AutoClearQueryBuffer() || !m_pNetwork->IsUserOnline()) {
                                NoQuery* pQuery = m_pNetwork->AddQuery(sTarget);
                                if (pQuery) {
                                    pQuery->addBuffer(":" + _NAMEDFMT(GetNickMask()) + " PRIVMSG " + _NAMEDFMT(sTarget) + " :\001ACTION {text}\001",
                                                      sMessage);
                                }
                            }
                        }

                        // Relay to the rest of the clients that may be connected to this user
                        const std::vector<NoClient*>& vClients = GetClients();

                        for (NoClient* pClient : vClients) {
                            if (pClient != this && (m_pNetwork->IsChan(sTarget) || pClient->HasSelfMessage())) {
                                pClient->PutClient(":" + GetNickMask() + " PRIVMSG " + sTarget + " :\001" + sCTCP + "\001");
                            }
                        }
                    } else {
                        NETWORKMODULECALL(OnUserCTCP(sTarget, sCTCP), m_pUser, m_pNetwork, this, &bContinue);
                        if (bContinue) continue;
                    }

                    PutIRC("PRIVMSG " + sTarget + " :\001" + sCTCP + "\001");
                }

                continue;
            }

            if (sTarget.TrimPrefix(m_pUser->GetStatusPrefix())) {
                if (sTarget.Equals("status")) {
                    UserCommand(sMsg);
                } else {
                    CALLMOD(sTarget, this, m_pUser, m_pNetwork, OnModCommand(sMsg));
                }
                continue;
            }

            NETWORKMODULECALL(OnUserMsg(sTarget, sMsg), m_pUser, m_pNetwork, this, &bContinue);
            if (bContinue) continue;

            if (!GetIRCSock()) {
                // Some lagmeters do a PRIVMSG to their own nick, ignore those.
                if (!sTarget.Equals(m_sNick))
                    PutStatus("Your message to [" + sTarget + "] got lost, "
                                                              "you are not connected to IRC!");
                continue;
            }

            if (m_pNetwork) {
                if (m_pNetwork->IsChan(sTarget)) {
                    NoChannel* pChan = m_pNetwork->FindChan(sTarget);

                    if ((pChan) && (!pChan->autoClearChanBuffer() || !m_pNetwork->IsUserOnline())) {
                        pChan->addBuffer(":" + _NAMEDFMT(GetNickMask()) + " PRIVMSG " + _NAMEDFMT(sTarget) + " :{text}", sMsg);
                    }
                } else {
                    if (!m_pUser->AutoClearQueryBuffer() || !m_pNetwork->IsUserOnline()) {
                        NoQuery* pQuery = m_pNetwork->AddQuery(sTarget);
                        if (pQuery) {
                            pQuery->addBuffer(":" + _NAMEDFMT(GetNickMask()) + " PRIVMSG " + _NAMEDFMT(sTarget) +
                                              " :{text}",
                                              sMsg);
                        }
                    }
                }

                PutIRC("PRIVMSG " + sTarget + " :" + sMsg);

                // Relay to the rest of the clients that may be connected to this user
                const std::vector<NoClient*>& vClients = GetClients();

                for (NoClient* pClient : vClients) {
                    if (pClient != this && (m_pNetwork->IsChan(sTarget) || pClient->HasSelfMessage())) {
                        pClient->PutClient(":" + GetNickMask() + " PRIVMSG " + sTarget + " :" + sMsg);
                    }
                }
            }
        }

        return;
    }

    if (!m_pNetwork) {
        return; // The following commands require a network
    }

    if (sCommand.Equals("DETACH")) {
        NoString sPatterns = sLine.Token(1, true);

        if (sPatterns.empty()) {
            PutStatusNotice("Usage: /detach <#chans>");
            return;
        }

        NoStringVector vsChans;
        sPatterns.Replace(",", " ");
        sPatterns.Split(" ", vsChans, false, "", "", true, true);

        std::set<NoChannel*> sChans;
        for (const NoString& sChan : vsChans) {
            std::vector<NoChannel*> vChans = m_pNetwork->FindChans(sChan);
            sChans.insert(vChans.begin(), vChans.end());
        }

        uint uDetached = 0;
        for (NoChannel* pChan : sChans) {
            if (pChan->isDetached()) continue;
            uDetached++;
            pChan->detachUser();
        }

        PutStatusNotice("There were [" + NoString(sChans.size()) + "] channels matching [" + sPatterns + "]");
        PutStatusNotice("Detached [" + NoString(uDetached) + "] channels");

        return;
    } else if (sCommand.Equals("JOIN")) {
        NoString sChans = sLine.Token(1).TrimPrefix_n();
        NoString sKey = sLine.Token(2);

        NoStringVector vsChans;
        sChans.Split(",", vsChans, false);
        sChans.clear();

        for (NoString& sChannel : vsChans) {
            bool bContinue = false;
            NETWORKMODULECALL(OnUserJoin(sChannel, sKey), m_pUser, m_pNetwork, this, &bContinue);
            if (bContinue) continue;

            NoChannel* pChan = m_pNetwork->FindChan(sChannel);
            if (pChan) {
                if (pChan->isDetached())
                    pChan->attachUser(this);
                else
                    pChan->joinUser(sKey);
                continue;
            }

            if (!sChannel.empty()) {
                sChans += (sChans.empty()) ? sChannel : NoString("," + sChannel);
            }
        }

        if (sChans.empty()) {
            return;
        }

        sLine = "JOIN " + sChans;

        if (!sKey.empty()) {
            sLine += " " + sKey;
        }
    } else if (sCommand.Equals("PART")) {
        NoString sChans = sLine.Token(1).TrimPrefix_n();
        NoString sMessage = sLine.Token(2, true).TrimPrefix_n();

        NoStringVector vsChans;
        sChans.Split(",", vsChans, false);
        sChans.clear();

        for (NoString& sChan : vsChans) {
            bool bContinue = false;
            NETWORKMODULECALL(OnUserPart(sChan, sMessage), m_pUser, m_pNetwork, this, &bContinue);
            if (bContinue) continue;

            NoChannel* pChan = m_pNetwork->FindChan(sChan);

            if (pChan && !pChan->isOn()) {
                PutStatusNotice("Removing channel [" + sChan + "]");
                m_pNetwork->DelChan(sChan);
            } else {
                sChans += (sChans.empty()) ? sChan : NoString("," + sChan);
            }
        }

        if (sChans.empty()) {
            return;
        }

        sLine = "PART " + sChans;

        if (!sMessage.empty()) {
            sLine += " :" + sMessage;
        }
    } else if (sCommand.Equals("TOPIC")) {
        NoString sChan = sLine.Token(1);
        NoString sTopic = sLine.Token(2, true).TrimPrefix_n();

        if (!sTopic.empty()) {
            NETWORKMODULECALL(OnUserTopic(sChan, sTopic), m_pUser, m_pNetwork, this, &bReturn);
            if (bReturn) return;
            sLine = "TOPIC " + sChan + " :" + sTopic;
        } else {
            NETWORKMODULECALL(OnUserTopicRequest(sChan), m_pUser, m_pNetwork, this, &bReturn);
            if (bReturn) return;
        }
    } else if (sCommand.Equals("MODE")) {
        NoString sTarget = sLine.Token(1);
        NoString sModes = sLine.Token(2, true);

        if (m_pNetwork->IsChan(sTarget) && sModes.empty()) {
            // If we are on that channel and already received a
            // /mode reply from the server, we can answer this
            // request ourself.

            NoChannel* pChan = m_pNetwork->FindChan(sTarget);
            if (pChan && pChan->isOn() && !pChan->getModeString().empty()) {
                PutClient(":" + m_pNetwork->GetIRNoServer() + " 324 " + GetNick() + " " + sTarget + " " + pChan->getModeString());
                if (pChan->getCreationDate() > 0) {
                    PutClient(":" + m_pNetwork->GetIRNoServer() + " 329 " + GetNick() + " " + sTarget + " " +
                              NoString(pChan->getCreationDate()));
                }
                return;
            }
        }
    }

    PutIRC(sLine);
}

void NoClient::SetNick(const NoString& s) { m_sNick = s; }

void NoClient::SetNetwork(NoNetwork* pNetwork, bool bDisconnect, bool bReconnect)
{
    if (bDisconnect) {
        if (m_pNetwork) {
            m_pNetwork->ClientDisconnected(this);

            // Tell the client they are no longer in these channels.
            const std::vector<NoChannel*>& vChans = m_pNetwork->GetChans();
            for (const NoChannel* pChan : vChans) {
                if (!(pChan->isDetached())) {
                    PutClient(":" + m_pNetwork->GetIRNoNick().GetNickMask() + " PART " + pChan->getName());
                }
            }
        } else if (m_pUser) {
            m_pUser->UserDisconnected(this);
        }
    }

    m_pNetwork = pNetwork;

    if (bReconnect) {
        if (m_pNetwork) {
            m_pNetwork->ClientConnected(this);
        } else if (m_pUser) {
            m_pUser->UserConnected(this);
        }
    }
}

const std::vector<NoClient*>& NoClient::GetClients() const
{
    if (m_pNetwork) {
        return m_pNetwork->GetClients();
    }

    return m_pUser->GetUserClients();
}

const NoIrcSock* NoClient::GetIRCSock() const
{
    if (m_pNetwork) {
        return m_pNetwork->GetIRCSock();
    }

    return nullptr;
}

NoIrcSock* NoClient::GetIRCSock()
{
    if (m_pNetwork) {
        return m_pNetwork->GetIRCSock();
    }

    return nullptr;
}

void NoClient::StatusCTCP(const NoString& sLine)
{
    NoString sCommand = sLine.Token(0);

    if (sCommand.Equals("PING")) {
        PutStatusNotice("\001PING " + sLine.Token(1, true) + "\001");
    } else if (sCommand.Equals("VERSION")) {
        PutStatusNotice("\001VERSION " + NoApp::GetTag() + "\001");
    }
}

bool NoClient::SendMotd()
{
    const NoStringVector& vsMotd = NoApp::Get().GetMotd();

    if (!vsMotd.size()) {
        return false;
    }

    for (const NoString& sLine : vsMotd) {
        if (m_pNetwork) {
            PutStatusNotice(m_pNetwork->ExpandString(sLine));
        } else {
            PutStatusNotice(m_pUser->ExpandString(sLine));
        }
    }

    return true;
}

void NoClient::AuthUser()
{
    if (!m_bGotNick || !m_bGotUser || !m_bGotPass || m_bInCap || IsAttached()) return;

    m_spAuth = std::make_shared<NoClientAuth>(this, m_sUser, m_sPass);

    NoApp::Get().AuthUser(m_spAuth);
}

NoClientAuth::NoClientAuth(NoClient* pClient, const NoString& sUsername, const NoString& sPassword)
    : NoAuthBase(sUsername, sPassword, pClient), m_pClient(pClient)
{
}

void NoClientAuth::RefusedLogin(const NoString& sReason)
{
    if (m_pClient) {
        m_pClient->RefuseLogin(sReason);
    }
}

NoString NoAuthBase::GetRemoteIP() const
{
    if (m_pSock) return m_pSock->GetRemoteIP();
    return "";
}

void NoAuthBase::Invalidate() { m_pSock = nullptr; }

void NoAuthBase::AcceptLogin(NoUser& User)
{
    if (m_pSock) {
        AcceptedLogin(User);
        Invalidate();
    }
}

void NoAuthBase::RefuseLogin(const NoString& sReason)
{
    if (!m_pSock) return;

    NoUser* pUser = NoApp::Get().FindUser(GetUsername());

    // If the username is valid, notify that user that someone tried to
    // login. Use sReason because there are other reasons than "wrong
    // password" for a login to be rejected (e.g. fail2ban).
    if (pUser) {
        pUser->PutStatus("A client from [" + GetRemoteIP() + "] attempted "
                                                             "to login as you, but was rejected [" +
                         sReason + "].");
    }

    GLOBALMODULECALL(OnFailedLogin(GetUsername(), GetRemoteIP()), NOTHING);
    RefusedLogin(sReason);
    Invalidate();
}

void NoClient::RefuseLogin(const NoString& sReason)
{
    PutStatus("Bad username and/or password.");
    PutClient(":irc.znc.in 464 " + GetNick() + " :" + sReason);
    Close(Csock::CLT_AFTERWRITE);
}

void NoClientAuth::AcceptedLogin(NoUser& User)
{
    if (m_pClient) {
        m_pClient->AcceptLogin(User);
    }
}

void NoClient::AcceptLogin(NoUser& User)
{
    m_sPass = "";
    m_pUser = &User;

    // Set our proper timeout and set back our proper timeout mode
    // (constructor set a different timeout and mode)
    SetTimeout(NoNetwork::NO_TRAFFIC_TIMEOUT, TMO_READ);

    SetSockName("USR::" + m_pUser->GetUserName());
    SetEncoding(m_pUser->GetClientEncoding());

    if (!m_sNetwork.empty()) {
        m_pNetwork = m_pUser->FindNetwork(m_sNetwork);
        if (!m_pNetwork) {
            PutStatus("Network (" + m_sNetwork + ") doesn't exist.");
        }
    } else if (!m_pUser->GetNetworks().empty()) {
        // If a user didn't supply a network, and they have a network called "default" then automatically use this
        // network.
        m_pNetwork = m_pUser->FindNetwork("default");
        // If no "default" network, try "user" network. It's for compatibility with early network stuff in ZNC, which
        // converted old configs to "user" network.
        if (!m_pNetwork) m_pNetwork = m_pUser->FindNetwork("user");
        // Otherwise, just try any network of the user.
        if (!m_pNetwork) m_pNetwork = *m_pUser->GetNetworks().begin();
        if (m_pNetwork && m_pUser->GetNetworks().size() > 1) {
            PutStatusNotice("You have several networks configured, but no network was specified for the connection.");
            PutStatusNotice("Selecting network [" + m_pNetwork->GetName() +
                            "]. To see list of all configured networks, use /znc ListNetworks");
            PutStatusNotice(
            "If you want to choose another network, use /znc JumpNetwork <network>, or connect to ZNC with username " +
            m_pUser->GetUserName() + "/<network> (instead of just " + m_pUser->GetUserName() + ")");
        }
    } else {
        PutStatusNotice("You have no networks configured. Use /znc AddNetwork <network> to add one.");
    }

    SetNetwork(m_pNetwork, false);

    SendMotd();

    NETWORKMODULECALL(OnClientLogin(), m_pUser, m_pNetwork, this, NOTHING);
}

void NoClient::Timeout() { PutClient("ERROR :Closing link [Timeout]"); }

void NoClient::Connected() { DEBUG(GetSockName() << " == Connected();"); }

void NoClient::ConnectionRefused() { DEBUG(GetSockName() << " == ConnectionRefused()"); }

void NoClient::Disconnected()
{
    DEBUG(GetSockName() << " == Disconnected()");
    NoNetwork* pNetwork = m_pNetwork;
    SetNetwork(nullptr, true, false);

    if (m_pUser) {
        NETWORKMODULECALL(OnClientDisconnect(), m_pUser, pNetwork, this, NOTHING);
    }
}

void NoClient::ReachedMaxBuffer()
{
    DEBUG(GetSockName() << " == ReachedMaxBuffer()");
    if (IsAttached()) {
        PutClient("ERROR :Closing link [Too long raw line]");
    }
    Close();
}

void NoClient::BouncedOff()
{
    PutStatusNotice("You are being disconnected because another user just authenticated as you.");
    Close(Csock::CLT_AFTERWRITE);
}

void NoClient::PutIRC(const NoString& sLine)
{
    if (m_pNetwork) {
        m_pNetwork->PutIRC(sLine);
    }
}

NoString NoClient::GetFullName() const
{
    if (!m_pUser) return GetRemoteIP();
    NoString sFullName = m_pUser->GetUserName();
    if (!m_sIdentifier.empty()) sFullName += "@" + m_sIdentifier;
    if (m_pNetwork) sFullName += "/" + m_pNetwork->GetName();
    return sFullName;
}

void NoClient::PutClient(const NoString& sLine)
{
    bool bReturn = false;
    NoString sCopy = sLine;
    NETWORKMODULECALL(OnSendToClient(sCopy, *this), m_pUser, m_pNetwork, this, &bReturn);
    if (bReturn) return;
    DEBUG("(" << GetFullName() << ") ZNC -> CLI [" << sCopy << "]");
    Write(sCopy + "\r\n");
}

void NoClient::PutStatusNotice(const NoString& sLine) { PutModNotice("status", sLine); }

uint NoClient::PutStatus(const NoTable& table)
{
    uint idx = 0;
    NoString sLine;
    while (table.GetLine(idx++, sLine)) PutStatus(sLine);
    return idx - 1;
}

void NoClient::PutStatus(const NoString& sLine) { PutModule("status", sLine); }

void NoClient::PutModNotice(const NoString& sModule, const NoString& sLine)
{
    if (!m_pUser) {
        return;
    }

    DEBUG("(" << GetFullName() << ") ZNC -> CLI [:" + m_pUser->GetStatusPrefix() + ((sModule.empty()) ? "status" : sModule) + "!znc@znc.in NOTICE "
              << GetNick() << " :" << sLine << "]");
    Write(":" + m_pUser->GetStatusPrefix() + ((sModule.empty()) ? "status" : sModule) + "!znc@znc.in NOTICE " +
          GetNick() + " :" + sLine + "\r\n");
}

void NoClient::PutModule(const NoString& sModule, const NoString& sLine)
{
    if (!m_pUser) {
        return;
    }

    DEBUG("(" << GetFullName() << ") ZNC -> CLI [:" + m_pUser->GetStatusPrefix() + ((sModule.empty()) ? "status" : sModule) + "!znc@znc.in PRIVMSG "
              << GetNick() << " :" << sLine << "]");

    NoStringVector vsLines;
    sLine.Split("\n", vsLines);
    for (const NoString& s : vsLines) {
        Write(":" + m_pUser->GetStatusPrefix() + ((sModule.empty()) ? "status" : sModule) + "!znc@znc.in PRIVMSG " +
              GetNick() + " :" + s + "\r\n");
    }
}

NoString NoClient::GetNick(bool bAllowIRNoNick) const
{
    NoString sRet;

    const NoIrcSock* pSock = GetIRCSock();
    if (bAllowIRNoNick && pSock && pSock->IsAuthed()) {
        sRet = pSock->GetNick();
    }

    return (sRet.empty()) ? m_sNick : sRet;
}

NoString NoClient::GetNickMask() const
{
    if (GetIRCSock() && GetIRCSock()->IsAuthed()) {
        return GetIRCSock()->GetNickMask();
    }

    NoString sHost = m_pNetwork ? m_pNetwork->GetBindHost() : m_pUser->GetBindHost();
    if (sHost.empty()) {
        sHost = "irc.znc.in";
    }

    return GetNick() + "!" + (m_pNetwork ? m_pNetwork->GetBindHost() : m_pUser->GetIdent()) + "@" + sHost;
}

bool NoClient::IsValidIdentifier(const NoString& sIdentifier)
{
    // ^[-\w]+$

    if (sIdentifier.empty()) {
        return false;
    }

    const char* p = sIdentifier.c_str();
    while (*p) {
        if (*p != '_' && *p != '-' && !isalnum(*p)) {
            return false;
        }

        p++;
    }

    return true;
}

void NoClient::RespondCap(const NoString& sResponse) { PutClient(":irc.znc.in CAP " + GetNick() + " " + sResponse); }

void NoClient::HandleCap(const NoString& sLine)
{
    // TODO support ~ and = modifiers
    NoString sSubCmd = sLine.Token(1);

    if (sSubCmd.Equals("LS")) {
        NoStringSet ssOfferCaps;
        GLOBALMODULECALL(OnClientCapLs(this, ssOfferCaps), NOTHING);
        ssOfferCaps.insert("userhost-in-names");
        ssOfferCaps.insert("multi-prefix");
        ssOfferCaps.insert("znc.in/server-time-iso");
        ssOfferCaps.insert("znc.in/batch");
        ssOfferCaps.insert("znc.in/self-message");
        NoString sRes = NoString(" ").Join(ssOfferCaps.begin(), ssOfferCaps.end());
        RespondCap("LS :" + sRes);
        m_bInCap = true;
    } else if (sSubCmd.Equals("END")) {
        m_bInCap = false;
        if (!IsAttached()) {
            if (!m_pUser && m_bGotUser && !m_bGotPass) {
                SendRequiredPasswordNotice();
            } else {
                AuthUser();
            }
        }
    } else if (sSubCmd.Equals("REQ")) {
        NoStringVector vsTokens;
        sLine.Token(2, true).TrimPrefix_n(":").Split(" ", vsTokens, false);

        for (const NoString& sToken : vsTokens) {
            bool bVal = true;
            NoString sCap = sToken;
            if (sCap.TrimPrefix("-")) bVal = false;

            bool bAccepted = ("multi-prefix" == sCap) || ("userhost-in-names" == sCap) || ("znc.in/server-time-iso" == sCap) ||
                             ("znc.in/batch" == sCap) || ("znc.in/self-message" == sCap);
            GLOBALMODULECALL(IsClientCapSupported(this, sCap, bVal), &bAccepted);

            if (!bAccepted) {
                // Some unsupported capability is requested
                RespondCap("NAK :" + sLine.Token(2, true).TrimPrefix_n(":"));
                return;
            }
        }

        // All is fine, we support what was requested
        for (const NoString& sToken : vsTokens) {
            bool bVal = true;
            NoString sCap = sToken;
            if (sCap.TrimPrefix("-")) bVal = false;

            if ("multi-prefix" == sCap) {
                m_bNamesx = bVal;
            } else if ("userhost-in-names" == sCap) {
                m_bUHNames = bVal;
            } else if ("znc.in/server-time-iso" == sCap) {
                m_bServerTime = bVal;
            } else if ("znc.in/batch" == sCap) {
                m_bBatch = bVal;
            } else if ("znc.in/self-message" == sCap) {
                m_bSelfMessage = bVal;
            }
            GLOBALMODULECALL(OnClientCapRequest(this, sCap, bVal), NOTHING);

            if (bVal) {
                m_ssAcceptedCaps.insert(sCap);
            } else {
                m_ssAcceptedCaps.erase(sCap);
            }
        }

        RespondCap("ACK :" + sLine.Token(2, true).TrimPrefix_n(":"));
    } else if (sSubCmd.Equals("LIST")) {
        NoString sList = NoString(" ").Join(m_ssAcceptedCaps.begin(), m_ssAcceptedCaps.end());
        RespondCap("LIST :" + sList);
    } else if (sSubCmd.Equals("CLEAR")) {
        NoStringSet ssRemoved;
        for (const NoString& sCap : m_ssAcceptedCaps) {
            bool bRemoving = false;
            GLOBALMODULECALL(IsClientCapSupported(this, sCap, false), &bRemoving);
            if (bRemoving) {
                GLOBALMODULECALL(OnClientCapRequest(this, sCap, false), NOTHING);
                ssRemoved.insert(sCap);
            }
        }
        if (m_bNamesx) {
            m_bNamesx = false;
            ssRemoved.insert("multi-prefix");
        }
        if (m_bUHNames) {
            m_bUHNames = false;
            ssRemoved.insert("userhost-in-names");
        }
        if (m_bServerTime) {
            m_bServerTime = false;
            ssRemoved.insert("znc.in/server-time-iso");
        }
        if (m_bBatch) {
            m_bBatch = false;
            ssRemoved.insert("znc.in/batch");
        }
        if (m_bSelfMessage) {
            m_bSelfMessage = false;
            ssRemoved.insert("znc.in/self-message");
        }
        NoString sList = "";
        for (const NoString& sCap : ssRemoved) {
            m_ssAcceptedCaps.erase(sCap);
            sList += "-" + sCap + " ";
        }
        RespondCap("ACK :" + sList.TrimSuffix_n(" "));
    } else {
        PutClient(":irc.znc.in 410 " + GetNick() + " " + sSubCmd + " :Invalid CAP subcommand");
    }
}

void NoClient::ParsePass(const NoString& sAuthLine)
{
    // [user[@identifier][/network]:]password

    const size_t uColon = sAuthLine.find(":");
    if (uColon != NoString::npos) {
        m_sPass = sAuthLine.substr(uColon + 1);

        ParseUser(sAuthLine.substr(0, uColon));
    } else {
        m_sPass = sAuthLine;
    }
}

void NoClient::ParseUser(const NoString& sAuthLine)
{
    // user[@identifier][/network]

    const size_t uSlash = sAuthLine.rfind("/");
    if (uSlash != NoString::npos) {
        m_sNetwork = sAuthLine.substr(uSlash + 1);

        ParseIdentifier(sAuthLine.substr(0, uSlash));
    } else {
        ParseIdentifier(sAuthLine);
    }
}

void NoClient::ParseIdentifier(const NoString& sAuthLine)
{
    // user[@identifier]

    const size_t uAt = sAuthLine.rfind("@");
    if (uAt != NoString::npos) {
        const NoString sId = sAuthLine.substr(uAt + 1);

        if (IsValidIdentifier(sId)) {
            m_sIdentifier = sId;
            m_sUser = sAuthLine.substr(0, uAt);
        } else {
            m_sUser = sAuthLine;
        }
    } else {
        m_sUser = sAuthLine;
    }
}
