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
#include "noclient_p.h"
#include "nosocket.h"
#include "nosocket_p.h"
#include "nochannel.h"
#include "noircsocket.h"
#include "noauthenticator.h"
#include "nodebug.h"
#include "nouser.h"
#include "nonetwork.h"
#include "noquery.h"
#include "nomodulecall.h"
#include "noapp.h"
#include "noescape.h"

#define CALLMOD(MOD, CLIENT, USER, NETWORK, FUNC)                             \
    {                                                                         \
        NoModule* pModule = nullptr;                                           \
        if (NETWORK && (pModule = (NETWORK)->GetModules().FindModule(MOD))) { \
            try {                                                             \
                pModule->SetClient(CLIENT);                                   \
                pModule->FUNC;                                                \
                pModule->SetClient(nullptr);                                  \
            } catch (const NoModule::ModException& e) {                       \
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
            } catch (const NoModule::ModException& e) {                       \
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
            } catch (const NoModule::ModException& e) {                       \
                if (e == NoModule::UNLOAD) {                                   \
                    NoApp::Get().GetModules().UnloadModule(MOD);               \
                }                                                             \
            }                                                                 \
        } else {                                                              \
            PutStatus("No such module [" + MOD + "]");                        \
        }                                                                     \
    }

class NoClientSocket : public NoSocket
{
public:
    NoClientSocket(NoClient* pClient) : m_pClient(pClient)
    {
        NoSocketPrivate::get(this)->allowControlCodes = true;

        EnableReadLine();
        // RFC says a line can have 512 chars max, but we are
        // a little more gentle ;)
        SetMaxBufferThreshold(1024);
    }

    void ReadLineImpl(const NoString& sData) override { m_pClient->ReadLine(sData); }
    void TimeoutImpl() override { m_pClient->PutClient("ERROR :Closing link [Timeout]"); }
    void ConnectedImpl() override { NO_DEBUG(GetSockName() << " == Connected();"); }
    void ConnectionRefusedImpl() override { NO_DEBUG(GetSockName() << " == ConnectionRefused()"); }

    void DisconnectedImpl() override
    {
        NO_DEBUG(GetSockName() << " == Disconnected()");
        NoNetwork* pNetwork = m_pClient->GetNetwork();
        m_pClient->SetNetwork(nullptr, true, false);

        NoUser* pUser = m_pClient->GetUser();
        if (pUser)
            NETWORKMODULECALL(OnClientDisconnect(), pUser, pNetwork, m_pClient, NOTHING);
    }

    void ReachedMaxBufferImpl() override
    {
        NO_DEBUG(GetSockName() << " == ReachedMaxBuffer()");
        if (m_pClient->IsAttached()) {
            m_pClient->PutClient("ERROR :Closing link [Too long raw line]");
        }
        Close();
    }

private:
    NoClient* m_pClient;
};

class NoClientAuth : public NoAuthenticator
{
public:
    NoClientAuth(NoClient* pClient, const NoString& sUsername, const NoString& sPassword)
        : NoAuthenticator(sUsername, sPassword, pClient->GetSocket()), m_pClient(pClient)
    {
    }

    void invalidate() override
    {
        m_pClient = nullptr;
        NoAuthenticator::invalidate();
    }

    void loginAccepted(NoUser* user) override
    {
        if (m_pClient)
            m_pClient->AcceptLogin(*user);
    }

    void loginRefused(NoUser* user, const NoString& reason) override
    {
        if (m_pClient)
            m_pClient->RefuseLogin(reason);
    }

private:
    NoClient* m_pClient;
};

NoClient::NoClient() : d(new NoClientPrivate)
{
    d->pSocket = new NoClientSocket(this);
}

NoClient::~NoClient()
{
    if (d->spAuth) {
        NoClientAuth* pAuth = (NoClientAuth*)&(*d->spAuth);
        pAuth->invalidate();
    }
    if (d->pUser != nullptr) {
        d->pUser->AddBytesRead(d->pSocket->GetBytesRead());
        d->pUser->AddBytesWritten(d->pSocket->GetBytesWritten());
    }
    delete d->pSocket;
}

NoSocket*NoClient::GetSocket() const { return d->pSocket; }

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

    sLine.trimRight("\n\r");

    NO_DEBUG("(" << GetFullName() << ") CLI -> ZNC [" << sLine << "]");

    if (sLine.left(1) == "@") {
        // TODO support message-tags properly
        sLine = No::tokens(sLine, 1);
    }

    bool bReturn = false;
    if (IsAttached()) {
        NETWORKMODULECALL(OnUserRaw(sLine), d->pUser, d->pNetwork, this, &bReturn);
    } else {
        GLOBALMODULECALL(OnUnknownUserRaw(this, sLine), &bReturn);
    }
    if (bReturn) return;

    NoString sCommand = No::token(sLine, 0);
    if (sCommand.left(1) == ":") {
        // Evil client! Sending a nickmask prefix on client's command
        // is bad, bad, bad, bad, bad, bad, bad, bad, BAD, B A D!
        sLine = No::tokens(sLine, 1);
        sCommand = No::token(sLine, 0);
    }

    if (!IsAttached()) { // The following commands happen before authentication with ZNC
        if (sCommand.equals("PASS")) {
            d->bGotPass = true;

            NoString sAuthLine = No::tokens(sLine, 1).trimPrefix_n();
            ParsePass(sAuthLine);

            AuthUser();
            return; // Don't forward this msg.  ZNC has already registered us.
        } else if (sCommand.equals("NICK")) {
            NoString sNick = No::token(sLine, 1).trimPrefix_n();

            d->sNick = sNick;
            d->bGotNick = true;

            AuthUser();
            return; // Don't forward this msg.  ZNC will handle nick changes until auth is complete
        } else if (sCommand.equals("USER")) {
            NoString sAuthLine = No::token(sLine, 1);

            if (d->sUser.empty() && !sAuthLine.empty()) {
                ParseUser(sAuthLine);
            }

            d->bGotUser = true;
            if (d->bGotPass) {
                AuthUser();
            } else if (!d->bInCap) {
                SendRequiredPasswordNotice();
            }

            return; // Don't forward this msg.  ZNC has already registered us.
        }
    }

    if (sCommand.equals("CAP")) {
        HandleCap(sLine);

        // Don't let the client talk to the server directly about CAP,
        // we don't want anything enabled that ZNC does not support.
        return;
    }

    if (!d->pUser) {
        // Only CAP, NICK, USER and PASS are allowed before login
        return;
    }

    if (sCommand.equals("ZNC")) {
        NoString sTarget = No::token(sLine, 1);
        NoString sModCommand;

        if (sTarget.trimPrefix(d->pUser->GetStatusPrefix())) {
            sModCommand = No::tokens(sLine, 2);
        } else {
            sTarget = "status";
            sModCommand = No::tokens(sLine, 1);
        }

        if (sTarget.equals("status")) {
            if (sModCommand.empty())
                PutStatus("Hello. How may I help you?");
            else
                UserCommand(sModCommand);
        } else {
            if (sModCommand.empty())
                CALLMOD(sTarget, this, d->pUser, d->pNetwork, PutModule("Hello. How may I help you?"))
            else
                CALLMOD(sTarget, this, d->pUser, d->pNetwork, OnModCommand(sModCommand))
        }
        return;
    } else if (sCommand.equals("PING")) {
        // All PONGs are generated by ZNC. We will still forward this to
        // the ircd, but all PONGs from irc will be blocked.
        if (sLine.length() >= 5)
            PutClient(":irc.znc.in PONG irc.znc.in " + sLine.substr(5));
        else
            PutClient(":irc.znc.in PONG irc.znc.in");
    } else if (sCommand.equals("PONG")) {
        // Block PONGs, we already responded to the pings
        return;
    } else if (sCommand.equals("QUIT")) {
        NoString sMsg = No::tokens(sLine, 1).trimPrefix_n();
        NETWORKMODULECALL(OnUserQuit(sMsg), d->pUser, d->pNetwork, this, &bReturn);
        if (bReturn) return;
        d->pSocket->Close(NoSocket::CLT_AFTERWRITE); // Treat a client quit as a detach
        return; // Don't forward this msg.  We don't want the client getting us disconnected.
    } else if (sCommand.equals("PROTOCTL")) {
        NoStringVector vsTokens = No::tokens(sLine, 1).split(" ", No::SkipEmptyParts);

        for (const NoString& sToken : vsTokens) {
            if (sToken == "NAMESX") {
                d->bNamesx = true;
            } else if (sToken == "UHNAMES") {
                d->bUHNames = true;
            }
        }
        return; // If the server understands it, we already enabled namesx / uhnames
    } else if (sCommand.equals("NOTICE")) {
        NoString sTargets = No::token(sLine, 1).trimPrefix_n();
        NoString sMsg = No::tokens(sLine, 2).trimPrefix_n();
        NoStringVector vTargets = sTargets.split(",", No::SkipEmptyParts);

        for (NoString& sTarget : vTargets) {
            if (sTarget.trimPrefix(d->pUser->GetStatusPrefix())) {
                if (!sTarget.equals("status")) {
                    CALLMOD(sTarget, this, d->pUser, d->pNetwork, OnModNotice(sMsg));
                }
                continue;
            }

            bool bContinue = false;
            if (No::wildCmp(sMsg, "\001*\001")) {
                NoString sCTCP = sMsg;
                sCTCP.leftChomp(1);
                sCTCP.rightChomp(1);

                if (No::token(sCTCP, 0) == "VERSION") {
                    sCTCP += " via " + NoApp::GetTag(false);
                }

                NETWORKMODULECALL(OnUserCTCPReply(sTarget, sCTCP), d->pUser, d->pNetwork, this, &bContinue);
                if (bContinue) continue;

                sMsg = "\001" + sCTCP + "\001";
            } else {
                NETWORKMODULECALL(OnUserNotice(sTarget, sMsg), d->pUser, d->pNetwork, this, &bContinue);
                if (bContinue) continue;
            }

            if (!GetIRCSock()) {
                // Some lagmeters do a NOTICE to their own nick, ignore those.
                if (!sTarget.equals(d->sNick))
                    PutStatus("Your notice to [" + sTarget + "] got lost, "
                                                             "you are not connected to IRC!");
                continue;
            }

            if (d->pNetwork) {
                NoChannel* pChan = d->pNetwork->FindChan(sTarget);

                if ((pChan) && (!pChan->autoClearChanBuffer())) {
                    pChan->addBuffer(":" + _NAMEDFMT(GetNickMask()) + " NOTICE " + _NAMEDFMT(sTarget) + " :{text}", sMsg);
                }

                // Relay to the rest of the clients that may be connected to this user
                const std::vector<NoClient*>& vClients = GetClients();

                for (NoClient* pClient : vClients) {
                    if (pClient != this && (d->pNetwork->IsChan(sTarget) || pClient->HasSelfMessage())) {
                        pClient->PutClient(":" + GetNickMask() + " NOTICE " + sTarget + " :" + sMsg);
                    }
                }

                PutIRC("NOTICE " + sTarget + " :" + sMsg);
            }
        }

        return;
    } else if (sCommand.equals("PRIVMSG")) {
        NoString sTargets = No::token(sLine, 1);
        NoString sMsg = No::tokens(sLine, 2).trimPrefix_n();
        NoStringVector vTargets = sTargets.split(",", No::SkipEmptyParts);

        for (NoString& sTarget : vTargets) {
            bool bContinue = false;
            if (No::wildCmp(sMsg, "\001*\001")) {
                NoString sCTCP = sMsg;
                sCTCP.leftChomp(1);
                sCTCP.rightChomp(1);

                if (sTarget.trimPrefix(d->pUser->GetStatusPrefix())) {
                    if (sTarget.equals("status")) {
                        StatusCTCP(sCTCP);
                    } else {
                        CALLMOD(sTarget, this, d->pUser, d->pNetwork, OnModCTCP(sCTCP));
                    }
                    continue;
                }

                if (d->pNetwork) {
                    if (No::token(sCTCP, 0).equals("ACTION")) {
                        NoString sMessage = No::tokens(sCTCP, 1);
                        NETWORKMODULECALL(OnUserAction(sTarget, sMessage), d->pUser, d->pNetwork, this, &bContinue);
                        if (bContinue) continue;
                        sCTCP = "ACTION " + sMessage;

                        if (d->pNetwork->IsChan(sTarget)) {
                            NoChannel* pChan = d->pNetwork->FindChan(sTarget);

                            if (pChan && (!pChan->autoClearChanBuffer() || !d->pNetwork->IsUserOnline())) {
                                pChan->addBuffer(":" + _NAMEDFMT(GetNickMask()) + " PRIVMSG " + _NAMEDFMT(sTarget) +
                                                 " :\001ACTION {text}\001",
                                                 sMessage);
                            }
                        } else {
                            if (!d->pUser->AutoClearQueryBuffer() || !d->pNetwork->IsUserOnline()) {
                                NoQuery* pQuery = d->pNetwork->AddQuery(sTarget);
                                if (pQuery) {
                                    pQuery->addBuffer(":" + _NAMEDFMT(GetNickMask()) + " PRIVMSG " + _NAMEDFMT(sTarget) + " :\001ACTION {text}\001",
                                                      sMessage);
                                }
                            }
                        }

                        // Relay to the rest of the clients that may be connected to this user
                        const std::vector<NoClient*>& vClients = GetClients();

                        for (NoClient* pClient : vClients) {
                            if (pClient != this && (d->pNetwork->IsChan(sTarget) || pClient->HasSelfMessage())) {
                                pClient->PutClient(":" + GetNickMask() + " PRIVMSG " + sTarget + " :\001" + sCTCP + "\001");
                            }
                        }
                    } else {
                        NETWORKMODULECALL(OnUserCTCP(sTarget, sCTCP), d->pUser, d->pNetwork, this, &bContinue);
                        if (bContinue) continue;
                    }

                    PutIRC("PRIVMSG " + sTarget + " :\001" + sCTCP + "\001");
                }

                continue;
            }

            if (sTarget.trimPrefix(d->pUser->GetStatusPrefix())) {
                if (sTarget.equals("status")) {
                    UserCommand(sMsg);
                } else {
                    CALLMOD(sTarget, this, d->pUser, d->pNetwork, OnModCommand(sMsg));
                }
                continue;
            }

            NETWORKMODULECALL(OnUserMsg(sTarget, sMsg), d->pUser, d->pNetwork, this, &bContinue);
            if (bContinue) continue;

            if (!GetIRCSock()) {
                // Some lagmeters do a PRIVMSG to their own nick, ignore those.
                if (!sTarget.equals(d->sNick))
                    PutStatus("Your message to [" + sTarget + "] got lost, "
                                                              "you are not connected to IRC!");
                continue;
            }

            if (d->pNetwork) {
                if (d->pNetwork->IsChan(sTarget)) {
                    NoChannel* pChan = d->pNetwork->FindChan(sTarget);

                    if ((pChan) && (!pChan->autoClearChanBuffer() || !d->pNetwork->IsUserOnline())) {
                        pChan->addBuffer(":" + _NAMEDFMT(GetNickMask()) + " PRIVMSG " + _NAMEDFMT(sTarget) + " :{text}", sMsg);
                    }
                } else {
                    if (!d->pUser->AutoClearQueryBuffer() || !d->pNetwork->IsUserOnline()) {
                        NoQuery* pQuery = d->pNetwork->AddQuery(sTarget);
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
                    if (pClient != this && (d->pNetwork->IsChan(sTarget) || pClient->HasSelfMessage())) {
                        pClient->PutClient(":" + GetNickMask() + " PRIVMSG " + sTarget + " :" + sMsg);
                    }
                }
            }
        }

        return;
    }

    if (!d->pNetwork) {
        return; // The following commands require a network
    }

    if (sCommand.equals("DETACH")) {
        NoString sPatterns = No::tokens(sLine, 1);

        if (sPatterns.empty()) {
            PutStatusNotice("Usage: /detach <#chans>");
            return;
        }

        sPatterns.replace(",", " ");
        NoStringVector vsChans = sPatterns.split(" ", No::SkipEmptyParts);

        std::set<NoChannel*> sChans;
        for (const NoString& sChan : vsChans) {
            std::vector<NoChannel*> vChans = d->pNetwork->FindChans(sChan);
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
    } else if (sCommand.equals("JOIN")) {
        NoString sChans = No::token(sLine, 1).trimPrefix_n();
        NoString sKey = No::token(sLine, 2);

        NoStringVector vsChans = sChans.split(",", No::SkipEmptyParts);
        sChans.clear();

        for (NoString& sChannel : vsChans) {
            bool bContinue = false;
            NETWORKMODULECALL(OnUserJoin(sChannel, sKey), d->pUser, d->pNetwork, this, &bContinue);
            if (bContinue) continue;

            NoChannel* pChan = d->pNetwork->FindChan(sChannel);
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
    } else if (sCommand.equals("PART")) {
        NoString sChans = No::token(sLine, 1).trimPrefix_n();
        NoString sMessage = No::tokens(sLine, 2).trimPrefix_n();

        NoStringVector vsChans = sChans.split(",", No::SkipEmptyParts);
        sChans.clear();

        for (NoString& sChan : vsChans) {
            bool bContinue = false;
            NETWORKMODULECALL(OnUserPart(sChan, sMessage), d->pUser, d->pNetwork, this, &bContinue);
            if (bContinue) continue;

            NoChannel* pChan = d->pNetwork->FindChan(sChan);

            if (pChan && !pChan->isOn()) {
                PutStatusNotice("Removing channel [" + sChan + "]");
                d->pNetwork->DelChan(sChan);
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
    } else if (sCommand.equals("TOPIC")) {
        NoString sChan = No::token(sLine, 1);
        NoString sTopic = No::tokens(sLine, 2).trimPrefix_n();

        if (!sTopic.empty()) {
            NETWORKMODULECALL(OnUserTopic(sChan, sTopic), d->pUser, d->pNetwork, this, &bReturn);
            if (bReturn) return;
            sLine = "TOPIC " + sChan + " :" + sTopic;
        } else {
            NETWORKMODULECALL(OnUserTopicRequest(sChan), d->pUser, d->pNetwork, this, &bReturn);
            if (bReturn) return;
        }
    } else if (sCommand.equals("MODE")) {
        NoString sTarget = No::token(sLine, 1);
        NoString sModes = No::tokens(sLine, 2);

        if (d->pNetwork->IsChan(sTarget) && sModes.empty()) {
            // If we are on that channel and already received a
            // /mode reply from the server, we can answer this
            // request ourself.

            NoChannel* pChan = d->pNetwork->FindChan(sTarget);
            if (pChan && pChan->isOn() && !pChan->getModeString().empty()) {
                PutClient(":" + d->pNetwork->GetIRCServer() + " 324 " + GetNick() + " " + sTarget + " " + pChan->getModeString());
                if (pChan->getCreationDate() > 0) {
                    PutClient(":" + d->pNetwork->GetIRCServer() + " 329 " + GetNick() + " " + sTarget + " " +
                              NoString(pChan->getCreationDate()));
                }
                return;
            }
        }
    }

    PutIRC(sLine);
}

void NoClient::SetNick(const NoString& s) { d->sNick = s; }

void NoClient::SetAway(bool bAway) { d->bAway = bAway; }
NoUser* NoClient::GetUser() const { return d->pUser; }

NoNetwork* NoClient::GetNetwork() const { return d->pNetwork; }
void NoClient::SetNetwork(NoNetwork* pNetwork, bool bDisconnect, bool bReconnect)
{
    if (bDisconnect) {
        if (d->pNetwork) {
            d->pNetwork->ClientDisconnected(this);

            // Tell the client they are no longer in these channels.
            const std::vector<NoChannel*>& vChans = d->pNetwork->GetChans();
            for (const NoChannel* pChan : vChans) {
                if (!(pChan->isDetached())) {
                    PutClient(":" + d->pNetwork->GetIRCNick().nickMask() + " PART " + pChan->getName());
                }
            }
        } else if (d->pUser) {
            d->pUser->UserDisconnected(this);
        }
    }

    d->pNetwork = pNetwork;

    if (bReconnect) {
        if (d->pNetwork) {
            d->pNetwork->ClientConnected(this);
        } else if (d->pUser) {
            d->pUser->UserConnected(this);
        }
    }
}

std::vector<NoClient*> NoClient::GetClients() const
{
    if (d->pNetwork) {
        return d->pNetwork->GetClients();
    }

    return d->pUser->GetUserClients();
}

NoIrcSocket* NoClient::GetIRCSock() const
{
    if (d->pNetwork) {
        return d->pNetwork->GetIRCSock();
    }

    return nullptr;
}

void NoClient::StatusCTCP(const NoString& sLine)
{
    NoString sCommand = No::token(sLine, 0);

    if (sCommand.equals("PING")) {
        PutStatusNotice("\001PING " + No::tokens(sLine, 1) + "\001");
    } else if (sCommand.equals("VERSION")) {
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
        if (d->pNetwork) {
            PutStatusNotice(d->pNetwork->ExpandString(sLine));
        } else {
            PutStatusNotice(d->pUser->ExpandString(sLine));
        }
    }

    return true;
}

void NoClient::AuthUser()
{
    if (!d->bGotNick || !d->bGotUser || !d->bGotPass || d->bInCap || IsAttached()) return;

    d->spAuth = std::make_shared<NoClientAuth>(this, d->sUser, d->sPass);

    NoApp::Get().AuthUser(d->spAuth);
}

void NoClient::RefuseLogin(const NoString& sReason)
{
    PutStatus("Bad username and/or password.");
    PutClient(":irc.znc.in 464 " + GetNick() + " :" + sReason);
    d->pSocket->Close(NoSocket::CLT_AFTERWRITE);
}

void NoClient::AcceptLogin(NoUser& User)
{
    d->sPass = "";
    d->pUser = &User;

    // Set our proper timeout and set back our proper timeout mode
    // (constructor set a different timeout and mode)
    d->pSocket->SetTimeout(NoNetwork::NO_TRAFFIC_TIMEOUT, NoSocket::TMO_READ);

    d->pSocket->SetSockName("USR::" + d->pUser->GetUserName());
    d->pSocket->SetEncoding(d->pUser->GetClientEncoding());

    if (!d->sNetwork.empty()) {
        d->pNetwork = d->pUser->FindNetwork(d->sNetwork);
        if (!d->pNetwork) {
            PutStatus("Network (" + d->sNetwork + ") doesn't exist.");
        }
    } else if (!d->pUser->GetNetworks().empty()) {
        // If a user didn't supply a network, and they have a network called "default" then automatically use this
        // network.
        d->pNetwork = d->pUser->FindNetwork("default");
        // If no "default" network, try "user" network. It's for compatibility with early network stuff in ZNC, which
        // converted old configs to "user" network.
        if (!d->pNetwork) d->pNetwork = d->pUser->FindNetwork("user");
        // Otherwise, just try any network of the user.
        if (!d->pNetwork) d->pNetwork = *d->pUser->GetNetworks().begin();
        if (d->pNetwork && d->pUser->GetNetworks().size() > 1) {
            PutStatusNotice("You have several networks configured, but no network was specified for the connection.");
            PutStatusNotice("Selecting network [" + d->pNetwork->GetName() +
                            "]. To see list of all configured networks, use /znc ListNetworks");
            PutStatusNotice(
            "If you want to choose another network, use /znc JumpNetwork <network>, or connect to ZNC with username " +
            d->pUser->GetUserName() + "/<network> (instead of just " + d->pUser->GetUserName() + ")");
        }
    } else {
        PutStatusNotice("You have no networks configured. Use /znc AddNetwork <network> to add one.");
    }

    SetNetwork(d->pNetwork, false);

    SendMotd();

    NETWORKMODULECALL(OnClientLogin(), d->pUser, d->pNetwork, this, NOTHING);
}

void NoClient::BouncedOff()
{
    PutStatusNotice("You are being disconnected because another user just authenticated as you.");
    d->pSocket->Close(NoSocket::CLT_AFTERWRITE);
}

bool NoClient::IsAttached() const { return d->pUser != nullptr; }

bool NoClient::IsPlaybackActive() const { return d->bPlaybackActive; }
void NoClient::SetPlaybackActive(bool bActive) { d->bPlaybackActive = bActive; }

void NoClient::PutIRC(const NoString& sLine)
{
    if (d->pNetwork) {
        d->pNetwork->PutIRC(sLine);
    }
}

NoString NoClient::GetFullName() const
{
    if (!d->pUser) return d->pSocket->GetRemoteIP();
    NoString sFullName = d->pUser->GetUserName();
    if (!d->sIdentifier.empty()) sFullName += "@" + d->sIdentifier;
    if (d->pNetwork) sFullName += "/" + d->pNetwork->GetName();
    return sFullName;
}

void NoClient::PutClient(const NoString& sLine)
{
    bool bReturn = false;
    NoString sCopy = sLine;
    NETWORKMODULECALL(OnSendToClient(sCopy, *this), d->pUser, d->pNetwork, this, &bReturn);
    if (bReturn) return;
    NO_DEBUG("(" << GetFullName() << ") ZNC -> CLI [" << sCopy << "]");
    d->pSocket->Write(sCopy + "\r\n");
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
    if (!d->pUser) {
        return;
    }

    NO_DEBUG("(" << GetFullName() << ") ZNC -> CLI [:" + d->pUser->GetStatusPrefix() + ((sModule.empty()) ? "status" : sModule) + "!znc@znc.in NOTICE "
              << GetNick() << " :" << sLine << "]");
    d->pSocket->Write(":" + d->pUser->GetStatusPrefix() + ((sModule.empty()) ? "status" : sModule) + "!znc@znc.in NOTICE " +
          GetNick() + " :" + sLine + "\r\n");
}

void NoClient::PutModule(const NoString& sModule, const NoString& sLine)
{
    if (!d->pUser) {
        return;
    }

    NO_DEBUG("(" << GetFullName() << ") ZNC -> CLI [:" + d->pUser->GetStatusPrefix() + ((sModule.empty()) ? "status" : sModule) + "!znc@znc.in PRIVMSG "
              << GetNick() << " :" << sLine << "]");

    NoStringVector vsLines = sLine.split("\n");
    for (const NoString& s : vsLines) {
        d->pSocket->Write(":" + d->pUser->GetStatusPrefix() + ((sModule.empty()) ? "status" : sModule) + "!znc@znc.in PRIVMSG " +
              GetNick() + " :" + s + "\r\n");
    }
}

bool NoClient::IsCapEnabled(const NoString& sCap) const { return 1 == d->ssAcceptedCaps.count(sCap); }

NoString NoClient::GetNick(bool bAllowIRCNick) const
{
    NoString sRet;

    const NoIrcSocket* pSock = GetIRCSock();
    if (bAllowIRCNick && pSock && pSock->IsAuthed()) {
        sRet = pSock->GetNick();
    }

    return (sRet.empty()) ? d->sNick : sRet;
}

NoString NoClient::GetNickMask() const
{
    if (GetIRCSock() && GetIRCSock()->IsAuthed()) {
        return GetIRCSock()->GetNickMask();
    }

    NoString sHost = d->pNetwork ? d->pNetwork->GetBindHost() : d->pUser->GetBindHost();
    if (sHost.empty()) {
        sHost = "irc.znc.in";
    }

    return GetNick() + "!" + (d->pNetwork ? d->pNetwork->GetBindHost() : d->pUser->GetIdent()) + "@" + sHost;
}

NoString NoClient::GetIdentifier() const { return d->sIdentifier; }
bool NoClient::HasNamesx() const { return d->bNamesx; }
bool NoClient::HasUHNames() const { return d->bUHNames; }
bool NoClient::IsAway() const { return d->bAway; }
bool NoClient::HasServerTime() const { return d->bServerTime; }
bool NoClient::HasBatch() const { return d->bBatch; }
bool NoClient::HasSelfMessage() const { return d->bSelfMessage; }

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
    NoString sSubCmd = No::token(sLine, 1);

    if (sSubCmd.equals("LS")) {
        NoStringSet ssOfferCaps;
        GLOBALMODULECALL(OnClientCapLs(this, ssOfferCaps), NOTHING);
        ssOfferCaps.insert("userhost-in-names");
        ssOfferCaps.insert("multi-prefix");
        ssOfferCaps.insert("znc.in/server-time-iso");
        ssOfferCaps.insert("znc.in/batch");
        ssOfferCaps.insert("znc.in/self-message");
        NoString sRes = NoString(" ").join(ssOfferCaps.begin(), ssOfferCaps.end());
        RespondCap("LS :" + sRes);
        d->bInCap = true;
    } else if (sSubCmd.equals("END")) {
        d->bInCap = false;
        if (!IsAttached()) {
            if (!d->pUser && d->bGotUser && !d->bGotPass) {
                SendRequiredPasswordNotice();
            } else {
                AuthUser();
            }
        }
    } else if (sSubCmd.equals("REQ")) {
        NoStringVector vsTokens = No::tokens(sLine, 2).trimPrefix_n(":").split(" ", No::SkipEmptyParts);

        for (const NoString& sToken : vsTokens) {
            bool bVal = true;
            NoString sCap = sToken;
            if (sCap.trimPrefix("-")) bVal = false;

            bool bAccepted = ("multi-prefix" == sCap) || ("userhost-in-names" == sCap) || ("znc.in/server-time-iso" == sCap) ||
                             ("znc.in/batch" == sCap) || ("znc.in/self-message" == sCap);
            GLOBALMODULECALL(IsClientCapSupported(this, sCap, bVal), &bAccepted);

            if (!bAccepted) {
                // Some unsupported capability is requested
                RespondCap("NAK :" + No::tokens(sLine, 2).trimPrefix_n(":"));
                return;
            }
        }

        // All is fine, we support what was requested
        for (const NoString& sToken : vsTokens) {
            bool bVal = true;
            NoString sCap = sToken;
            if (sCap.trimPrefix("-")) bVal = false;

            if ("multi-prefix" == sCap) {
                d->bNamesx = bVal;
            } else if ("userhost-in-names" == sCap) {
                d->bUHNames = bVal;
            } else if ("znc.in/server-time-iso" == sCap) {
                d->bServerTime = bVal;
            } else if ("znc.in/batch" == sCap) {
                d->bBatch = bVal;
            } else if ("znc.in/self-message" == sCap) {
                d->bSelfMessage = bVal;
            }
            GLOBALMODULECALL(OnClientCapRequest(this, sCap, bVal), NOTHING);

            if (bVal) {
                d->ssAcceptedCaps.insert(sCap);
            } else {
                d->ssAcceptedCaps.erase(sCap);
            }
        }

        RespondCap("ACK :" + No::tokens(sLine, 2).trimPrefix_n(":"));
    } else if (sSubCmd.equals("LIST")) {
        NoString sList = NoString(" ").join(d->ssAcceptedCaps.begin(), d->ssAcceptedCaps.end());
        RespondCap("LIST :" + sList);
    } else if (sSubCmd.equals("CLEAR")) {
        NoStringSet ssRemoved;
        for (const NoString& sCap : d->ssAcceptedCaps) {
            bool bRemoving = false;
            GLOBALMODULECALL(IsClientCapSupported(this, sCap, false), &bRemoving);
            if (bRemoving) {
                GLOBALMODULECALL(OnClientCapRequest(this, sCap, false), NOTHING);
                ssRemoved.insert(sCap);
            }
        }
        if (d->bNamesx) {
            d->bNamesx = false;
            ssRemoved.insert("multi-prefix");
        }
        if (d->bUHNames) {
            d->bUHNames = false;
            ssRemoved.insert("userhost-in-names");
        }
        if (d->bServerTime) {
            d->bServerTime = false;
            ssRemoved.insert("znc.in/server-time-iso");
        }
        if (d->bBatch) {
            d->bBatch = false;
            ssRemoved.insert("znc.in/batch");
        }
        if (d->bSelfMessage) {
            d->bSelfMessage = false;
            ssRemoved.insert("znc.in/self-message");
        }
        NoString sList = "";
        for (const NoString& sCap : ssRemoved) {
            d->ssAcceptedCaps.erase(sCap);
            sList += "-" + sCap + " ";
        }
        RespondCap("ACK :" + sList.trimSuffix_n(" "));
    } else {
        PutClient(":irc.znc.in 410 " + GetNick() + " " + sSubCmd + " :Invalid CAP subcommand");
    }
}

void NoClient::ParsePass(const NoString& sAuthLine)
{
    // [user[@identifier][/network]:]password

    const size_t uColon = sAuthLine.find(":");
    if (uColon != NoString::npos) {
        d->sPass = sAuthLine.substr(uColon + 1);

        ParseUser(sAuthLine.substr(0, uColon));
    } else {
        d->sPass = sAuthLine;
    }
}

void NoClient::ParseUser(const NoString& sAuthLine)
{
    // user[@identifier][/network]

    const size_t uSlash = sAuthLine.rfind("/");
    if (uSlash != NoString::npos) {
        d->sNetwork = sAuthLine.substr(uSlash + 1);

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
            d->sIdentifier = sId;
            d->sUser = sAuthLine.substr(0, uAt);
        } else {
            d->sUser = sAuthLine;
        }
    } else {
        d->sUser = sAuthLine;
    }
}
