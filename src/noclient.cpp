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
#include "nonick.h"

#define CALLMOD(MOD, CLIENT, USER, NETWORK, FUNC)                             \
    {                                                                         \
        NoModule* pModule = nullptr;                                           \
        if (NETWORK && (pModule = (NETWORK)->loader()->findModule(MOD))) { \
            try {                                                             \
                pModule->setClient(CLIENT);                                   \
                pModule->FUNC;                                                \
                pModule->setClient(nullptr);                                  \
            } catch (const NoModule::ModException& e) {                       \
                if (e == NoModule::UNLOAD) {                                   \
                    (NETWORK)->loader()->unloadModule(MOD);                \
                }                                                             \
            }                                                                 \
        } else if ((pModule = (USER)->loader()->findModule(MOD))) {        \
            try {                                                             \
                pModule->setClient(CLIENT);                                   \
                pModule->setNetwork(NETWORK);                                 \
                pModule->FUNC;                                                \
                pModule->setClient(nullptr);                                  \
                pModule->setNetwork(nullptr);                                 \
            } catch (const NoModule::ModException& e) {                       \
                if (e == NoModule::UNLOAD) {                                   \
                    (USER)->loader()->unloadModule(MOD);                   \
                }                                                             \
            }                                                                 \
        } else if ((pModule = NoApp::Get().GetLoader()->findModule(MOD))) {    \
            try {                                                             \
                pModule->setClient(CLIENT);                                   \
                pModule->setNetwork(NETWORK);                                 \
                pModule->setUser(USER);                                       \
                pModule->FUNC;                                                \
                pModule->setClient(nullptr);                                  \
                pModule->setNetwork(nullptr);                                 \
                pModule->setUser(nullptr);                                    \
            } catch (const NoModule::ModException& e) {                       \
                if (e == NoModule::UNLOAD) {                                   \
                    NoApp::Get().GetLoader()->unloadModule(MOD);               \
                }                                                             \
            }                                                                 \
        } else {                                                              \
            putStatus("No such module [" + MOD + "]");                        \
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
        NoNetwork* pNetwork = m_pClient->network();
        m_pClient->SetNetwork(nullptr, true, false);

        NoUser* pUser = m_pClient->user();
        if (pUser)
            NETWORKMODULECALL(onClientDisconnect(), pUser, pNetwork, m_pClient, NOTHING);
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
    d->socket = new NoClientSocket(this);
}

NoClient::~NoClient()
{
    if (d->authenticator) {
        NoClientAuth* pAuth = (NoClientAuth*)&(*d->authenticator);
        pAuth->invalidate();
    }
    if (d->user != nullptr) {
        d->user->addBytesRead(d->socket->GetBytesRead());
        d->user->addBytesWritten(d->socket->GetBytesWritten());
    }
    delete d->socket;
}

NoSocket*NoClient::GetSocket() const { return d->socket; }

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
        NETWORKMODULECALL(onUserRaw(sLine), d->user, d->network, this, &bReturn);
    } else {
        GLOBALMODULECALL(onUnknownUserRaw(this, sLine), &bReturn);
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
            d->receivedPass = true;

            NoString sAuthLine = No::tokens(sLine, 1).trimPrefix_n();
            ParsePass(sAuthLine);

            AuthUser();
            return; // Don't forward this msg.  ZNC has already registered us.
        } else if (sCommand.equals("NICK")) {
            NoString sNick = No::token(sLine, 1).trimPrefix_n();

            d->nickname = sNick;
            d->receivedNick = true;

            AuthUser();
            return; // Don't forward this msg.  ZNC will handle nick changes until auth is complete
        } else if (sCommand.equals("USER")) {
            NoString sAuthLine = No::token(sLine, 1);

            if (d->username.empty() && !sAuthLine.empty()) {
                ParseUser(sAuthLine);
            }

            d->receivedUser = true;
            if (d->receivedPass) {
                AuthUser();
            } else if (!d->inCapLs) {
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

    if (!d->user) {
        // Only CAP, NICK, USER and PASS are allowed before login
        return;
    }

    if (sCommand.equals("ZNC")) {
        NoString sTarget = No::token(sLine, 1);
        NoString sModCommand;

        if (sTarget.trimPrefix(d->user->statusPrefix())) {
            sModCommand = No::tokens(sLine, 2);
        } else {
            sTarget = "status";
            sModCommand = No::tokens(sLine, 1);
        }

        if (sTarget.equals("status")) {
            if (sModCommand.empty())
                putStatus("Hello. How may I help you?");
            else
                UserCommand(sModCommand);
        } else {
            if (sModCommand.empty())
                CALLMOD(sTarget, this, d->user, d->network, putModule("Hello. How may I help you?"))
            else
                CALLMOD(sTarget, this, d->user, d->network, onModCommand(sModCommand))
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
        NETWORKMODULECALL(onUserQuit(sMsg), d->user, d->network, this, &bReturn);
        if (bReturn) return;
        d->socket->Close(NoSocket::CLT_AFTERWRITE); // Treat a client quit as a detach
        return; // Don't forward this msg.  We don't want the client getting us disconnected.
    } else if (sCommand.equals("PROTOCTL")) {
        NoStringVector vsTokens = No::tokens(sLine, 1).split(" ", No::SkipEmptyParts);

        for (const NoString& sToken : vsTokens) {
            if (sToken == "NAMESX") {
                d->hasNamesX = true;
            } else if (sToken == "UHNAMES") {
                d->hasUhNames = true;
            }
        }
        return; // If the server understands it, we already enabled namesx / uhnames
    } else if (sCommand.equals("NOTICE")) {
        NoString sTargets = No::token(sLine, 1).trimPrefix_n();
        NoString sMsg = No::tokens(sLine, 2).trimPrefix_n();
        NoStringVector vTargets = sTargets.split(",", No::SkipEmptyParts);

        for (NoString& sTarget : vTargets) {
            if (sTarget.trimPrefix(d->user->statusPrefix())) {
                if (!sTarget.equals("status")) {
                    CALLMOD(sTarget, this, d->user, d->network, onModNotice(sMsg));
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

                NETWORKMODULECALL(onUserCtcpReply(sTarget, sCTCP), d->user, d->network, this, &bContinue);
                if (bContinue) continue;

                sMsg = "\001" + sCTCP + "\001";
            } else {
                NETWORKMODULECALL(onUserNotice(sTarget, sMsg), d->user, d->network, this, &bContinue);
                if (bContinue) continue;
            }

            if (!ircSocket()) {
                // Some lagmeters do a NOTICE to their own nick, ignore those.
                if (!sTarget.equals(d->nickname))
                    putStatus("Your notice to [" + sTarget + "] got lost, "
                                                             "you are not connected to IRC!");
                continue;
            }

            if (d->network) {
                NoChannel* pChan = d->network->findChannel(sTarget);

                if ((pChan) && (!pChan->autoClearChanBuffer())) {
                    pChan->addBuffer(":" + _NAMEDFMT(GetNickMask()) + " NOTICE " + _NAMEDFMT(sTarget) + " :{text}", sMsg);
                }

                // Relay to the rest of the clients that may be connected to this user
                const std::vector<NoClient*>& vClients = clients();

                for (NoClient* pClient : vClients) {
                    if (pClient != this && (d->network->isChannel(sTarget) || pClient->HasSelfMessage())) {
                        pClient->PutClient(":" + GetNickMask() + " NOTICE " + sTarget + " :" + sMsg);
                    }
                }

                putIrc("NOTICE " + sTarget + " :" + sMsg);
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

                if (sTarget.trimPrefix(d->user->statusPrefix())) {
                    if (sTarget.equals("status")) {
                        StatusCTCP(sCTCP);
                    } else {
                        CALLMOD(sTarget, this, d->user, d->network, onModCTCP(sCTCP));
                    }
                    continue;
                }

                if (d->network) {
                    if (No::token(sCTCP, 0).equals("ACTION")) {
                        NoString sMessage = No::tokens(sCTCP, 1);
                        NETWORKMODULECALL(onUserAction(sTarget, sMessage), d->user, d->network, this, &bContinue);
                        if (bContinue) continue;
                        sCTCP = "ACTION " + sMessage;

                        if (d->network->isChannel(sTarget)) {
                            NoChannel* pChan = d->network->findChannel(sTarget);

                            if (pChan && (!pChan->autoClearChanBuffer() || !d->network->isUserOnline())) {
                                pChan->addBuffer(":" + _NAMEDFMT(GetNickMask()) + " PRIVMSG " + _NAMEDFMT(sTarget) +
                                                 " :\001ACTION {text}\001",
                                                 sMessage);
                            }
                        } else {
                            if (!d->user->autoclearQueryBuffer() || !d->network->isUserOnline()) {
                                NoQuery* pQuery = d->network->addQuery(sTarget);
                                if (pQuery) {
                                    pQuery->addBuffer(":" + _NAMEDFMT(GetNickMask()) + " PRIVMSG " + _NAMEDFMT(sTarget) + " :\001ACTION {text}\001",
                                                      sMessage);
                                }
                            }
                        }

                        // Relay to the rest of the clients that may be connected to this user
                        const std::vector<NoClient*>& vClients = clients();

                        for (NoClient* pClient : vClients) {
                            if (pClient != this && (d->network->isChannel(sTarget) || pClient->HasSelfMessage())) {
                                pClient->PutClient(":" + GetNickMask() + " PRIVMSG " + sTarget + " :\001" + sCTCP + "\001");
                            }
                        }
                    } else {
                        NETWORKMODULECALL(onUserCtcp(sTarget, sCTCP), d->user, d->network, this, &bContinue);
                        if (bContinue) continue;
                    }

                    putIrc("PRIVMSG " + sTarget + " :\001" + sCTCP + "\001");
                }

                continue;
            }

            if (sTarget.trimPrefix(d->user->statusPrefix())) {
                if (sTarget.equals("status")) {
                    UserCommand(sMsg);
                } else {
                    CALLMOD(sTarget, this, d->user, d->network, onModCommand(sMsg));
                }
                continue;
            }

            NETWORKMODULECALL(onUserMsg(sTarget, sMsg), d->user, d->network, this, &bContinue);
            if (bContinue) continue;

            if (!ircSocket()) {
                // Some lagmeters do a PRIVMSG to their own nick, ignore those.
                if (!sTarget.equals(d->nickname))
                    putStatus("Your message to [" + sTarget + "] got lost, "
                                                              "you are not connected to IRC!");
                continue;
            }

            if (d->network) {
                if (d->network->isChannel(sTarget)) {
                    NoChannel* pChan = d->network->findChannel(sTarget);

                    if ((pChan) && (!pChan->autoClearChanBuffer() || !d->network->isUserOnline())) {
                        pChan->addBuffer(":" + _NAMEDFMT(GetNickMask()) + " PRIVMSG " + _NAMEDFMT(sTarget) + " :{text}", sMsg);
                    }
                } else {
                    if (!d->user->autoclearQueryBuffer() || !d->network->isUserOnline()) {
                        NoQuery* pQuery = d->network->addQuery(sTarget);
                        if (pQuery) {
                            pQuery->addBuffer(":" + _NAMEDFMT(GetNickMask()) + " PRIVMSG " + _NAMEDFMT(sTarget) +
                                              " :{text}",
                                              sMsg);
                        }
                    }
                }

                putIrc("PRIVMSG " + sTarget + " :" + sMsg);

                // Relay to the rest of the clients that may be connected to this user
                const std::vector<NoClient*>& vClients = clients();

                for (NoClient* pClient : vClients) {
                    if (pClient != this && (d->network->isChannel(sTarget) || pClient->HasSelfMessage())) {
                        pClient->PutClient(":" + GetNickMask() + " PRIVMSG " + sTarget + " :" + sMsg);
                    }
                }
            }
        }

        return;
    }

    if (!d->network) {
        return; // The following commands require a network
    }

    if (sCommand.equals("DETACH")) {
        NoString sPatterns = No::tokens(sLine, 1);

        if (sPatterns.empty()) {
            putStatusNotice("Usage: /detach <#chans>");
            return;
        }

        sPatterns.replace(",", " ");
        NoStringVector vsChans = sPatterns.split(" ", No::SkipEmptyParts);

        std::set<NoChannel*> sChans;
        for (const NoString& sChan : vsChans) {
            std::vector<NoChannel*> vChans = d->network->findChannels(sChan);
            sChans.insert(vChans.begin(), vChans.end());
        }

        uint uDetached = 0;
        for (NoChannel* pChan : sChans) {
            if (pChan->isDetached()) continue;
            uDetached++;
            pChan->detachUser();
        }

        putStatusNotice("There were [" + NoString(sChans.size()) + "] channels matching [" + sPatterns + "]");
        putStatusNotice("Detached [" + NoString(uDetached) + "] channels");

        return;
    } else if (sCommand.equals("JOIN")) {
        NoString sChans = No::token(sLine, 1).trimPrefix_n();
        NoString sKey = No::token(sLine, 2);

        NoStringVector vsChans = sChans.split(",", No::SkipEmptyParts);
        sChans.clear();

        for (NoString& sChannel : vsChans) {
            bool bContinue = false;
            NETWORKMODULECALL(onUserJoin(sChannel, sKey), d->user, d->network, this, &bContinue);
            if (bContinue) continue;

            NoChannel* pChan = d->network->findChannel(sChannel);
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
            NETWORKMODULECALL(onUserPart(sChan, sMessage), d->user, d->network, this, &bContinue);
            if (bContinue) continue;

            NoChannel* pChan = d->network->findChannel(sChan);

            if (pChan && !pChan->isOn()) {
                putStatusNotice("Removing channel [" + sChan + "]");
                d->network->removeChannel(sChan);
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
            NETWORKMODULECALL(onUserTopic(sChan, sTopic), d->user, d->network, this, &bReturn);
            if (bReturn) return;
            sLine = "TOPIC " + sChan + " :" + sTopic;
        } else {
            NETWORKMODULECALL(onUserTopicRequest(sChan), d->user, d->network, this, &bReturn);
            if (bReturn) return;
        }
    } else if (sCommand.equals("MODE")) {
        NoString sTarget = No::token(sLine, 1);
        NoString sModes = No::tokens(sLine, 2);

        if (d->network->isChannel(sTarget) && sModes.empty()) {
            // If we are on that channel and already received a
            // /mode reply from the server, we can answer this
            // request ourself.

            NoChannel* pChan = d->network->findChannel(sTarget);
            if (pChan && pChan->isOn() && !pChan->modeString().empty()) {
                PutClient(":" + d->network->ircServer() + " 324 " + GetNick() + " " + sTarget + " " + pChan->modeString());
                if (pChan->creationDate() > 0) {
                    PutClient(":" + d->network->ircServer() + " 329 " + GetNick() + " " + sTarget + " " +
                              NoString(pChan->creationDate()));
                }
                return;
            }
        }
    }

    putIrc(sLine);
}

void NoClient::SetNick(const NoString& s) { d->nickname = s; }

void NoClient::SetAway(bool bAway) { d->away = bAway; }
NoUser* NoClient::user() const { return d->user; }

NoNetwork* NoClient::network() const { return d->network; }
void NoClient::SetNetwork(NoNetwork* pNetwork, bool bDisconnect, bool bReconnect)
{
    if (bDisconnect) {
        if (d->network) {
            d->network->clientDisconnected(this);

            // Tell the client they are no longer in these channels.
            const std::vector<NoChannel*>& vChans = d->network->channels();
            for (const NoChannel* pChan : vChans) {
                if (!(pChan->isDetached())) {
                    PutClient(":" + d->network->ircNick().nickMask() + " PART " + pChan->name());
                }
            }
        } else if (d->user) {
            d->user->userDisconnected(this);
        }
    }

    d->network = pNetwork;

    if (bReconnect) {
        if (d->network) {
            d->network->clientConnected(this);
        } else if (d->user) {
            d->user->userConnected(this);
        }
    }
}

std::vector<NoClient*> NoClient::clients() const
{
    if (d->network) {
        return d->network->clients();
    }

    return d->user->userClients();
}

NoIrcSocket* NoClient::ircSocket() const
{
    if (d->network) {
        return d->network->ircSocket();
    }

    return nullptr;
}

void NoClient::StatusCTCP(const NoString& sLine)
{
    NoString sCommand = No::token(sLine, 0);

    if (sCommand.equals("PING")) {
        putStatusNotice("\001PING " + No::tokens(sLine, 1) + "\001");
    } else if (sCommand.equals("VERSION")) {
        putStatusNotice("\001VERSION " + NoApp::GetTag() + "\001");
    }
}

bool NoClient::SendMotd()
{
    const NoStringVector& vsMotd = NoApp::Get().GetMotd();

    if (!vsMotd.size()) {
        return false;
    }

    for (const NoString& sLine : vsMotd) {
        if (d->network) {
            putStatusNotice(d->network->expandString(sLine));
        } else {
            putStatusNotice(d->user->expandString(sLine));
        }
    }

    return true;
}

void NoClient::AuthUser()
{
    if (!d->receivedNick || !d->receivedUser || !d->receivedPass || d->inCapLs || IsAttached()) return;

    d->authenticator = std::make_shared<NoClientAuth>(this, d->username, d->password);

    NoApp::Get().AuthUser(d->authenticator);
}

void NoClient::RefuseLogin(const NoString& sReason)
{
    putStatus("Bad username and/or password.");
    PutClient(":irc.znc.in 464 " + GetNick() + " :" + sReason);
    d->socket->Close(NoSocket::CLT_AFTERWRITE);
}

void NoClient::AcceptLogin(NoUser& User)
{
    d->password = "";
    d->user = &User;

    // Set our proper timeout and set back our proper timeout mode
    // (constructor set a different timeout and mode)
    d->socket->SetTimeout(NoNetwork::NoTrafficTimeout, NoSocket::TMO_READ);

    d->socket->SetSockName("USR::" + d->user->userName());
    d->socket->SetEncoding(d->user->clientEncoding());

    if (!d->sNetwork.empty()) {
        d->network = d->user->findNetwork(d->sNetwork);
        if (!d->network) {
            putStatus("Network (" + d->sNetwork + ") doesn't exist.");
        }
    } else if (!d->user->networks().empty()) {
        // If a user didn't supply a network, and they have a network called "default" then automatically use this
        // network.
        d->network = d->user->findNetwork("default");
        // If no "default" network, try "user" network. It's for compatibility with early network stuff in ZNC, which
        // converted old configs to "user" network.
        if (!d->network) d->network = d->user->findNetwork("user");
        // Otherwise, just try any network of the user.
        if (!d->network) d->network = *d->user->networks().begin();
        if (d->network && d->user->networks().size() > 1) {
            putStatusNotice("You have several networks configured, but no network was specified for the connection.");
            putStatusNotice("Selecting network [" + d->network->name() +
                            "]. To see list of all configured networks, use /znc ListNetworks");
            putStatusNotice(
            "If you want to choose another network, use /znc JumpNetwork <network>, or connect to ZNC with username " +
            d->user->userName() + "/<network> (instead of just " + d->user->userName() + ")");
        }
    } else {
        putStatusNotice("You have no networks configured. Use /znc AddNetwork <network> to add one.");
    }

    SetNetwork(d->network, false);

    SendMotd();

    NETWORKMODULECALL(onClientLogin(), d->user, d->network, this, NOTHING);
}

void NoClient::BouncedOff()
{
    putStatusNotice("You are being disconnected because another user just authenticated as you.");
    d->socket->Close(NoSocket::CLT_AFTERWRITE);
}

bool NoClient::IsAttached() const { return d->user != nullptr; }

bool NoClient::IsPlaybackActive() const { return d->inPlayback; }
void NoClient::SetPlaybackActive(bool bActive) { d->inPlayback = bActive; }

void NoClient::putIrc(const NoString& sLine)
{
    if (d->network) {
        d->network->putIrc(sLine);
    }
}

NoString NoClient::GetFullName() const
{
    if (!d->user) return d->socket->GetRemoteIP();
    NoString sFullName = d->user->userName();
    if (!d->identifier.empty()) sFullName += "@" + d->identifier;
    if (d->network) sFullName += "/" + d->network->name();
    return sFullName;
}

void NoClient::PutClient(const NoString& sLine)
{
    bool bReturn = false;
    NoString sCopy = sLine;
    NETWORKMODULECALL(onSendToClient(sCopy, *this), d->user, d->network, this, &bReturn);
    if (bReturn) return;
    NO_DEBUG("(" << GetFullName() << ") ZNC -> CLI [" << sCopy << "]");
    d->socket->Write(sCopy + "\r\n");
}

void NoClient::putStatusNotice(const NoString& sLine) { putModuleNotice("status", sLine); }

uint NoClient::putStatus(const NoTable& table)
{
    NoStringVector lines = table.toString();
    for (const NoString& line : lines)
        putStatus(line);
    return lines.size() - 1;
}

void NoClient::putStatus(const NoString& sLine) { putModule("status", sLine); }

void NoClient::putModuleNotice(const NoString& sModule, const NoString& sLine)
{
    if (!d->user) {
        return;
    }

    NO_DEBUG("(" << GetFullName() << ") ZNC -> CLI [:" + d->user->statusPrefix() + ((sModule.empty()) ? "status" : sModule) + "!znc@znc.in NOTICE "
              << GetNick() << " :" << sLine << "]");
    d->socket->Write(":" + d->user->statusPrefix() + ((sModule.empty()) ? "status" : sModule) + "!znc@znc.in NOTICE " +
          GetNick() + " :" + sLine + "\r\n");
}

void NoClient::putModule(const NoString& sModule, const NoString& sLine)
{
    if (!d->user) {
        return;
    }

    NO_DEBUG("(" << GetFullName() << ") ZNC -> CLI [:" + d->user->statusPrefix() + ((sModule.empty()) ? "status" : sModule) + "!znc@znc.in PRIVMSG "
              << GetNick() << " :" << sLine << "]");

    NoStringVector vsLines = sLine.split("\n");
    for (const NoString& s : vsLines) {
        d->socket->Write(":" + d->user->statusPrefix() + ((sModule.empty()) ? "status" : sModule) + "!znc@znc.in PRIVMSG " +
              GetNick() + " :" + s + "\r\n");
    }
}

bool NoClient::IsCapEnabled(const NoString& sCap) const { return 1 == d->acceptedCaps.count(sCap); }

NoString NoClient::GetNick(bool bAllowIRCNick) const
{
    NoString sRet;

    const NoIrcSocket* pSock = ircSocket();
    if (bAllowIRCNick && pSock && pSock->IsAuthed()) {
        sRet = pSock->GetNick();
    }

    return (sRet.empty()) ? d->nickname : sRet;
}

NoString NoClient::GetNickMask() const
{
    if (ircSocket() && ircSocket()->IsAuthed()) {
        return ircSocket()->GetNickMask();
    }

    NoString sHost = d->network ? d->network->bindHost() : d->user->bindHost();
    if (sHost.empty()) {
        sHost = "irc.znc.in";
    }

    return GetNick() + "!" + (d->network ? d->network->bindHost() : d->user->ident()) + "@" + sHost;
}

NoString NoClient::GetIdentifier() const { return d->identifier; }
bool NoClient::HasNamesx() const { return d->hasNamesX; }
bool NoClient::HasUHNames() const { return d->hasUhNames; }
bool NoClient::IsAway() const { return d->away; }
bool NoClient::HasServerTime() const { return d->hasServerTime; }
bool NoClient::HasBatch() const { return d->hasBatch; }
bool NoClient::HasSelfMessage() const { return d->hasSelfMessage; }

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
        GLOBALMODULECALL(onClientCapLs(this, ssOfferCaps), NOTHING);
        ssOfferCaps.insert("userhost-in-names");
        ssOfferCaps.insert("multi-prefix");
        ssOfferCaps.insert("znc.in/server-time-iso");
        ssOfferCaps.insert("znc.in/batch");
        ssOfferCaps.insert("znc.in/self-message");
        NoString sRes = NoString(" ").join(ssOfferCaps.begin(), ssOfferCaps.end());
        RespondCap("LS :" + sRes);
        d->inCapLs = true;
    } else if (sSubCmd.equals("END")) {
        d->inCapLs = false;
        if (!IsAttached()) {
            if (!d->user && d->receivedUser && !d->receivedPass) {
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
            GLOBALMODULECALL(isClientCapSupported(this, sCap, bVal), &bAccepted);

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
                d->hasNamesX = bVal;
            } else if ("userhost-in-names" == sCap) {
                d->hasUhNames = bVal;
            } else if ("znc.in/server-time-iso" == sCap) {
                d->hasServerTime = bVal;
            } else if ("znc.in/batch" == sCap) {
                d->hasBatch = bVal;
            } else if ("znc.in/self-message" == sCap) {
                d->hasSelfMessage = bVal;
            }
            GLOBALMODULECALL(onClientCapRequest(this, sCap, bVal), NOTHING);

            if (bVal) {
                d->acceptedCaps.insert(sCap);
            } else {
                d->acceptedCaps.erase(sCap);
            }
        }

        RespondCap("ACK :" + No::tokens(sLine, 2).trimPrefix_n(":"));
    } else if (sSubCmd.equals("LIST")) {
        NoString sList = NoString(" ").join(d->acceptedCaps.begin(), d->acceptedCaps.end());
        RespondCap("LIST :" + sList);
    } else if (sSubCmd.equals("CLEAR")) {
        NoStringSet ssRemoved;
        for (const NoString& sCap : d->acceptedCaps) {
            bool bRemoving = false;
            GLOBALMODULECALL(isClientCapSupported(this, sCap, false), &bRemoving);
            if (bRemoving) {
                GLOBALMODULECALL(onClientCapRequest(this, sCap, false), NOTHING);
                ssRemoved.insert(sCap);
            }
        }
        if (d->hasNamesX) {
            d->hasNamesX = false;
            ssRemoved.insert("multi-prefix");
        }
        if (d->hasUhNames) {
            d->hasUhNames = false;
            ssRemoved.insert("userhost-in-names");
        }
        if (d->hasServerTime) {
            d->hasServerTime = false;
            ssRemoved.insert("znc.in/server-time-iso");
        }
        if (d->hasBatch) {
            d->hasBatch = false;
            ssRemoved.insert("znc.in/batch");
        }
        if (d->hasSelfMessage) {
            d->hasSelfMessage = false;
            ssRemoved.insert("znc.in/self-message");
        }
        NoString sList = "";
        for (const NoString& sCap : ssRemoved) {
            d->acceptedCaps.erase(sCap);
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
        d->password = sAuthLine.substr(uColon + 1);

        ParseUser(sAuthLine.substr(0, uColon));
    } else {
        d->password = sAuthLine;
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
            d->identifier = sId;
            d->username = sAuthLine.substr(0, uAt);
        } else {
            d->username = sAuthLine;
        }
    } else {
        d->username = sAuthLine;
    }
}
