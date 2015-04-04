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
#include "nouser_p.h"
#include "nonetwork.h"
#include "noquery.h"
#include "nomodule_p.h"
#include "noapp.h"
#include "noescape.h"
#include "nonick.h"
#include "notable.h"
#include "noexception.h"

#define CALLMOD(MOD, CLIENT, USER, NETWORK, FUNC)                           \
    {                                                                       \
        NoModule* module = nullptr;                                        \
        if (NETWORK && (module = (NETWORK)->loader()->findModule(MOD))) {  \
            try {                                                           \
                NoModulePrivate::get(module)->client = CLIENT;                                 \
                module->FUNC;                                              \
                NoModulePrivate::get(module)->client = nullptr;                                \
            } catch (const NoException& e) {                     \
                if (e.type() == NoException::Unload) {                                \
                    (NETWORK)->loader()->unloadModule(MOD);                 \
                }                                                           \
            }                                                               \
        } else if ((module = (USER)->loader()->findModule(MOD))) {         \
            try {                                                           \
                NoModulePrivate::get(module)->client = CLIENT;                                 \
                NoModulePrivate::get(module)->network = NETWORK;                               \
                module->FUNC;                                              \
                NoModulePrivate::get(module)->client = nullptr;                                \
                NoModulePrivate::get(module)->network = nullptr;                               \
            } catch (const NoException& e) {                     \
                if (e.type() == NoException::Unload) {                                \
                    (USER)->loader()->unloadModule(MOD);                    \
                }                                                           \
            }                                                               \
        } else if ((module = noApp->loader()->findModule(MOD))) { \
            try {                                                           \
                NoModulePrivate::get(module)->client = CLIENT;                                 \
                NoModulePrivate::get(module)->network = NETWORK;                               \
                NoModulePrivate::get(module)->user = USER;                                     \
                module->FUNC;                                              \
                NoModulePrivate::get(module)->client = nullptr;                                \
                NoModulePrivate::get(module)->network = nullptr;                               \
                NoModulePrivate::get(module)->user = nullptr;                                  \
            } catch (const NoException& e) {                     \
                if (e.type() == NoException::Unload) {                                \
                    noApp->loader()->unloadModule(MOD);            \
                }                                                           \
            }                                                               \
        } else {                                                            \
            putStatus("No such module [" + MOD + "]");                      \
        }                                                                   \
    }

class NoClientSocket : public NoSocket
{
public:
    NoClientSocket(NoClient* client) : m_pClient(client)
    {
        NoSocketPrivate::get(this)->allowControlCodes = true;

        enableReadLine();
        // RFC says a line can have 512 chars max, but we are
        // a little more gentle ;)
        setMaxBufferThreshold(1024);
    }

    void readLine(const NoString& data) override
    {
        m_pClient->readLine(data);
    }
    void onTimeout() override
    {
        m_pClient->putClient("ERROR :Closing link [Timeout]");
    }
    void onConnected() override
    {
        NO_DEBUG(name() << " == Connected();");
    }
    void onConnectionRefused() override
    {
        NO_DEBUG(name() << " == ConnectionRefused()");
    }

    void onDisconnected() override
    {
        NO_DEBUG(name() << " == Disconnected()");
        NoNetwork* network = m_pClient->network();
        m_pClient->setNetwork(nullptr, true, false);

        NoUser* user = m_pClient->user();
        if (user)
            NETWORKMODULECALL(onClientDisconnect(), user, network, m_pClient, NOTHING);
    }

    void onReachedMaxBuffer() override
    {
        NO_DEBUG(name() << " == ReachedMaxBuffer()");
        if (m_pClient->isAttached()) {
            m_pClient->putClient("ERROR :Closing link [Too long raw line]");
        }
        close();
    }

private:
    NoClient* m_pClient;
};

class NoClientAuth : public NoAuthenticator
{
public:
    NoClientAuth(NoClient* client, const NoString& username, const NoString& sPassword)
        : NoAuthenticator(username, sPassword, client->socket()), m_pClient(client)
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
            m_pClient->acceptLogin(user);
    }

    void loginRefused(NoUser* user, const NoString& reason) override
    {
        if (m_pClient)
            m_pClient->refuseLogin(reason);
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
        NoUserPrivate::get(d->user)->addBytesRead(d->socket->bytesRead());
        NoUserPrivate::get(d->user)->addBytesWritten(d->socket->bytesWritten());
    }
    delete d->socket;
}

NoSocket* NoClient::socket() const
{
    return d->socket;
}

void NoClient::sendRequiredPasswordNotice()
{
    putClient(":irc.znc.in 464 " + nick() + " :Password required");
    putClient(":irc.znc.in NOTICE AUTH :*** "
              "You need to send your password. "
              "Configure your client to send a server password.");
    putClient(":irc.znc.in NOTICE AUTH :*** "
              "To connect now, you can use /quote PASS <username>:<password>, "
              "or /quote PASS <username>/<network>:<password> to connect to a specific network.");
}

void NoClient::readLine(const NoString& data)
{
    NoString line = data;

    line.trimRight("\n\r");

    NO_DEBUG("(" << fullName() << ") CLI -> ZNC [" << line << "]");

    if (line.left(1) == "@") {
        // TODO support message-tags properly
        line = No::tokens(line, 1);
    }

    bool bReturn = false;
    if (isAttached()) {
        NETWORKMODULECALL(onUserRaw(line), d->user, d->network, this, &bReturn);
    } else {
        GLOBALMODULECALL(onUnknownUserRaw(this, line), &bReturn);
    }
    if (bReturn)
        return;

    NoString command = No::token(line, 0);
    if (command.left(1) == ":") {
        // Evil client! Sending a nickmask prefix on client's command
        // is bad, bad, bad, bad, bad, bad, bad, bad, BAD, B A D!
        line = No::tokens(line, 1);
        command = No::token(line, 0);
    }

    if (!isAttached()) { // The following commands happen before authentication with ZNC
        if (command.equals("PASS")) {
            d->receivedPass = true;

            NoString auth = No::tokens(line, 1).trimPrefix_n();
            parsePass(auth);

            authUser();
            return; // Don't forward this msg.  ZNC has already registered us.
        } else if (command.equals("NICK")) {
            NoString nick = No::token(line, 1).trimPrefix_n();

            d->nickname = nick;
            d->receivedNick = true;

            authUser();
            return; // Don't forward this msg.  ZNC will handle nick changes until auth is complete
        } else if (command.equals("USER")) {
            NoString auth = No::token(line, 1);

            if (d->username.empty() && !line.empty()) {
                parseUser(auth);
            }

            d->receivedUser = true;
            if (d->receivedPass) {
                authUser();
            } else if (!d->inCapLs) {
                sendRequiredPasswordNotice();
            }

            return; // Don't forward this msg.  ZNC has already registered us.
        }
    }

    if (command.equals("CAP")) {
        handleCap(line);

        // Don't let the client talk to the server directly about CAP,
        // we don't want anything enabled that ZNC does not support.
        return;
    }

    if (!d->user) {
        // Only CAP, NICK, USER and PASS are allowed before login
        return;
    }

    if (command.equals("ZNC")) {
        NoString target = No::token(line, 1);
        NoString sModCommand;

        if (target.trimPrefix(d->user->statusPrefix())) {
            sModCommand = No::tokens(line, 2);
        } else {
            target = "status";
            sModCommand = No::tokens(line, 1);
        }

        if (target.equals("status")) {
            if (sModCommand.empty())
                putStatus("Hello. How may I help you?");
            else
                userCommand(sModCommand);
        } else {
            if (sModCommand.empty())
                CALLMOD(target, this, d->user, d->network, putModule("Hello. How may I help you?"))
            else
                CALLMOD(target, this, d->user, d->network, onModCommand(sModCommand))
        }
        return;
    } else if (command.equals("PING")) {
        // All PONGs are generated by ZNC. We will still forward this to
        // the ircd, but all PONGs from irc will be blocked.
        if (line.length() >= 5)
            putClient(":irc.znc.in PONG irc.znc.in " + line.substr(5));
        else
            putClient(":irc.znc.in PONG irc.znc.in");
    } else if (command.equals("PONG")) {
        // Block PONGs, we already responded to the pings
        return;
    } else if (command.equals("QUIT")) {
        NoString msg = No::tokens(line, 1).trimPrefix_n();
        NETWORKMODULECALL(onUserQuit(msg), d->user, d->network, this, &bReturn);
        if (bReturn)
            return;
        d->socket->close(NoSocket::CloseAfterWrite); // Treat a client quit as a detach
        return; // Don't forward this msg.  We don't want the client getting us disconnected.
    } else if (command.equals("PROTOCTL")) {
        NoStringVector vsTokens = No::tokens(line, 1).split(" ", No::SkipEmptyParts);

        for (const NoString& sToken : vsTokens) {
            if (sToken == "NAMESX") {
                d->hasNamesX = true;
            } else if (sToken == "UHNAMES") {
                d->hasUhNames = true;
            }
        }
        return; // If the server understands it, we already enabled namesx / uhnames
    } else if (command.equals("NOTICE")) {
        NoString sTargets = No::token(line, 1).trimPrefix_n();
        NoString msg = No::tokens(line, 2).trimPrefix_n();
        NoStringVector vTargets = sTargets.split(",", No::SkipEmptyParts);

        for (NoString& target : vTargets) {
            if (target.trimPrefix(d->user->statusPrefix())) {
                if (!target.equals("status")) {
                    CALLMOD(target, this, d->user, d->network, onModNotice(msg));
                }
                continue;
            }

            bool bContinue = false;
            if (No::wildCmp(msg, "\001*\001")) {
                NoString ctcp = msg;
                ctcp.leftChomp(1);
                ctcp.rightChomp(1);

                if (No::token(ctcp, 0) == "VERSION") {
                    ctcp += " via " + NoApp::tag(false);
                }

                NETWORKMODULECALL(onUserCtcpReply(target, ctcp), d->user, d->network, this, &bContinue);
                if (bContinue)
                    continue;

                msg = "\001" + ctcp + "\001";
            } else {
                NETWORKMODULECALL(onUserNotice(target, msg), d->user, d->network, this, &bContinue);
                if (bContinue)
                    continue;
            }

            if (!ircSocket()) {
                // Some lagmeters do a NOTICE to their own nick, ignore those.
                if (!target.equals(d->nickname))
                    putStatus("Your notice to [" + target + "] got lost, "
                                                             "you are not connected to IRC!");
                continue;
            }

            if (d->network) {
                NoChannel* channel = d->network->findChannel(target);

                if ((channel) && (!channel->autoClearChanBuffer())) {
                    channel->addBuffer(":" + _NAMEDFMT(nickMask()) + " NOTICE " + _NAMEDFMT(target) + " :{text}", msg);
                }

                // Relay to the rest of the clients that may be connected to this user
                const std::vector<NoClient*>& vClients = clients();

                for (NoClient* client : vClients) {
                    if (client != this && (d->network->isChannel(target) || client->hasSelfMessage())) {
                        client->putClient(":" + nickMask() + " NOTICE " + target + " :" + msg);
                    }
                }

                putIrc("NOTICE " + target + " :" + msg);
            }
        }

        return;
    } else if (command.equals("PRIVMSG")) {
        NoString sTargets = No::token(line, 1);
        NoString msg = No::tokens(line, 2).trimPrefix_n();
        NoStringVector vTargets = sTargets.split(",", No::SkipEmptyParts);

        for (NoString& target : vTargets) {
            bool bContinue = false;
            if (No::wildCmp(msg, "\001*\001")) {
                NoString ctcp = msg;
                ctcp.leftChomp(1);
                ctcp.rightChomp(1);

                if (target.trimPrefix(d->user->statusPrefix())) {
                    if (target.equals("status")) {
                        statusCtcp(ctcp);
                    } else {
                        CALLMOD(target, this, d->user, d->network, onModCTCP(ctcp));
                    }
                    continue;
                }

                if (d->network) {
                    if (No::token(ctcp, 0).equals("ACTION")) {
                        NoString message = No::tokens(ctcp, 1);
                        NETWORKMODULECALL(onUserAction(target, message), d->user, d->network, this, &bContinue);
                        if (bContinue)
                            continue;
                        ctcp = "ACTION " + message;

                        if (d->network->isChannel(target)) {
                            NoChannel* channel = d->network->findChannel(target);

                            if (channel && (!channel->autoClearChanBuffer() || !d->network->isUserOnline())) {
                                channel->addBuffer(":" + _NAMEDFMT(nickMask()) + " PRIVMSG " + _NAMEDFMT(target) +
                                                 " :\001ACTION {text}\001",
                                                 message);
                            }
                        } else {
                            if (!d->user->autoclearQueryBuffer() || !d->network->isUserOnline()) {
                                NoQuery* query = d->network->addQuery(target);
                                if (query) {
                                    query->addBuffer(":" + _NAMEDFMT(nickMask()) + " PRIVMSG " + _NAMEDFMT(target) + " :\001ACTION {text}\001",
                                                      message);
                                }
                            }
                        }

                        // Relay to the rest of the clients that may be connected to this user
                        const std::vector<NoClient*>& vClients = clients();

                        for (NoClient* client : vClients) {
                            if (client != this && (d->network->isChannel(target) || client->hasSelfMessage())) {
                                client->putClient(":" + nickMask() + " PRIVMSG " + target + " :\001" + ctcp + "\001");
                            }
                        }
                    } else {
                        NETWORKMODULECALL(onUserCtcp(target, ctcp), d->user, d->network, this, &bContinue);
                        if (bContinue)
                            continue;
                    }

                    putIrc("PRIVMSG " + target + " :\001" + ctcp + "\001");
                }

                continue;
            }

            if (target.trimPrefix(d->user->statusPrefix())) {
                if (target.equals("status")) {
                    userCommand(msg);
                } else {
                    CALLMOD(target, this, d->user, d->network, onModCommand(msg));
                }
                continue;
            }

            NETWORKMODULECALL(onUserMsg(target, msg), d->user, d->network, this, &bContinue);
            if (bContinue)
                continue;

            if (!ircSocket()) {
                // Some lagmeters do a PRIVMSG to their own nick, ignore those.
                if (!target.equals(d->nickname))
                    putStatus("Your message to [" + target + "] got lost, "
                                                              "you are not connected to IRC!");
                continue;
            }

            if (d->network) {
                if (d->network->isChannel(target)) {
                    NoChannel* channel = d->network->findChannel(target);

                    if ((channel) && (!channel->autoClearChanBuffer() || !d->network->isUserOnline())) {
                        channel->addBuffer(":" + _NAMEDFMT(nickMask()) + " PRIVMSG " + _NAMEDFMT(target) + " :{text}", msg);
                    }
                } else {
                    if (!d->user->autoclearQueryBuffer() || !d->network->isUserOnline()) {
                        NoQuery* query = d->network->addQuery(target);
                        if (query) {
                            query->addBuffer(":" + _NAMEDFMT(nickMask()) + " PRIVMSG " + _NAMEDFMT(target) +
                                              " :{text}",
                                              msg);
                        }
                    }
                }

                putIrc("PRIVMSG " + target + " :" + msg);

                // Relay to the rest of the clients that may be connected to this user
                const std::vector<NoClient*>& vClients = clients();

                for (NoClient* client : vClients) {
                    if (client != this && (d->network->isChannel(target) || client->hasSelfMessage())) {
                        client->putClient(":" + nickMask() + " PRIVMSG " + target + " :" + msg);
                    }
                }
            }
        }

        return;
    }

    if (!d->network) {
        return; // The following commands require a network
    }

    if (command.equals("DETACH")) {
        NoString sPatterns = No::tokens(line, 1);

        if (sPatterns.empty()) {
            putStatusNotice("Usage: /detach <#chans>");
            return;
        }

        sPatterns.replace(",", " ");
        NoStringVector vsChans = sPatterns.split(" ", No::SkipEmptyParts);

        std::set<NoChannel*> sChans;
        for (const NoString& sChan : vsChans) {
            std::vector<NoChannel*> channels = d->network->findChannels(sChan);
            sChans.insert(channels.begin(), channels.end());
        }

        uint uDetached = 0;
        for (NoChannel* channel : sChans) {
            if (channel->isDetached())
                continue;
            uDetached++;
            channel->detachUser();
        }

        putStatusNotice("There were [" + NoString(sChans.size()) + "] channels matching [" + sPatterns + "]");
        putStatusNotice("Detached [" + NoString(uDetached) + "] channels");

        return;
    } else if (command.equals("JOIN")) {
        NoString sChans = No::token(line, 1).trimPrefix_n();
        NoString key = No::token(line, 2);

        NoStringVector vsChans = sChans.split(",", No::SkipEmptyParts);
        sChans.clear();

        for (NoString& name : vsChans) {
            bool bContinue = false;
            NETWORKMODULECALL(onUserJoin(name, key), d->user, d->network, this, &bContinue);
            if (bContinue)
                continue;

            NoChannel* channel = d->network->findChannel(name);
            if (channel) {
                if (channel->isDetached())
                    channel->attachUser(this);
                else
                    channel->joinUser(key);
                continue;
            }

            if (!name.empty()) {
                sChans += (sChans.empty()) ? name : NoString("," + name);
            }
        }

        if (sChans.empty()) {
            return;
        }

        line = "JOIN " + sChans;

        if (!key.empty()) {
            line += " " + key;
        }
    } else if (command.equals("PART")) {
        NoString sChans = No::token(line, 1).trimPrefix_n();
        NoString message = No::tokens(line, 2).trimPrefix_n();

        NoStringVector vsChans = sChans.split(",", No::SkipEmptyParts);
        sChans.clear();

        for (NoString& sChan : vsChans) {
            bool bContinue = false;
            NETWORKMODULECALL(onUserPart(sChan, message), d->user, d->network, this, &bContinue);
            if (bContinue)
                continue;

            NoChannel* channel = d->network->findChannel(sChan);

            if (channel && !channel->isOn()) {
                putStatusNotice("Removing channel [" + sChan + "]");
                d->network->removeChannel(sChan);
            } else {
                sChans += (sChans.empty()) ? sChan : NoString("," + sChan);
            }
        }

        if (sChans.empty()) {
            return;
        }

        line = "PART " + sChans;

        if (!message.empty()) {
            line += " :" + message;
        }
    } else if (command.equals("TOPIC")) {
        NoString sChan = No::token(line, 1);
        NoString topic = No::tokens(line, 2).trimPrefix_n();

        if (!topic.empty()) {
            NETWORKMODULECALL(onUserTopic(sChan, topic), d->user, d->network, this, &bReturn);
            if (bReturn)
                return;
            line = "TOPIC " + sChan + " :" + topic;
        } else {
            NETWORKMODULECALL(onUserTopicRequest(sChan), d->user, d->network, this, &bReturn);
            if (bReturn)
                return;
        }
    } else if (command.equals("MODE")) {
        NoString target = No::token(line, 1);
        NoString modes = No::tokens(line, 2);

        if (d->network->isChannel(target) && modes.empty()) {
            // If we are on that channel and already received a
            // /mode reply from the server, we can answer this
            // request ourself.

            NoChannel* channel = d->network->findChannel(target);
            if (channel && channel->isOn() && !channel->modeString().empty()) {
                putClient(":" + d->network->ircServer() + " 324 " + nick() + " " + target + " " + channel->modeString());
                if (channel->creationDate() > 0) {
                    putClient(":" + d->network->ircServer() + " 329 " + nick() + " " + target + " " +
                              NoString(channel->creationDate()));
                }
                return;
            }
        }
    }

    putIrc(line);
}

void NoClient::setNick(const NoString& s)
{
    d->nickname = s;
}

void NoClient::setAway(bool away)
{
    d->away = away;
}
NoUser* NoClient::user() const
{
    return d->user;
}

NoNetwork* NoClient::network() const
{
    return d->network;
}
void NoClient::setNetwork(NoNetwork* network, bool bDisconnect, bool bReconnect)
{
    if (bDisconnect) {
        if (d->network) {
            d->network->clientDisconnected(this);

            // Tell the client they are no longer in these channels.
            const std::vector<NoChannel*>& channels = d->network->channels();
            for (const NoChannel* channel : channels) {
                if (!(channel->isDetached())) {
                    putClient(":" + d->network->ircNick().hostMask() + " PART " + channel->name());
                }
            }
        } else if (d->user) {
            d->user->userDisconnected(this);
        }
    }

    d->network = network;

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

void NoClient::statusCtcp(const NoString& line)
{
    NoString command = No::token(line, 0);

    if (command.equals("PING")) {
        putStatusNotice("\001PING " + No::tokens(line, 1) + "\001");
    } else if (command.equals("VERSION")) {
        putStatusNotice("\001VERSION " + NoApp::tag() + "\001");
    }
}

bool NoClient::sendMotd()
{
    NoStringVector vsMotd = noApp->motd();

    if (!vsMotd.size()) {
        return false;
    }

    for (const NoString& line : vsMotd) {
        if (d->network) {
            putStatusNotice(d->network->expandString(line));
        } else {
            putStatusNotice(d->user->expandString(line));
        }
    }

    return true;
}

void NoClient::authUser()
{
    if (!d->receivedNick || !d->receivedUser || !d->receivedPass || d->inCapLs || isAttached())
        return;

    d->authenticator = std::make_shared<NoClientAuth>(this, d->username, d->password);

    noApp->authUser(d->authenticator);
}

void NoClient::refuseLogin(const NoString& reason)
{
    putStatus("Bad username and/or password.");
    putClient(":irc.znc.in 464 " + nick() + " :" + reason);
    d->socket->close(NoSocket::CloseAfterWrite);
}

void NoClient::acceptLogin(NoUser* user)
{
    d->password = "";
    d->user = user;

    // Set our proper timeout and set back our proper timeout mode
    // (constructor set a different timeout and mode)
    d->socket->setTimeout(NoNetwork::NoTrafficTimeout, NoSocket::ReadTimeout);

    d->socket->setName("USR::" + d->user->userName());
    d->socket->setEncoding(d->user->clientEncoding());

    if (!d->sNetwork.empty()) {
        d->network = d->user->findNetwork(d->sNetwork);
        if (!d->network) {
            putStatus("network (" + d->sNetwork + ") doesn't exist.");
        }
    } else if (!d->user->networks().empty()) {
        // If a user didn't supply a network, and they have a network called "default" then automatically use this
        // network.
        d->network = d->user->findNetwork("default");
        // If no "default" network, try "user" network. It's for compatibility with early network stuff in ZNC, which
        // converted old configs to "user" network.
        if (!d->network)
            d->network = d->user->findNetwork("user");
        // Otherwise, just try any network of the user.
        if (!d->network)
            d->network = *d->user->networks().begin();
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

    setNetwork(d->network, false);

    sendMotd();

    NETWORKMODULECALL(onClientLogin(), d->user, d->network, this, NOTHING);
}

void NoClient::bouncedOff()
{
    putStatusNotice("You are being disconnected because another user just authenticated as you.");
    d->socket->close(NoSocket::CloseAfterWrite);
}

bool NoClient::isAttached() const
{
    return d->user != nullptr;
}

bool NoClient::isPlaybackActive() const
{
    return d->inPlayback;
}
void NoClient::setPlaybackActive(bool active)
{
    d->inPlayback = active;
}

void NoClient::putIrc(const NoString& line)
{
    if (d->network) {
        d->network->putIrc(line);
    }
}

NoString NoClient::fullName() const
{
    if (!d->user)
        return d->socket->remoteAddress();
    NoString sFullName = d->user->userName();
    if (!d->identifier.empty())
        sFullName += "@" + d->identifier;
    if (d->network)
        sFullName += "/" + d->network->name();
    return sFullName;
}

void NoClient::putClient(const NoString& line)
{
    bool bReturn = false;
    NoString sCopy = line;
    NETWORKMODULECALL(onSendToClient(sCopy, this), d->user, d->network, this, &bReturn);
    if (bReturn)
        return;
    NO_DEBUG("(" << fullName() << ") ZNC -> CLI [" << sCopy << "]");
    d->socket->write(sCopy + "\r\n");
}

void NoClient::putStatusNotice(const NoString& line)
{
    putModuleNotice("status", line);
}

uint NoClient::putStatus(const NoTable& table)
{
    NoStringVector lines = table.toString();
    for (const NoString& line : lines)
        putStatus(line);
    return lines.size() - 1;
}

void NoClient::putStatus(const NoString& line)
{
    putModule("status", line);
}

void NoClient::putModuleNotice(const NoString& module, const NoString& line)
{
    if (!d->user) {
        return;
    }

    NO_DEBUG("(" << fullName() << ") ZNC -> CLI [:" + d->user->statusPrefix() + ((module.empty()) ? "status" : module) + "!znc@znc.in NOTICE "
                 << nick() << " :" << line << "]");
    d->socket->write(":" + d->user->statusPrefix() + ((module.empty()) ? "status" : module) + "!znc@znc.in NOTICE " +
                     nick() + " :" + line + "\r\n");
}

void NoClient::putModule(const NoString& module, const NoString& line)
{
    if (!d->user) {
        return;
    }

    NO_DEBUG("(" << fullName() << ") ZNC -> CLI [:" + d->user->statusPrefix() + ((module.empty()) ? "status" : module) + "!znc@znc.in PRIVMSG "
                 << nick() << " :" << line << "]");

    NoStringVector vsLines = line.split("\n");
    for (const NoString& s : vsLines) {
        d->socket->write(":" + d->user->statusPrefix() + ((module.empty()) ? "status" : module) +
                         "!znc@znc.in PRIVMSG " + nick() + " :" + s + "\r\n");
    }
}

bool NoClient::isCapEnabled(const NoString& cap) const
{
    return 1 == d->acceptedCaps.count(cap);
}

NoString NoClient::nick(bool allowIRCNick) const
{
    NoString ret;

    const NoIrcSocket* socket = ircSocket();
    if (allowIRCNick && socket && socket->isAuthed()) {
        ret = socket->nick();
    }

    return (ret.empty()) ? d->nickname : ret;
}

NoString NoClient::nickMask() const
{
    if (ircSocket() && ircSocket()->isAuthed()) {
        return ircSocket()->nickMask();
    }

    NoString host = d->network ? d->network->bindHost() : d->user->bindHost();
    if (host.empty()) {
        host = "irc.znc.in";
    }

    return nick() + "!" + (d->network ? d->network->bindHost() : d->user->ident()) + "@" + host;
}

NoString NoClient::identifier() const
{
    return d->identifier;
}
bool NoClient::hasNamesX() const
{
    return d->hasNamesX;
}
bool NoClient::hasUhNames() const
{
    return d->hasUhNames;
}
bool NoClient::isAway() const
{
    return d->away;
}
bool NoClient::hasServerTime() const
{
    return d->hasServerTime;
}
bool NoClient::hasBatch() const
{
    return d->hasBatch;
}
bool NoClient::hasSelfMessage() const
{
    return d->hasSelfMessage;
}

bool NoClient::isValidIdentifier(const NoString& identifier)
{
    // ^[-\w]+$

    if (identifier.empty()) {
        return false;
    }

    const char* p = identifier.c_str();
    while (*p) {
        if (*p != '_' && *p != '-' && !isalnum(*p)) {
            return false;
        }

        p++;
    }

    return true;
}

void NoClient::respondCap(const NoString& response)
{
    putClient(":irc.znc.in CAP " + nick() + " " + response);
}

void NoClient::handleCap(const NoString& line)
{
    // TODO support ~ and = modifiers
    NoString sSubCmd = No::token(line, 1);

    if (sSubCmd.equals("LS")) {
        NoStringSet ssOfferCaps;
        GLOBALMODULECALL(onClientCapLs(this, ssOfferCaps), NOTHING);
        ssOfferCaps.insert("userhost-in-names");
        ssOfferCaps.insert("multi-prefix");
        ssOfferCaps.insert("znc.in/server-time-iso");
        ssOfferCaps.insert("znc.in/batch");
        ssOfferCaps.insert("znc.in/self-message");
        NoString sRes = NoString(" ").join(ssOfferCaps.begin(), ssOfferCaps.end());
        respondCap("LS :" + sRes);
        d->inCapLs = true;
    } else if (sSubCmd.equals("END")) {
        d->inCapLs = false;
        if (!isAttached()) {
            if (!d->user && d->receivedUser && !d->receivedPass) {
                sendRequiredPasswordNotice();
            } else {
                authUser();
            }
        }
    } else if (sSubCmd.equals("REQ")) {
        NoStringVector vsTokens = No::tokens(line, 2).trimPrefix_n(":").split(" ", No::SkipEmptyParts);

        for (const NoString& sToken : vsTokens) {
            bool bVal = true;
            NoString cap = sToken;
            if (cap.trimPrefix("-"))
                bVal = false;

            bool bAccepted = ("multi-prefix" == cap) || ("userhost-in-names" == cap) || ("znc.in/server-time-iso" == cap) ||
                             ("znc.in/batch" == cap) || ("znc.in/self-message" == cap);
            GLOBALMODULECALL(isClientCapSupported(this, cap, bVal), &bAccepted);

            if (!bAccepted) {
                // Some unsupported capability is requested
                respondCap("NAK :" + No::tokens(line, 2).trimPrefix_n(":"));
                return;
            }
        }

        // All is fine, we support what was requested
        for (const NoString& sToken : vsTokens) {
            bool bVal = true;
            NoString cap = sToken;
            if (cap.trimPrefix("-"))
                bVal = false;

            if ("multi-prefix" == cap) {
                d->hasNamesX = bVal;
            } else if ("userhost-in-names" == cap) {
                d->hasUhNames = bVal;
            } else if ("znc.in/server-time-iso" == cap) {
                d->hasServerTime = bVal;
            } else if ("znc.in/batch" == cap) {
                d->hasBatch = bVal;
            } else if ("znc.in/self-message" == cap) {
                d->hasSelfMessage = bVal;
            }
            GLOBALMODULECALL(onClientCapRequest(this, cap, bVal), NOTHING);

            if (bVal) {
                d->acceptedCaps.insert(cap);
            } else {
                d->acceptedCaps.erase(cap);
            }
        }

        respondCap("ACK :" + No::tokens(line, 2).trimPrefix_n(":"));
    } else if (sSubCmd.equals("LIST")) {
        NoString sList = NoString(" ").join(d->acceptedCaps.begin(), d->acceptedCaps.end());
        respondCap("LIST :" + sList);
    } else if (sSubCmd.equals("CLEAR")) {
        NoStringSet ssRemoved;
        for (const NoString& cap : d->acceptedCaps) {
            bool bRemoving = false;
            GLOBALMODULECALL(isClientCapSupported(this, cap, false), &bRemoving);
            if (bRemoving) {
                GLOBALMODULECALL(onClientCapRequest(this, cap, false), NOTHING);
                ssRemoved.insert(cap);
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
        for (const NoString& cap : ssRemoved) {
            d->acceptedCaps.erase(cap);
            sList += "-" + cap + " ";
        }
        respondCap("ACK :" + sList.trimSuffix_n(" "));
    } else {
        putClient(":irc.znc.in 410 " + nick() + " " + sSubCmd + " :Invalid CAP subcommand");
    }
}

void NoClient::parsePass(const NoString& line)
{
    // [user[@identifier][/network]:]password

    const size_t uColon = line.find(":");
    if (uColon != NoString::npos) {
        d->password = line.substr(uColon + 1);

        parseUser(line.substr(0, uColon));
    } else {
        d->password = line;
    }
}

void NoClient::parseUser(const NoString& line)
{
    // user[@identifier][/network]

    const size_t uSlash = line.rfind("/");
    if (uSlash != NoString::npos) {
        d->sNetwork = line.substr(uSlash + 1);

        parseIdentifier(line.substr(0, uSlash));
    } else {
        parseIdentifier(line);
    }
}

void NoClient::parseIdentifier(const NoString& line)
{
    // user[@identifier]

    const size_t uAt = line.rfind("@");
    if (uAt != NoString::npos) {
        const NoString sId = line.substr(uAt + 1);

        if (isValidIdentifier(sId)) {
            d->identifier = sId;
            d->username = line.substr(0, uAt);
        } else {
            d->username = line;
        }
    } else {
        d->username = line;
    }
}
