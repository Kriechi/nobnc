/*
 * Copyright (C) 2015 NoBNC
 * Copyright (C) 2004-2015 ZNC, see the NOTICE file for details.
 * Author: imaginos <imaginos@imaginos.net>
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

/*
 * Secure chat system
 */

#define REQUIRESSL

#include <nobnc/nomodule.h>
#include <nobnc/nofile.h>
#include <nobnc/nouser.h>
#include <nobnc/nonetwork.h>
#include <nobnc/noapp.h>
#include <nobnc/nomodulesocket.h>
#include <nobnc/nonick.h>
#include <nobnc/nohostmask.h>
#include <nobnc/notimer.h>
#include <nobnc/notable.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#endif

class NoSChat;

class NoRemMarkerJob : public NoTimer
{
public:
    NoRemMarkerJob(NoModule* module, const NoString& nick) : NoTimer(module), m_sNick(nick)
    {
        setName("Remove (s)" + nick);
        setDescription("Removes this nicks entry for waiting DCC.");
    }

protected:
    void run() override;
    NoString m_sNick;
};

class NoSChatSock : public NoModuleSocket
{
public:
    NoSChatSock(NoSChat* mod, const NoString& sChatNick);
    NoSChatSock(NoSChat* mod, const NoString& sChatNick, const NoString& host, u_short port);
    ~NoSChatSock();

    NoSocket* createSocket(const NoString& hostname, u_short port) override
    {
        NoSChatSock* p = new NoSChatSock(m_module, m_sChatNick, hostname, port);
        return (p);
    }

    bool onConnectionFrom(const NoString& host, u_short port) override
    {
        close(); // close the listener after the first connection
        return (true);
    }

    void onConnected() override;
    void onTimeout() override;

    const NoString& GetChatNick() const
    {
        return (m_sChatNick);
    }

    void PutQuery(const NoString& text);

    void readLine(const NoString& line) override;
    void onDisconnected() override;

    void AddLine(const NoString& line)
    {
        m_vBuffer.insert(m_vBuffer.begin(), line);
        if (m_vBuffer.size() > 200)
            m_vBuffer.pop_back();
    }

    void DumpBuffer()
    {
        if (m_vBuffer.empty()) {
            // Always show a message to the user, so he knows
            // this schat still exists.
            readLine("*** Reattached.");
        } else {
            // Buffer playback
            std::vector<NoString>::reverse_iterator it = m_vBuffer.rbegin();
            for (; it != m_vBuffer.rend(); ++it)
                readLine(*it);

            m_vBuffer.clear();
        }
    }

private:
    NoSChat* m_module;
    NoString m_sChatNick;
    NoStringVector m_vBuffer;
};

class NoSChat : public NoModule
{
public:
    MODCONSTRUCTOR(NoSChat)
    {
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        m_sPemFile = args;

        if (m_sPemFile.empty()) {
            m_sPemFile = noApp->pemLocation();
        }

        if (!NoFile::Exists(m_sPemFile)) {
            message = "Unable to load pem file [" + m_sPemFile + "]";
            return false;
        }

        return true;
    }

    void onClientLogin() override
    {
        for (NoSChatSock* p : m_sockets) {
            if (!p->isListener())
                p->DumpBuffer();
        }
    }

    ModRet onUserRaw(NoString& line) override
    {
        if (line.startsWith("schat ")) {
            onModuleCommand("chat " + line.substr(6));
            return (HALT);

        } else if (line.equals("schat")) {
            putModule("SChat User Area ...");
            onModuleCommand("help");
            return (HALT);
        }

        return (CONTINUE);
    }

    void onModuleCommand(const NoString& command) override
    {
        NoString sCom = No::token(command, 0);
        NoString args = No::tokens(command, 1);

        if (sCom.equals("chat") && !args.empty()) {
            NoString nick = "(s)" + args;
            for (NoSChatSock* socket : m_sockets) {
                if (socket->GetChatNick().equals(nick)) {
                    putModule("Already Connected to [" + args + "]");
                    return;
                }
            }

            NoSChatSock* socket = new NoSChatSock(this, nick);
            socket->setCipher("HIGH");
            socket->setPemFile(m_sPemFile);

            u_short port =
            noApp->manager()->listenRand(socket->name() + "::LISTENER", user()->localDccIp(), true, SOMAXCONN, socket, 60);

            if (port == 0) {
                putModule("Failed to start chat!");
                return;
            }

            std::stringstream s;
            s << "PRIVMSG " << args << " :\001";
            s << "DCC SCHAT chat ";
            s << No::formatLongIp(user()->localDccIp());
            s << " " << port << "\001";

            putIrc(s.str());

        } else if (sCom.equals("list")) {
            NoTable Table;
            Table.addColumn("Nick");
            Table.addColumn("Created");
            Table.addColumn("Host");
            Table.addColumn("Port");
            Table.addColumn("Status");
            Table.addColumn("Cipher");

            for (NoSChatSock* socket : m_sockets) {
                Table.addRow();
                Table.setValue("Nick", socket->GetChatNick());
                ulonglong iStartTime = socket->startTime();
                time_t iTime = iStartTime / 1000;
                char* pTime = ctime(&iTime);
                if (pTime) {
                    NoString sTime = pTime;
                    sTime.trim();
                    Table.setValue("Created", sTime);
                }

                if (!socket->isListener()) {
                    Table.setValue("Status", "Established");
                    Table.setValue("Host", socket->remoteAddress());
                    Table.setValue("Port", NoString(socket->remotePort()));
                    SSL_SESSION* pSession = socket->sslSession();
                    if (pSession && pSession->cipher && pSession->cipher->name)
                        Table.setValue("Cipher", pSession->cipher->name);

                } else {
                    Table.setValue("Status", "Waiting");
                    Table.setValue("Port", NoString(socket->localPort()));
                }
            }
            if (Table.size()) {
                putModule(Table);
            } else
                putModule("No SDCCs currently in session");

        } else if (sCom.equals("close")) {
            if (!args.startsWith("(s)"))
                args = "(s)" + args;

            for (NoSChatSock* socket : m_sockets) {
                if (args.equals(socket->GetChatNick())) {
                    socket->close();
                    return;
                }
            }
            putModule("No Such Chat [" + args + "]");
        } else if (sCom.equals("showsocks") && user()->isAdmin()) {
            NoTable Table;
            Table.addColumn("SockName");
            Table.addColumn("Created");
            Table.addColumn("LocalIP:Port");
            Table.addColumn("RemoteIP:Port");
            Table.addColumn("Type");
            Table.addColumn("Cipher");

            for (NoSChatSock* socket : m_sockets) {
                Table.addRow();
                Table.setValue("SockName", socket->name());
                ulonglong iStartTime = socket->startTime();
                time_t iTime = iStartTime / 1000;
                char* pTime = ctime(&iTime);
                if (pTime) {
                    NoString sTime = pTime;
                    sTime.trim();
                    Table.setValue("Created", sTime);
                }

                if (!socket->isListener()) {
                    if (socket->isOutbound())
                        Table.setValue("Type", "Outbound");
                    else
                        Table.setValue("Type", "Inbound");
                    Table.setValue("LocalIP:Port", socket->localAddress() + ":" + NoString(socket->localPort()));
                    Table.setValue("RemoteIP:Port", socket->remoteAddress() + ":" + NoString(socket->remotePort()));
                    SSL_SESSION* pSession = socket->sslSession();
                    if (pSession && pSession->cipher && pSession->cipher->name)
                        Table.setValue("Cipher", pSession->cipher->name);
                    else
                        Table.setValue("Cipher", "None");

                } else {
                    Table.setValue("Type", "Listener");
                    Table.setValue("LocalIP:Port", socket->localAddress() + ":" + NoString(socket->localPort()));
                    Table.setValue("RemoteIP:Port", "0.0.0.0:0");
                }
            }
            if (Table.size())
                putModule(Table);
            else
                putModule("Error Finding Sockets");

        } else if (sCom.equals("help")) {
            putModule("Commands are:");
            putModule("    help           - This text.");
            putModule("    chat <nick>    - Chat a nick.");
            putModule("    list           - List current chats.");
            putModule("    close <nick>   - Close a chat to a nick.");
            putModule("    timers         - Shows related timers.");
            if (user()->isAdmin()) {
                putModule("    showsocks      - Shows all socket connections.");
            }
        } else {
            putModule("Unknown command [" + sCom + "] [" + args + "]");
        }
    }

    ModRet onPrivateCtcp(NoHostMask& nick, NoString& message) override
    {
        if (message.startsWith("DCC SCHAT ")) {
            // chat ip port
            ulong iIP = No::token(message, 3).toULong();
            ushort port = No::token(message, 4).toUShort();

            if (iIP > 0 && port > 0) {
                std::pair<u_long, u_short> pTmp;
                NoString sMask;

                pTmp.first = iIP;
                pTmp.second = port;
                sMask = "(s)" + nick.nick() + "!" + "(s)" + nick.nick() + "@" + No::formatIp(iIP);

                m_siiWaitingChats["(s)" + nick.nick()] = pTmp;
                SendToUser(sMask, "*** Incoming DCC SCHAT, Accept ? (yes/no)");
                NoRemMarkerJob* p = new NoRemMarkerJob(this, nick.nick());
                p->setSingleShot(true);
                p->start(60);
                return (HALT);
            }
        }

        return (CONTINUE);
    }

    void AcceptSDCC(const NoString& nick, u_long iIP, u_short port)
    {
        NoSChatSock* p = new NoSChatSock(this, nick, No::formatIp(iIP), port);
        noApp->manager()->connect(No::formatIp(iIP), port, p->name(), 60, true, user()->localDccIp(), p);
        delete findTimer("Remove " + nick); // delete any associated timer to this nick
    }

    ModRet onUserMessage(NoString& target, NoString& message) override
    {
        if (target.left(3) == "(s)") {
            NoString name = moduleName().toUpper() + "::" + target;
            NoSChatSock* p = (NoSChatSock*)findSocket(name);
            if (!p) {
                std::map<NoString, std::pair<u_long, u_short>>::iterator it;
                it = m_siiWaitingChats.find(target);

                if (it != m_siiWaitingChats.end()) {
                    if (!message.equals("yes"))
                        SendToUser(target + "!" + target + "@" + No::formatIp(it->second.first),
                                   "Refusing to accept DCC SCHAT!");
                    else
                        AcceptSDCC(target, it->second.first, it->second.second);

                    m_siiWaitingChats.erase(it);
                    return (HALT);
                }
                putModule("No such SCHAT to [" + target + "]");
            } else
                p->write(message + "\n");

            return (HALT);
        }
        return (CONTINUE);
    }

    void RemoveMarker(const NoString& nick)
    {
        std::map<NoString, std::pair<u_long, u_short>>::iterator it = m_siiWaitingChats.find(nick);
        if (it != m_siiWaitingChats.end())
            m_siiWaitingChats.erase(it);
    }

    void SendToUser(const NoString& sFrom, const NoString& text)
    {
        //:*schat!znc@znc.in PRIVMSG Jim :
        NoString sSend = ":" + sFrom + " PRIVMSG " + network()->currentNick() + " :" + text;
        putUser(sSend);
    }

    bool IsAttached()
    {
        return (network()->isUserAttached());
    }

    void AddSocket(NoSChatSock* socket)
    {
        m_sockets.insert(socket);
    }
    void RemoveSocket(NoSChatSock* socket)
    {
        m_sockets.erase(socket);
    }

private:
    std::map<NoString, std::pair<u_long, u_short>> m_siiWaitingChats;
    NoString m_sPemFile;
    std::set<NoSChatSock*> m_sockets;
};


//////////////////// methods ////////////////

NoSChatSock::NoSChatSock(NoSChat* mod, const NoString& sChatNick) : NoModuleSocket(mod)
{
    m_module = mod;
    m_sChatNick = sChatNick;
    setName(mod->moduleName().toUpper() + "::" + m_sChatNick);
    mod->AddSocket(this);
}

NoSChatSock::NoSChatSock(NoSChat* mod, const NoString& sChatNick, const NoString& host, u_short port)
    : NoModuleSocket(mod, host, port)
{
    m_module = mod;
    enableReadLine();
    m_sChatNick = sChatNick;
    setName(mod->moduleName().toUpper() + "::" + m_sChatNick);
    mod->AddSocket(this);
}

NoSChatSock::~NoSChatSock()
{
    m_module->RemoveSocket(this);
}

void NoSChatSock::PutQuery(const NoString& text)
{
    m_module->SendToUser(m_sChatNick + "!" + m_sChatNick + "@" + remoteAddress(), text);
}

void NoSChatSock::readLine(const NoString& line)
{
    if (m_module) {
        NoString text = line;

        text.trimRight("\r\n");

        if (m_module->IsAttached())
            PutQuery(text);
        else
            AddLine(m_module->user()->addTimestamp(text));
    }
}

void NoSChatSock::onDisconnected()
{
    if (m_module)
        PutQuery("*** Disconnected.");
}

void NoSChatSock::onConnected()
{
    setTimeout(0);
    if (m_module)
        PutQuery("*** Connected.");
}

void NoSChatSock::onTimeout()
{
    if (m_module) {
        if (isListener())
            m_module->putModule("Timeout while waiting for [" + m_sChatNick + "]");
        else
            PutQuery("*** Connection Timed out.");
    }
}

void NoRemMarkerJob::run()
{
    static_cast<NoSChat*>(module())->RemoveMarker(m_sNick);

    // store buffer
}

template <>
void no_moduleInfo<NoSChat>(NoModuleInfo& info)
{
    info.setWikiPage("schat");
    info.setHasArgs(true);
    info.setArgsHelpText("Path to .pem file, if differs from main ZNC's one");
}

NETWORKMODULEDEFS(NoSChat, "Secure cross platform (:P) chat system")
