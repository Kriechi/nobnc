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

#include <no/nomodule.h>
#include <no/nofile.h>
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/noapp.h>
#include <no/nomodulesocket.h>
#include <no/nonick.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#endif

class NoSChat;

class NoRemMarkerJob : public NoTimer
{
public:
    NoRemMarkerJob(NoModule* pModule, const NoString& sNick) : NoTimer(pModule), m_sNick(sNick)
    {
        setName("Remove (s)" + sNick);
        setDescription("Removes this nicks entry for waiting DCC.");
    }

protected:
    void run() override;
    NoString m_sNick;
};

class NoSChatSock : public NoModuleSocket
{
public:
    NoSChatSock(NoSChat* pMod, const NoString& sChatNick);
    NoSChatSock(NoSChat* pMod, const NoString& sChatNick, const NoString& sHost, u_short iPort);
    ~NoSChatSock();

    NoSocket* createSocket(const NoString& sHostname, u_short iPort) override
    {
        NoSChatSock* p = new NoSChatSock(m_module, m_sChatNick, sHostname, iPort);
        return (p);
    }

    bool onConnectionFrom(const NoString& sHost, u_short iPort) override
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

    void PutQuery(const NoString& sText);

    void readLine(const NoString& sLine) override;
    void onDisconnected() override;

    void AddLine(const NoString& sLine)
    {
        m_vBuffer.insert(m_vBuffer.begin(), sLine);
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

    bool onLoad(const NoString& sArgs, NoString& sMessage) override
    {
        m_sPemFile = sArgs;

        if (m_sPemFile.empty()) {
            m_sPemFile = NoApp::Get().GetPemLocation();
        }

        if (!NoFile::Exists(m_sPemFile)) {
            sMessage = "Unable to load pem file [" + m_sPemFile + "]";
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

    ModRet onUserRaw(NoString& sLine) override
    {
        if (sLine.startsWith("schat ")) {
            onModCommand("chat " + sLine.substr(6));
            return (HALT);

        } else if (sLine.equals("schat")) {
            putModule("SChat User Area ...");
            onModCommand("help");
            return (HALT);
        }

        return (CONTINUE);
    }

    void onModCommand(const NoString& sCommand) override
    {
        NoString sCom = No::token(sCommand, 0);
        NoString sArgs = No::tokens(sCommand, 1);

        if (sCom.equals("chat") && !sArgs.empty()) {
            NoString sNick = "(s)" + sArgs;
            for (NoSChatSock* pSock : m_sockets) {
                if (pSock->GetChatNick().equals(sNick)) {
                    putModule("Already Connected to [" + sArgs + "]");
                    return;
                }
            }

            NoSChatSock* pSock = new NoSChatSock(this, sNick);
            pSock->setCipher("HIGH");
            pSock->setPemFile(m_sPemFile);

            u_short iPort =
            manager()->listenRand(pSock->name() + "::LISTENER", user()->localDccIp(), true, SOMAXCONN, pSock, 60);

            if (iPort == 0) {
                putModule("Failed to start chat!");
                return;
            }

            std::stringstream s;
            s << "PRIVMSG " << sArgs << " :\001";
            s << "DCC SCHAT chat ";
            s << No::formatLongIp(user()->localDccIp());
            s << " " << iPort << "\001";

            putIrc(s.str());

        } else if (sCom.equals("list")) {
            NoTable Table;
            Table.addColumn("Nick");
            Table.addColumn("Created");
            Table.addColumn("Host");
            Table.addColumn("Port");
            Table.addColumn("Status");
            Table.addColumn("Cipher");

            for (NoSChatSock* pSock : m_sockets) {
                Table.addRow();
                Table.setValue("Nick", pSock->GetChatNick());
                ulonglong iStartTime = pSock->startTime();
                time_t iTime = iStartTime / 1000;
                char* pTime = ctime(&iTime);
                if (pTime) {
                    NoString sTime = pTime;
                    sTime.trim();
                    Table.setValue("Created", sTime);
                }

                if (!pSock->isListener()) {
                    Table.setValue("Status", "Established");
                    Table.setValue("Host", pSock->remoteAddress());
                    Table.setValue("Port", NoString(pSock->remotePort()));
                    SSL_SESSION* pSession = pSock->sslSession();
                    if (pSession && pSession->cipher && pSession->cipher->name)
                        Table.setValue("Cipher", pSession->cipher->name);

                } else {
                    Table.setValue("Status", "Waiting");
                    Table.setValue("Port", NoString(pSock->localPort()));
                }
            }
            if (Table.size()) {
                putModule(Table);
            } else
                putModule("No SDCCs currently in session");

        } else if (sCom.equals("close")) {
            if (!sArgs.startsWith("(s)"))
                sArgs = "(s)" + sArgs;

            for (NoSChatSock* pSock : m_sockets) {
                if (sArgs.equals(pSock->GetChatNick())) {
                    pSock->close();
                    return;
                }
            }
            putModule("No Such Chat [" + sArgs + "]");
        } else if (sCom.equals("showsocks") && user()->isAdmin()) {
            NoTable Table;
            Table.addColumn("SockName");
            Table.addColumn("Created");
            Table.addColumn("LocalIP:Port");
            Table.addColumn("RemoteIP:Port");
            Table.addColumn("Type");
            Table.addColumn("Cipher");

            for (NoSChatSock* pSock : m_sockets) {
                Table.addRow();
                Table.setValue("SockName", pSock->name());
                ulonglong iStartTime = pSock->startTime();
                time_t iTime = iStartTime / 1000;
                char* pTime = ctime(&iTime);
                if (pTime) {
                    NoString sTime = pTime;
                    sTime.trim();
                    Table.setValue("Created", sTime);
                }

                if (!pSock->isListener()) {
                    if (pSock->isOutbound())
                        Table.setValue("Type", "Outbound");
                    else
                        Table.setValue("Type", "Inbound");
                    Table.setValue("LocalIP:Port", pSock->localAddress() + ":" + NoString(pSock->localPort()));
                    Table.setValue("RemoteIP:Port", pSock->remoteAddress() + ":" + NoString(pSock->remotePort()));
                    SSL_SESSION* pSession = pSock->sslSession();
                    if (pSession && pSession->cipher && pSession->cipher->name)
                        Table.setValue("Cipher", pSession->cipher->name);
                    else
                        Table.setValue("Cipher", "None");

                } else {
                    Table.setValue("Type", "Listener");
                    Table.setValue("LocalIP:Port", pSock->localAddress() + ":" + NoString(pSock->localPort()));
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
        } else if (sCom.equals("timers"))
            listTimers();
        else
            putModule("Unknown command [" + sCom + "] [" + sArgs + "]");
    }

    ModRet onPrivCtcp(NoNick& Nick, NoString& sMessage) override
    {
        if (sMessage.startsWith("DCC SCHAT ")) {
            // chat ip port
            ulong iIP = No::token(sMessage, 3).toULong();
            ushort iPort = No::token(sMessage, 4).toUShort();

            if (iIP > 0 && iPort > 0) {
                std::pair<u_long, u_short> pTmp;
                NoString sMask;

                pTmp.first = iIP;
                pTmp.second = iPort;
                sMask = "(s)" + Nick.nick() + "!" + "(s)" + Nick.nick() + "@" + No::formatIp(iIP);

                m_siiWaitingChats["(s)" + Nick.nick()] = pTmp;
                SendToUser(sMask, "*** Incoming DCC SCHAT, Accept ? (yes/no)");
                NoRemMarkerJob* p = new NoRemMarkerJob(this, Nick.nick());
                p->setSingleShot(true);
                p->start(60);
                return (HALT);
            }
        }

        return (CONTINUE);
    }

    void AcceptSDCC(const NoString& sNick, u_long iIP, u_short iPort)
    {
        NoSChatSock* p = new NoSChatSock(this, sNick, No::formatIp(iIP), iPort);
        manager()->connect(No::formatIp(iIP), iPort, p->name(), 60, true, user()->localDccIp(), p);
        delete findTimer("Remove " + sNick); // delete any associated timer to this nick
    }

    ModRet onUserMsg(NoString& sTarget, NoString& sMessage) override
    {
        if (sTarget.left(3) == "(s)") {
            NoString sSockName = moduleName().toUpper() + "::" + sTarget;
            NoSChatSock* p = (NoSChatSock*)findSocket(sSockName);
            if (!p) {
                std::map<NoString, std::pair<u_long, u_short>>::iterator it;
                it = m_siiWaitingChats.find(sTarget);

                if (it != m_siiWaitingChats.end()) {
                    if (!sMessage.equals("yes"))
                        SendToUser(sTarget + "!" + sTarget + "@" + No::formatIp(it->second.first),
                                   "Refusing to accept DCC SCHAT!");
                    else
                        AcceptSDCC(sTarget, it->second.first, it->second.second);

                    m_siiWaitingChats.erase(it);
                    return (HALT);
                }
                putModule("No such SCHAT to [" + sTarget + "]");
            } else
                p->write(sMessage + "\n");

            return (HALT);
        }
        return (CONTINUE);
    }

    void RemoveMarker(const NoString& sNick)
    {
        std::map<NoString, std::pair<u_long, u_short>>::iterator it = m_siiWaitingChats.find(sNick);
        if (it != m_siiWaitingChats.end())
            m_siiWaitingChats.erase(it);
    }

    void SendToUser(const NoString& sFrom, const NoString& sText)
    {
        //:*schat!znc@znc.in PRIVMSG Jim :
        NoString sSend = ":" + sFrom + " PRIVMSG " + network()->currentNick() + " :" + sText;
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

NoSChatSock::NoSChatSock(NoSChat* pMod, const NoString& sChatNick) : NoModuleSocket(pMod)
{
    m_module = pMod;
    m_sChatNick = sChatNick;
    setName(pMod->moduleName().toUpper() + "::" + m_sChatNick);
    pMod->AddSocket(this);
}

NoSChatSock::NoSChatSock(NoSChat* pMod, const NoString& sChatNick, const NoString& sHost, u_short iPort)
    : NoModuleSocket(pMod, sHost, iPort)
{
    m_module = pMod;
    enableReadLine();
    m_sChatNick = sChatNick;
    setName(pMod->moduleName().toUpper() + "::" + m_sChatNick);
    pMod->AddSocket(this);
}

NoSChatSock::~NoSChatSock()
{
    m_module->RemoveSocket(this);
}

void NoSChatSock::PutQuery(const NoString& sText)
{
    m_module->SendToUser(m_sChatNick + "!" + m_sChatNick + "@" + remoteAddress(), sText);
}

void NoSChatSock::readLine(const NoString& sLine)
{
    if (m_module) {
        NoString sText = sLine;

        sText.trimRight("\r\n");

        if (m_module->IsAttached())
            PutQuery(sText);
        else
            AddLine(m_module->user()->addTimestamp(sText));
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
void no_moduleInfo<NoSChat>(NoModuleInfo& Info)
{
    Info.setWikiPage("schat");
    Info.setHasArgs(true);
    Info.setArgsHelpText("Path to .pem file, if differs from main ZNC's one");
}

NETWORKMODULEDEFS(NoSChat, "Secure cross platform (:P) chat system")
