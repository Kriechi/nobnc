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

#include <nobnc/nomodule.h>
#include <nobnc/nouser.h>
#include <nobnc/nonetwork.h>
#include <nobnc/nodebug.h>
#include <nobnc/noclient.h>
#include <nobnc/noapp.h>
#include <nobnc/nomodulesocket.h>
#include <nobnc/noregistry.h>
#include <nobnc/nonick.h>
#include <nobnc/nohostmask.h>
#include <nobnc/notable.h>

class NoBounceDccMod;

class NoDccBounce : public NoModuleSocket
{
public:
    NoDccBounce(NoBounceDccMod* mod,
                ulong uLongIP,
                ushort port,
                const NoString& fileName,
                const NoString& sRemoteNick,
                const NoString& sRemoteIP,
                bool bIsChat = false);
    NoDccBounce(NoBounceDccMod* mod,
                const NoString& hostname,
                ushort port,
                const NoString& sRemoteNick,
                const NoString& sRemoteIP,
                const NoString& fileName,
                bool bIsChat = false);
    virtual ~NoDccBounce();

    static ushort
    DCCRequest(const NoString& nick, ulong uLongIP, ushort port, const NoString& fileName, bool bIsChat, NoBounceDccMod* mod, const NoString& sRemoteIP);

    void readLine(const NoString& data) override;
    void readData(const char* data, size_t len) override;
    void onReadPaused() override;
    void onTimeout() override;
    void onConnectionRefused() override;
    void onReachedMaxBuffer() override;
    void onSocketError(int iErrno, const NoString& description) override;
    void onConnected() override;
    void onDisconnected() override;
    NoSocket* createSocket(const NoString& host, ushort port) override;
    void Shutdown();
    void PutServ(const NoString& line);
    void PutPeer(const NoString& line);
    bool IsPeerConnected()
    {
        return (m_pPeer) ? m_pPeer->isConnected() : false;
    }

    // Setters
    void SetPeer(NoDccBounce* p)
    {
        m_pPeer = p;
    }
    void SetRemoteIP(const NoString& s)
    {
        m_sRemoteIP = s;
    }
    void SetRemoteNick(const NoString& s)
    {
        m_sRemoteNick = s;
    }
    void SetRemote(bool b)
    {
        m_bIsRemote = b;
    }
    // !Setters

    // Getters
    ushort GetUserPort() const
    {
        return m_uRemotePort;
    }
    const NoString& GetRemoteAddr() const
    {
        return m_sRemoteIP;
    }
    const NoString& GetRemoteNick() const
    {
        return m_sRemoteNick;
    }
    const NoString& GetFileName() const
    {
        return m_sFileName;
    }
    NoDccBounce* GetPeer() const
    {
        return m_pPeer;
    }
    bool IsRemote()
    {
        return m_bIsRemote;
    }
    bool IsChat()
    {
        return m_bIsChat;
    }
    // !Getters
private:
protected:
    NoString m_sRemoteNick;
    NoString m_sRemoteIP;
    NoString m_sConnectIP;
    NoString m_sLocalIP;
    NoString m_sFileName;
    NoBounceDccMod* m_module;
    NoDccBounce* m_pPeer;
    ushort m_uRemotePort;
    bool m_bIsChat;
    bool m_bIsRemote;

    static const uint m_uiMaxDCCBuffer;
    static const uint m_uiMinDCCBuffer;
};

// If we buffer more than this in memory, we will throttle the receiving side
const uint NoDccBounce::m_uiMaxDCCBuffer = 10 * 1024;
// If less than this is in the buffer, the receiving side continues
const uint NoDccBounce::m_uiMinDCCBuffer = 2 * 1024;

class NoBounceDccMod : public NoModule
{
public:
    void ListDCCsCommand(const NoString& line)
    {
        NoTable Table;
        Table.addColumn("Type");
        Table.addColumn("State");
        Table.addColumn("Speed");
        Table.addColumn("Nick");
        Table.addColumn("IP");
        Table.addColumn("File");

        for (NoDccBounce* socket : m_sockets) {
            NoString name = socket->name();

            if (!(socket->IsRemote())) {
                Table.addRow();
                Table.setValue("Nick", socket->GetRemoteNick());
                Table.setValue("IP", socket->GetRemoteAddr());

                if (socket->IsChat()) {
                    Table.setValue("Type", "Chat");
                } else {
                    Table.setValue("Type", "Xfer");
                    Table.setValue("File", socket->GetFileName());
                }

                NoString sState = "Waiting";
                if ((socket->isConnected()) || (socket->IsPeerConnected())) {
                    sState = "Halfway";
                    if ((socket->isConnected()) && (socket->IsPeerConnected())) {
                        sState = "Connected";
                    }
                }
                Table.setValue("State", sState);
            }
        }

        if (putModule(Table) == 0) {
            putModule("You have no active DCCs.");
        }
    }

    void UseClientIPCommand(const NoString& line)
    {
        NoString value = No::tokens(line, 1);

        NoRegistry registry(this);
        if (!value.empty()) {
            registry.setValue("UseClientIP", value);
        }

        putModule("UseClientIP: " + NoString(registry.value("UseClientIP").toBool()));
    }

    MODCONSTRUCTOR(NoBounceDccMod)
    {
        addHelpCommand();
        addCommand("ListDCCs",
                   static_cast<NoModule::CommandFunction>(&NoBounceDccMod::ListDCCsCommand),
                   "",
                   "List all active DCCs");
        addCommand("UseClientIP",
                   static_cast<NoModule::CommandFunction>(&NoBounceDccMod::UseClientIPCommand),
                   "<true|false>");
    }

    NoString GetLocalDCCIP()
    {
        return user()->localDccIp();
    }

    bool UseClientIP()
    {
        return NoRegistry(this).value("UseClientIP").toBool();
    }

    Return onUserCtcp(NoString& target, NoString& message) override
    {
        if (message.startsWith("DCC ")) {
            NoStringVector tokens = No::quoteSplit(message);
            tokens.resize(6);
            NoString sType = tokens.at(1).trim_n("\"");
            NoString sFile = tokens.at(2);
            ulong uLongIP = tokens.at(3).trim_n("\"").toULong();
            ushort port = tokens.at(4).trim_n("\"").toUShort();
            ulong uFileSize = tokens.at(5).trim_n("\"").toULong();
            NoString address = GetLocalDCCIP();

            if (!UseClientIP()) {
                uLongIP = No::formatLongIp(client()->socket()->remoteAddress());
            }

            if (sType.equals("CHAT")) {
                ushort uBNCPort = NoDccBounce::DCCRequest(target, uLongIP, port, "", true, this, "");
                if (uBNCPort) {
                    putIrc("PRIVMSG " + target + " :\001DCC CHAT chat " + NoString(No::formatLongIp(address)) + " " +
                           NoString(uBNCPort) + "\001");
                }
            } else if (sType.equals("SEND")) {
                // DCC SEND readme.txt 403120438 5550 1104
                ushort uBNCPort = NoDccBounce::DCCRequest(target, uLongIP, port, sFile, false, this, "");
                if (uBNCPort) {
                    putIrc("PRIVMSG " + target + " :\001DCC SEND " + sFile + " " + NoString(No::formatLongIp(address)) +
                           " " + NoString(uBNCPort) + " " + NoString(uFileSize) + "\001");
                }
            } else if (sType.equals("RESUME")) {
                // PRIVMSG user :DCC RESUME "znc.o" 58810 151552
                ushort uResumePort = No::token(message, 3).toUShort();

                for (NoDccBounce* socket : m_sockets) {
                    if (socket->localPort() == uResumePort) {
                        putIrc("PRIVMSG " + target + " :\001DCC " + sType + " " + sFile + " " +
                               NoString(socket->GetUserPort()) + " " + No::token(message, 4) + "\001");
                    }
                }
            } else if (sType.equals("ACCEPT")) {
                // Need to lookup the connection by port, filter the port, and forward to the user

                for (NoDccBounce* socket : m_sockets) {
                    if (socket->GetUserPort() == No::token(message, 3).toUShort()) {
                        putIrc("PRIVMSG " + target + " :\001DCC " + sType + " " + sFile + " " +
                               NoString(socket->localPort()) + " " + No::token(message, 4) + "\001");
                    }
                }
            }

            return HaltCore;
        }

        return Continue;
    }

    Return onPrivateCtcp(NoHostMask& nick, NoString& message) override
    {
        NoNetwork* network = NoModule::network();
        if (message.startsWith("DCC ") && network->isUserAttached()) {
            // DCC CHAT chat 2453612361 44592
            NoStringVector tokens = No::quoteSplit(message);
            tokens.resize(6);
            NoString sType = tokens.at(1).trim_n("\"");
            NoString sFile = tokens.at(2);
            ulong uLongIP = tokens.at(3).trim_n("\"").toULong();
            ushort port = tokens.at(4).trim_n("\"").toUShort();
            ulong uFileSize = tokens.at(5).trim_n("\"").toULong();

            if (sType.equals("CHAT")) {
                NoNick FromNick(nick.toString());
                ushort uBNCPort = NoDccBounce::DCCRequest(FromNick.nick(), uLongIP, port, "", true, this, No::formatIp(uLongIP));
                if (uBNCPort) {
                    NoString address = GetLocalDCCIP();
                    putUser(":" + nick.toString() + " PRIVMSG " + network->currentNick() + " :\001DCC CHAT chat " +
                            NoString(No::formatLongIp(address)) + " " + NoString(uBNCPort) + "\001");
                }
            } else if (sType.equals("SEND")) {
                // DCC SEND readme.txt 403120438 5550 1104
                ushort uBNCPort = NoDccBounce::DCCRequest(nick.nick(), uLongIP, port, sFile, false, this, No::formatIp(uLongIP));
                if (uBNCPort) {
                    NoString address = GetLocalDCCIP();
                    putUser(":" + nick.toString() + " PRIVMSG " + network->currentNick() + " :\001DCC SEND " + sFile + " " +
                            NoString(No::formatLongIp(address)) + " " + NoString(uBNCPort) + " " + NoString(uFileSize) + "\001");
                }
            } else if (sType.equals("RESUME")) {
                // Need to lookup the connection by port, filter the port, and forward to the user
                ushort uResumePort = No::token(message, 3).toUShort();

                for (NoDccBounce* socket : m_sockets) {
                    if (socket->localPort() == uResumePort) {
                        putUser(":" + nick.toString() + " PRIVMSG " + network->currentNick() + " :\001DCC " + sType + " " +
                                sFile + " " + NoString(socket->GetUserPort()) + " " + No::token(message, 4) + "\001");
                    }
                }
            } else if (sType.equals("ACCEPT")) {
                // Need to lookup the connection by port, filter the port, and forward to the user
                for (NoDccBounce* socket : m_sockets) {
                    if (socket->GetUserPort() == No::token(message, 3).toUShort()) {
                        putUser(":" + nick.toString() + " PRIVMSG " + network->currentNick() + " :\001DCC " + sType + " " +
                                sFile + " " + NoString(socket->localPort()) + " " + No::token(message, 4) + "\001");
                    }
                }
            }

            return HaltCore;
        }

        return Continue;
    }
    void AddSocket(NoDccBounce* socket)
    {
        m_sockets.insert(socket);
    }
    void RemoveSocket(NoDccBounce* socket)
    {
        m_sockets.erase(socket);
    }

private:
    std::set<NoDccBounce*> m_sockets;
};

NoDccBounce::NoDccBounce(NoBounceDccMod* mod,
                         ulong uLongIP,
                         ushort port,
                         const NoString& fileName,
                         const NoString& sRemoteNick,
                         const NoString& sRemoteIP,
                         bool bIsChat)
    : NoModuleSocket(mod)
{
    m_uRemotePort = port;
    m_sConnectIP = No::formatIp(uLongIP);
    m_sRemoteIP = sRemoteIP;
    m_sFileName = fileName;
    m_sRemoteNick = sRemoteNick;
    m_module = mod;
    m_bIsChat = bIsChat;
    m_sLocalIP = mod->GetLocalDCCIP();
    m_pPeer = nullptr;
    m_bIsRemote = false;

    if (bIsChat) {
        enableReadLine();
    } else {
        disableReadLine();
    }
    mod->AddSocket(this);
}

NoDccBounce::NoDccBounce(NoBounceDccMod* mod,
                         const NoString& hostname,
                         ushort port,
                         const NoString& sRemoteNick,
                         const NoString& sRemoteIP,
                         const NoString& fileName,
                         bool bIsChat)
    : NoModuleSocket(mod, hostname, port)
{
    m_uRemotePort = 0;
    m_bIsChat = bIsChat;
    m_module = mod;
    m_pPeer = nullptr;
    m_sRemoteNick = sRemoteNick;
    m_sFileName = fileName;
    m_sRemoteIP = sRemoteIP;
    m_bIsRemote = false;

    setMaxBufferThreshold(10240);
    if (bIsChat) {
        enableReadLine();
    } else {
        disableReadLine();
    }
    mod->AddSocket(this);
}

NoDccBounce::~NoDccBounce()
{
    if (m_pPeer) {
        m_pPeer->Shutdown();
        m_pPeer = nullptr;
    }
    m_module->RemoveSocket(this);
}

void NoDccBounce::readLine(const NoString& data)
{
    NoString line = data.trimRight_n("\r\n");

    NO_DEBUG(name() << " <- [" << line << "]");

    PutPeer(line);
}

void NoDccBounce::onReachedMaxBuffer()
{
    NO_DEBUG(name() << " == ReachedMaxBuffer()");

    NoString sType = (m_bIsChat) ? "Chat" : "Xfer";

    m_module->putModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Too long line received");
    close();
}

void NoDccBounce::readData(const char* data, size_t len)
{
    if (m_pPeer) {
        m_pPeer->write(data, len);

        size_t BufLen = m_pPeer->internalWriteBuffer().length();

        if (BufLen >= m_uiMaxDCCBuffer) {
            NO_DEBUG(name() << " The send buffer is over the "
                                      "limit (" << BufLen << "), throttling");
            pauseRead();
        }
    }
}

void NoDccBounce::onReadPaused()
{
    if (!m_pPeer || m_pPeer->internalWriteBuffer().length() <= m_uiMinDCCBuffer)
        resumeRead();
}

void NoDccBounce::onTimeout()
{
    NO_DEBUG(name() << " == Timeout()");
    NoString sType = (m_bIsChat) ? "Chat" : "Xfer";

    if (IsRemote()) {
        NoString host = NoSocket::host();
        if (!host.empty()) {
            host = " to [" + host + " " + NoString(NoSocket::port()) + "]";
        } else {
            host = ".";
        }

        m_module->putModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Timeout while connecting" + host);
    } else {
        m_module->putModule("DCC " + sType + " Bounce (" + m_sRemoteNick +
                            "): Timeout waiting for incoming connection [" + NoSocket::localAddress() + ":" +
                            NoString(NoSocket::localPort()) + "]");
    }
}

void NoDccBounce::onConnectionRefused()
{
    NO_DEBUG(name() << " == ConnectionRefused()");

    NoString sType = (m_bIsChat) ? "Chat" : "Xfer";
    NoString host = NoSocket::host();
    if (!host.empty()) {
        host = " to [" + host + " " + NoString(NoSocket::port()) + "]";
    } else {
        host = ".";
    }

    m_module->putModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Connection Refused while connecting" + host);
}

void NoDccBounce::onSocketError(int iErrno, const NoString& description)
{
    NO_DEBUG(name() << " == SockError(" << iErrno << ")");
    NoString sType = (m_bIsChat) ? "Chat" : "Xfer";

    if (IsRemote()) {
        NoString host = NoSocket::host();
        if (!host.empty()) {
            host = "[" + host + " " + NoString(NoSocket::port()) + "]";
        }

        m_module->putModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Socket error [" + description + "]" + host);
    } else {
        m_module->putModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Socket error [" + description + "] [" +
                            NoSocket::localAddress() + ":" + NoString(NoSocket::localPort()) + "]");
    }
}

void NoDccBounce::onConnected()
{
    setTimeout(0);
    NO_DEBUG(name() << " == Connected()");
}

void NoDccBounce::onDisconnected()
{
    NO_DEBUG(name() << " == Disconnected()");
}

void NoDccBounce::Shutdown()
{
    m_pPeer = nullptr;
    NO_DEBUG(name() << " == Close(); because my peer told me to");
    close();
}

NoSocket* NoDccBounce::createSocket(const NoString& host, ushort port)
{
    close();

    if (m_sRemoteIP.empty()) {
        m_sRemoteIP = host;
    }

    NoDccBounce* socket = new NoDccBounce(m_module, host, port, m_sRemoteNick, m_sRemoteIP, m_sFileName, m_bIsChat);
    NoDccBounce* pRemoteSock = new NoDccBounce(m_module, host, port, m_sRemoteNick, m_sRemoteIP, m_sFileName, m_bIsChat);
    socket->SetPeer(pRemoteSock);
    pRemoteSock->SetPeer(socket);
    pRemoteSock->SetRemote(true);
    socket->SetRemote(false);

    noApp->manager()->connect(m_sConnectIP,
                                   m_uRemotePort,
                                   "DCC::" + NoString((m_bIsChat) ? "Chat" : "XFER") + "::Remote::" + m_sRemoteNick,
                                   false,
                                   m_sLocalIP,
                                   pRemoteSock);

    socket->setName(name());
    return socket;
}

void NoDccBounce::PutServ(const NoString& line)
{
    NO_DEBUG(name() << " -> [" << line << "]");
    write(line + "\r\n");
}

void NoDccBounce::PutPeer(const NoString& line)
{
    if (m_pPeer) {
        m_pPeer->PutServ(line);
    } else {
        PutServ("*** Not connected yet ***");
    }
}

ushort NoDccBounce::DCCRequest(const NoString& nick,
                               ulong uLongIP,
                               ushort port,
                               const NoString& fileName,
                               bool bIsChat,
                               NoBounceDccMod* mod,
                               const NoString& sRemoteIP)
{
    NoDccBounce* pDCCBounce = new NoDccBounce(mod, uLongIP, port, fileName, nick, sRemoteIP, bIsChat);
    noApp->manager()->listen(0, "DCC::" + NoString((bIsChat) ? "Chat" : "Xfer") + "::Local::" + nick, mod->GetLocalDCCIP(), false, pDCCBounce);
    pDCCBounce->setTimeout(120);

    return pDCCBounce->port();
}

template <>
void no_moduleInfo<NoBounceDccMod>(NoModuleInfo& info)
{
    info.setWikiPage("bouncedcc");
}

USERMODULEDEFS(NoBounceDccMod, "Bounces DCC transfers through ZNC instead of sending them directly to the user. ")
