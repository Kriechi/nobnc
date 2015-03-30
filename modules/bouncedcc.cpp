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

#include <no/nomodule.h>
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/nodebug.h>
#include <no/noclient.h>
#include <no/noapp.h>
#include <no/nomodulesocket.h>
#include <no/noregistry.h>
#include <no/nonick.h>

class NoBounceDccMod;

class NoDccBounce : public NoModuleSocket
{
public:
    NoDccBounce(NoBounceDccMod* pMod,
                ulong uLongIP,
                ushort uPort,
                const NoString& sFileName,
                const NoString& sRemoteNick,
                const NoString& sRemoteIP,
                bool bIsChat = false);
    NoDccBounce(NoBounceDccMod* pMod,
                const NoString& sHostname,
                ushort uPort,
                const NoString& sRemoteNick,
                const NoString& sRemoteIP,
                const NoString& sFileName,
                bool bIsChat = false);
    virtual ~NoDccBounce();

    static ushort
    DCCRequest(const NoString& sNick, ulong uLongIP, ushort uPort, const NoString& sFileName, bool bIsChat, NoBounceDccMod* pMod, const NoString& sRemoteIP);

    void readLine(const NoString& sData) override;
    void readData(const char* data, size_t len) override;
    void onReadPaused() override;
    void onTimeout() override;
    void onConnectionRefused() override;
    void onReachedMaxBuffer() override;
    void onSocketError(int iErrno, const NoString& sDescription) override;
    void onConnected() override;
    void onDisconnected() override;
    NoSocket* createSocket(const NoString& sHost, ushort uPort) override;
    void Shutdown();
    void PutServ(const NoString& sLine);
    void PutPeer(const NoString& sLine);
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
    void ListDCCsCommand(const NoString& sLine)
    {
        NoTable Table;
        Table.addColumn("Type");
        Table.addColumn("State");
        Table.addColumn("Speed");
        Table.addColumn("Nick");
        Table.addColumn("IP");
        Table.addColumn("File");

        for (NoDccBounce* pSock : m_sockets) {
            NoString sSockName = pSock->name();

            if (!(pSock->IsRemote())) {
                Table.addRow();
                Table.setValue("Nick", pSock->GetRemoteNick());
                Table.setValue("IP", pSock->GetRemoteAddr());

                if (pSock->IsChat()) {
                    Table.setValue("Type", "Chat");
                } else {
                    Table.setValue("Type", "Xfer");
                    Table.setValue("File", pSock->GetFileName());
                }

                NoString sState = "Waiting";
                if ((pSock->isConnected()) || (pSock->IsPeerConnected())) {
                    sState = "Halfway";
                    if ((pSock->isConnected()) && (pSock->IsPeerConnected())) {
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

    void UseClientIPCommand(const NoString& sLine)
    {
        NoString sValue = No::tokens(sLine, 1);

        NoRegistry registry(this);
        if (!sValue.empty()) {
            registry.setValue("UseClientIP", sValue);
        }

        putModule("UseClientIP: " + NoString(registry.value("UseClientIP").toBool()));
    }

    MODCONSTRUCTOR(NoBounceDccMod)
    {
        addHelpCommand();
        addCommand("ListDCCs",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoBounceDccMod::ListDCCsCommand),
                   "",
                   "List all active DCCs");
        addCommand("UseClientIP",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoBounceDccMod::UseClientIPCommand),
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

    ModRet onUserCtcp(NoString& sTarget, NoString& sMessage) override
    {
        if (sMessage.startsWith("DCC ")) {
            NoStringVector tokens = No::quoteSplit(sMessage);
            tokens.resize(6);
            NoString sType = tokens.at(1).trim_n("\"");
            NoString sFile = tokens.at(2);
            ulong uLongIP = tokens.at(3).trim_n("\"").toULong();
            ushort uPort = tokens.at(4).trim_n("\"").toUShort();
            ulong uFileSize = tokens.at(5).trim_n("\"").toULong();
            NoString sIP = GetLocalDCCIP();

            if (!UseClientIP()) {
                uLongIP = No::formatLongIp(client()->socket()->remoteAddress());
            }

            if (sType.equals("CHAT")) {
                ushort uBNCPort = NoDccBounce::DCCRequest(sTarget, uLongIP, uPort, "", true, this, "");
                if (uBNCPort) {
                    putIrc("PRIVMSG " + sTarget + " :\001DCC CHAT chat " + NoString(No::formatLongIp(sIP)) + " " +
                           NoString(uBNCPort) + "\001");
                }
            } else if (sType.equals("SEND")) {
                // DCC SEND readme.txt 403120438 5550 1104
                ushort uBNCPort = NoDccBounce::DCCRequest(sTarget, uLongIP, uPort, sFile, false, this, "");
                if (uBNCPort) {
                    putIrc("PRIVMSG " + sTarget + " :\001DCC SEND " + sFile + " " + NoString(No::formatLongIp(sIP)) +
                           " " + NoString(uBNCPort) + " " + NoString(uFileSize) + "\001");
                }
            } else if (sType.equals("RESUME")) {
                // PRIVMSG user :DCC RESUME "znc.o" 58810 151552
                ushort uResumePort = No::token(sMessage, 3).toUShort();

                for (NoDccBounce* pSock : m_sockets) {
                    if (pSock->localPort() == uResumePort) {
                        putIrc("PRIVMSG " + sTarget + " :\001DCC " + sType + " " + sFile + " " +
                               NoString(pSock->GetUserPort()) + " " + No::token(sMessage, 4) + "\001");
                    }
                }
            } else if (sType.equals("ACCEPT")) {
                // Need to lookup the connection by port, filter the port, and forward to the user

                for (NoDccBounce* pSock : m_sockets) {
                    if (pSock->GetUserPort() == No::token(sMessage, 3).toUShort()) {
                        putIrc("PRIVMSG " + sTarget + " :\001DCC " + sType + " " + sFile + " " +
                               NoString(pSock->localPort()) + " " + No::token(sMessage, 4) + "\001");
                    }
                }
            }

            return HALTCORE;
        }

        return CONTINUE;
    }

    ModRet onPrivCtcp(NoNick& Nick, NoString& sMessage) override
    {
        NoNetwork* pNetwork = network();
        if (sMessage.startsWith("DCC ") && pNetwork->isUserAttached()) {
            // DCC CHAT chat 2453612361 44592
            NoStringVector tokens = No::quoteSplit(sMessage);
            tokens.resize(6);
            NoString sType = tokens.at(1).trim_n("\"");
            NoString sFile = tokens.at(2);
            ulong uLongIP = tokens.at(3).trim_n("\"").toULong();
            ushort uPort = tokens.at(4).trim_n("\"").toUShort();
            ulong uFileSize = tokens.at(5).trim_n("\"").toULong();

            if (sType.equals("CHAT")) {
                NoNick FromNick(Nick.nickMask());
                ushort uBNCPort = NoDccBounce::DCCRequest(FromNick.nick(), uLongIP, uPort, "", true, this, No::formatIp(uLongIP));
                if (uBNCPort) {
                    NoString sIP = GetLocalDCCIP();
                    putUser(":" + Nick.nickMask() + " PRIVMSG " + pNetwork->currentNick() + " :\001DCC CHAT chat " +
                            NoString(No::formatLongIp(sIP)) + " " + NoString(uBNCPort) + "\001");
                }
            } else if (sType.equals("SEND")) {
                // DCC SEND readme.txt 403120438 5550 1104
                ushort uBNCPort = NoDccBounce::DCCRequest(Nick.nick(), uLongIP, uPort, sFile, false, this, No::formatIp(uLongIP));
                if (uBNCPort) {
                    NoString sIP = GetLocalDCCIP();
                    putUser(":" + Nick.nickMask() + " PRIVMSG " + pNetwork->currentNick() + " :\001DCC SEND " + sFile + " " +
                            NoString(No::formatLongIp(sIP)) + " " + NoString(uBNCPort) + " " + NoString(uFileSize) + "\001");
                }
            } else if (sType.equals("RESUME")) {
                // Need to lookup the connection by port, filter the port, and forward to the user
                ushort uResumePort = No::token(sMessage, 3).toUShort();

                for (NoDccBounce* pSock : m_sockets) {
                    if (pSock->localPort() == uResumePort) {
                        putUser(":" + Nick.nickMask() + " PRIVMSG " + pNetwork->currentNick() + " :\001DCC " + sType + " " +
                                sFile + " " + NoString(pSock->GetUserPort()) + " " + No::token(sMessage, 4) + "\001");
                    }
                }
            } else if (sType.equals("ACCEPT")) {
                // Need to lookup the connection by port, filter the port, and forward to the user
                for (NoDccBounce* pSock : m_sockets) {
                    if (pSock->GetUserPort() == No::token(sMessage, 3).toUShort()) {
                        putUser(":" + Nick.nickMask() + " PRIVMSG " + pNetwork->currentNick() + " :\001DCC " + sType + " " +
                                sFile + " " + NoString(pSock->localPort()) + " " + No::token(sMessage, 4) + "\001");
                    }
                }
            }

            return HALTCORE;
        }

        return CONTINUE;
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

NoDccBounce::NoDccBounce(NoBounceDccMod* pMod,
                         ulong uLongIP,
                         ushort uPort,
                         const NoString& sFileName,
                         const NoString& sRemoteNick,
                         const NoString& sRemoteIP,
                         bool bIsChat)
    : NoModuleSocket(pMod)
{
    m_uRemotePort = uPort;
    m_sConnectIP = No::formatIp(uLongIP);
    m_sRemoteIP = sRemoteIP;
    m_sFileName = sFileName;
    m_sRemoteNick = sRemoteNick;
    m_module = pMod;
    m_bIsChat = bIsChat;
    m_sLocalIP = pMod->GetLocalDCCIP();
    m_pPeer = nullptr;
    m_bIsRemote = false;

    if (bIsChat) {
        enableReadLine();
    } else {
        disableReadLine();
    }
    pMod->AddSocket(this);
}

NoDccBounce::NoDccBounce(NoBounceDccMod* pMod,
                         const NoString& sHostname,
                         ushort uPort,
                         const NoString& sRemoteNick,
                         const NoString& sRemoteIP,
                         const NoString& sFileName,
                         bool bIsChat)
    : NoModuleSocket(pMod, sHostname, uPort)
{
    m_uRemotePort = 0;
    m_bIsChat = bIsChat;
    m_module = pMod;
    m_pPeer = nullptr;
    m_sRemoteNick = sRemoteNick;
    m_sFileName = sFileName;
    m_sRemoteIP = sRemoteIP;
    m_bIsRemote = false;

    setMaxBufferThreshold(10240);
    if (bIsChat) {
        enableReadLine();
    } else {
        disableReadLine();
    }
    pMod->AddSocket(this);
}

NoDccBounce::~NoDccBounce()
{
    if (m_pPeer) {
        m_pPeer->Shutdown();
        m_pPeer = nullptr;
    }
    m_module->RemoveSocket(this);
}

void NoDccBounce::readLine(const NoString& sData)
{
    NoString sLine = sData.trimRight_n("\r\n");

    NO_DEBUG(name() << " <- [" << sLine << "]");

    PutPeer(sLine);
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
        NoString sHost = NoSocket::host();
        if (!sHost.empty()) {
            sHost = " to [" + sHost + " " + NoString(NoSocket::port()) + "]";
        } else {
            sHost = ".";
        }

        m_module->putModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Timeout while connecting" + sHost);
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
    NoString sHost = NoSocket::host();
    if (!sHost.empty()) {
        sHost = " to [" + sHost + " " + NoString(NoSocket::port()) + "]";
    } else {
        sHost = ".";
    }

    m_module->putModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Connection Refused while connecting" + sHost);
}

void NoDccBounce::onSocketError(int iErrno, const NoString& sDescription)
{
    NO_DEBUG(name() << " == SockError(" << iErrno << ")");
    NoString sType = (m_bIsChat) ? "Chat" : "Xfer";

    if (IsRemote()) {
        NoString sHost = NoSocket::host();
        if (!sHost.empty()) {
            sHost = "[" + sHost + " " + NoString(NoSocket::port()) + "]";
        }

        m_module->putModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Socket error [" + sDescription + "]" + sHost);
    } else {
        m_module->putModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Socket error [" + sDescription + "] [" +
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

NoSocket* NoDccBounce::createSocket(const NoString& sHost, ushort uPort)
{
    close();

    if (m_sRemoteIP.empty()) {
        m_sRemoteIP = sHost;
    }

    NoDccBounce* pSock = new NoDccBounce(m_module, sHost, uPort, m_sRemoteNick, m_sRemoteIP, m_sFileName, m_bIsChat);
    NoDccBounce* pRemoteSock = new NoDccBounce(m_module, sHost, uPort, m_sRemoteNick, m_sRemoteIP, m_sFileName, m_bIsChat);
    pSock->SetPeer(pRemoteSock);
    pRemoteSock->SetPeer(pSock);
    pRemoteSock->SetRemote(true);
    pSock->SetRemote(false);

    NoApp::instance().manager().connect(m_sConnectIP,
                                   m_uRemotePort,
                                   "DCC::" + NoString((m_bIsChat) ? "Chat" : "XFER") + "::Remote::" + m_sRemoteNick,
                                   60,
                                   false,
                                   m_sLocalIP,
                                   pRemoteSock);

    pSock->setName(name());
    return pSock;
}

void NoDccBounce::PutServ(const NoString& sLine)
{
    NO_DEBUG(name() << " -> [" << sLine << "]");
    write(sLine + "\r\n");
}

void NoDccBounce::PutPeer(const NoString& sLine)
{
    if (m_pPeer) {
        m_pPeer->PutServ(sLine);
    } else {
        PutServ("*** Not connected yet ***");
    }
}

ushort NoDccBounce::DCCRequest(const NoString& sNick,
                               ulong uLongIP,
                               ushort uPort,
                               const NoString& sFileName,
                               bool bIsChat,
                               NoBounceDccMod* pMod,
                               const NoString& sRemoteIP)
{
    NoDccBounce* pDCCBounce = new NoDccBounce(pMod, uLongIP, uPort, sFileName, sNick, sRemoteIP, bIsChat);
    ushort uListenPort = NoApp::instance().manager().listenRand(
    "DCC::" + NoString((bIsChat) ? "Chat" : "Xfer") + "::Local::" + sNick, pMod->GetLocalDCCIP(), false, SOMAXCONN, pDCCBounce, 120);

    return uListenPort;
}

template <>
void no_moduleInfo<NoBounceDccMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("bouncedcc");
}

USERMODULEDEFS(NoBounceDccMod, "Bounces DCC transfers through ZNC instead of sending them directly to the user. ")
