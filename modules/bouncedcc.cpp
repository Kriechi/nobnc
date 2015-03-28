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

    static ushort DCCRequest(const NoString& sNick,
                                     ulong uLongIP,
                                     ushort uPort,
                                     const NoString& sFileName,
                                     bool bIsChat,
                                     NoBounceDccMod* pMod,
                                     const NoString& sRemoteIP);

    void ReadLineImpl(const NoString& sData) override;
    void ReadDataImpl(const char* data, size_t len) override;
    void ReadPausedImpl() override;
    void TimeoutImpl() override;
    void ConnectionRefusedImpl() override;
    void ReachedMaxBufferImpl() override;
    void SockErrorImpl(int iErrno, const NoString& sDescription) override;
    void ConnectedImpl() override;
    void DisconnectedImpl() override;
    NoSocket* GetSockObjImpl(const NoString& sHost, ushort uPort) override;
    void Shutdown();
    void PutServ(const NoString& sLine);
    void PutPeer(const NoString& sLine);
    bool IsPeerConnected() { return (m_pPeer) ? m_pPeer->IsConnected() : false; }

    // Setters
    void SetPeer(NoDccBounce* p) { m_pPeer = p; }
    void SetRemoteIP(const NoString& s) { m_sRemoteIP = s; }
    void SetRemoteNick(const NoString& s) { m_sRemoteNick = s; }
    void SetRemote(bool b) { m_bIsRemote = b; }
    // !Setters

    // Getters
    ushort GetUserPort() const { return m_uRemotePort; }
    const NoString& GetRemoteAddr() const { return m_sRemoteIP; }
    const NoString& GetRemoteNick() const { return m_sRemoteNick; }
    const NoString& GetFileName() const { return m_sFileName; }
    NoDccBounce* GetPeer() const { return m_pPeer; }
    bool IsRemote() { return m_bIsRemote; }
    bool IsChat() { return m_bIsChat; }
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
            NoString sSockName = pSock->GetSockName();

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
                if ((pSock->IsConnected()) || (pSock->IsPeerConnected())) {
                    sState = "Halfway";
                    if ((pSock->IsConnected()) && (pSock->IsPeerConnected())) {
                        sState = "Connected";
                    }
                }
                Table.setValue("State", sState);
            }
        }

        if (PutModule(Table) == 0) {
            PutModule("You have no active DCCs.");
        }
    }

    void UseClientIPCommand(const NoString& sLine)
    {
        NoString sValue = No::tokens(sLine, 1);

        NoRegistry registry(this);
        if (!sValue.empty()) {
            registry.setValue("UseClientIP", sValue);
        }

        PutModule("UseClientIP: " + NoString(registry.value("UseClientIP").toBool()));
    }

    MODCONSTRUCTOR(NoBounceDccMod)
    {
        AddHelpCommand();
        AddCommand("ListDCCs",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoBounceDccMod::ListDCCsCommand),
                   "",
                   "List all active DCCs");
        AddCommand("UseClientIP",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoBounceDccMod::UseClientIPCommand),
                   "<true|false>");
    }

    NoString GetLocalDCCIP() { return GetUser()->localDccIp(); }

    bool UseClientIP() { return NoRegistry(this).value("UseClientIP").toBool(); }

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
                uLongIP = No::formatLongIp(GetClient()->GetSocket()->GetRemoteIP());
            }

            if (sType.equals("CHAT")) {
                ushort uBNCPort = NoDccBounce::DCCRequest(sTarget, uLongIP, uPort, "", true, this, "");
                if (uBNCPort) {
                    PutIRC("PRIVMSG " + sTarget + " :\001DCC CHAT chat " + NoString(No::formatLongIp(sIP)) + " " +
                           NoString(uBNCPort) + "\001");
                }
            } else if (sType.equals("SEND")) {
                // DCC SEND readme.txt 403120438 5550 1104
                ushort uBNCPort = NoDccBounce::DCCRequest(sTarget, uLongIP, uPort, sFile, false, this, "");
                if (uBNCPort) {
                    PutIRC("PRIVMSG " + sTarget + " :\001DCC SEND " + sFile + " " + NoString(No::formatLongIp(sIP)) +
                           " " + NoString(uBNCPort) + " " + NoString(uFileSize) + "\001");
                }
            } else if (sType.equals("RESUME")) {
                // PRIVMSG user :DCC RESUME "znc.o" 58810 151552
                ushort uResumePort = No::token(sMessage, 3).toUShort();

                for (NoDccBounce* pSock : m_sockets) {
                    if (pSock->GetLocalPort() == uResumePort) {
                        PutIRC("PRIVMSG " + sTarget + " :\001DCC " + sType + " " + sFile + " " +
                               NoString(pSock->GetUserPort()) + " " + No::token(sMessage, 4) + "\001");
                    }
                }
            } else if (sType.equals("ACCEPT")) {
                // Need to lookup the connection by port, filter the port, and forward to the user

                for (NoDccBounce* pSock : m_sockets) {
                    if (pSock->GetUserPort() == No::token(sMessage, 3).toUShort()) {
                        PutIRC("PRIVMSG " + sTarget + " :\001DCC " + sType + " " + sFile + " " +
                               NoString(pSock->GetLocalPort()) + " " + No::token(sMessage, 4) + "\001");
                    }
                }
            }

            return HALTCORE;
        }

        return CONTINUE;
    }

    ModRet onPrivCtcp(NoNick& Nick, NoString& sMessage) override
    {
        NoNetwork* pNetwork = GetNetwork();
        if (sMessage.startsWith("DCC ") && pNetwork->IsUserAttached()) {
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
                ushort uBNCPort =
                NoDccBounce::DCCRequest(FromNick.nick(), uLongIP, uPort, "", true, this, No::formatIp(uLongIP));
                if (uBNCPort) {
                    NoString sIP = GetLocalDCCIP();
                    PutUser(":" + Nick.nickMask() + " PRIVMSG " + pNetwork->GetCurNick() + " :\001DCC CHAT chat " +
                            NoString(No::formatLongIp(sIP)) + " " + NoString(uBNCPort) + "\001");
                }
            } else if (sType.equals("SEND")) {
                // DCC SEND readme.txt 403120438 5550 1104
                ushort uBNCPort =
                NoDccBounce::DCCRequest(Nick.nick(), uLongIP, uPort, sFile, false, this, No::formatIp(uLongIP));
                if (uBNCPort) {
                    NoString sIP = GetLocalDCCIP();
                    PutUser(":" + Nick.nickMask() + " PRIVMSG " + pNetwork->GetCurNick() + " :\001DCC SEND " + sFile + " " +
                            NoString(No::formatLongIp(sIP)) + " " + NoString(uBNCPort) + " " + NoString(uFileSize) + "\001");
                }
            } else if (sType.equals("RESUME")) {
                // Need to lookup the connection by port, filter the port, and forward to the user
                ushort uResumePort = No::token(sMessage, 3).toUShort();

                for (NoDccBounce* pSock : m_sockets) {
                    if (pSock->GetLocalPort() == uResumePort) {
                        PutUser(":" + Nick.nickMask() + " PRIVMSG " + pNetwork->GetCurNick() + " :\001DCC " + sType +
                                " " + sFile + " " + NoString(pSock->GetUserPort()) + " " + No::token(sMessage, 4) + "\001");
                    }
                }
            } else if (sType.equals("ACCEPT")) {
                // Need to lookup the connection by port, filter the port, and forward to the user
                for (NoDccBounce* pSock : m_sockets) {
                    if (pSock->GetUserPort() == No::token(sMessage, 3).toUShort()) {
                        PutUser(":" + Nick.nickMask() + " PRIVMSG " + pNetwork->GetCurNick() + " :\001DCC " + sType +
                                " " + sFile + " " + NoString(pSock->GetLocalPort()) + " " + No::token(sMessage, 4) + "\001");
                    }
                }
            }

            return HALTCORE;
        }

        return CONTINUE;
    }
    void AddSocket(NoDccBounce* socket) { m_sockets.insert(socket); }
    void RemoveSocket(NoDccBounce* socket) { m_sockets.erase(socket); }
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
        EnableReadLine();
    } else {
        DisableReadLine();
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

    SetMaxBufferThreshold(10240);
    if (bIsChat) {
        EnableReadLine();
    } else {
        DisableReadLine();
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

void NoDccBounce::ReadLineImpl(const NoString& sData)
{
    NoString sLine = sData.trimRight_n("\r\n");

    NO_DEBUG(GetSockName() << " <- [" << sLine << "]");

    PutPeer(sLine);
}

void NoDccBounce::ReachedMaxBufferImpl()
{
    NO_DEBUG(GetSockName() << " == ReachedMaxBuffer()");

    NoString sType = (m_bIsChat) ? "Chat" : "Xfer";

    m_module->PutModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Too long line received");
    Close();
}

void NoDccBounce::ReadDataImpl(const char* data, size_t len)
{
    if (m_pPeer) {
        m_pPeer->Write(data, len);

        size_t BufLen = m_pPeer->GetInternalWriteBuffer().length();

        if (BufLen >= m_uiMaxDCCBuffer) {
            NO_DEBUG(GetSockName() << " The send buffer is over the "
                                   "limit (" << BufLen << "), throttling");
            PauseRead();
        }
    }
}

void NoDccBounce::ReadPausedImpl()
{
    if (!m_pPeer || m_pPeer->GetInternalWriteBuffer().length() <= m_uiMinDCCBuffer) UnPauseRead();
}

void NoDccBounce::TimeoutImpl()
{
    NO_DEBUG(GetSockName() << " == Timeout()");
    NoString sType = (m_bIsChat) ? "Chat" : "Xfer";

    if (IsRemote()) {
        NoString sHost = NoSocket::GetHostName();
        if (!sHost.empty()) {
            sHost = " to [" + sHost + " " + NoString(NoSocket::GetPort()) + "]";
        } else {
            sHost = ".";
        }

        m_module->PutModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Timeout while connecting" + sHost);
    } else {
        m_module->PutModule("DCC " + sType + " Bounce (" + m_sRemoteNick +
                             "): Timeout waiting for incoming connection [" + NoSocket::GetLocalIP() + ":" +
                             NoString(NoSocket::GetLocalPort()) + "]");
    }
}

void NoDccBounce::ConnectionRefusedImpl()
{
    NO_DEBUG(GetSockName() << " == ConnectionRefused()");

    NoString sType = (m_bIsChat) ? "Chat" : "Xfer";
    NoString sHost = NoSocket::GetHostName();
    if (!sHost.empty()) {
        sHost = " to [" + sHost + " " + NoString(NoSocket::GetPort()) + "]";
    } else {
        sHost = ".";
    }

    m_module->PutModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Connection Refused while connecting" + sHost);
}

void NoDccBounce::SockErrorImpl(int iErrno, const NoString& sDescription)
{
    NO_DEBUG(GetSockName() << " == SockError(" << iErrno << ")");
    NoString sType = (m_bIsChat) ? "Chat" : "Xfer";

    if (IsRemote()) {
        NoString sHost = NoSocket::GetHostName();
        if (!sHost.empty()) {
            sHost = "[" + sHost + " " + NoString(NoSocket::GetPort()) + "]";
        }

        m_module->PutModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Socket error [" + sDescription + "]" + sHost);
    } else {
        m_module->PutModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Socket error [" + sDescription + "] [" +
                             NoSocket::GetLocalIP() + ":" + NoString(NoSocket::GetLocalPort()) + "]");
    }
}

void NoDccBounce::ConnectedImpl()
{
    SetTimeout(0);
    NO_DEBUG(GetSockName() << " == Connected()");
}

void NoDccBounce::DisconnectedImpl() { NO_DEBUG(GetSockName() << " == Disconnected()"); }

void NoDccBounce::Shutdown()
{
    m_pPeer = nullptr;
    NO_DEBUG(GetSockName() << " == Close(); because my peer told me to");
    Close();
}

NoSocket* NoDccBounce::GetSockObjImpl(const NoString& sHost, ushort uPort)
{
    Close();

    if (m_sRemoteIP.empty()) {
        m_sRemoteIP = sHost;
    }

    NoDccBounce* pSock = new NoDccBounce(m_module, sHost, uPort, m_sRemoteNick, m_sRemoteIP, m_sFileName, m_bIsChat);
    NoDccBounce* pRemoteSock = new NoDccBounce(m_module, sHost, uPort, m_sRemoteNick, m_sRemoteIP, m_sFileName, m_bIsChat);
    pSock->SetPeer(pRemoteSock);
    pRemoteSock->SetPeer(pSock);
    pRemoteSock->SetRemote(true);
    pSock->SetRemote(false);

    NoApp::Get().GetManager().Connect(m_sConnectIP,
                                     m_uRemotePort,
                                     "DCC::" + NoString((m_bIsChat) ? "Chat" : "XFER") + "::Remote::" + m_sRemoteNick,
                                     60,
                                     false,
                                     m_sLocalIP,
                                     pRemoteSock);

    pSock->SetSockName(GetSockName());
    return pSock;
}

void NoDccBounce::PutServ(const NoString& sLine)
{
    NO_DEBUG(GetSockName() << " -> [" << sLine << "]");
    Write(sLine + "\r\n");
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
    ushort uListenPort = NoApp::Get().GetManager().ListenRand(
    "DCC::" + NoString((bIsChat) ? "Chat" : "Xfer") + "::Local::" + sNick, pMod->GetLocalDCCIP(), false, SOMAXCONN, pDCCBounce, 120);

    return uListenPort;
}

template <> void no_moduleInfo<NoBounceDccMod>(NoModuleInfo& Info) { Info.SetWikiPage("bouncedcc"); }

USERMODULEDEFS(NoBounceDccMod, "Bounces DCC transfers through ZNC instead of sending them directly to the user. ")
