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

#include <no/nouser.h>
#include <no/nonetwork.h>

class NoBounceDccMod;

class NoDccBounce : public NoSocket
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
               int iTimeout = 60,
               bool bIsChat = false);
    virtual ~NoDccBounce();

    static ushort DCCRequest(const NoString& sNick,
                                     ulong uLongIP,
                                     ushort uPort,
                                     const NoString& sFileName,
                                     bool bIsChat,
                                     NoBounceDccMod* pMod,
                                     const NoString& sRemoteIP);

    void ReadLine(const NoString& sData) override;
    void ReadData(const char* data, size_t len) override;
    void ReadPaused() override;
    void Timeout() override;
    void ConnectionRefused() override;
    void ReachedMaxBuffer() override;
    void SockError(int iErrno, const NoString& sDescription) override;
    void Connected() override;
    void Disconnected() override;
    Csock* GetSockObj(const NoString& sHost, ushort uPort) override;
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
    NoBounceDccMod* m_pModule;
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
        Table.AddColumn("Type");
        Table.AddColumn("State");
        Table.AddColumn("Speed");
        Table.AddColumn("Nick");
        Table.AddColumn("IP");
        Table.AddColumn("File");

        std::set<NoSocket*>::const_iterator it;
        for (it = BeginSockets(); it != EndSockets(); ++it) {
            NoDccBounce* pSock = (NoDccBounce*)*it;
            NoString sSockName = pSock->GetSockName();

            if (!(pSock->IsRemote())) {
                Table.AddRow();
                Table.SetCell("Nick", pSock->GetRemoteNick());
                Table.SetCell("IP", pSock->GetRemoteAddr());

                if (pSock->IsChat()) {
                    Table.SetCell("Type", "Chat");
                } else {
                    Table.SetCell("Type", "Xfer");
                    Table.SetCell("File", pSock->GetFileName());
                }

                NoString sState = "Waiting";
                if ((pSock->IsConnected()) || (pSock->IsPeerConnected())) {
                    sState = "Halfway";
                    if ((pSock->IsConnected()) && (pSock->IsPeerConnected())) {
                        sState = "Connected";
                    }
                }
                Table.SetCell("State", sState);
            }
        }

        if (PutModule(Table) == 0) {
            PutModule("You have no active DCCs.");
        }
    }

    void UseClientIPCommand(const NoString& sLine)
    {
        NoString sValue = sLine.Token(1, true);

        if (!sValue.empty()) {
            SetNV("UseClientIP", sValue);
        }

        PutModule("UseClientIP: " + NoString(GetNV("UseClientIP").ToBool()));
    }

    MODCONSTRUCTOR(NoBounceDccMod)
    {
        AddHelpCommand();
        AddCommand("ListDCCs",
                   static_cast<NoModCommand::ModCmdFunc>(&NoBounceDccMod::ListDCCsCommand),
                   "",
                   "List all active DCCs");
        AddCommand("UseClientIP",
                   static_cast<NoModCommand::ModCmdFunc>(&NoBounceDccMod::UseClientIPCommand),
                   "<true|false>");
    }

    virtual ~NoBounceDccMod() {}

    NoString GetLocalDCCIP() { return GetUser()->GetLocalDCCIP(); }

    bool UseClientIP() { return GetNV("UseClientIP").ToBool(); }

    EModRet OnUserCTCP(NoString& sTarget, NoString& sMessage) override
    {
        if (sMessage.StartsWith("DCC ")) {
            NoString sType = sMessage.Token(1, false, " ", false, "\"", "\"", true);
            NoString sFile = sMessage.Token(2, false, " ", false, "\"", "\"", false);
            ulong uLongIP = sMessage.Token(3, false, " ", false, "\"", "\"", true).ToULong();
            ushort uPort = sMessage.Token(4, false, " ", false, "\"", "\"", true).ToUShort();
            ulong uFileSize = sMessage.Token(5, false, " ", false, "\"", "\"", true).ToULong();
            NoString sIP = GetLocalDCCIP();

            if (!UseClientIP()) {
                uLongIP = NoUtils::GetLongIP(GetClient()->GetRemoteIP());
            }

            if (sType.Equals("CHAT")) {
                ushort uBNCPort = NoDccBounce::DCCRequest(sTarget, uLongIP, uPort, "", true, this, "");
                if (uBNCPort) {
                    PutIRC("PRIVMSG " + sTarget + " :\001DCC CHAT chat " + NoString(NoUtils::GetLongIP(sIP)) + " " +
                           NoString(uBNCPort) + "\001");
                }
            } else if (sType.Equals("SEND")) {
                // DCC SEND readme.txt 403120438 5550 1104
                ushort uBNCPort = NoDccBounce::DCCRequest(sTarget, uLongIP, uPort, sFile, false, this, "");
                if (uBNCPort) {
                    PutIRC("PRIVMSG " + sTarget + " :\001DCC SEND " + sFile + " " + NoString(NoUtils::GetLongIP(sIP)) +
                           " " + NoString(uBNCPort) + " " + NoString(uFileSize) + "\001");
                }
            } else if (sType.Equals("RESUME")) {
                // PRIVMSG user :DCC RESUME "znc.o" 58810 151552
                ushort uResumePort = sMessage.Token(3).ToUShort();

                std::set<NoSocket*>::const_iterator it;
                for (it = BeginSockets(); it != EndSockets(); ++it) {
                    NoDccBounce* pSock = (NoDccBounce*)*it;

                    if (pSock->GetLocalPort() == uResumePort) {
                        PutIRC("PRIVMSG " + sTarget + " :\001DCC " + sType + " " + sFile + " " +
                               NoString(pSock->GetUserPort()) + " " + sMessage.Token(4) + "\001");
                    }
                }
            } else if (sType.Equals("ACCEPT")) {
                // Need to lookup the connection by port, filter the port, and forward to the user

                std::set<NoSocket*>::const_iterator it;
                for (it = BeginSockets(); it != EndSockets(); ++it) {
                    NoDccBounce* pSock = (NoDccBounce*)*it;
                    if (pSock->GetUserPort() == sMessage.Token(3).ToUShort()) {
                        PutIRC("PRIVMSG " + sTarget + " :\001DCC " + sType + " " + sFile + " " +
                               NoString(pSock->GetLocalPort()) + " " + sMessage.Token(4) + "\001");
                    }
                }
            }

            return HALTCORE;
        }

        return CONTINUE;
    }

    EModRet OnPrivCTCP(NoNick& Nick, NoString& sMessage) override
    {
        NoNetwork* pNetwork = GetNetwork();
        if (sMessage.StartsWith("DCC ") && pNetwork->IsUserAttached()) {
            // DCC CHAT chat 2453612361 44592
            NoString sType = sMessage.Token(1, false, " ", false, "\"", "\"", true);
            NoString sFile = sMessage.Token(2, false, " ", false, "\"", "\"", false);
            ulong uLongIP = sMessage.Token(3, false, " ", false, "\"", "\"", true).ToULong();
            ushort uPort = sMessage.Token(4, false, " ", false, "\"", "\"", true).ToUShort();
            ulong uFileSize = sMessage.Token(5, false, " ", false, "\"", "\"", true).ToULong();

            if (sType.Equals("CHAT")) {
                NoNick FromNick(Nick.GetNickMask());
                ushort uBNCPort =
                NoDccBounce::DCCRequest(FromNick.GetNick(), uLongIP, uPort, "", true, this, NoUtils::GetIP(uLongIP));
                if (uBNCPort) {
                    NoString sIP = GetLocalDCCIP();
                    PutUser(":" + Nick.GetNickMask() + " PRIVMSG " + pNetwork->GetCurNick() + " :\001DCC CHAT chat " +
                            NoString(NoUtils::GetLongIP(sIP)) + " " + NoString(uBNCPort) + "\001");
                }
            } else if (sType.Equals("SEND")) {
                // DCC SEND readme.txt 403120438 5550 1104
                ushort uBNCPort =
                NoDccBounce::DCCRequest(Nick.GetNick(), uLongIP, uPort, sFile, false, this, NoUtils::GetIP(uLongIP));
                if (uBNCPort) {
                    NoString sIP = GetLocalDCCIP();
                    PutUser(":" + Nick.GetNickMask() + " PRIVMSG " + pNetwork->GetCurNick() + " :\001DCC SEND " + sFile + " " +
                            NoString(NoUtils::GetLongIP(sIP)) + " " + NoString(uBNCPort) + " " + NoString(uFileSize) + "\001");
                }
            } else if (sType.Equals("RESUME")) {
                // Need to lookup the connection by port, filter the port, and forward to the user
                ushort uResumePort = sMessage.Token(3).ToUShort();

                std::set<NoSocket*>::const_iterator it;
                for (it = BeginSockets(); it != EndSockets(); ++it) {
                    NoDccBounce* pSock = (NoDccBounce*)*it;

                    if (pSock->GetLocalPort() == uResumePort) {
                        PutUser(":" + Nick.GetNickMask() + " PRIVMSG " + pNetwork->GetCurNick() + " :\001DCC " + sType +
                                " " + sFile + " " + NoString(pSock->GetUserPort()) + " " + sMessage.Token(4) + "\001");
                    }
                }
            } else if (sType.Equals("ACCEPT")) {
                // Need to lookup the connection by port, filter the port, and forward to the user
                std::set<NoSocket*>::const_iterator it;
                for (it = BeginSockets(); it != EndSockets(); ++it) {
                    NoDccBounce* pSock = (NoDccBounce*)*it;

                    if (pSock->GetUserPort() == sMessage.Token(3).ToUShort()) {
                        PutUser(":" + Nick.GetNickMask() + " PRIVMSG " + pNetwork->GetCurNick() + " :\001DCC " + sType +
                                " " + sFile + " " + NoString(pSock->GetLocalPort()) + " " + sMessage.Token(4) + "\001");
                    }
                }
            }

            return HALTCORE;
        }

        return CONTINUE;
    }
};

NoDccBounce::NoDccBounce(NoBounceDccMod* pMod,
                       ulong uLongIP,
                       ushort uPort,
                       const NoString& sFileName,
                       const NoString& sRemoteNick,
                       const NoString& sRemoteIP,
                       bool bIsChat)
    : NoSocket(pMod)
{
    m_uRemotePort = uPort;
    m_sConnectIP = NoUtils::GetIP(uLongIP);
    m_sRemoteIP = sRemoteIP;
    m_sFileName = sFileName;
    m_sRemoteNick = sRemoteNick;
    m_pModule = pMod;
    m_bIsChat = bIsChat;
    m_sLocalIP = pMod->GetLocalDCCIP();
    m_pPeer = nullptr;
    m_bIsRemote = false;

    if (bIsChat) {
        EnableReadLine();
    } else {
        DisableReadLine();
    }
}

NoDccBounce::NoDccBounce(NoBounceDccMod* pMod,
                       const NoString& sHostname,
                       ushort uPort,
                       const NoString& sRemoteNick,
                       const NoString& sRemoteIP,
                       const NoString& sFileName,
                       int iTimeout,
                       bool bIsChat)
    : NoSocket(pMod, sHostname, uPort, iTimeout)
{
    m_uRemotePort = 0;
    m_bIsChat = bIsChat;
    m_pModule = pMod;
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
}

NoDccBounce::~NoDccBounce()
{
    if (m_pPeer) {
        m_pPeer->Shutdown();
        m_pPeer = nullptr;
    }
}

void NoDccBounce::ReadLine(const NoString& sData)
{
    NoString sLine = sData.TrimRight_n("\r\n");

    DEBUG(GetSockName() << " <- [" << sLine << "]");

    PutPeer(sLine);
}

void NoDccBounce::ReachedMaxBuffer()
{
    DEBUG(GetSockName() << " == ReachedMaxBuffer()");

    NoString sType = (m_bIsChat) ? "Chat" : "Xfer";

    m_pModule->PutModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Too long line received");
    Close();
}

void NoDccBounce::ReadData(const char* data, size_t len)
{
    if (m_pPeer) {
        m_pPeer->Write(data, len);

        size_t BufLen = m_pPeer->GetInternalWriteBuffer().length();

        if (BufLen >= m_uiMaxDCCBuffer) {
            DEBUG(GetSockName() << " The send buffer is over the "
                                   "limit (" << BufLen << "), throttling");
            PauseRead();
        }
    }
}

void NoDccBounce::ReadPaused()
{
    if (!m_pPeer || m_pPeer->GetInternalWriteBuffer().length() <= m_uiMinDCCBuffer) UnPauseRead();
}

void NoDccBounce::Timeout()
{
    DEBUG(GetSockName() << " == Timeout()");
    NoString sType = (m_bIsChat) ? "Chat" : "Xfer";

    if (IsRemote()) {
        NoString sHost = Csock::GetHostName();
        if (!sHost.empty()) {
            sHost = " to [" + sHost + " " + NoString(Csock::GetPort()) + "]";
        } else {
            sHost = ".";
        }

        m_pModule->PutModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Timeout while connecting" + sHost);
    } else {
        m_pModule->PutModule("DCC " + sType + " Bounce (" + m_sRemoteNick +
                             "): Timeout waiting for incoming connection [" + Csock::GetLocalIP() + ":" +
                             NoString(Csock::GetLocalPort()) + "]");
    }
}

void NoDccBounce::ConnectionRefused()
{
    DEBUG(GetSockName() << " == ConnectionRefused()");

    NoString sType = (m_bIsChat) ? "Chat" : "Xfer";
    NoString sHost = Csock::GetHostName();
    if (!sHost.empty()) {
        sHost = " to [" + sHost + " " + NoString(Csock::GetPort()) + "]";
    } else {
        sHost = ".";
    }

    m_pModule->PutModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Connection Refused while connecting" + sHost);
}

void NoDccBounce::SockError(int iErrno, const NoString& sDescription)
{
    DEBUG(GetSockName() << " == SockError(" << iErrno << ")");
    NoString sType = (m_bIsChat) ? "Chat" : "Xfer";

    if (IsRemote()) {
        NoString sHost = Csock::GetHostName();
        if (!sHost.empty()) {
            sHost = "[" + sHost + " " + NoString(Csock::GetPort()) + "]";
        }

        m_pModule->PutModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Socket error [" + sDescription + "]" + sHost);
    } else {
        m_pModule->PutModule("DCC " + sType + " Bounce (" + m_sRemoteNick + "): Socket error [" + sDescription + "] [" +
                             Csock::GetLocalIP() + ":" + NoString(Csock::GetLocalPort()) + "]");
    }
}

void NoDccBounce::Connected()
{
    SetTimeout(0);
    DEBUG(GetSockName() << " == Connected()");
}

void NoDccBounce::Disconnected() { DEBUG(GetSockName() << " == Disconnected()"); }

void NoDccBounce::Shutdown()
{
    m_pPeer = nullptr;
    DEBUG(GetSockName() << " == Close(); because my peer told me to");
    Close();
}

Csock* NoDccBounce::GetSockObj(const NoString& sHost, ushort uPort)
{
    Close();

    if (m_sRemoteIP.empty()) {
        m_sRemoteIP = sHost;
    }

    NoDccBounce* pSock = new NoDccBounce(m_pModule, sHost, uPort, m_sRemoteNick, m_sRemoteIP, m_sFileName, m_bIsChat);
    NoDccBounce* pRemoteSock = new NoDccBounce(m_pModule, sHost, uPort, m_sRemoteNick, m_sRemoteIP, m_sFileName, m_bIsChat);
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
    DEBUG(GetSockName() << " -> [" << sLine << "]");
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

template <> void TModInfo<NoBounceDccMod>(NoModInfo& Info) { Info.SetWikiPage("bouncedcc"); }

USERMODULEDEFS(NoBounceDccMod, "Bounces DCC transfers through ZNC instead of sending them directly to the user. ")
