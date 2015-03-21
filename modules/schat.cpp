/*
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
    NoSChatSock(NoSChat* pMod, const NoString& sChatNick, const NoString& sHost, u_short iPort, int iTimeout = 60);
    ~NoSChatSock();

    NoSocket* GetSockObjImpl(const NoString& sHostname, u_short iPort) override
    {
        NoSChatSock* p = new NoSChatSock(m_pModule, m_sChatNick, sHostname, iPort);
        return (p);
    }

    bool ConnectionFromImpl(const NoString& sHost, u_short iPort) override
    {
        Close(); // close the listener after the first connection
        return (true);
    }

    void ConnectedImpl() override;
    void TimeoutImpl() override;

    const NoString& GetChatNick() const { return (m_sChatNick); }

    void PutQuery(const NoString& sText);

    void ReadLineImpl(const NoString& sLine) override;
    void DisconnectedImpl() override;

    void AddLine(const NoString& sLine)
    {
        m_vBuffer.insert(m_vBuffer.begin(), sLine);
        if (m_vBuffer.size() > 200) m_vBuffer.pop_back();
    }

    void DumpBuffer()
    {
        if (m_vBuffer.empty()) {
            // Always show a message to the user, so he knows
            // this schat still exists.
            ReadLineImpl("*** Reattached.");
        } else {
            // Buffer playback
            std::vector<NoString>::reverse_iterator it = m_vBuffer.rbegin();
            for (; it != m_vBuffer.rend(); ++it) ReadLineImpl(*it);

            m_vBuffer.clear();
        }
    }

private:
    NoSChat* m_pModule;
    NoString m_sChatNick;
    NoStringVector m_vBuffer;
};

class NoSChat : public NoModule
{
public:
    MODCONSTRUCTOR(NoSChat) {}

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
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

    void OnClientLogin() override
    {
        for (NoSChatSock* p : m_sockets) {
            if (!p->IsListener())
                p->DumpBuffer();
        }
    }

    ModRet OnUserRaw(NoString& sLine) override
    {
        if (sLine.startsWith("schat ")) {
            OnModCommand("chat " + sLine.substr(6));
            return (HALT);

        } else if (sLine.equals("schat")) {
            PutModule("SChat User Area ...");
            OnModCommand("help");
            return (HALT);
        }

        return (CONTINUE);
    }

    void OnModCommand(const NoString& sCommand) override
    {
        NoString sCom = No::token(sCommand, 0);
        NoString sArgs = No::tokens(sCommand, 1);

        if (sCom.equals("chat") && !sArgs.empty()) {
            NoString sNick = "(s)" + sArgs;
            for (NoSChatSock* pSock : m_sockets) {
                if (pSock->GetChatNick().equals(sNick)) {
                    PutModule("Already Connected to [" + sArgs + "]");
                    return;
                }
            }

            NoSChatSock* pSock = new NoSChatSock(this, sNick);
            pSock->SetCipher("HIGH");
            pSock->SetPemLocation(m_sPemFile);

            u_short iPort =
            GetManager()->ListenRand(pSock->GetSockName() + "::LISTENER", GetUser()->GetLocalDCCIP(), true, SOMAXCONN, pSock, 60);

            if (iPort == 0) {
                PutModule("Failed to start chat!");
                return;
            }

            std::stringstream s;
            s << "PRIVMSG " << sArgs << " :\001";
            s << "DCC SCHAT chat ";
            s << No::formatLongIp(GetUser()->GetLocalDCCIP());
            s << " " << iPort << "\001";

            PutIRC(s.str());

        } else if (sCom.equals("list")) {
            NoTable Table;
            Table.AddColumn("Nick");
            Table.AddColumn("Created");
            Table.AddColumn("Host");
            Table.AddColumn("Port");
            Table.AddColumn("Status");
            Table.AddColumn("Cipher");

            for (NoSChatSock* pSock : m_sockets) {
                Table.AddRow();
                Table.SetCell("Nick", pSock->GetChatNick());
                ulonglong iStartTime = pSock->GetStartTime();
                time_t iTime = iStartTime / 1000;
                char* pTime = ctime(&iTime);
                if (pTime) {
                    NoString sTime = pTime;
                    sTime.trim();
                    Table.SetCell("Created", sTime);
                }

                if (!pSock->IsListener()) {
                    Table.SetCell("Status", "Established");
                    Table.SetCell("Host", pSock->GetRemoteIP());
                    Table.SetCell("Port", NoString(pSock->GetRemotePort()));
                    SSL_SESSION* pSession = pSock->GetSSLSession();
                    if (pSession && pSession->cipher && pSession->cipher->name)
                        Table.SetCell("Cipher", pSession->cipher->name);

                } else {
                    Table.SetCell("Status", "Waiting");
                    Table.SetCell("Port", NoString(pSock->GetLocalPort()));
                }
            }
            if (Table.size()) {
                PutModule(Table);
            } else
                PutModule("No SDCCs currently in session");

        } else if (sCom.equals("close")) {
            if (!sArgs.startsWith("(s)")) sArgs = "(s)" + sArgs;

            for (NoSChatSock* pSock : m_sockets) {
                if (sArgs.equals(pSock->GetChatNick())) {
                    pSock->Close();
                    return;
                }
            }
            PutModule("No Such Chat [" + sArgs + "]");
        } else if (sCom.equals("showsocks") && GetUser()->IsAdmin()) {
            NoTable Table;
            Table.AddColumn("SockName");
            Table.AddColumn("Created");
            Table.AddColumn("LocalIP:Port");
            Table.AddColumn("RemoteIP:Port");
            Table.AddColumn("Type");
            Table.AddColumn("Cipher");

            for (NoSChatSock* pSock : m_sockets) {
                Table.AddRow();
                Table.SetCell("SockName", pSock->GetSockName());
                ulonglong iStartTime = pSock->GetStartTime();
                time_t iTime = iStartTime / 1000;
                char* pTime = ctime(&iTime);
                if (pTime) {
                    NoString sTime = pTime;
                    sTime.trim();
                    Table.SetCell("Created", sTime);
                }

                if (!pSock->IsListener()) {
                    if (pSock->IsOutbound())
                        Table.SetCell("Type", "Outbound");
                    else
                        Table.SetCell("Type", "Inbound");
                    Table.SetCell("LocalIP:Port", pSock->GetLocalIP() + ":" + NoString(pSock->GetLocalPort()));
                    Table.SetCell("RemoteIP:Port", pSock->GetRemoteIP() + ":" + NoString(pSock->GetRemotePort()));
                    SSL_SESSION* pSession = pSock->GetSSLSession();
                    if (pSession && pSession->cipher && pSession->cipher->name)
                        Table.SetCell("Cipher", pSession->cipher->name);
                    else
                        Table.SetCell("Cipher", "None");

                } else {
                    Table.SetCell("Type", "Listener");
                    Table.SetCell("LocalIP:Port", pSock->GetLocalIP() + ":" + NoString(pSock->GetLocalPort()));
                    Table.SetCell("RemoteIP:Port", "0.0.0.0:0");
                }
            }
            if (Table.size())
                PutModule(Table);
            else
                PutModule("Error Finding Sockets");

        } else if (sCom.equals("help")) {
            PutModule("Commands are:");
            PutModule("    help           - This text.");
            PutModule("    chat <nick>    - Chat a nick.");
            PutModule("    list           - List current chats.");
            PutModule("    close <nick>   - Close a chat to a nick.");
            PutModule("    timers         - Shows related timers.");
            if (GetUser()->IsAdmin()) {
                PutModule("    showsocks      - Shows all socket connections.");
            }
        } else if (sCom.equals("timers"))
            ListTimers();
        else
            PutModule("Unknown command [" + sCom + "] [" + sArgs + "]");
    }

    ModRet OnPrivCTCP(NoNick& Nick, NoString& sMessage) override
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
        NoSChatSock* p = new NoSChatSock(this, sNick, No::formatIp(iIP), iPort, 60);
        GetManager()->Connect(No::formatIp(iIP), iPort, p->GetSockName(), 60, true, GetUser()->GetLocalDCCIP(), p);
        delete FindTimer("Remove " + sNick); // delete any associated timer to this nick
    }

    ModRet OnUserMsg(NoString& sTarget, NoString& sMessage) override
    {
        if (sTarget.left(3) == "(s)") {
            NoString sSockName = GetModName().toUpper() + "::" + sTarget;
            NoSChatSock* p = (NoSChatSock*)FindSocket(sSockName);
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
                PutModule("No such SCHAT to [" + sTarget + "]");
            } else
                p->Write(sMessage + "\n");

            return (HALT);
        }
        return (CONTINUE);
    }

    void RemoveMarker(const NoString& sNick)
    {
        std::map<NoString, std::pair<u_long, u_short>>::iterator it = m_siiWaitingChats.find(sNick);
        if (it != m_siiWaitingChats.end()) m_siiWaitingChats.erase(it);
    }

    void SendToUser(const NoString& sFrom, const NoString& sText)
    {
        //:*schat!znc@znc.in PRIVMSG Jim :
        NoString sSend = ":" + sFrom + " PRIVMSG " + GetNetwork()->GetCurNick() + " :" + sText;
        PutUser(sSend);
    }

    bool IsAttached() { return (GetNetwork()->IsUserAttached()); }

    void AddSocket(NoSChatSock* socket) { m_sockets.insert(socket); }
    void RemoveSocket(NoSChatSock* socket) { m_sockets.erase(socket); }

private:
    std::map<NoString, std::pair<u_long, u_short>> m_siiWaitingChats;
    NoString m_sPemFile;
    std::set<NoSChatSock*> m_sockets;
};


//////////////////// methods ////////////////

NoSChatSock::NoSChatSock(NoSChat* pMod, const NoString& sChatNick) : NoModuleSocket(pMod)
{
    m_pModule = pMod;
    m_sChatNick = sChatNick;
    SetSockName(pMod->GetModName().toUpper() + "::" + m_sChatNick);
    pMod->AddSocket(this);
}

NoSChatSock::NoSChatSock(NoSChat* pMod, const NoString& sChatNick, const NoString& sHost, u_short iPort, int iTimeout)
    : NoModuleSocket(pMod, sHost, iPort, iTimeout)
{
    m_pModule = pMod;
    EnableReadLine();
    m_sChatNick = sChatNick;
    SetSockName(pMod->GetModName().toUpper() + "::" + m_sChatNick);
    pMod->AddSocket(this);
}

NoSChatSock::~NoSChatSock()
{
    m_pModule->RemoveSocket(this);
}

void NoSChatSock::PutQuery(const NoString& sText)
{
    m_pModule->SendToUser(m_sChatNick + "!" + m_sChatNick + "@" + GetRemoteIP(), sText);
}

void NoSChatSock::ReadLineImpl(const NoString& sLine)
{
    if (m_pModule) {
        NoString sText = sLine;

        sText.trimRight("\r\n");

        if (m_pModule->IsAttached())
            PutQuery(sText);
        else
            AddLine(m_pModule->GetUser()->AddTimestamp(sText));
    }
}

void NoSChatSock::DisconnectedImpl()
{
    if (m_pModule) PutQuery("*** Disconnected.");
}

void NoSChatSock::ConnectedImpl()
{
    SetTimeout(0);
    if (m_pModule) PutQuery("*** Connected.");
}

void NoSChatSock::TimeoutImpl()
{
    if (m_pModule) {
        if (IsListener())
            m_pModule->PutModule("Timeout while waiting for [" + m_sChatNick + "]");
        else
            PutQuery("*** Connection Timed out.");
    }
}

void NoRemMarkerJob::run()
{
    static_cast<NoSChat*>(module())->RemoveMarker(m_sNick);

    // store buffer
}

template <> void no_moduleInfo<NoSChat>(NoModuleInfo& Info)
{
    Info.SetWikiPage("schat");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("Path to .pem file, if differs from main ZNC's one");
}

NETWORKMODULEDEFS(NoSChat, "Secure cross platform (:P) chat system")
