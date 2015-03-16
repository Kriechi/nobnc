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

#include <znc/nofile.h>
#include <znc/nouser.h>
#include <znc/nonetwork.h>

using std::pair;
using std::stringstream;
using std::map;
using std::set;
using std::vector;

class NoSChat;

class NoRemMarkerJob : public NoTimer
{
public:
    NoRemMarkerJob(NoModule* pModule, unsigned int uInterval, unsigned int uCycles, const NoString& sLabel, const NoString& sDescription)
        : NoTimer(pModule, uInterval, uCycles, sLabel, sDescription)
    {
    }

    virtual ~NoRemMarkerJob() {}
    void SetNick(const NoString& sNick) { m_sNick = sNick; }

protected:
    void RunJob() override;
    NoString m_sNick;
};

class NoSChatSock : public NoSocket
{
public:
    NoSChatSock(NoSChat* pMod, const NoString& sChatNick);
    NoSChatSock(NoSChat* pMod, const NoString& sChatNick, const NoString& sHost, u_short iPort, int iTimeout = 60);
    ~NoSChatSock() {}

    Csock* GetSockObj(const CS_STRING& sHostname, u_short iPort) override
    {
        NoSChatSock* p = new NoSChatSock(m_pModule, m_sChatNick, sHostname, iPort);
        return (p);
    }

    bool ConnectionFrom(const CS_STRING& sHost, u_short iPort) override
    {
        Close(); // close the listener after the first connection
        return (true);
    }

    void Connected() override;
    void Timeout() override;

    const NoString& GetChatNick() const { return (m_sChatNick); }

    void PutQuery(const NoString& sText);

    void ReadLine(const CS_STRING& sLine) override;
    void Disconnected() override;

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
            ReadLine("*** Reattached.");
        } else {
            // Buffer playback
            vector<CS_STRING>::reverse_iterator it = m_vBuffer.rbegin();
            for (; it != m_vBuffer.rend(); ++it) ReadLine(*it);

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
    virtual ~NoSChat() {}

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        m_sPemFile = sArgs;

        if (m_sPemFile.empty()) {
            m_sPemFile = CZNC::Get().GetPemLocation();
        }

        if (!NoFile::Exists(m_sPemFile)) {
            sMessage = "Unable to load pem file [" + m_sPemFile + "]";
            return false;
        }

        return true;
    }

    void OnClientLogin() override
    {
        set<NoSocket*>::const_iterator it;
        for (it = BeginSockets(); it != EndSockets(); ++it) {
            NoSChatSock* p = (NoSChatSock*)*it;

            if (p->GetType() == NoSChatSock::LISTENER) continue;

            p->DumpBuffer();
        }
    }

    EModRet OnUserRaw(NoString& sLine) override
    {
        if (sLine.StartsWith("schat ")) {
            OnModCommand("chat " + sLine.substr(6));
            return (HALT);

        } else if (sLine.Equals("schat")) {
            PutModule("SChat User Area ...");
            OnModCommand("help");
            return (HALT);
        }

        return (CONTINUE);
    }

    void OnModCommand(const NoString& sCommand) override
    {
        NoString sCom = sCommand.Token(0);
        NoString sArgs = sCommand.Token(1, true);

        if (sCom.Equals("chat") && !sArgs.empty()) {
            NoString sNick = "(s)" + sArgs;
            set<NoSocket*>::const_iterator it;
            for (it = BeginSockets(); it != EndSockets(); ++it) {
                NoSChatSock* pSock = (NoSChatSock*)*it;

                if (pSock->GetChatNick().Equals(sNick)) {
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

            stringstream s;
            s << "PRIVMSG " << sArgs << " :\001";
            s << "DCC SCHAT chat ";
            s << NoUtils::GetLongIP(GetUser()->GetLocalDCCIP());
            s << " " << iPort << "\001";

            PutIRC(s.str());

        } else if (sCom.Equals("list")) {
            NoTable Table;
            Table.AddColumn("Nick");
            Table.AddColumn("Created");
            Table.AddColumn("Host");
            Table.AddColumn("Port");
            Table.AddColumn("Status");
            Table.AddColumn("Cipher");

            set<NoSocket*>::const_iterator it;
            for (it = BeginSockets(); it != EndSockets(); ++it) {
                Table.AddRow();

                NoSChatSock* pSock = (NoSChatSock*)*it;
                Table.SetCell("Nick", pSock->GetChatNick());
                unsigned long long iStartTime = pSock->GetStartTime();
                time_t iTime = iStartTime / 1000;
                char* pTime = ctime(&iTime);
                if (pTime) {
                    NoString sTime = pTime;
                    sTime.Trim();
                    Table.SetCell("Created", sTime);
                }

                if (pSock->GetType() != NoSChatSock::LISTENER) {
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

        } else if (sCom.Equals("close")) {
            if (!sArgs.StartsWith("(s)")) sArgs = "(s)" + sArgs;

            set<NoSocket*>::const_iterator it;
            for (it = BeginSockets(); it != EndSockets(); ++it) {
                NoSChatSock* pSock = (NoSChatSock*)*it;

                if (sArgs.Equals(pSock->GetChatNick())) {
                    pSock->Close();
                    return;
                }
            }
            PutModule("No Such Chat [" + sArgs + "]");
        } else if (sCom.Equals("showsocks") && GetUser()->IsAdmin()) {
            NoTable Table;
            Table.AddColumn("SockName");
            Table.AddColumn("Created");
            Table.AddColumn("LocalIP:Port");
            Table.AddColumn("RemoteIP:Port");
            Table.AddColumn("Type");
            Table.AddColumn("Cipher");

            set<NoSocket*>::const_iterator it;
            for (it = BeginSockets(); it != EndSockets(); ++it) {
                Table.AddRow();
                Csock* pSock = *it;
                Table.SetCell("SockName", pSock->GetSockName());
                unsigned long long iStartTime = pSock->GetStartTime();
                time_t iTime = iStartTime / 1000;
                char* pTime = ctime(&iTime);
                if (pTime) {
                    NoString sTime = pTime;
                    sTime.Trim();
                    Table.SetCell("Created", sTime);
                }

                if (pSock->GetType() != Csock::LISTENER) {
                    if (pSock->GetType() == Csock::OUTBOUND)
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

        } else if (sCom.Equals("help")) {
            PutModule("Commands are:");
            PutModule("    help           - This text.");
            PutModule("    chat <nick>    - Chat a nick.");
            PutModule("    list           - List current chats.");
            PutModule("    close <nick>   - Close a chat to a nick.");
            PutModule("    timers         - Shows related timers.");
            if (GetUser()->IsAdmin()) {
                PutModule("    showsocks      - Shows all socket connections.");
            }
        } else if (sCom.Equals("timers"))
            ListTimers();
        else
            PutModule("Unknown command [" + sCom + "] [" + sArgs + "]");
    }

    EModRet OnPrivCTCP(NoNick& Nick, NoString& sMessage) override
    {
        if (sMessage.StartsWith("DCC SCHAT ")) {
            // chat ip port
            unsigned long iIP = sMessage.Token(3).ToULong();
            unsigned short iPort = sMessage.Token(4).ToUShort();

            if (iIP > 0 && iPort > 0) {
                pair<u_long, u_short> pTmp;
                NoString sMask;

                pTmp.first = iIP;
                pTmp.second = iPort;
                sMask = "(s)" + Nick.GetNick() + "!" + "(s)" + Nick.GetNick() + "@" + NoUtils::GetIP(iIP);

                m_siiWaitingChats["(s)" + Nick.GetNick()] = pTmp;
                SendToUser(sMask, "*** Incoming DCC SCHAT, Accept ? (yes/no)");
                NoRemMarkerJob* p = new NoRemMarkerJob(
                this, 60, 1, "Remove (s)" + Nick.GetNick(), "Removes this nicks entry for waiting DCC.");
                p->SetNick("(s)" + Nick.GetNick());
                AddTimer(p);
                return (HALT);
            }
        }

        return (CONTINUE);
    }

    void AcceptSDCC(const NoString& sNick, u_long iIP, u_short iPort)
    {
        NoSChatSock* p = new NoSChatSock(this, sNick, NoUtils::GetIP(iIP), iPort, 60);
        GetManager()->Connect(NoUtils::GetIP(iIP), iPort, p->GetSockName(), 60, true, GetUser()->GetLocalDCCIP(), p);
        RemTimer("Remove " + sNick); // delete any associated timer to this nick
    }

    EModRet OnUserMsg(NoString& sTarget, NoString& sMessage) override
    {
        if (sTarget.Left(3) == "(s)") {
            NoString sSockName = GetModName().AsUpper() + "::" + sTarget;
            NoSChatSock* p = (NoSChatSock*)FindSocket(sSockName);
            if (!p) {
                map<NoString, pair<u_long, u_short>>::iterator it;
                it = m_siiWaitingChats.find(sTarget);

                if (it != m_siiWaitingChats.end()) {
                    if (!sMessage.Equals("yes"))
                        SendToUser(sTarget + "!" + sTarget + "@" + NoUtils::GetIP(it->second.first),
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
        map<NoString, pair<u_long, u_short>>::iterator it = m_siiWaitingChats.find(sNick);
        if (it != m_siiWaitingChats.end()) m_siiWaitingChats.erase(it);
    }

    void SendToUser(const NoString& sFrom, const NoString& sText)
    {
        //:*schat!znc@znc.in PRIVMSG Jim :
        NoString sSend = ":" + sFrom + " PRIVMSG " + GetNetwork()->GetCurNick() + " :" + sText;
        PutUser(sSend);
    }

    bool IsAttached() { return (GetNetwork()->IsUserAttached()); }

private:
    map<NoString, pair<u_long, u_short>> m_siiWaitingChats;
    NoString m_sPemFile;
};


//////////////////// methods ////////////////

NoSChatSock::NoSChatSock(NoSChat* pMod, const NoString& sChatNick) : NoSocket(pMod)
{
    m_pModule = pMod;
    m_sChatNick = sChatNick;
    SetSockName(pMod->GetModName().AsUpper() + "::" + m_sChatNick);
}

NoSChatSock::NoSChatSock(NoSChat* pMod, const NoString& sChatNick, const NoString& sHost, u_short iPort, int iTimeout)
    : NoSocket(pMod, sHost, iPort, iTimeout)
{
    m_pModule = pMod;
    EnableReadLine();
    m_sChatNick = sChatNick;
    SetSockName(pMod->GetModName().AsUpper() + "::" + m_sChatNick);
}

void NoSChatSock::PutQuery(const NoString& sText)
{
    m_pModule->SendToUser(m_sChatNick + "!" + m_sChatNick + "@" + GetRemoteIP(), sText);
}

void NoSChatSock::ReadLine(const CS_STRING& sLine)
{
    if (m_pModule) {
        NoString sText = sLine;

        sText.TrimRight("\r\n");

        if (m_pModule->IsAttached())
            PutQuery(sText);
        else
            AddLine(m_pModule->GetUser()->AddTimestamp(sText));
    }
}

void NoSChatSock::Disconnected()
{
    if (m_pModule) PutQuery("*** Disconnected.");
}

void NoSChatSock::Connected()
{
    SetTimeout(0);
    if (m_pModule) PutQuery("*** Connected.");
}

void NoSChatSock::Timeout()
{
    if (m_pModule) {
        if (GetType() == LISTENER)
            m_pModule->PutModule("Timeout while waiting for [" + m_sChatNick + "]");
        else
            PutQuery("*** Connection Timed out.");
    }
}

void NoRemMarkerJob::RunJob()
{
    NoSChat* p = (NoSChat*)GetModule();
    p->RemoveMarker(m_sNick);

    // store buffer
}

template <> void TModInfo<NoSChat>(NoModInfo& Info)
{
    Info.SetWikiPage("schat");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("Path to .pem file, if differs from main ZNC's one");
}

NETWORKMODULEDEFS(NoSChat, "Secure cross platform (:P) chat system")
