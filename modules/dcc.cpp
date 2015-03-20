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

#include <no/nomodule.h>
#include <no/noapp.h>
#include <no/nouser.h>
#include <no/nofile.h>
#include <no/nodir.h>
#include <no/nodebug.h>
#include <no/noclient.h>

#include <netinet/in.h>
#include <arpa/inet.h>

class NoDccMod;

class NoDccSock : public NoModuleSocket
{
public:
    NoDccSock(NoDccMod* pMod, const NoString& sRemoteNick, const NoString& sLocalFile, ulong uFileSize = 0, NoFile* pFile = nullptr);
    NoDccSock(NoDccMod* pMod, const NoString& sRemoteNick, const NoString& sRemoteIP, ushort uRemotePort, const NoString& sLocalFile, ulong uFileSize);
    virtual ~NoDccSock();

    void ReadDataImpl(const char* data, size_t len) override;
    void ConnectionRefusedImpl() override;
    void SockErrorImpl(int iErrno, const NoString& sDescription) override;
    void TimeoutImpl() override;
    void ConnectedImpl() override;
    void DisconnectedImpl() override;
    void SendPacket();
    NoSocket* GetSockObjImpl(const NoString& sHost, ushort uPort) override;
    NoFile* OpenFile(bool bWrite = true);
    bool Seek(ulong uPos);

    // Setters
    void SetRemoteIP(const NoString& s) { m_sRemoteIP = s; }
    void SetRemoteNick(const NoString& s) { m_sRemoteNick = s; }
    void SetFileName(const NoString& s) { m_sFileName = s; }
    void SetFileOffset(ulong u) { m_uBytesSoFar = u; }
    // !Setters

    // Getters
    ushort GetUserPort() const { return m_uRemotePort; }
    const NoString& GetRemoteNick() const { return m_sRemoteNick; }
    const NoString& GetFileName() const { return m_sFileName; }
    const NoString& GetLocalFile() const { return m_sLocalFile; }
    NoFile* GetFile() { return m_pFile; }
    double GetProgress() const
    {
        return ((m_uFileSize) && (m_uBytesSoFar)) ? (double)(((double)m_uBytesSoFar / (double)m_uFileSize) * 100.0) : 0;
    }
    bool IsSend() const { return m_bSend; }
    // const NoString& GetRemoteIP() const { return m_sRemoteIP; }
    // !Getters
private:
protected:
    NoString m_sRemoteNick;
    NoString m_sRemoteIP;
    NoString m_sFileName;
    NoString m_sLocalFile;
    NoString m_sSendBuf;
    ushort m_uRemotePort;
    ulonglong m_uFileSize;
    ulonglong m_uBytesSoFar;
    bool m_bSend;
    bool m_bNoDelFile;
    NoFile* m_pFile;
    NoDccMod* m_pModule;
};

class NoDccMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoDccMod)
    {
        AddHelpCommand();
        AddCommand("Send", static_cast<NoModuleCommand::ModCmdFunc>(&NoDccMod::SendCommand), "<nick> <file>");
        AddCommand("Get", static_cast<NoModuleCommand::ModCmdFunc>(&NoDccMod::GetCommand), "<file>");
        AddCommand("ListTransfers", static_cast<NoModuleCommand::ModCmdFunc>(&NoDccMod::ListTransfersCommand));
    }

#ifndef MOD_DCC_ALLOW_EVERYONE
    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        if (!GetUser()->IsAdmin()) {
            sMessage = "You must be admin to use the DCC module";
            return false;
        }

        return true;
    }
#endif

    bool SendFile(const NoString& sRemoteNick, const NoString& sFileName)
    {
        NoString sFullPath = NoDir::ChangeDir(GetSavePath(), sFileName, NoApp::Get().GetHomePath());
        NoDccSock* pSock = new NoDccSock(this, sRemoteNick, sFullPath);

        NoFile* pFile = pSock->OpenFile(false);

        if (!pFile) {
            delete pSock;
            return false;
        }

        NoString sLocalDCCIP = GetUser()->GetLocalDCCIP();
        ushort uPort =
        NoApp::Get().GetManager().ListenRand("DCC::LISTEN::" + sRemoteNick, sLocalDCCIP, false, SOMAXCONN, pSock, 120);

        if (GetUser()->GetNick().equals(sRemoteNick)) {
            PutUser(":*dcc!znc@znc.in PRIVMSG " + sRemoteNick + " :\001DCC SEND " + pFile->GetShortName() + " " +
                    NoString(NoUtils::GetLongIP(sLocalDCCIP)) + " " + NoString(uPort) + " " + NoString(pFile->GetSize()) + "\001");
        } else {
            PutIRC("PRIVMSG " + sRemoteNick + " :\001DCC SEND " + pFile->GetShortName() + " " +
                   NoString(NoUtils::GetLongIP(sLocalDCCIP)) + " " + NoString(uPort) + " " + NoString(pFile->GetSize()) + "\001");
        }

        PutModule("DCC -> [" + sRemoteNick + "][" + pFile->GetShortName() + "] - Attempting Send.");
        return true;
    }

    bool GetFile(const NoString& sRemoteNick, const NoString& sRemoteIP, ushort uRemotePort, const NoString& sFileName, ulong uFileSize)
    {
        if (NoFile::Exists(sFileName)) {
            PutModule("DCC <- [" + sRemoteNick + "][" + sFileName + "] - File already exists.");
            return false;
        }

        NoDccSock* pSock = new NoDccSock(this, sRemoteNick, sRemoteIP, uRemotePort, sFileName, uFileSize);

        if (!pSock->OpenFile()) {
            delete pSock;
            return false;
        }

        NoApp::Get().GetManager().Connect(sRemoteIP, uRemotePort, "DCC::GET::" + sRemoteNick, 60, false, GetUser()->GetLocalDCCIP(), pSock);

        PutModule("DCC <- [" + sRemoteNick + "][" + sFileName + "] - Attempting to connect to [" + sRemoteIP + "]");
        return true;
    }

    void SendCommand(const NoString& sLine)
    {
        NoString sToNick = sLine.token(1);
        NoString sFile = sLine.token(2);
        NoString sAllowedPath = GetSavePath();
        NoString sAbsolutePath;

        if ((sToNick.empty()) || (sFile.empty())) {
            PutModule("Usage: Send <nick> <file>");
            return;
        }

        sAbsolutePath = NoDir::CheckPathPrefix(sAllowedPath, sFile);

        if (sAbsolutePath.empty()) {
            PutStatus("Illegal path.");
            return;
        }

        SendFile(sToNick, sFile);
    }

    void GetCommand(const NoString& sLine)
    {
        NoString sFile = sLine.token(1);
        NoString sAllowedPath = GetSavePath();
        NoString sAbsolutePath;

        if (sFile.empty()) {
            PutModule("Usage: Get <file>");
            return;
        }

        sAbsolutePath = NoDir::CheckPathPrefix(sAllowedPath, sFile);

        if (sAbsolutePath.empty()) {
            PutModule("Illegal path.");
            return;
        }

        SendFile(GetUser()->GetNick(), sFile);
    }

    void ListTransfersCommand(const NoString& sLine)
    {
        NoTable Table;
        Table.AddColumn("Type");
        Table.AddColumn("State");
        Table.AddColumn("Speed");
        Table.AddColumn("Nick");
        Table.AddColumn("IP");
        Table.AddColumn("File");

        std::set<NoModuleSocket*>::const_iterator it;
        for (it = BeginSockets(); it != EndSockets(); ++it) {
            NoDccSock* pSock = (NoDccSock*)*it;

            Table.AddRow();
            Table.SetCell("Nick", pSock->GetRemoteNick());
            Table.SetCell("IP", pSock->GetRemoteIP());
            Table.SetCell("File", pSock->GetFileName());

            if (pSock->IsSend()) {
                Table.SetCell("Type", "Sending");
            } else {
                Table.SetCell("Type", "Getting");
            }

            if (pSock->IsListener()) {
                Table.SetCell("State", "Waiting");
            } else {
                Table.SetCell("State", NoUtils::ToPercent(pSock->GetProgress()));
                Table.SetCell("Speed", NoString((int)(pSock->GetAvgRead() / 1024.0)) + " KiB/s");
            }
        }

        if (PutModule(Table) == 0) {
            PutModule("You have no active DCC transfers.");
        }
    }

    void OnModCTCP(const NoString& sMessage) override
    {
        if (sMessage.startsWith("DCC RESUME ")) {
            NoString sFile = sMessage.token(2);
            ushort uResumePort = sMessage.token(3).toUShort();
            ulong uResumeSize = sMessage.token(4).toULong();

            std::set<NoModuleSocket*>::const_iterator it;
            for (it = BeginSockets(); it != EndSockets(); ++it) {
                NoDccSock* pSock = (NoDccSock*)*it;

                if (pSock->GetLocalPort() == uResumePort) {
                    if (pSock->Seek(uResumeSize)) {
                        PutModule("DCC -> [" + pSock->GetRemoteNick() + "][" + pSock->GetFileName() +
                                  "] - Attempting to resume from file position [" + NoString(uResumeSize) + "]");
                        PutUser(":*dcc!znc@znc.in PRIVMSG " + GetUser()->GetNick() + " :\001DCC ACCEPT " + sFile + " " +
                                NoString(uResumePort) + " " + NoString(uResumeSize) + "\001");
                    } else {
                        PutModule("DCC -> [" + GetUser()->GetNick() + "][" + sFile +
                                  "] Unable to find send to initiate resume.");
                    }
                }
            }
        } else if (sMessage.startsWith("DCC SEND ")) {
            NoString sLocalFile = NoDir::CheckPathPrefix(GetSavePath(), sMessage.token(2));
            if (sLocalFile.empty()) {
                PutModule("Bad DCC file: " + sMessage.token(2));
            }
            ulong uLongIP = sMessage.token(3).toULong();
            ushort uPort = sMessage.token(4).toUShort();
            ulong uFileSize = sMessage.token(5).toULong();
            GetFile(GetClient()->GetNick(), NoUtils::GetIP(uLongIP), uPort, sLocalFile, uFileSize);
        }
    }
};

NoDccSock::NoDccSock(NoDccMod* pMod, const NoString& sRemoteNick, const NoString& sLocalFile, ulong uFileSize, NoFile* pFile)
    : NoModuleSocket(pMod)
{
    m_sRemoteNick = sRemoteNick;
    m_uFileSize = uFileSize;
    m_uRemotePort = 0;
    m_uBytesSoFar = 0;
    m_pModule = pMod;
    m_pFile = pFile;
    m_sLocalFile = sLocalFile;
    m_bSend = true;
    m_bNoDelFile = false;
    SetMaxBufferThreshold(0);
}

NoDccSock::NoDccSock(NoDccMod* pMod,
                   const NoString& sRemoteNick,
                   const NoString& sRemoteIP,
                   ushort uRemotePort,
                   const NoString& sLocalFile,
                   ulong uFileSize)
    : NoModuleSocket(pMod)
{
    m_sRemoteNick = sRemoteNick;
    m_sRemoteIP = sRemoteIP;
    m_uRemotePort = uRemotePort;
    m_uFileSize = uFileSize;
    m_uBytesSoFar = 0;
    m_pModule = pMod;
    m_pFile = nullptr;
    m_sLocalFile = sLocalFile;
    m_bSend = false;
    m_bNoDelFile = false;
    SetMaxBufferThreshold(0);
}

NoDccSock::~NoDccSock()
{
    if ((m_pFile) && (!m_bNoDelFile)) {
        m_pFile->Close();
        delete m_pFile;
    }
}

void NoDccSock::ReadDataImpl(const char* data, size_t len)
{
    if (!m_pFile) {
        NO_DEBUG("File not open! closing get.");
        m_pModule->PutModule(((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName +
                             "] - File not open!");
        Close();
    }

    // DCC specs says the receiving end sends the number of bytes it
    // received so far as a 4 byte integer in network byte order, so we need
    // uint32_t to do the job portably. This also means that the maximum
    // file that we can transfer is 4 GiB big (see OpenFile()).
    if (m_bSend) {
        m_sSendBuf.append(data, len);

        while (m_sSendBuf.size() >= 4) {
            uint32_t iRemoteSoFar;
            memcpy(&iRemoteSoFar, m_sSendBuf.data(), sizeof(iRemoteSoFar));
            iRemoteSoFar = ntohl(iRemoteSoFar);

            if ((iRemoteSoFar + 65536) >= m_uBytesSoFar) {
                SendPacket();
            }

            m_sSendBuf.erase(0, 4);
        }
    } else {
        m_pFile->Write(data, len);
        m_uBytesSoFar += len;
        uint32_t uSoFar = htonl((uint32_t)m_uBytesSoFar);
        Write((char*)&uSoFar, sizeof(uSoFar));

        if (m_uBytesSoFar >= m_uFileSize) {
            Close();
        }
    }
}

void NoDccSock::ConnectionRefusedImpl()
{
    NO_DEBUG(GetSockName() << " == ConnectionRefused()");
    m_pModule->PutModule(((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName +
                         "] - Connection Refused.");
}

void NoDccSock::TimeoutImpl()
{
    NO_DEBUG(GetSockName() << " == Timeout()");
    m_pModule->PutModule(((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName + "] - Timed Out.");
}

void NoDccSock::SockErrorImpl(int iErrno, const NoString& sDescription)
{
    NO_DEBUG(GetSockName() << " == SockError(" << iErrno << ", " << sDescription << ")");
    m_pModule->PutModule(((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName +
                         "] - Socket Error [" + sDescription + "]");
}

void NoDccSock::ConnectedImpl()
{
    NO_DEBUG(GetSockName() << " == Connected(" << GetRemoteIP() << ")");
    m_pModule->PutModule(((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName +
                         "] - Transfer Started.");

    if (m_bSend) {
        SendPacket();
    }

    SetTimeout(120);
}

void NoDccSock::DisconnectedImpl()
{
    const NoString sStart = ((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName + "] - ";

    NO_DEBUG(GetSockName() << " == Disconnected()");

    if (m_uBytesSoFar > m_uFileSize) {
        m_pModule->PutModule(sStart + "TooMuchData!");
    } else if (m_uBytesSoFar == m_uFileSize) {
        if (m_bSend) {
            m_pModule->PutModule(sStart + "Completed! - Sent [" + m_sLocalFile + "] at [" +
                                 NoString((int)(GetAvgWrite() / 1024.0)) + " KiB/s ]");
        } else {
            m_pModule->PutModule(sStart + "Completed! - Saved to [" + m_sLocalFile + "] at [" +
                                 NoString((int)(GetAvgRead() / 1024.0)) + " KiB/s ]");
        }
    } else {
        m_pModule->PutModule(sStart + "Incomplete!");
    }
}

void NoDccSock::SendPacket()
{
    if (!m_pFile) {
        m_pModule->PutModule(((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName +
                             "] - File closed prematurely.");
        Close();
        return;
    }

    if (GetInternalWriteBuffer().size() > 1024 * 1024) {
        // There is still enough data to be written, don't add more
        // stuff to that buffer.
        NO_DEBUG("SendPacket(): Skipping send, buffer still full enough [" << GetInternalWriteBuffer().size() << "]["
                                                                        << m_sRemoteNick << "][" << m_sFileName << "]");
        return;
    }

    char szBuf[4096];
    ssize_t iLen = m_pFile->Read(szBuf, 4096);

    if (iLen < 0) {
        m_pModule->PutModule(((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName +
                             "] - Error reading from file.");
        Close();
        return;
    }

    if (iLen > 0) {
        Write(szBuf, iLen);
        m_uBytesSoFar += iLen;
    }
}

NoSocket* NoDccSock::GetSockObjImpl(const NoString& sHost, ushort uPort)
{
    Close();

    NoDccSock* pSock = new NoDccSock(m_pModule, m_sRemoteNick, m_sLocalFile, m_uFileSize, m_pFile);
    pSock->SetSockName("DCC::SEND::" + m_sRemoteNick);
    pSock->SetTimeout(120);
    pSock->SetFileName(m_sFileName);
    pSock->SetFileOffset(m_uBytesSoFar);
    m_bNoDelFile = true;

    return pSock;
}

NoFile* NoDccSock::OpenFile(bool bWrite)
{
    if ((m_pFile) || (m_sLocalFile.empty())) {
        m_pModule->PutModule(((bWrite) ? "DCC <- [" : "DCC -> [") + m_sRemoteNick + "][" + m_sLocalFile +
                             "] - Unable to open file.");
        return nullptr;
    }

    m_pFile = new NoFile(m_sLocalFile);

    if (bWrite) {
        if (m_pFile->Exists()) {
            delete m_pFile;
            m_pFile = nullptr;
            m_pModule->PutModule("DCC <- [" + m_sRemoteNick + "] - File already exists [" + m_sLocalFile + "]");
            return nullptr;
        }

        if (!m_pFile->Open(O_WRONLY | O_TRUNC | O_CREAT)) {
            delete m_pFile;
            m_pFile = nullptr;
            m_pModule->PutModule("DCC <- [" + m_sRemoteNick + "] - Could not open file [" + m_sLocalFile + "]");
            return nullptr;
        }
    } else {
        if (!m_pFile->IsReg()) {
            delete m_pFile;
            m_pFile = nullptr;
            m_pModule->PutModule("DCC -> [" + m_sRemoteNick + "] - Not a file [" + m_sLocalFile + "]");
            return nullptr;
        }

        if (!m_pFile->Open()) {
            delete m_pFile;
            m_pFile = nullptr;
            m_pModule->PutModule("DCC -> [" + m_sRemoteNick + "] - Could not open file [" + m_sLocalFile + "]");
            return nullptr;
        }

        // The DCC specs only allow file transfers with files smaller
        // than 4GiB (see ReadData()).
        ulonglong uFileSize = m_pFile->GetSize();
        if (uFileSize > (ulonglong)0xffffffffULL) {
            delete m_pFile;
            m_pFile = nullptr;
            m_pModule->PutModule("DCC -> [" + m_sRemoteNick + "] - File too large (>4 GiB) [" + m_sLocalFile + "]");
            return nullptr;
        }

        m_uFileSize = uFileSize;
    }

    m_sFileName = m_pFile->GetShortName();

    return m_pFile;
}

bool NoDccSock::Seek(ulong uPos)
{
    if (m_pFile) {
        if (m_pFile->Seek(uPos)) {
            m_uBytesSoFar = uPos;
            return true;
        }
    }

    return false;
}

template <> void no_moduleInfo<NoDccMod>(NoModuleInfo& Info) { Info.SetWikiPage("dcc"); }

USERMODULEDEFS(NoDccMod, "This module allows you to transfer files to and from ZNC")
