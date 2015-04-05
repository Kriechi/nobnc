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
#include <nobnc/noapp.h>
#include <nobnc/nouser.h>
#include <nobnc/nofile.h>
#include <nobnc/nodir.h>
#include <nobnc/nodebug.h>
#include <nobnc/noclient.h>
#include <nobnc/nomodulesocket.h>
#include <nobnc/notable.h>

#include <netinet/in.h>
#include <arpa/inet.h>

class NoDccMod;

class NoDccSock : public NoModuleSocket
{
public:
    NoDccSock(NoDccMod* mod, const NoString& sRemoteNick, const NoString& sLocalFile, ulong uFileSize = 0, NoFile* pFile = nullptr);
    NoDccSock(NoDccMod* mod, const NoString& sRemoteNick, const NoString& sRemoteIP, ushort uRemotePort, const NoString& sLocalFile, ulong uFileSize);
    virtual ~NoDccSock();

    void readData(const char* data, size_t len) override;
    void onConnectionRefused() override;
    void onSocketError(int iErrno, const NoString& description) override;
    void onTimeout() override;
    void onConnected() override;
    void onDisconnected() override;
    void SendPacket();
    NoSocket* createSocket(const NoString& host, ushort port) override;
    NoFile* OpenFile(bool bWrite = true);
    bool Seek(ulong uPos);

    // Setters
    void SetRemoteIP(const NoString& s)
    {
        m_sRemoteIP = s;
    }
    void SetRemoteNick(const NoString& s)
    {
        m_sRemoteNick = s;
    }
    void SetFileName(const NoString& s)
    {
        m_sFileName = s;
    }
    void SetFileOffset(ulong u)
    {
        m_uBytesSoFar = u;
    }
    // !Setters

    // Getters
    ushort GetUserPort() const
    {
        return m_uRemotePort;
    }
    const NoString& GetRemoteNick() const
    {
        return m_sRemoteNick;
    }
    const NoString& GetFileName() const
    {
        return m_sFileName;
    }
    const NoString& GetLocalFile() const
    {
        return m_sLocalFile;
    }
    NoFile* GetFile()
    {
        return m_pFile;
    }
    double GetProgress() const
    {
        return ((m_uFileSize) && (m_uBytesSoFar)) ? (double)(((double)m_uBytesSoFar / (double)m_uFileSize) * 100.0) : 0;
    }
    bool IsSend() const
    {
        return m_bSend;
    }
    // const NoString& remoteAddress() const { return m_sRemoteIP; }
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
    NoDccMod* m_module;
};

class NoDccMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoDccMod)
    {
        addHelpCommand();
        addCommand("Send", static_cast<NoModuleCommand::ModCmdFunc>(&NoDccMod::SendCommand), "<nick> <file>");
        addCommand("Get", static_cast<NoModuleCommand::ModCmdFunc>(&NoDccMod::GetCommand), "<file>");
        addCommand("ListTransfers", static_cast<NoModuleCommand::ModCmdFunc>(&NoDccMod::ListTransfersCommand));
    }

#ifndef MOD_DCC_ALLOW_EVERYONE
    bool onLoad(const NoString& args, NoString& message) override
    {
        if (!user()->isAdmin()) {
            message = "You must be admin to use the DCC module";
            return false;
        }

        return true;
    }
#endif

    bool SendFile(const NoString& sRemoteNick, const NoString& fileName)
    {
        NoString sFullPath = NoDir(savePath()).filePath(fileName);
        NoDccSock* socket = new NoDccSock(this, sRemoteNick, sFullPath);

        NoFile* pFile = socket->OpenFile(false);

        if (!pFile) {
            delete socket;
            return false;
        }

        NoString sLocalDCCIP = user()->localDccIp();
        ushort port =
        noApp->manager()->listenRand("DCC::LISTEN::" + sRemoteNick, sLocalDCCIP, false, SOMAXCONN, socket, 120);

        if (user()->nick().equals(sRemoteNick)) {
            putUser(":*dcc!znc@znc.in PRIVMSG " + sRemoteNick + " :\001DCC SEND " + pFile->GetShortName() + " " +
                    NoString(No::formatLongIp(sLocalDCCIP)) + " " + NoString(port) + " " + NoString(pFile->GetSize()) + "\001");
        } else {
            putIrc("PRIVMSG " + sRemoteNick + " :\001DCC SEND " + pFile->GetShortName() + " " +
                   NoString(No::formatLongIp(sLocalDCCIP)) + " " + NoString(port) + " " + NoString(pFile->GetSize()) + "\001");
        }

        putModule("DCC -> [" + sRemoteNick + "][" + pFile->GetShortName() + "] - Attempting Send.");
        return true;
    }

    bool GetFile(const NoString& sRemoteNick, const NoString& sRemoteIP, ushort uRemotePort, const NoString& fileName, ulong uFileSize)
    {
        if (NoFile::Exists(fileName)) {
            putModule("DCC <- [" + sRemoteNick + "][" + fileName + "] - File already exists.");
            return false;
        }

        NoDccSock* socket = new NoDccSock(this, sRemoteNick, sRemoteIP, uRemotePort, fileName, uFileSize);

        if (!socket->OpenFile()) {
            delete socket;
            return false;
        }

        noApp->manager()->connect(sRemoteIP, uRemotePort, "DCC::GET::" + sRemoteNick, 60, false, user()->localDccIp(), socket);

        putModule("DCC <- [" + sRemoteNick + "][" + fileName + "] - Attempting to connect to [" + sRemoteIP + "]");
        return true;
    }

    void SendCommand(const NoString& line)
    {
        NoString sToNick = No::token(line, 1);
        NoString sFile = No::token(line, 2);

        if ((sToNick.empty()) || (sFile.empty())) {
            putModule("Usage: Send <nick> <file>");
            return;
        }

        if (!NoDir(savePath()).isParent(sFile)) {
            putStatus("Illegal path.");
            return;
        }

        SendFile(sToNick, sFile);
    }

    void GetCommand(const NoString& line)
    {
        NoString sFile = No::token(line, 1);

        if (sFile.empty()) {
            putModule("Usage: Get <file>");
            return;
        }

        if (!NoDir(savePath()).isParent(sFile)) {
            putModule("Illegal path.");
            return;
        }

        SendFile(user()->nick(), sFile);
    }

    void ListTransfersCommand(const NoString& line)
    {
        NoTable Table;
        Table.addColumn("Type");
        Table.addColumn("State");
        Table.addColumn("Speed");
        Table.addColumn("Nick");
        Table.addColumn("IP");
        Table.addColumn("File");

        for (NoDccSock* socket : m_sockets) {
            Table.addRow();
            Table.setValue("Nick", socket->GetRemoteNick());
            Table.setValue("IP", socket->remoteAddress());
            Table.setValue("File", socket->GetFileName());

            if (socket->IsSend()) {
                Table.setValue("Type", "Sending");
            } else {
                Table.setValue("Type", "Getting");
            }

            if (socket->isListener()) {
                Table.setValue("State", "Waiting");
            } else {
                Table.setValue("State", No::toPercent(socket->GetProgress()));
                Table.setValue("Speed", NoString((int)(socket->averageReadSpeed() / 1024.0)) + " KiB/s");
            }
        }

        if (putModule(Table) == 0) {
            putModule("You have no active DCC transfers.");
        }
    }

    void onModuleCtcp(const NoString& message) override
    {
        if (message.startsWith("DCC RESUME ")) {
            NoString sFile = No::token(message, 2);
            ushort uResumePort = No::token(message, 3).toUShort();
            ulong uResumeSize = No::token(message, 4).toULong();

            for (NoDccSock* socket : m_sockets) {
                if (socket->localPort() == uResumePort) {
                    if (socket->Seek(uResumeSize)) {
                        putModule("DCC -> [" + socket->GetRemoteNick() + "][" + socket->GetFileName() +
                                  "] - Attempting to resume from file position [" + NoString(uResumeSize) + "]");
                        putUser(":*dcc!znc@znc.in PRIVMSG " + user()->nick() + " :\001DCC ACCEPT " + sFile + " " +
                                NoString(uResumePort) + " " + NoString(uResumeSize) + "\001");
                    } else {
                        putModule("DCC -> [" + user()->nick() + "][" + sFile +
                                  "] Unable to find send to initiate resume.");
                    }
                }
            }
        } else if (message.startsWith("DCC SEND ")) {
            NoDir saveDir(savePath());
            NoString sFile = No::token(message, 2);
            if (!saveDir.isParent(sFile)) {
                putModule("Bad DCC file: " + No::token(message, 2));
            }
            ulong uLongIP = No::token(message, 3).toULong();
            ushort port = No::token(message, 4).toUShort();
            ulong uFileSize = No::token(message, 5).toULong();
            NoString sLocalFile = saveDir.filePath(sFile);
            GetFile(client()->nick(), No::formatIp(uLongIP), port, sLocalFile, uFileSize);
        }
    }
    void AddSocket(NoDccSock* socket)
    {
        m_sockets.insert(socket);
    }
    void RemoveSocket(NoDccSock* socket)
    {
        m_sockets.erase(socket);
    }

private:
    std::set<NoDccSock*> m_sockets;
};

NoDccSock::NoDccSock(NoDccMod* mod, const NoString& sRemoteNick, const NoString& sLocalFile, ulong uFileSize, NoFile* pFile)
    : NoModuleSocket(mod)
{
    m_sRemoteNick = sRemoteNick;
    m_uFileSize = uFileSize;
    m_uRemotePort = 0;
    m_uBytesSoFar = 0;
    m_module = mod;
    m_pFile = pFile;
    m_sLocalFile = sLocalFile;
    m_bSend = true;
    m_bNoDelFile = false;
    setMaxBufferThreshold(0);
    mod->AddSocket(this);
}

NoDccSock::NoDccSock(NoDccMod* mod, const NoString& sRemoteNick, const NoString& sRemoteIP, ushort uRemotePort, const NoString& sLocalFile, ulong uFileSize)
    : NoModuleSocket(mod)
{
    m_sRemoteNick = sRemoteNick;
    m_sRemoteIP = sRemoteIP;
    m_uRemotePort = uRemotePort;
    m_uFileSize = uFileSize;
    m_uBytesSoFar = 0;
    m_module = mod;
    m_pFile = nullptr;
    m_sLocalFile = sLocalFile;
    m_bSend = false;
    m_bNoDelFile = false;
    setMaxBufferThreshold(0);
    mod->AddSocket(this);
}

NoDccSock::~NoDccSock()
{
    if ((m_pFile) && (!m_bNoDelFile)) {
        m_pFile->Close();
        delete m_pFile;
    }
    m_module->RemoveSocket(this);
}

void NoDccSock::readData(const char* data, size_t len)
{
    if (!m_pFile) {
        NO_DEBUG("File not open! closing get.");
        m_module->putModule(((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName +
                            "] - File not open!");
        close();
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
        write((char*)&uSoFar, sizeof(uSoFar));

        if (m_uBytesSoFar >= m_uFileSize) {
            close();
        }
    }
}

void NoDccSock::onConnectionRefused()
{
    NO_DEBUG(name() << " == ConnectionRefused()");
    m_module->putModule(((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName +
                        "] - Connection Refused.");
}

void NoDccSock::onTimeout()
{
    NO_DEBUG(name() << " == Timeout()");
    m_module->putModule(((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName + "] - Timed Out.");
}

void NoDccSock::onSocketError(int iErrno, const NoString& description)
{
    NO_DEBUG(name() << " == SockError(" << iErrno << ", " << description << ")");
    m_module->putModule(((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName +
                        "] - Socket Error [" + description + "]");
}

void NoDccSock::onConnected()
{
    NO_DEBUG(name() << " == Connected(" << remoteAddress() << ")");
    m_module->putModule(((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName +
                        "] - Transfer Started.");

    if (m_bSend) {
        SendPacket();
    }

    setTimeout(120);
}

void NoDccSock::onDisconnected()
{
    const NoString sStart = ((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName + "] - ";

    NO_DEBUG(name() << " == Disconnected()");

    if (m_uBytesSoFar > m_uFileSize) {
        m_module->putModule(sStart + "TooMuchData!");
    } else if (m_uBytesSoFar == m_uFileSize) {
        if (m_bSend) {
            m_module->putModule(sStart + "Completed! - Sent [" + m_sLocalFile + "] at [" +
                                NoString((int)(averageWriteSpeed() / 1024.0)) + " KiB/s ]");
        } else {
            m_module->putModule(sStart + "Completed! - Saved to [" + m_sLocalFile + "] at [" +
                                NoString((int)(averageReadSpeed() / 1024.0)) + " KiB/s ]");
        }
    } else {
        m_module->putModule(sStart + "Incomplete!");
    }
}

void NoDccSock::SendPacket()
{
    if (!m_pFile) {
        m_module->putModule(((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName +
                            "] - File closed prematurely.");
        close();
        return;
    }

    if (internalWriteBuffer().size() > 1024 * 1024) {
        // There is still enough data to be written, don't add more
        // stuff to that buffer.
        NO_DEBUG("SendPacket(): Skipping send, buffer still full enough ["
                 << internalWriteBuffer().size() << "][" << m_sRemoteNick << "][" << m_sFileName << "]");
        return;
    }

    char szBuf[4096];
    ssize_t iLen = m_pFile->Read(szBuf, 4096);

    if (iLen < 0) {
        m_module->putModule(((m_bSend) ? "DCC -> [" : "DCC <- [") + m_sRemoteNick + "][" + m_sFileName +
                            "] - Error reading from file.");
        close();
        return;
    }

    if (iLen > 0) {
        write(szBuf, iLen);
        m_uBytesSoFar += iLen;
    }
}

NoSocket* NoDccSock::createSocket(const NoString& host, ushort port)
{
    close();

    NoDccSock* socket = new NoDccSock(m_module, m_sRemoteNick, m_sLocalFile, m_uFileSize, m_pFile);
    socket->setName("DCC::SEND::" + m_sRemoteNick);
    socket->setTimeout(120);
    socket->SetFileName(m_sFileName);
    socket->SetFileOffset(m_uBytesSoFar);
    m_bNoDelFile = true;

    return socket;
}

NoFile* NoDccSock::OpenFile(bool bWrite)
{
    if ((m_pFile) || (m_sLocalFile.empty())) {
        m_module->putModule(((bWrite) ? "DCC <- [" : "DCC -> [") + m_sRemoteNick + "][" + m_sLocalFile +
                            "] - Unable to open file.");
        return nullptr;
    }

    m_pFile = new NoFile(m_sLocalFile);

    if (bWrite) {
        if (m_pFile->Exists()) {
            delete m_pFile;
            m_pFile = nullptr;
            m_module->putModule("DCC <- [" + m_sRemoteNick + "] - File already exists [" + m_sLocalFile + "]");
            return nullptr;
        }

        if (!m_pFile->Open(O_WRONLY | O_TRUNC | O_CREAT)) {
            delete m_pFile;
            m_pFile = nullptr;
            m_module->putModule("DCC <- [" + m_sRemoteNick + "] - Could not open file [" + m_sLocalFile + "]");
            return nullptr;
        }
    } else {
        if (!m_pFile->IsReg()) {
            delete m_pFile;
            m_pFile = nullptr;
            m_module->putModule("DCC -> [" + m_sRemoteNick + "] - Not a file [" + m_sLocalFile + "]");
            return nullptr;
        }

        if (!m_pFile->Open()) {
            delete m_pFile;
            m_pFile = nullptr;
            m_module->putModule("DCC -> [" + m_sRemoteNick + "] - Could not open file [" + m_sLocalFile + "]");
            return nullptr;
        }

        // The DCC specs only allow file transfers with files smaller
        // than 4GiB (see ReadData()).
        ulonglong uFileSize = m_pFile->GetSize();
        if (uFileSize > (ulonglong)0xffffffffULL) {
            delete m_pFile;
            m_pFile = nullptr;
            m_module->putModule("DCC -> [" + m_sRemoteNick + "] - File too large (>4 GiB) [" + m_sLocalFile + "]");
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

template <>
void no_moduleInfo<NoDccMod>(NoModuleInfo& info)
{
    info.setWikiPage("dcc");
}

USERMODULEDEFS(NoDccMod, "This module allows you to transfer files to and from ZNC")
