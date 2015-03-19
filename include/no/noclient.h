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

#ifndef NOCLIENT_H
#define NOCLIENT_H

#include <no/noglobal.h>
#include <no/noircsocket.h>
#include <no/noutils.h>
#include <no/notable.h>
#include <memory>

class NoApp;
class NoUser;
class NoNetwork;
class NoIrcConnection;
class NoClient;

class NO_EXPORT NoAuthBase
{
public:
    NoAuthBase(const NoString& sUsername, const NoString& sPassword, NoSocket* pSock)
        : m_sUsername(sUsername), m_sPassword(sPassword), m_pSock(pSock)
    {
    }

    virtual ~NoAuthBase() {}

    NoAuthBase(const NoAuthBase&) = delete;
    NoAuthBase& operator=(const NoAuthBase&) = delete;

    virtual void SetLoginInfo(const NoString& sUsername, const NoString& sPassword, NoSocket* pSock)
    {
        m_sUsername = sUsername;
        m_sPassword = sPassword;
        m_pSock = pSock;
    }

    void AcceptLogin(NoUser& User);
    void RefuseLogin(const NoString& sReason);

    const NoString& GetUsername() const { return m_sUsername; }
    const NoString& GetPassword() const { return m_sPassword; }
    NoSocket* GetSocket() const { return m_pSock; }
    NoString GetRemoteIP() const;

    // Invalidate this NoAuthBase instance which means it will no longer use
    // m_pSock and AcceptLogin() or RefusedLogin() will have no effect.
    virtual void Invalidate();

protected:
    virtual void AcceptedLogin(NoUser& User) = 0;
    virtual void RefusedLogin(const NoString& sReason) = 0;

private:
    NoString m_sUsername;
    NoString m_sPassword;
    NoSocket* m_pSock;
};


class NO_EXPORT NoClientAuth : public NoAuthBase
{
public:
    NoClientAuth(NoClient* pClient, const NoString& sUsername, const NoString& sPassword);
    virtual ~NoClientAuth() {}

    NoClientAuth(const NoClientAuth&) = delete;
    NoClientAuth& operator=(const NoClientAuth&) = delete;

    void Invalidate() override
    {
        m_pClient = nullptr;
        NoAuthBase::Invalidate();
    }
    void AcceptedLogin(NoUser& User) override;
    void RefusedLogin(const NoString& sReason) override;

private:
    NoClient* m_pClient;
};

class NO_EXPORT NoClient : public NoIrcSocket
{
public:
    NoClient();
    virtual ~NoClient();

    NoClient(const NoClient&) = delete;
    NoClient& operator=(const NoClient&) = delete;

    void SendRequiredPasswordNotice();
    void AcceptLogin(NoUser& User);
    void RefuseLogin(const NoString& sReason);

    NoString GetNick(bool bAllowIRCNick = true) const;
    NoString GetNickMask() const;
    NoString GetIdentifier() const;
    bool HasNamesx() const;
    bool HasUHNames() const;
    bool IsAway() const;
    bool HasServerTime() const;
    bool HasBatch() const;
    bool HasSelfMessage() const;

    static bool IsValidIdentifier(const NoString& sIdentifier);

    void UserCommand(NoString& sLine);
    void UserPortCommand(NoString& sLine);
    void StatusCTCP(const NoString& sCommand);
    void BouncedOff();
    bool IsAttached() const;

    bool IsPlaybackActive() const;
    void SetPlaybackActive(bool bActive);

    void PutIRC(const NoString& sLine);
    void PutClient(const NoString& sLine);
    uint PutStatus(const NoTable& table);
    void PutStatus(const NoString& sLine);
    void PutStatusNotice(const NoString& sLine);
    void PutModule(const NoString& sModule, const NoString& sLine);
    void PutModNotice(const NoString& sModule, const NoString& sLine);

    bool IsCapEnabled(const NoString& sCap) const;

    void ReadLineImpl(const NoString& sData) override;
    bool SendMotd();
    void HelpUser(const NoString& sFilter = "");
    void AuthUser();
    void ConnectedImpl() override;
    void TimeoutImpl() override;
    void DisconnectedImpl() override;
    void ConnectionRefusedImpl() override;
    void ReachedMaxBufferImpl() override;

    void SetNick(const NoString& s);
    void SetAway(bool bAway);
    NoUser* GetUser() const;
    void SetNetwork(NoNetwork* pNetwork, bool bDisconnect = true, bool bReconnect = true);
    NoNetwork* GetNetwork() const;
    std::vector<NoClient*> GetClients() const;
    NoIrcConnection* GetIRCSock() const;
    NoString GetFullName() const;

private:
    void HandleCap(const NoString& sLine);
    void RespondCap(const NoString& sResponse);
    void ParsePass(const NoString& sAuthLine);
    void ParseUser(const NoString& sAuthLine);
    void ParseIdentifier(const NoString& sAuthLine);

private:
    bool m_bGotPass;
    bool m_bGotNick;
    bool m_bGotUser;
    bool m_bInCap;
    bool m_bNamesx;
    bool m_bUHNames;
    bool m_bAway;
    bool m_bServerTime;
    bool m_bBatch;
    bool m_bSelfMessage;
    bool m_bPlaybackActive;
    NoUser* m_pUser;
    NoNetwork* m_pNetwork;
    NoString m_sNick;
    NoString m_sPass;
    NoString m_sUser;
    NoString m_sNetwork;
    NoString m_sIdentifier;
    std::shared_ptr<NoAuthBase> m_spAuth;
    NoStringSet m_ssAcceptedCaps;

    friend class ClientTest;
};

#endif // NOCLIENT_H
