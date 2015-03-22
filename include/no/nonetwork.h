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

#ifndef NONETWORK_H
#define NONETWORK_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <no/nobuffer.h>
#include <no/nonick.h>

class NoModules;
class NoUser;
class NoClient;
class NoSettings;
class NoChannel;
class NoQuery;
class NoServerInfo;
class NoIrcSocket;
class NoNetworkPingTimer;
class NoNetworkJoinTimer;

class NO_EXPORT NoNetwork
{
public:
    static bool IsValidNetwork(const NoString& sNetwork);

    NoNetwork(NoUser* pUser, const NoString& sName);
    NoNetwork(NoUser* pUser, const NoNetwork& Network);
    ~NoNetwork();

    NoNetwork(const NoNetwork&) = delete;
    NoNetwork& operator=(const NoNetwork&) = delete;

    enum {
        JOIN_FREQUENCY = 30,
        /** How long must an IRC connection be idle before ZNC sends a ping */
        PING_FREQUENCY = 270,
        /** Time between checks if PINGs need to be sent */
        PING_SLACK = 30,
        /** Timeout after which IRC connections are closed. Must
         *  obviously be greater than PING_FREQUENCY + PING_SLACK.
         */
        NO_TRAFFIC_TIMEOUT = 540
    };

    void Clone(const NoNetwork& Network, bool bCloneName = true);

    NoString GetNetworkPath() const;

    void DelServers();

    bool ParseConfig(NoSettings* pConfig, NoString& sError, bool bUpgrade = false);
    NoSettings ToConfig() const;

    bool IsUserAttached() const;
    bool IsUserOnline() const;
    void ClientConnected(NoClient* pClient);
    void ClientDisconnected(NoClient* pClient);

    NoUser* GetUser() const;
    NoString GetName() const;
    bool IsNetworkAttached() const;
    std::vector<NoClient*> GetClients() const;
    std::vector<NoClient*> FindClients(const NoString& sIdentifier) const;

    void SetUser(NoUser* pUser);
    bool SetName(const NoString& sName);

    NoModules& GetModules();
    const NoModules& GetModules() const;

    bool PutUser(const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);
    bool PutStatus(const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);
    bool PutModule(const NoString& sModule, const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);

    std::vector<NoChannel*> GetChans() const;
    NoChannel* FindChan(NoString sName) const;
    std::vector<NoChannel*> FindChans(const NoString& sWild) const;
    bool AddChan(NoChannel* pChan);
    bool AddChan(const NoString& sName, bool bInConfig);
    bool DelChan(const NoString& sName);
    void JoinChans();

    std::vector<NoQuery*> GetQueries() const;
    NoQuery* FindQuery(const NoString& sName) const;
    std::vector<NoQuery*> FindQueries(const NoString& sWild) const;
    NoQuery* AddQuery(const NoString& sName);
    bool DelQuery(const NoString& sName);

    NoString GetChanPrefixes() const;
    void SetChanPrefixes(const NoString& s);
    bool IsChan(const NoString& sChan) const;

    std::vector<NoServerInfo*> GetServers() const;
    bool HasServers() const;
    NoServerInfo* FindServer(const NoString& sName) const;
    bool DelServer(const NoString& sName, ushort uPort, const NoString& sPass);
    bool AddServer(const NoString& sName);
    bool AddServer(const NoString& sName, ushort uPort, const NoString& sPass = "", bool bSSL = false);
    NoServerInfo* GetNextServer();
    NoServerInfo* GetCurrentServer() const;
    void SetIRCServer(const NoString& s);
    bool SetNextServer(const NoServerInfo* pServer);
    bool IsLastServer() const;

    NoStringSet GetTrustedFingerprints() const;
    void AddTrustedFingerprint(const NoString& sFP);
    void DelTrustedFingerprint(const NoString& sFP);

    void SetIRCConnectEnabled(bool b);
    bool GetIRCConnectEnabled() const;

    NoIrcSocket* GetIRCSock() const;
    NoString GetIRCServer() const;
    const NoNick& GetIRCNick() const;
    void SetIRCNick(const NoNick& n);
    NoString GetCurNick() const;
    bool IsIRCAway() const;
    void SetIRCAway(bool b);

    bool Connect();
    bool IsIRCConnected() const;
    void SetIRCSocket(NoIrcSocket* pIRCSock);
    void IRCConnected();
    void IRCDisconnected();
    void CheckIRCConnect();

    bool PutIRC(const NoString& sLine);

    void AddRawBuffer(const NoString& sFormat, const NoString& sText = "");
    void UpdateRawBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText = "");
    void UpdateExactRawBuffer(const NoString& sFormat, const NoString& sText = "");
    void ClearRawBuffer();

    void AddMotdBuffer(const NoString& sFormat, const NoString& sText = "");
    void UpdateMotdBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText = "");
    void ClearMotdBuffer();

    void AddNoticeBuffer(const NoString& sFormat, const NoString& sText = "");
    void UpdateNoticeBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText = "");
    void ClearNoticeBuffer();

    void ClearQueryBuffer();

    NoString GetNick(const bool bAllowDefault = true) const;
    NoString GetAltNick(const bool bAllowDefault = true) const;
    NoString GetIdent(const bool bAllowDefault = true) const;
    NoString GetRealName() const;
    NoString GetBindHost() const;
    NoString GetEncoding() const;
    NoString GetQuitMsg() const;

    void SetNick(const NoString& s);
    void SetAltNick(const NoString& s);
    void SetIdent(const NoString& s);
    void SetRealName(const NoString& s);
    void SetBindHost(const NoString& s);
    void SetEncoding(const NoString& s);
    void SetQuitMsg(const NoString& s);

    double GetFloodRate() const;
    ushort GetFloodBurst() const;
    void SetFloodRate(double fFloodRate);
    void SetFloodBurst(ushort uFloodBurst);

    ushort GetJoinDelay() const;
    void SetJoinDelay(ushort uJoinDelay);

    NoString ExpandString(const NoString& sStr) const;
    NoString& ExpandString(const NoString& sStr, NoString& sRet) const;

private:
    void BounceAllClients();
    bool JoinChan(NoChannel* pChan);
    void JoinChans(std::set<NoChannel*>& sChans);
    bool LoadModule(const NoString& sModName, const NoString& sArgs, const NoString& sNotice, NoString& sError);

    NoString m_sName;
    NoUser* m_pUser;

    NoString m_sNick;
    NoString m_sAltNick;
    NoString m_sIdent;
    NoString m_sRealName;
    NoString m_sBindHost;
    NoString m_sEncoding;
    NoString m_sQuitMsg;
    NoStringSet m_ssTrustedFingerprints;

    NoModules* m_pModules;

    std::vector<NoClient*> m_vClients;

    NoIrcSocket* m_pIRCSock;

    std::vector<NoChannel*> m_vChans;
    std::vector<NoQuery*> m_vQueries;

    NoString m_sChanPrefixes;

    bool m_bIRCConnectEnabled;
    NoString m_sIRCServer;
    std::vector<NoServerInfo*> m_vServers;
    size_t m_uServerIdx; ///< Index in m_vServers of our current server + 1

    NoNick m_IRCNick;
    bool m_bIRCAway;

    double m_fFloodRate; ///< Set to -1 to disable protection.
    ushort m_uFloodBurst;

    NoBuffer m_RawBuffer;
    NoBuffer m_MotdBuffer;
    NoBuffer m_NoticeBuffer;

    NoNetworkPingTimer* m_pPingTimer;
    NoNetworkJoinTimer* m_pJoinTimer;

    ushort m_uJoinDelay;
};

#endif // NONETWORK_H
