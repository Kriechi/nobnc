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

#include <znc/noconfig.h>
#include <znc/nostring.h>
#include <znc/nobuffer.h>
#include <znc/nonick.h>
#include <znc/noapp.h>

class NoModules;
class NoUser;
class NoFile;
class NoSettings;
class NoClient;
class NoSettings;
class NoChannel;
class NoQuery;
class NoServer;
class NoIrcSock;
class NoNetworkPingTimer;
class NoNetworkJoinTimer;

class NoNetwork
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

    void BounceAllClients();

    bool IsUserAttached() const { return !m_vClients.empty(); }
    bool IsUserOnline() const;
    void ClientConnected(NoClient* pClient);
    void ClientDisconnected(NoClient* pClient);

    NoUser* GetUser() const;
    const NoString& GetName() const;
    bool IsNetworkAttached() const { return !m_vClients.empty(); }
    const std::vector<NoClient*>& GetClients() const { return m_vClients; }
    std::vector<NoClient*> FindClients(const NoString& sIdentifier) const;

    void SetUser(NoUser* pUser);
    bool SetName(const NoString& sName);

    NoModules& GetModules() { return *m_pModules; }
    const NoModules& GetModules() const { return *m_pModules; }

    bool PutUser(const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);
    bool PutStatus(const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);
    bool PutModule(const NoString& sModule, const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);

    const std::vector<NoChannel*>& GetChans() const;
    NoChannel* FindChan(NoString sName) const;
    std::vector<NoChannel*> FindChans(const NoString& sWild) const;
    bool AddChan(NoChannel* pChan);
    bool AddChan(const NoString& sName, bool bInConfig);
    bool DelChan(const NoString& sName);
    void JoinChans();
    void JoinChans(std::set<NoChannel*>& sChans);

    const std::vector<NoQuery*>& GetQueries() const;
    NoQuery* FindQuery(const NoString& sName) const;
    std::vector<NoQuery*> FindQueries(const NoString& sWild) const;
    NoQuery* AddQuery(const NoString& sName);
    bool DelQuery(const NoString& sName);

    const NoString& GetChanPrefixes() const { return m_sChanPrefixes; }
    void SetChanPrefixes(const NoString& s) { m_sChanPrefixes = s; }
    bool IsChan(const NoString& sChan) const;

    const std::vector<NoServer*>& GetServers() const;
    bool HasServers() const { return !m_vServers.empty(); }
    NoServer* FindServer(const NoString& sName) const;
    bool DelServer(const NoString& sName, unsigned short uPort, const NoString& sPass);
    bool AddServer(const NoString& sName);
    bool AddServer(const NoString& sName, unsigned short uPort, const NoString& sPass = "", bool bSSL = false);
    NoServer* GetNextServer();
    NoServer* GetCurrentServer() const;
    void SetIRNoServer(const NoString& s);
    bool SetNextServer(const NoServer* pServer);
    bool IsLastServer() const;

    const NoStringSet& GetTrustedFingerprints() const { return m_ssTrustedFingerprints; }
    void AddTrustedFingerprint(const NoString& sFP)
    {
        m_ssTrustedFingerprints.insert(sFP.Escape_n(NoString::EHEXCOLON, NoString::EHEXCOLON));
    }
    void DelTrustedFingerprint(const NoString& sFP) { m_ssTrustedFingerprints.erase(sFP); }

    void SetIRCConnectEnabled(bool b);
    bool GetIRCConnectEnabled() const { return m_bIRCConnectEnabled; }

    NoIrcSock* GetIRCSock() { return m_pIRCSock; }
    const NoIrcSock* GetIRCSock() const { return m_pIRCSock; }
    const NoString& GetIRNoServer() const;
    const NoNick& GetIRNoNick() const;
    void SetIRNoNick(const NoNick& n);
    NoString GetCurNick() const;
    bool IsIRNoAway() const { return m_bIRNoAway; }
    void SetIRNoAway(bool b) { m_bIRNoAway = b; }

    bool Connect();
    bool IsIRCConnected() const;
    void SetIRNoSocket(NoIrcSock* pIRCSock);
    void IRCConnected();
    void IRCDisconnected();
    void CheckIRCConnect();

    bool PutIRC(const NoString& sLine);

    void AddRawBuffer(const NoString& sFormat, const NoString& sText = "") { m_RawBuffer.AddLine(sFormat, sText); }
    void UpdateRawBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText = "")
    {
        m_RawBuffer.UpdateLine(sMatch, sFormat, sText);
    }
    void UpdateExactRawBuffer(const NoString& sFormat, const NoString& sText = "")
    {
        m_RawBuffer.UpdateExactLine(sFormat, sText);
    }
    void ClearRawBuffer() { m_RawBuffer.Clear(); }

    void AddMotdBuffer(const NoString& sFormat, const NoString& sText = "") { m_MotdBuffer.AddLine(sFormat, sText); }
    void UpdateMotdBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText = "")
    {
        m_MotdBuffer.UpdateLine(sMatch, sFormat, sText);
    }
    void ClearMotdBuffer() { m_MotdBuffer.Clear(); }

    void AddNoticeBuffer(const NoString& sFormat, const NoString& sText = "") { m_NoticeBuffer.AddLine(sFormat, sText); }
    void UpdateNoticeBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText = "")
    {
        m_NoticeBuffer.UpdateLine(sMatch, sFormat, sText);
    }
    void ClearNoticeBuffer() { m_NoticeBuffer.Clear(); }

    void ClearQueryBuffer();

    const NoString& GetNick(const bool bAllowDefault = true) const;
    const NoString& GetAltNick(const bool bAllowDefault = true) const;
    const NoString& GetIdent(const bool bAllowDefault = true) const;
    const NoString& GetRealName() const;
    const NoString& GetBindHost() const;
    const NoString& GetEncoding() const;
    NoString GetQuitMsg() const;

    void SetNick(const NoString& s);
    void SetAltNick(const NoString& s);
    void SetIdent(const NoString& s);
    void SetRealName(const NoString& s);
    void SetBindHost(const NoString& s);
    void SetEncoding(const NoString& s);
    void SetQuitMsg(const NoString& s);

    double GetFloodRate() const { return m_fFloodRate; }
    unsigned short int GetFloodBurst() const { return m_uFloodBurst; }
    void SetFloodRate(double fFloodRate) { m_fFloodRate = fFloodRate; }
    void SetFloodBurst(unsigned short int uFloodBurst) { m_uFloodBurst = uFloodBurst; }

    unsigned short int GetJoinDelay() const { return m_uJoinDelay; }
    void SetJoinDelay(unsigned short int uJoinDelay) { m_uJoinDelay = uJoinDelay; }

    NoString ExpandString(const NoString& sStr) const;
    NoString& ExpandString(const NoString& sStr, NoString& sRet) const;

private:
    bool JoinChan(NoChannel* pChan);
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

    NoIrcSock* m_pIRCSock;

    std::vector<NoChannel*> m_vChans;
    std::vector<NoQuery*> m_vQueries;

    NoString m_sChanPrefixes;

    bool m_bIRCConnectEnabled;
    NoString m_sIRNoServer;
    std::vector<NoServer*> m_vServers;
    size_t m_uServerIdx; ///< Index in m_vServers of our current server + 1

    NoNick m_IRNoNick;
    bool m_bIRNoAway;

    double m_fFloodRate; ///< Set to -1 to disable protection.
    unsigned short int m_uFloodBurst;

    NoBuffer m_RawBuffer;
    NoBuffer m_MotdBuffer;
    NoBuffer m_NoticeBuffer;

    NoNetworkPingTimer* m_pPingTimer;
    NoNetworkJoinTimer* m_pJoinTimer;

    unsigned short int m_uJoinDelay;
};

#endif // NONETWORK_H
