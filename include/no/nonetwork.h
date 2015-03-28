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

#ifndef NONETWORK_H
#define NONETWORK_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <memory>

class NoUser;
class NoNick;
class NoQuery;
class NoClient;
class NoChannel;
class NoModuleLoader;
class NoSettings;
class NoIrcSocket;
class NoServerInfo;
class NoNetworkPrivate;

class NO_EXPORT NoNetwork
{
public:
    static bool isValidNetwork(const NoString& sNetwork);

    NoNetwork(NoUser* pUser, const NoString& sName);
    NoNetwork(NoUser* pUser, const NoNetwork& Network);
    ~NoNetwork();

    enum {
        JoinFrequence = 30,
        /** How long must an IRC connection be idle before ZNC sends a ping */
        PingFrequency = 270,
        /** Time between checks if PINGs need to be sent */
        PingSlack = 30,
        /** Timeout after which IRC connections are closed. Must
         *  obviously be greater than PING_FREQUENCY + PING_SLACK.
         */
        NoTrafficTimeout = 540
    };

    void clone(const NoNetwork& Network, bool bCloneName = true);

    NoString networkPath() const;

    void delServers();

    bool parseConfig(NoSettings* pConfig, NoString& sError, bool bUpgrade = false);
    NoSettings toConfig() const;

    bool isUserAttached() const;
    bool isUserOnline() const;
    void clientConnected(NoClient* pClient);
    void clientDisconnected(NoClient* pClient);

    NoUser* user() const;
    NoString name() const;
    bool isNetworkAttached() const;
    std::vector<NoClient*> clients() const;
    std::vector<NoClient*> findClients(const NoString& sIdentifier) const;

    void setUser(NoUser* pUser);
    bool setName(const NoString& sName);

    NoModuleLoader* loader() const;

    bool putUser(const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);
    bool putStatus(const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);
    bool putModule(const NoString& sModule, const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);

    std::vector<NoChannel*> channels() const;
    NoChannel* findChannel(NoString sName) const;
    std::vector<NoChannel*> findChannels(const NoString& sWild) const;
    bool addChannel(NoChannel* pChan);
    bool addChannel(const NoString& sName, bool bInConfig);
    bool removeChannel(const NoString& sName);
    void joinChannels();

    std::vector<NoQuery*> queries() const;
    NoQuery* findQuery(const NoString& sName) const;
    std::vector<NoQuery*> findQueries(const NoString& sWild) const;
    NoQuery* addQuery(const NoString& sName);
    bool removeQuery(const NoString& sName);

    NoString channelPrefixes() const;
    void setChannelPrefixes(const NoString& s);
    bool isChannel(const NoString& sChan) const;

    std::vector<NoServerInfo*> servers() const;
    bool hasServers() const;
    NoServerInfo* findServer(const NoString& sName) const;
    bool removeServer(const NoString& sName, ushort uPort, const NoString& sPass);
    bool addServer(const NoString& sName);
    bool addServer(const NoString& sName, ushort uPort, const NoString& sPass = "", bool bSSL = false);
    NoServerInfo* nextServer();
    NoServerInfo* currentServer() const;
    void setIrcServer(const NoString& s);
    bool setNextServer(const NoServerInfo* pServer);
    bool isLastServer() const;

    NoStringSet trustedFingerprints() const;
    void addTrustedFingerprint(const NoString& sFP);
    void removeTrustedFingerprint(const NoString& sFP);

    void setEnabled(bool b);
    bool isEnabled() const;

    NoIrcSocket* ircSocket() const;
    NoString ircServer() const;
    const NoNick& ircNick() const;
    void setIrcNick(const NoNick& n);
    NoString currentNick() const;
    bool isIrcAway() const;
    void setIrcAway(bool b);

    bool connect();
    bool isIrcConnected() const;
    void setIrcSocket(NoIrcSocket* pIRCSock);
    void ircConnected();
    void ircDisconnected();
    void checkIrcConnect();

    bool putIrc(const NoString& sLine);

    void addRawBuffer(const NoString& sFormat, const NoString& sText = "");
    void updateRawBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText = "");
    void updateExactRawBuffer(const NoString& sFormat, const NoString& sText = "");
    void clearRawBuffer();

    void addMotdBuffer(const NoString& sFormat, const NoString& sText = "");
    void updateMotdBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText = "");
    void clearMotdBuffer();

    void addNoticeBuffer(const NoString& sFormat, const NoString& sText = "");
    void updateNoticeBuffer(const NoString& sMatch, const NoString& sFormat, const NoString& sText = "");
    void clearNoticeBuffer();

    void clearQueryBuffer();

    NoString nick(const bool bAllowDefault = true) const;
    NoString altNick(const bool bAllowDefault = true) const;
    NoString ident(const bool bAllowDefault = true) const;
    NoString realName() const;
    NoString bindHost() const;
    NoString encoding() const;
    NoString quitMsg() const;

    void setNick(const NoString& s);
    void setAltNick(const NoString& s);
    void setIdent(const NoString& s);
    void setRealName(const NoString& s);
    void setBindHost(const NoString& s);
    void setEncoding(const NoString& s);
    void setQuitMsg(const NoString& s);

    double floodRate() const;
    ushort floodBurst() const;
    void setFloodRate(double fFloodRate);
    void setFloodBurst(ushort uFloodBurst);

    ushort joinDelay() const;
    void setJoinDelay(ushort uJoinDelay);

    NoString expandString(const NoString& sStr) const;
    NoString& expandString(const NoString& sStr, NoString& sRet) const;

private:
    void bounceAllClients();
    bool joinChan(NoChannel* pChan);
    void joinChannels(std::set<NoChannel*>& sChans);
    bool loadModule(const NoString& sModName, const NoString& sArgs, const NoString& sNotice, NoString& sError);

    NoNetwork(const NoNetwork&) = delete;
    NoNetwork& operator=(const NoNetwork&) = delete;

    std::unique_ptr<NoNetworkPrivate> d;
};

#endif // NONETWORK_H
