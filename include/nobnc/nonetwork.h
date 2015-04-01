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

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
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

    NoNetwork(NoUser* user, const NoString& name);
    NoNetwork(NoUser* user, const NoNetwork& network);
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

    void clone(const NoNetwork& network, bool cloneName = true);

    NoString networkPath() const;

    void delServers();

    bool parseConfig(NoSettings* settings, NoString& error, bool bUpgrade = false);
    NoSettings toConfig() const;

    bool isUserAttached() const;
    bool isUserOnline() const;
    void clientConnected(NoClient* client);
    void clientDisconnected(NoClient* client);

    NoUser* user() const;
    NoString name() const;
    bool isNetworkAttached() const;
    std::vector<NoClient*> clients() const;
    std::vector<NoClient*> findClients(const NoString& identifier) const;

    void setUser(NoUser* user);
    bool setName(const NoString& name);

    NoModuleLoader* loader() const;

    bool putUser(const NoString& line, NoClient* client = nullptr, NoClient* skipClient = nullptr);
    bool putStatus(const NoString& line, NoClient* client = nullptr, NoClient* skipClient = nullptr);
    bool putModule(const NoString& module, const NoString& line, NoClient* client = nullptr, NoClient* skipClient = nullptr);

    std::vector<NoChannel*> channels() const;
    NoChannel* findChannel(NoString name) const;
    std::vector<NoChannel*> findChannels(const NoString& wild) const;
    bool addChannel(NoChannel* channel);
    bool addChannel(const NoString& name, bool bInConfig);
    bool removeChannel(const NoString& name);
    void joinChannels();

    std::vector<NoQuery*> queries() const;
    NoQuery* findQuery(const NoString& name) const;
    std::vector<NoQuery*> findQueries(const NoString& wild) const;
    NoQuery* addQuery(const NoString& name);
    bool removeQuery(const NoString& name);

    NoString channelPrefixes() const;
    void setChannelPrefixes(const NoString& s);
    bool isChannel(const NoString& sChan) const;

    std::vector<NoServerInfo*> servers() const;
    bool hasServers() const;
    NoServerInfo* findServer(const NoString& name) const;
    bool removeServer(const NoString& name, ushort port, const NoString& pass);
    bool addServer(const NoString& name);
    bool addServer(const NoString& name, ushort port, const NoString& pass = "", bool ssl = false);
    NoServerInfo* nextServer();
    NoServerInfo* currentServer() const;
    void setIrcServer(const NoString& s);
    bool setNextServer(const NoServerInfo* server);
    bool isLastServer() const;

    NoStringSet trustedFingerprints() const;
    void addTrustedFingerprint(const NoString& fingerprint);
    void removeTrustedFingerprint(const NoString& fingerprint);

    void setEnabled(bool b);
    bool isEnabled() const;

    NoIrcSocket* ircSocket() const;
    NoString ircServer() const;
    NoNick ircNick() const;
    void setIrcNick(const NoNick& n);
    NoString currentNick() const;
    bool isIrcAway() const;
    void setIrcAway(bool b);

    bool connect();
    bool isIrcConnected() const;
    void setIrcSocket(NoIrcSocket* socket);
    void ircConnected();
    void ircDisconnected();
    void checkIrcConnect();

    bool putIrc(const NoString& line);

    void addRawBuffer(const NoString& format, const NoString& text = "");
    void updateRawBuffer(const NoString& match, const NoString& format, const NoString& text = "");
    void updateExactRawBuffer(const NoString& format, const NoString& text = "");
    void clearRawBuffer();

    void addMotdBuffer(const NoString& format, const NoString& text = "");
    void updateMotdBuffer(const NoString& match, const NoString& format, const NoString& text = "");
    void clearMotdBuffer();

    void addNoticeBuffer(const NoString& format, const NoString& text = "");
    void updateNoticeBuffer(const NoString& match, const NoString& format, const NoString& text = "");
    void clearNoticeBuffer();

    void clearQueryBuffer();

    NoString nick(const bool allowDefault = true) const;
    NoString altNick(const bool allowDefault = true) const;
    NoString ident(const bool allowDefault = true) const;
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

    NoString expandString(const NoString& str) const;
    NoString& expandString(const NoString& str, NoString& ret) const;

private:
    void bounceAllClients();
    bool joinChan(NoChannel* channel);
    void joinChannels(std::set<NoChannel*>& sChans);
    bool loadModule(const NoString& name, const NoString& args, const NoString& notice, NoString& error);

    NoNetwork(const NoNetwork&) = delete;
    NoNetwork& operator=(const NoNetwork&) = delete;

    std::unique_ptr<NoNetworkPrivate> d;
};

#endif // NONETWORK_H
