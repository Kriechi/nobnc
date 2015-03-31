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

#ifndef NOUSER_H
#define NOUSER_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <no/noutils.h> // TODO: kill NoUser::SaltedHash()
#include <memory>

class NoClient;
class NoNetwork;
class NoModuleLoader;
class NoSettings;
class NoUserPrivate;

class NO_EXPORT NoUser
{
public:
    NoUser(const NoString& userName);
    ~NoUser();

    bool parseConfig(NoSettings* Config, NoString& error);

    // TODO refactor this
    enum HashType { HashNone, HashMd5, HashSha256, HashDefault = HashSha256 };

    // If you change the default hash here and in HASH_DEFAULT,
    // don't forget No::sDefaultHash!
    // TODO refactor this
    static NoString saltedHash(const NoString& pass, const NoString& salt)
    {
        return No::saltedSha256(pass, salt);
    }

    NoSettings toConfig() const;
    bool checkPass(const NoString& pass) const;
    bool addAllowedHost(const NoString& hostMask);
    bool isHostAllowed(const NoString& hostMask) const;
    bool isValid(NoString& sErrMsg, bool bSkipPass = false) const;
    static bool isValidUserName(const NoString& userName);
    static NoString makeCleanUserName(const NoString& userName);

    NoModuleLoader* loader() const;

    NoNetwork* addNetwork(const NoString& sNetwork, NoString& sErrorRet);
    bool deleteNetwork(const NoString& sNetwork);
    bool addNetwork(NoNetwork* network);
    void removeNetwork(NoNetwork* network);
    NoNetwork* findNetwork(const NoString& sNetwork) const;
    std::vector<NoNetwork*> networks() const;
    bool hasSpaceForNewNetwork() const;

    bool putUser(const NoString& line, NoClient* client = nullptr, NoClient* pSkipClient = nullptr);
    bool putAllUser(const NoString& line, NoClient* client = nullptr, NoClient* pSkipClient = nullptr);
    bool putStatus(const NoString& line, NoClient* client = nullptr, NoClient* pSkipClient = nullptr);
    bool putStatusNotice(const NoString& line, NoClient* client = nullptr, NoClient* pSkipClient = nullptr);
    bool putModule(const NoString& module, const NoString& line, NoClient* client = nullptr, NoClient* pSkipClient = nullptr);
    bool putModuleNotice(const NoString& module, const NoString& line, NoClient* client = nullptr, NoClient* pSkipClient = nullptr);

    bool isUserAttached() const;
    void userConnected(NoClient* client);
    void userDisconnected(NoClient* client);

    NoString localDccIp() const;

    NoString expandString(const NoString& str) const;
    NoString& expandString(const NoString& str, NoString& ret) const;

    NoString addTimestamp(const NoString& str) const;
    NoString addTimestamp(time_t tm, const NoString& str) const;

    void cloneNetworks(const NoUser& User);
    bool clone(const NoUser& User, NoString& sErrorRet, bool bCloneNetworks = true);

    void addBytesRead(ulonglong u);
    void addBytesWritten(ulonglong u);

    void setNick(const NoString& s);
    void setAltNick(const NoString& s);
    void setIdent(const NoString& s);
    void setRealName(const NoString& s);
    void setBindHost(const NoString& s);
    void setDccBindHost(const NoString& s);
    void setPassword(const NoString& s, HashType eHash, const NoString& salt = "");
    void setMultiClients(bool b);
    void setDenyLoadMod(bool b);
    void setAdmin(bool b);
    void setDenysetBindHost(bool b);
    bool setStatusPrefix(const NoString& s);
    void setDefaultChanModes(const NoString& s);
    void setClientEncoding(const NoString& s);
    void setQuitMsg(const NoString& s);
    bool addCtcpReply(const NoString& sCTCP, const NoString& sReply);
    bool removeCtcpReply(const NoString& sCTCP);
    bool setBufferCount(uint u, bool bForce = false);
    void setAutoClearChanBuffer(bool b);
    void setAutoclearQueryBuffer(bool b);

    void setBeingDeleted(bool b);
    void setTimestampFormat(const NoString& s);
    void setTimestampAppend(bool b);
    void setTimestampPrepend(bool b);
    void setTimezone(const NoString& s);
    void setJoinTries(uint i);
    void setMaxJoins(uint i);
    void setSkinName(const NoString& s);
    void setMaxNetworks(uint i);
    void setMaxQueryBuffers(uint i);

    std::vector<NoClient*> userClients() const;
    std::vector<NoClient*> allClients() const;
    NoString userName() const;
    NoString cleanUserName() const;
    NoString nick(bool allowDefault = true) const;
    NoString altNick(bool allowDefault = true) const;
    NoString ident(bool allowDefault = true) const;
    NoString realName() const;
    NoString bindHost() const;
    NoString dccBindHost() const;
    NoString password() const;
    HashType passwordHashType() const;
    NoString passwordSalt() const;
    std::set<NoString> allowedHosts() const;
    NoString timestampFormat() const;
    NoString clientEncoding() const;
    bool timestampAppend() const;
    bool timestampPrepend() const;

    NoString userPath() const;

    bool denyLoadMod() const;
    bool isAdmin() const;
    bool denysetBindHost() const;
    bool multiClients() const;
    NoString statusPrefix() const;
    NoString defaultChanModes() const;

    NoString quitMsg() const;
    NoStringMap ctcpReplies() const;
    uint bufferCount() const;
    bool autoClearChanBuffer() const;
    bool autoclearQueryBuffer() const;
    bool isBeingDeleted() const;
    NoString timezone() const;
    ulonglong bytesRead() const;
    ulonglong bytesWritten() const;
    uint joinTries() const;
    uint maxJoins() const;
    NoString skinName() const;
    uint maxNetworks() const;
    uint maxQueryBuffers() const;

private:
    void bounceAllClients();
    void setKeepBuffer(bool b); // XXX compatibility crap, added in 0.207
    bool loadModule(const NoString& sModName, const NoString& args, const NoString& notice, NoString& error);

    NoUser(const NoUser&) = delete;
    NoUser& operator=(const NoUser&) = delete;

    std::unique_ptr<NoUserPrivate> d;
};

#endif // NOUSER_H
