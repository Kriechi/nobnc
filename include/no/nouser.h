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

#ifndef NOUSER_H
#define NOUSER_H

#include <no/noglobal.h>
#include <no/noutils.h>
#include <no/nobuffer.h>
#include <no/nonick.h>
#include <set>
#include <vector>

class NoModules;
class NoChannel;
class NoClient;
class NoSettings;
class NoFile;
class NoNetwork;
class NoIrcConnection;
class NoUserTimer;
class NoServer;

class NO_EXPORT NoUser
{
public:
    NoUser(const NoString& sUserName);
    ~NoUser();

    NoUser(const NoUser&) = delete;
    NoUser& operator=(const NoUser&) = delete;

    bool ParseConfig(NoSettings* Config, NoString& sError);

    // TODO refactor this
    enum eHashType {
        HASH_NONE,
        HASH_MD5,
        HASH_SHA256,

        HASH_DEFAULT = HASH_SHA256
    };

    // If you change the default hash here and in HASH_DEFAULT,
    // don't forget NoUtils::sDefaultHash!
    // TODO refactor this
    static NoString SaltedHash(const NoString& sPass, const NoString& sSalt)
    {
        return NoUtils::SaltedSHA256Hash(sPass, sSalt);
    }

    NoSettings ToConfig() const;
    bool CheckPass(const NoString& sPass) const;
    bool AddAllowedHost(const NoString& sHostMask);
    bool IsHostAllowed(const NoString& sHostMask) const;
    bool IsValid(NoString& sErrMsg, bool bSkipPass = false) const;
    static bool IsValidUserName(const NoString& sUserName);
    static NoString MakeCleanUserName(const NoString& sUserName);

    NoModules& GetModules() { return *m_pModules; }
    const NoModules& GetModules() const { return *m_pModules; }

    NoNetwork* AddNetwork(const NoString& sNetwork, NoString& sErrorRet);
    bool DeleteNetwork(const NoString& sNetwork);
    bool AddNetwork(NoNetwork* pNetwork);
    void RemoveNetwork(NoNetwork* pNetwork);
    NoNetwork* FindNetwork(const NoString& sNetwork) const;
    const std::vector<NoNetwork*>& GetNetworks() const;
    bool HasSpaceForNewNetwork() const;

    bool PutUser(const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);
    bool PutAllUser(const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);
    bool PutStatus(const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);
    bool PutStatusNotice(const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);
    bool PutModule(const NoString& sModule, const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);
    bool PutModNotice(const NoString& sModule, const NoString& sLine, NoClient* pClient = nullptr, NoClient* pSkipClient = nullptr);

    bool IsUserAttached() const;
    void UserConnected(NoClient* pClient);
    void UserDisconnected(NoClient* pClient);

    NoString GetLocalDCCIP() const;

    NoString ExpandString(const NoString& sStr) const;
    NoString& ExpandString(const NoString& sStr, NoString& sRet) const;

    NoString AddTimestamp(const NoString& sStr) const;
    NoString AddTimestamp(time_t tm, const NoString& sStr) const;

    void CloneNetworks(const NoUser& User);
    bool Clone(const NoUser& User, NoString& sErrorRet, bool bCloneNetworks = true);

    void AddBytesRead(ulonglong u) { m_uBytesRead += u; }
    void AddBytesWritten(ulonglong u) { m_uBytesWritten += u; }

    void SetNick(const NoString& s);
    void SetAltNick(const NoString& s);
    void SetIdent(const NoString& s);
    void SetRealName(const NoString& s);
    void SetBindHost(const NoString& s);
    void SetDCCBindHost(const NoString& s);
    void SetPass(const NoString& s, eHashType eHash, const NoString& sSalt = "");
    void SetMultiClients(bool b);
    void SetDenyLoadMod(bool b);
    void SetAdmin(bool b);
    void SetDenySetBindHost(bool b);
    bool SetStatusPrefix(const NoString& s);
    void SetDefaultChanModes(const NoString& s);
    void SetClientEncoding(const NoString& s);
    void SetQuitMsg(const NoString& s);
    bool AddCTCPReply(const NoString& sCTCP, const NoString& sReply);
    bool DelCTCPReply(const NoString& sCTCP);
    bool SetBufferCount(uint u, bool bForce = false);
    void SetAutoClearChanBuffer(bool b);
    void SetAutoClearQueryBuffer(bool b);

    void SetBeingDeleted(bool b) { m_bBeingDeleted = b; }
    void SetTimestampFormat(const NoString& s) { m_sTimestampFormat = s; }
    void SetTimestampAppend(bool b) { m_bAppendTimestamp = b; }
    void SetTimestampPrepend(bool b) { m_bPrependTimestamp = b; }
    void SetTimezone(const NoString& s) { m_sTimezone = s; }
    void SetJoinTries(uint i) { m_uMaxJoinTries = i; }
    void SetMaxJoins(uint i) { m_uMaxJoins = i; }
    void SetSkinName(const NoString& s) { m_sSkinName = s; }
    void SetMaxNetworks(uint i) { m_uMaxNetworks = i; }
    void SetMaxQueryBuffers(uint i) { m_uMaxQueryBuffers = i; }

    const std::vector<NoClient*>& GetUserClients() const { return m_vClients; }
    std::vector<NoClient*> GetAllClients() const;
    const NoString& GetUserName() const;
    const NoString& GetCleanUserName() const;
    const NoString& GetNick(bool bAllowDefault = true) const;
    const NoString& GetAltNick(bool bAllowDefault = true) const;
    const NoString& GetIdent(bool bAllowDefault = true) const;
    const NoString& GetRealName() const;
    const NoString& GetBindHost() const;
    const NoString& GetDCCBindHost() const;
    const NoString& GetPass() const;
    eHashType GetPassHashType() const;
    const NoString& GetPassSalt() const;
    const std::set<NoString>& GetAllowedHosts() const;
    const NoString& GetTimestampFormat() const;
    const NoString& GetClientEncoding() const;
    bool GetTimestampAppend() const;
    bool GetTimestampPrepend() const;

    const NoString& GetUserPath() const;

    bool DenyLoadMod() const;
    bool IsAdmin() const;
    bool DenySetBindHost() const;
    bool MultiClients() const;
    const NoString& GetStatusPrefix() const;
    const NoString& GetDefaultChanModes() const;

    NoString GetQuitMsg() const;
    const NoStringMap& GetCTCPReplies() const;
    uint GetBufferCount() const;
    bool AutoClearChanBuffer() const;
    bool AutoClearQueryBuffer() const;
    bool IsBeingDeleted() const { return m_bBeingDeleted; }
    NoString GetTimezone() const { return m_sTimezone; }
    ulonglong BytesRead() const { return m_uBytesRead; }
    ulonglong BytesWritten() const { return m_uBytesWritten; }
    uint JoinTries() const { return m_uMaxJoinTries; }
    uint MaxJoins() const { return m_uMaxJoins; }
    NoString GetSkinName() const;
    uint MaxNetworks() const { return m_uMaxNetworks; }
    uint MaxQueryBuffers() const { return m_uMaxQueryBuffers; }

private:
    void BounceAllClients();

    const NoString m_sUserName;
    const NoString m_sCleanUserName;
    NoString m_sNick;
    NoString m_sAltNick;
    NoString m_sIdent;
    NoString m_sRealName;
    NoString m_sBindHost;
    NoString m_sDCCBindHost;
    NoString m_sPass;
    NoString m_sPassSalt;
    NoString m_sStatusPrefix;
    NoString m_sDefaultChanModes;
    NoString m_sClientEncoding;

    NoString m_sQuitMsg;
    NoStringMap m_mssCTCPReplies;
    NoString m_sTimestampFormat;
    NoString m_sTimezone;
    eHashType m_eHashType;

    NoString m_sUserPath;

    bool m_bMultiClients;
    bool m_bDenyLoadMod;
    bool m_bAdmin;
    bool m_bDenySetBindHost;
    bool m_bAutoClearChanBuffer;
    bool m_bAutoClearQueryBuffer;
    bool m_bBeingDeleted;
    bool m_bAppendTimestamp;
    bool m_bPrependTimestamp;

    NoUserTimer* m_pUserTimer;

    std::vector<NoNetwork*> m_vIRNoNetworks;
    std::vector<NoClient*> m_vClients;
    std::set<NoString> m_ssAllowedHosts;
    uint m_uBufferCount;
    ulonglong m_uBytesRead;
    ulonglong m_uBytesWritten;
    uint m_uMaxJoinTries;
    uint m_uMaxNetworks;
    uint m_uMaxQueryBuffers;
    uint m_uMaxJoins;
    NoString m_sSkinName;

    NoModules* m_pModules;

private:
    void SetKeepBuffer(bool b) { SetAutoClearChanBuffer(!b); } // XXX compatibility crap, added in 0.207
    bool LoadModule(const NoString& sModName, const NoString& sArgs, const NoString& sNotice, NoString& sError);
};

#endif // NOUSER_H
