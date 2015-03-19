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

class NoModules;
class NoClient;
class NoSettings;
class NoNetwork;
class NoUserTimer;

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

    NoModules& GetModules();
    const NoModules& GetModules() const;

    NoNetwork* AddNetwork(const NoString& sNetwork, NoString& sErrorRet);
    bool DeleteNetwork(const NoString& sNetwork);
    bool AddNetwork(NoNetwork* pNetwork);
    void RemoveNetwork(NoNetwork* pNetwork);
    NoNetwork* FindNetwork(const NoString& sNetwork) const;
    std::vector<NoNetwork*> GetNetworks() const;
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

    void AddBytesRead(ulonglong u);
    void AddBytesWritten(ulonglong u);

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

    void SetBeingDeleted(bool b);
    void SetTimestampFormat(const NoString& s);
    void SetTimestampAppend(bool b);
    void SetTimestampPrepend(bool b);
    void SetTimezone(const NoString& s);
    void SetJoinTries(uint i);
    void SetMaxJoins(uint i);
    void SetSkinName(const NoString& s);
    void SetMaxNetworks(uint i);
    void SetMaxQueryBuffers(uint i);

    std::vector<NoClient*> GetUserClients() const;
    std::vector<NoClient*> GetAllClients() const;
    NoString GetUserName() const;
    NoString GetCleanUserName() const;
    NoString GetNick(bool bAllowDefault = true) const;
    NoString GetAltNick(bool bAllowDefault = true) const;
    NoString GetIdent(bool bAllowDefault = true) const;
    NoString GetRealName() const;
    NoString GetBindHost() const;
    NoString GetDCCBindHost() const;
    NoString GetPass() const;
    eHashType GetPassHashType() const;
    NoString GetPassSalt() const;
    std::set<NoString> GetAllowedHosts() const;
    NoString GetTimestampFormat() const;
    NoString GetClientEncoding() const;
    bool GetTimestampAppend() const;
    bool GetTimestampPrepend() const;

    NoString GetUserPath() const;

    bool DenyLoadMod() const;
    bool IsAdmin() const;
    bool DenySetBindHost() const;
    bool MultiClients() const;
    NoString GetStatusPrefix() const;
    NoString GetDefaultChanModes() const;

    NoString GetQuitMsg() const;
    NoStringMap GetCTCPReplies() const;
    uint GetBufferCount() const;
    bool AutoClearChanBuffer() const;
    bool AutoClearQueryBuffer() const;
    bool IsBeingDeleted() const;
    NoString GetTimezone() const;
    ulonglong BytesRead() const;
    ulonglong BytesWritten() const;
    uint JoinTries() const;
    uint MaxJoins() const;
    NoString GetSkinName() const;
    uint MaxNetworks() const;
    uint MaxQueryBuffers() const;

private:
    void BounceAllClients();
    void SetKeepBuffer(bool b); // XXX compatibility crap, added in 0.207
    bool LoadModule(const NoString& sModName, const NoString& sArgs, const NoString& sNotice, NoString& sError);

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

    std::vector<NoNetwork*> m_vIRCNetworks;
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
};

#endif // NOUSER_H
