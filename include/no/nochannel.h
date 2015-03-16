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

#ifndef NOCHANNEL_H
#define NOCHANNEL_H

#include <no/noconfig.h>
#include <no/nonick.h>
#include <no/nostring.h>
#include <no/nobuffer.h>
#include <map>

class NoUser;
class NoNetwork;
class NoClient;
class NoSettings;
class NoFile;

class NoChannel
{
public:
    typedef enum { Voice = '+', HalfOp = '%', Op = '@', Admin = '!', Owner = '*' } EUserPerms;

    typedef enum {
        M_Private = 'p',
        M_Secret = 's',
        M_Moderated = 'm',
        M_InviteOnly = 'i',
        M_NoMessages = 'n',
        M_OpTopic = 't',
        M_Limit = 'l',
        M_Key = 'k',
        M_Op = 'o',
        M_Voice = 'v',
        M_Ban = 'b',
        M_Except = 'e'
    } EModes;

    NoChannel(const NoString& sName, NoNetwork* pNetwork, bool bInConfig, NoSettings* pConfig = nullptr);
    ~NoChannel();

    NoChannel(const NoChannel&) = delete;
    NoChannel& operator=(const NoChannel&) = delete;

    void Reset();
    NoSettings ToConfig() const;
    void Clone(NoChannel& chan);
    void Cycle() const;
    void JoinUser(const NoString& sKey = "");
    void AttachUser(NoClient* pClient = nullptr);
    void DetachUser();

    void OnWho(const NoString& sNick, const NoString& sIdent, const NoString& sHost);

    void SetModes(const NoString& s);
    void ModeChange(const NoString& sModes, const NoNick* OpNick = nullptr);
    bool AddMode(unsigned char uMode, const NoString& sArg);
    bool RemMode(unsigned char uMode);
    NoString GetModeString() const;
    NoString GetModeArg(NoString& sArgs) const;
    NoString GetModeForNames() const;

    void ClearNicks();
    const NoNick* FindNick(const NoString& sNick) const;
    NoNick* FindNick(const NoString& sNick);
    int AddNicks(const NoString& sNicks);
    bool AddNick(const NoString& sNick);
    bool RemNick(const NoString& sNick);
    bool ChangeNick(const NoString& sOldNick, const NoString& sNewNick);

    const NoBuffer& GetBuffer() const { return m_Buffer; }
    unsigned int GetBufferCount() const { return m_Buffer.getLimit(); }
    bool SetBufferCount(unsigned int u, bool bForce = false)
    {
        m_bHasBufferCountSet = true;
        return m_Buffer.setLimit(u, bForce);
    }
    void InheritBufferCount(unsigned int u, bool bForce = false)
    {
        if (!m_bHasBufferCountSet) m_Buffer.setLimit(u, bForce);
    }
    size_t AddBuffer(const NoString& sFormat, const NoString& sText = "", const timeval* ts = nullptr)
    {
        return m_Buffer.addLine(sFormat, sText, ts);
    }
    void ClearBuffer() { m_Buffer.clear(); }
    void SendBuffer(NoClient* pClient);
    void SendBuffer(NoClient* pClient, const NoBuffer& Buffer);

    NoString GetPermStr() const { return m_Nick.GetPermStr(); }
    bool HasPerm(unsigned char uPerm) const { return m_Nick.HasPerm(uPerm); }
    bool AddPerm(unsigned char uPerm) { return m_Nick.AddPerm(uPerm); }
    bool RemPerm(unsigned char uPerm) { return m_Nick.RemPerm(uPerm); }

    void SetModeKnown(bool b) { m_bModeKnown = b; }
    void SetIsOn(bool b)
    {
        m_bIsOn = b;
        if (!b) {
            Reset();
        }
    }
    void SetKey(const NoString& s);
    void SetTopic(const NoString& s) { m_sTopic = s; }
    void SetTopicOwner(const NoString& s) { m_sTopicOwner = s; }
    void SetTopicDate(unsigned long u) { m_ulTopicDate = u; }
    void SetDefaultModes(const NoString& s) { m_sDefaultModes = s; }
    void SetAutoClearChanBuffer(bool b);
    void InheritAutoClearChanBuffer(bool b);
    void SetDetached(bool b = true) { m_bDetached = b; }
    void SetInConfig(bool b);
    void SetCreationDate(unsigned long u) { m_ulCreationDate = u; }
    void Disable() { m_bDisabled = true; }
    void Enable();
    void IncJoinTries() { m_uJoinTries++; }
    void ResetJoinTries() { m_uJoinTries = 0; }

    bool IsModeKnown() const { return m_bModeKnown; }
    bool HasMode(unsigned char uMode) const;
    NoString GetOptions() const;
    NoString GetModeArg(unsigned char uMode) const;
    std::map<char, unsigned int> GetPermCounts() const;
    bool IsOn() const { return m_bIsOn; }
    const NoString& GetName() const { return m_sName; }
    const std::map<unsigned char, NoString>& GetModes() const { return m_musModes; }
    const NoString& GetKey() const { return m_sKey; }
    const NoString& GetTopic() const { return m_sTopic; }
    const NoString& GetTopicOwner() const { return m_sTopicOwner; }
    unsigned long GetTopicDate() const { return m_ulTopicDate; }
    const NoString& GetDefaultModes() const { return m_sDefaultModes; }
    const std::map<NoString, NoNick>& GetNicks() const { return m_msNicks; }
    size_t GetNickCount() const { return m_msNicks.size(); }
    bool AutoClearChanBuffer() const { return m_bAutoClearChanBuffer; }
    bool IsDetached() const { return m_bDetached; }
    bool InConfig() const { return m_bInConfig; }
    unsigned long GetCreationDate() const { return m_ulCreationDate; }
    bool IsDisabled() const { return m_bDisabled; }
    unsigned int GetJoinTries() const { return m_uJoinTries; }
    bool HasBufferCountSet() const { return m_bHasBufferCountSet; }
    bool HasAutoClearChanBufferSet() const { return m_bHasAutoClearChanBufferSet; }

private:
    bool m_bDetached;
    bool m_bIsOn;
    bool m_bAutoClearChanBuffer;
    bool m_bInConfig;
    bool m_bDisabled;
    bool m_bHasBufferCountSet;
    bool m_bHasAutoClearChanBufferSet;
    NoString m_sName;
    NoString m_sKey;
    NoString m_sTopic;
    NoString m_sTopicOwner;
    unsigned long m_ulTopicDate;
    unsigned long m_ulCreationDate;
    NoNetwork* m_pNetwork;
    NoNick m_Nick;
    unsigned int m_uJoinTries;
    NoString m_sDefaultModes;
    std::map<NoString, NoNick> m_msNicks; // Todo: make this caseless (irc style)
    NoBuffer m_Buffer;

    bool m_bModeKnown;
    std::map<unsigned char, NoString> m_musModes;
};

#endif // NOCHANNEL_H
