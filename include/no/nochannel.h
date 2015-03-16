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

    const NoBuffer& GetBuffer() const { return m_buffer; }
    unsigned int GetBufferCount() const { return m_buffer.getLimit(); }
    bool SetBufferCount(unsigned int u, bool bForce = false)
    {
        m_hasBufferCountSet = true;
        return m_buffer.setLimit(u, bForce);
    }
    void InheritBufferCount(unsigned int u, bool bForce = false)
    {
        if (!m_hasBufferCountSet) m_buffer.setLimit(u, bForce);
    }
    size_t AddBuffer(const NoString& sFormat, const NoString& sText = "", const timeval* ts = nullptr)
    {
        return m_buffer.addLine(sFormat, sText, ts);
    }
    void ClearBuffer() { m_buffer.clear(); }
    void SendBuffer(NoClient* pClient);
    void SendBuffer(NoClient* pClient, const NoBuffer& Buffer);

    NoString GetPermStr() const { return m_nick.GetPermStr(); }
    bool HasPerm(unsigned char uPerm) const { return m_nick.HasPerm(uPerm); }
    bool AddPerm(unsigned char uPerm) { return m_nick.AddPerm(uPerm); }
    bool RemPerm(unsigned char uPerm) { return m_nick.RemPerm(uPerm); }

    void SetModeKnown(bool b) { m_modeKnown = b; }
    void SetIsOn(bool b)
    {
        m_isOn = b;
        if (!b) {
            Reset();
        }
    }
    void SetKey(const NoString& s);
    void SetTopic(const NoString& s) { m_topic = s; }
    void SetTopicOwner(const NoString& s) { m_topicOwner = s; }
    void SetTopicDate(unsigned long u) { m_topicDate = u; }
    void SetDefaultModes(const NoString& s) { m_defaultModes = s; }
    void SetAutoClearChanBuffer(bool b);
    void InheritAutoClearChanBuffer(bool b);
    void SetDetached(bool b = true) { m_detached = b; }
    void SetInConfig(bool b);
    void SetCreationDate(unsigned long u) { m_creationDate = u; }
    void Disable() { m_disabled = true; }
    void Enable();
    void IncJoinTries() { m_joinTries++; }
    void ResetJoinTries() { m_joinTries = 0; }

    bool IsModeKnown() const { return m_modeKnown; }
    bool HasMode(unsigned char uMode) const;
    NoString GetOptions() const;
    NoString GetModeArg(unsigned char uMode) const;
    std::map<char, unsigned int> GetPermCounts() const;
    bool IsOn() const { return m_isOn; }
    const NoString& GetName() const { return m_name; }
    const std::map<unsigned char, NoString>& GetModes() const { return m_modes; }
    const NoString& GetKey() const { return m_key; }
    const NoString& GetTopic() const { return m_topic; }
    const NoString& GetTopicOwner() const { return m_topicOwner; }
    unsigned long GetTopicDate() const { return m_topicDate; }
    const NoString& GetDefaultModes() const { return m_defaultModes; }
    const std::map<NoString, NoNick>& GetNicks() const { return m_nicks; }
    size_t GetNickCount() const { return m_nicks.size(); }
    bool AutoClearChanBuffer() const { return m_autoClearChanBuffer; }
    bool IsDetached() const { return m_detached; }
    bool InConfig() const { return m_inConfig; }
    unsigned long GetCreationDate() const { return m_creationDate; }
    bool IsDisabled() const { return m_disabled; }
    unsigned int GetJoinTries() const { return m_joinTries; }
    bool HasBufferCountSet() const { return m_hasBufferCountSet; }
    bool HasAutoClearChanBufferSet() const { return m_hasAutoClearChanBufferSet; }

private:
    bool m_detached;
    bool m_isOn;
    bool m_autoClearChanBuffer;
    bool m_inConfig;
    bool m_disabled;
    bool m_hasBufferCountSet;
    bool m_hasAutoClearChanBufferSet;
    NoString m_name;
    NoString m_key;
    NoString m_topic;
    NoString m_topicOwner;
    unsigned long m_topicDate;
    unsigned long m_creationDate;
    NoNetwork* m_network;
    NoNick m_nick;
    unsigned int m_joinTries;
    NoString m_defaultModes;
    std::map<NoString, NoNick> m_nicks; // Todo: make this caseless (irc style)
    NoBuffer m_buffer;

    bool m_modeKnown;
    std::map<unsigned char, NoString> m_modes;
};

#endif // NOCHANNEL_H
