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

#include <no/noglobal.h>
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

    void reset();
    NoSettings toConfig() const;
    void clone(NoChannel& chan);
    void cycle() const;
    void joinUser(const NoString& sKey = "");
    void attachUser(NoClient* pClient = nullptr);
    void detachUser();

    void onWho(const NoString& sNick, const NoString& sIdent, const NoString& sHost);

    void setModes(const NoString& s);
    void modeChange(const NoString& sModes, const NoNick* OpNick = nullptr);
    bool addMode(uchar uMode, const NoString& sArg);
    bool remMode(uchar uMode);
    NoString getModeString() const;
    NoString getModeArg(NoString& sArgs) const;
    NoString getModeForNames() const;

    void clearNicks();
    const NoNick* findNick(const NoString& sNick) const;
    NoNick* findNick(const NoString& sNick);
    int addNicks(const NoString& sNicks);
    bool addNick(const NoString& sNick);
    bool remNick(const NoString& sNick);
    bool changeNick(const NoString& sOldNick, const NoString& sNewNick);

    const NoBuffer& getBuffer() const { return m_buffer; }
    uint getBufferCount() const { return m_buffer.getLimit(); }
    bool setBufferCount(uint u, bool bForce = false)
    {
        m_hasBufferCountSet = true;
        return m_buffer.setLimit(u, bForce);
    }
    void inheritBufferCount(uint u, bool bForce = false)
    {
        if (!m_hasBufferCountSet) m_buffer.setLimit(u, bForce);
    }
    size_t addBuffer(const NoString& sFormat, const NoString& sText = "", const timeval* ts = nullptr)
    {
        return m_buffer.addMessage(sFormat, sText, ts);
    }
    void clearBuffer() { m_buffer.clear(); }
    void sendBuffer(NoClient* pClient);
    void sendBuffer(NoClient* pClient, const NoBuffer& Buffer);

    NoString getPermStr() const { return m_nick.GetPermStr(); }
    bool hasPerm(uchar uPerm) const { return m_nick.HasPerm(uPerm); }
    bool addPerm(uchar uPerm) { return m_nick.AddPerm(uPerm); }
    bool remPerm(uchar uPerm) { return m_nick.RemPerm(uPerm); }

    void setModeKnown(bool b) { m_modeKnown = b; }
    void setIsOn(bool b)
    {
        m_isOn = b;
        if (!b) {
            reset();
        }
    }
    void setKey(const NoString& s);
    void setTopic(const NoString& s) { m_topic = s; }
    void setTopicOwner(const NoString& s) { m_topicOwner = s; }
    void setTopicDate(ulong u) { m_topicDate = u; }
    void setDefaultModes(const NoString& s) { m_defaultModes = s; }
    void setAutoClearChanBuffer(bool b);
    void inheritAutoClearChanBuffer(bool b);
    void setDetached(bool b = true) { m_detached = b; }
    void setInConfig(bool b);
    void setCreationDate(ulong u) { m_creationDate = u; }
    void disable() { m_disabled = true; }
    void enable();
    void incJoinTries() { m_joinTries++; }
    void resetJoinTries() { m_joinTries = 0; }

    bool isModeKnown() const { return m_modeKnown; }
    bool hasMode(uchar uMode) const;
    NoString getOptions() const;
    NoString getModeArg(uchar uMode) const;
    std::map<char, uint> getPermCounts() const;
    bool isOn() const { return m_isOn; }
    const NoString& getName() const { return m_name; }
    const std::map<uchar, NoString>& getModes() const { return m_modes; }
    const NoString& getKey() const { return m_key; }
    const NoString& getTopic() const { return m_topic; }
    const NoString& getTopicOwner() const { return m_topicOwner; }
    ulong getTopicDate() const { return m_topicDate; }
    const NoString& getDefaultModes() const { return m_defaultModes; }
    const std::map<NoString, NoNick>& getNicks() const { return m_nicks; }
    size_t getNickCount() const { return m_nicks.size(); }
    bool autoClearChanBuffer() const { return m_autoClearChanBuffer; }
    bool isDetached() const { return m_detached; }
    bool inConfig() const { return m_inConfig; }
    ulong getCreationDate() const { return m_creationDate; }
    bool isDisabled() const { return m_disabled; }
    uint getJoinTries() const { return m_joinTries; }
    bool hasBufferCountSet() const { return m_hasBufferCountSet; }
    bool hasAutoClearChanBufferSet() const { return m_hasAutoClearChanBufferSet; }

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
    ulong m_topicDate;
    ulong m_creationDate;
    NoNetwork* m_network;
    NoNick m_nick;
    uint m_joinTries;
    NoString m_defaultModes;
    std::map<NoString, NoNick> m_nicks; // Todo: make this caseless (irc style)
    NoBuffer m_buffer;

    bool m_modeKnown;
    std::map<uchar, NoString> m_modes;
};

#endif // NOCHANNEL_H
