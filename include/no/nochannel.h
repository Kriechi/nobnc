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
#include <no/nostring.h>
#include <memory>

class NoNick;
class NoBuffer;
class NoClient;
class NoNetwork;
class NoSettings;
class NoChannelPrivate;

class NO_EXPORT NoChannel
{
public:
    enum UserPerms { Voice = '+', HalfOp = '%', Op = '@', Admin = '!', Owner = '*' };

    enum Modes {
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
    };

    NoChannel(const NoString& sName, NoNetwork* pNetwork, bool bInConfig, NoSettings* pConfig = nullptr);
    ~NoChannel();

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

    const NoBuffer& getBuffer() const;
    uint getBufferCount() const;
    bool setBufferCount(uint u, bool bForce = false);
    void inheritBufferCount(uint u, bool bForce = false);
    size_t addBuffer(const NoString& sFormat, const NoString& sText = "", const timeval* ts = nullptr);
    void clearBuffer();
    void sendBuffer(NoClient* pClient);
    void sendBuffer(NoClient* pClient, const NoBuffer& Buffer);

    NoString getPermStr() const;
    bool hasPerm(uchar uPerm) const;
    void addPerm(uchar uPerm);
    void remPerm(uchar uPerm);

    void setModeKnown(bool b);
    void setIsOn(bool b);
    void setKey(const NoString& s);
    void setTopic(const NoString& s);
    void setTopicOwner(const NoString& s);
    void setTopicDate(ulong u);
    void setDefaultModes(const NoString& s);
    void setAutoClearChanBuffer(bool b);
    void inheritAutoClearChanBuffer(bool b);
    void setDetached(bool b = true);
    void setInConfig(bool b);
    void setCreationDate(ulong u);
    void disable();
    void enable();
    void incJoinTries();
    void resetJoinTries();

    bool isModeKnown() const;
    bool hasMode(uchar uMode) const;
    NoString getOptions() const;
    NoString getModeArg(uchar uMode) const;
    std::map<char, uint> getPermCounts() const;
    bool isOn() const;
    NoString getName() const;
    std::map<uchar, NoString> getModes() const;
    NoString getKey() const;
    NoString getTopic() const;
    NoString getTopicOwner() const;
    ulong getTopicDate() const;
    NoString getDefaultModes() const;
    std::map<NoString, NoNick> getNicks() const;
    size_t getNickCount() const;
    bool autoClearChanBuffer() const;
    bool isDetached() const;
    bool inConfig() const;
    ulong getCreationDate() const;
    bool isDisabled() const;
    uint getJoinTries() const;
    bool hasBufferCountSet() const;
    bool hasAutoClearChanBufferSet() const;

private:
    NoChannel(const NoChannel&) = delete;
    NoChannel& operator=(const NoChannel&) = delete;

    std::unique_ptr<NoChannelPrivate> d;
};

#endif // NOCHANNEL_H
