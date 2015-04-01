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

    NoChannel(const NoString& name, NoNetwork* network, bool bInConfig, NoSettings* settings = nullptr);
    ~NoChannel();

    void reset();
    NoSettings toConfig() const;
    void clone(NoChannel& chan);
    void cycle() const;
    void joinUser(const NoString& key = "");
    void attachUser(NoClient* client = nullptr);
    void detachUser();

    void onWho(const NoString& nick, const NoString& ident, const NoString& host);

    void setModes(const NoString& s);
    void modeChange(const NoString& modes, const NoNick* opNick = nullptr);
    bool addMode(uchar mode, const NoString& arg);
    bool remMode(uchar mode);
    NoString modeString() const;
    NoString modeArg(NoString& args) const;
    NoString modeForNames() const;

    void clearNicks();
    const NoNick* findNick(const NoString& nick) const;
    NoNick* findNick(const NoString& nick);
    int addNicks(const NoString& sNicks);
    bool addNick(const NoString& nick);
    bool remNick(const NoString& nick);
    bool changeNick(const NoString& sOldNick, const NoString& newNick);

    const NoBuffer& buffer() const;
    uint bufferCount() const;
    bool setBufferCount(uint u, bool force = false);
    void inheritBufferCount(uint u, bool force = false);
    size_t addBuffer(const NoString& format, const NoString& text = "", const timeval* ts = nullptr);
    void clearBuffer();
    void sendBuffer(NoClient* client);
    void sendBuffer(NoClient* client, const NoBuffer& Buffer);

    NoString permStr() const;
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
    bool hasMode(uchar mode) const;
    NoString options() const;
    NoString modeArg(uchar mode) const;
    std::map<char, uint> permCounts() const;
    bool isOn() const;
    NoString name() const;
    std::map<uchar, NoString> modes() const;
    NoString key() const;
    NoString topic() const;
    NoString topicOwner() const;
    ulong topicDate() const;
    NoString defaultModes() const;
    std::map<NoString, NoNick> nicks() const;
    size_t nickCount() const;
    bool autoClearChanBuffer() const;
    bool isDetached() const;
    bool inConfig() const;
    ulong creationDate() const;
    bool isDisabled() const;
    uint joinTries() const;
    bool hasBufferCountSet() const;
    bool hasAutoClearChanBufferSet() const;

private:
    NoChannel(const NoChannel&) = delete;
    NoChannel& operator=(const NoChannel&) = delete;

    std::unique_ptr<NoChannelPrivate> d;
};

#endif // NOCHANNEL_H
