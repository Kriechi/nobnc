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

#ifndef NOIRCSOCKET_H
#define NOIRCSOCKET_H

#include <nobnc/noglobal.h>
#include <nobnc/nosocket.h>
#include <memory>

class NoNick;
class NoClient;
class NoNetwork;
class NoHostMask;
class NoIrcSocketPrivate;

class NO_EXPORT NoIrcSocket : public NoSocket
{
public:
    NoIrcSocket(NoNetwork* network);
    virtual ~NoIrcSocket();

    enum ChanModeArgs {
        // These values must line up with their position in the CHANMODE argument to raw 005
        ListArg = 0,
        HasArg = 1,
        ArgWhenSet = 2,
        NoArg = 3
    };

    bool onCtcpReply(NoHostMask& nick, NoString& message);
    bool onPrivateCtcp(NoHostMask& nick, NoString& message);
    bool onChannelCtcp(NoNick& nick, const NoString& sChan, NoString& message);
    bool OnGeneralCTCP(NoHostMask& nick, NoString& message);
    bool onPrivateMessage(NoHostMask& nick, NoString& message);
    bool onChannelMessage(NoNick& nick, const NoString& sChan, NoString& message);
    bool onPrivateNotice(NoHostMask& nick, NoString& message);
    bool onChannelNotice(NoNick& nick, const NoString& sChan, NoString& message);
    bool onServerCapAvailable(const NoString& cap);

    void readLine(const NoString& data) override;
    void onConnected() override;
    void onDisconnected() override;
    void onConnectionRefused() override;
    void onSocketError(int iErrno, const NoString& description) override;
    void onTimeout() override;
    void onReachedMaxBuffer() override;

    void putIrc(const NoString& line);
    void putIrcQuick(const NoString& line); //!< Should be used for PONG only
    void resetChans();
    void quit(const NoString& message = "");

    /** You can call this from NoModule::onServerCapResult to suspend
     *  sending other CAP requests and CAP END for a while. Each
     *  call to PauseCap should be balanced with a call to ResumeCap.
     */
    void pauseCap();
    /** If you used PauseCap, call this when CAP negotiation and logging in
     *  should be resumed again.
     */
    void resumeCap();

    void setPassword(const NoString& s);

    uint maxNickLen() const;
    ChanModeArgs modeType(uchar mode) const;
    uchar permFromMode(uchar mode) const;
    std::map<uchar, ChanModeArgs> chanModes() const;
    bool isPermChar(const char c) const;
    bool isPermMode(const char c) const;
    NoString perms() const;
    NoString permModes() const;
    NoString nickMask() const;
    NoString nick() const;
    NoString password() const;
    NoNetwork* network() const;
    bool hasNamesX() const;
    bool hasUhNames() const;
    std::set<uchar> userModes() const;
    // This is true if we are past raw 001
    bool isAuthed() const;
    bool isCapAccepted(const NoString& cap);
    NoStringMap isupport() const;
    NoString isupport(const NoString& key, const NoString& sDefault = "") const;

    // This handles NAMESX and UHNAMES in a raw 353 reply
    void forwardRaw353(const NoString& line) const;
    void forwardRaw353(const NoString& line, NoClient* client) const;

    // TODO move this function to NoNetwork and make it non-static?
    static bool isFloodProtected(double fRate);

private:
    void setNick(const NoString& nick);
    void parseISupport(const NoString& line);
    // This is called when we connect and the nick we want is already taken
    void sendAltNick(const NoString& sBadNick);
    void sendNextCap();
    void trySend();

    friend class NoIrcFloodTimer;

private:
    NoIrcSocket(const NoIrcSocket&) = delete;
    NoIrcSocket& operator=(const NoIrcSocket&) = delete;

    std::unique_ptr<NoIrcSocketPrivate> d;
};

#endif // NOIRCSOCKET_H
