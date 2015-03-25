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

#include <no/noglobal.h>
#include <no/nosocket.h>
#include <memory>

class NoNick;
class NoClient;
class NoNetwork;
class NoIrcSocketPrivate;

class NO_EXPORT NoIrcSocket : public NoSocket
{
public:
    NoIrcSocket(NoNetwork* pNetwork);
    virtual ~NoIrcSocket();

    enum ChanModeArgs {
        // These values must line up with their position in the CHANMODE argument to raw 005
        ListArg = 0,
        HasArg = 1,
        ArgWhenSet = 2,
        NoArg = 3
    };

    bool onCtcpReply(NoNick& Nick, NoString& sMessage);
    bool onPrivCtcp(NoNick& Nick, NoString& sMessage);
    bool onChanCtcp(NoNick& Nick, const NoString& sChan, NoString& sMessage);
    bool OnGeneralCTCP(NoNick& Nick, NoString& sMessage);
    bool onPrivMsg(NoNick& Nick, NoString& sMessage);
    bool onChanMsg(NoNick& Nick, const NoString& sChan, NoString& sMessage);
    bool onPrivNotice(NoNick& Nick, NoString& sMessage);
    bool onChanNotice(NoNick& Nick, const NoString& sChan, NoString& sMessage);
    bool onServerCapAvailable(const NoString& sCap);

    void ReadLineImpl(const NoString& sData) override;
    void ConnectedImpl() override;
    void DisconnectedImpl() override;
    void ConnectionRefusedImpl() override;
    void SockErrorImpl(int iErrno, const NoString& sDescription) override;
    void TimeoutImpl() override;
    void ReachedMaxBufferImpl() override;

    void PutIRC(const NoString& sLine);
    void PutIRCQuick(const NoString& sLine); //!< Should be used for PONG only
    void ResetChans();
    void Quit(const NoString& sQuitMsg = "");

    /** You can call this from NoModule::onServerCapResult to suspend
     *  sending other CAP requests and CAP END for a while. Each
     *  call to PauseCap should be balanced with a call to ResumeCap.
     */
    void PauseCap();
    /** If you used PauseCap, call this when CAP negotiation and logging in
     *  should be resumed again.
     */
    void ResumeCap();

    void SetPass(const NoString& s);

    uint GetMaxNickLen() const;
    ChanModeArgs GetModeType(uchar uMode) const;
    uchar GetPermFromMode(uchar uMode) const;
    const std::map<uchar, ChanModeArgs>& GetChanModes() const;
    bool IsPermChar(const char c) const;
    bool IsPermMode(const char c) const;
    const NoString& GetPerms() const;
    const NoString& GetPermModes() const;
    NoString GetNickMask() const;
    NoString GetNick() const;
    const NoString& GetPass() const;
    NoNetwork* GetNetwork() const;
    bool HasNamesx() const;
    bool HasUHNames() const;
    const std::set<uchar>& GetUserModes() const;
    // This is true if we are past raw 001
    bool IsAuthed() const;
    bool IsCapAccepted(const NoString& sCap);
    const NoStringMap& GetISupport() const;
    NoString GetISupport(const NoString& sKey, const NoString& sDefault = "") const;

    // This handles NAMESX and UHNAMES in a raw 353 reply
    void ForwardRaw353(const NoString& sLine) const;
    void ForwardRaw353(const NoString& sLine, NoClient* pClient) const;

    // TODO move this function to NoNetwork and make it non-static?
    static bool IsFloodProtected(double fRate);

private:
    void SetNick(const NoString& sNick);
    void ParseISupport(const NoString& sLine);
    // This is called when we connect and the nick we want is already taken
    void SendAltNick(const NoString& sBadNick);
    void SendNextCap();
    void TrySend();

    friend class NoIrcFloodTimer;

private:
    NoIrcSocket(const NoIrcSocket&) = delete;
    NoIrcSocket& operator=(const NoIrcSocket&) = delete;

    std::unique_ptr<NoIrcSocketPrivate> d;
};

#endif // NOIRCSOCKET_H
