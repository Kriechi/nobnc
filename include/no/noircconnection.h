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

#ifndef NOIRCCONNECTION_H
#define NOIRCCONNECTION_H

#include <no/noglobal.h>
#include <no/noircsocket.h>
#include <no/nonick.h>

#include <deque>

class NoChannel;
class NoUser;
class NoNetwork;
class NoClient;

class NO_EXPORT NoIrcConnection : public NoIrcSocket
{
public:
    NoIrcConnection(NoNetwork* pNetwork);
    virtual ~NoIrcConnection();

    NoIrcConnection(const NoIrcConnection&) = delete;
    NoIrcConnection& operator=(const NoIrcConnection&) = delete;

    enum EChanModeArgs {
        // These values must line up with their position in the CHANMODE argument to raw 005
        ListArg = 0,
        HasArg = 1,
        ArgWhenSet = 2,
        NoArg = 3
    };

    bool OnCTCPReply(NoNick& Nick, NoString& sMessage);
    bool OnPrivCTCP(NoNick& Nick, NoString& sMessage);
    bool OnChanCTCP(NoNick& Nick, const NoString& sChan, NoString& sMessage);
    bool OnGeneralCTCP(NoNick& Nick, NoString& sMessage);
    bool OnPrivMsg(NoNick& Nick, NoString& sMessage);
    bool OnChanMsg(NoNick& Nick, const NoString& sChan, NoString& sMessage);
    bool OnPrivNotice(NoNick& Nick, NoString& sMessage);
    bool OnChanNotice(NoNick& Nick, const NoString& sChan, NoString& sMessage);
    bool OnServerCapAvailable(const NoString& sCap);

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

    /** You can call this from NoModule::OnServerCapResult to suspend
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
    EChanModeArgs GetModeType(uchar uMode) const;
    uchar GetPermFromMode(uchar uMode) const;
    const std::map<uchar, EChanModeArgs>& GetChanModes() const;
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

    bool m_bAuthed;
    bool m_bNamesx;
    bool m_bUHNames;
    NoString m_sPerms;
    NoString m_sPermModes;
    std::set<uchar> m_scUserModes;
    std::map<uchar, EChanModeArgs> m_mueChanModes;
    NoNetwork* m_pNetwork;
    NoNick m_Nick;
    NoString m_sPass;
    std::map<NoString, NoChannel*> m_msChans;
    uint m_uMaxNickLen;
    uint m_uCapPaused;
    NoStringSet m_ssAcceptedCaps;
    NoStringSet m_ssPendingCaps;
    time_t m_lastCTCP;
    uint m_uNumCTCP;
    static const time_t m_uCTCPFloodTime;
    static const uint m_uCTCPFloodCount;
    NoStringMap m_mISupport;
    std::deque<NoString> m_vsSendQueue;
    short int m_iSendsAllowed;
    ushort m_uFloodBurst;
    double m_fFloodRate;
    bool m_bFloodProtection;

    friend class NoIrcFloodTimer;
};

#endif // NOIRCCONNECTION_H
