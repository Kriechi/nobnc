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

#ifndef NOIRCSOCK_H
#define NOIRCSOCK_H

#include <znc/noconfig.h>
#include <znc/nosocket.h>
#include <znc/nonick.h>

#include <deque>

class NoChannel;
class NoUser;
class NoNetwork;
class NoClient;

// TODO: This class needs new name
class NoIrcSock : public NoIrcSocket
{
public:
    NoIrcSock(NoNetwork* pNetwork);
    virtual ~NoIrcSock();

    NoIrcSock(const NoIrcSock&) = delete;
    NoIrcSock& operator=(const NoIrcSock&) = delete;

    typedef enum {
        // These values must line up with their position in the CHANMODE argument to raw 005
        ListArg = 0,
        HasArg = 1,
        ArgWhenSet = 2,
        NoArg = 3
    } EChanModeArgs;

    bool OnCTCPReply(NoNick& Nick, NoString& sMessage);
    bool OnPrivCTCP(NoNick& Nick, NoString& sMessage);
    bool OnChanCTCP(NoNick& Nick, const NoString& sChan, NoString& sMessage);
    bool OnGeneralCTCP(NoNick& Nick, NoString& sMessage);
    bool OnPrivMsg(NoNick& Nick, NoString& sMessage);
    bool OnChanMsg(NoNick& Nick, const NoString& sChan, NoString& sMessage);
    bool OnPrivNotice(NoNick& Nick, NoString& sMessage);
    bool OnChanNotice(NoNick& Nick, const NoString& sChan, NoString& sMessage);
    bool OnServerCapAvailable(const NoString& sCap);

    void ReadLine(const NoString& sData) override;
    void Connected() override;
    void Disconnected() override;
    void ConnectionRefused() override;
    void SockError(int iErrno, const NoString& sDescription) override;
    void Timeout() override;
    void ReachedMaxBuffer() override;

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

    void SetPass(const NoString& s) { m_sPass = s; }

    unsigned int GetMaxNickLen() const { return m_uMaxNickLen; }
    EChanModeArgs GetModeType(unsigned char uMode) const;
    unsigned char GetPermFromMode(unsigned char uMode) const;
    const std::map<unsigned char, EChanModeArgs>& GetChanModes() const { return m_mueChanModes; }
    bool IsPermChar(const char c) const { return (c != '\0' && GetPerms().find(c) != NoString::npos); }
    bool IsPermMode(const char c) const { return (c != '\0' && GetPermModes().find(c) != NoString::npos); }
    const NoString& GetPerms() const { return m_sPerms; }
    const NoString& GetPermModes() const { return m_sPermModes; }
    NoString GetNickMask() const { return m_Nick.GetNickMask(); }
    const NoString& GetNick() const { return m_Nick.GetNick(); }
    const NoString& GetPass() const { return m_sPass; }
    NoNetwork* GetNetwork() const { return m_pNetwork; }
    bool HasNamesx() const { return m_bNamesx; }
    bool HasUHNames() const { return m_bUHNames; }
    const std::set<unsigned char>& GetUserModes() const { return m_scUserModes; }
    // This is true if we are past raw 001
    bool IsAuthed() const { return m_bAuthed; }
    bool IsCapAccepted(const NoString& sCap) { return 1 == m_ssAcceptedCaps.count(sCap); }
    const NoStringMap& GetISupport() const { return m_mISupport; }
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
    std::set<unsigned char> m_scUserModes;
    std::map<unsigned char, EChanModeArgs> m_mueChanModes;
    NoNetwork* m_pNetwork;
    NoNick m_Nick;
    NoString m_sPass;
    std::map<NoString, NoChannel*> m_msChans;
    unsigned int m_uMaxNickLen;
    unsigned int m_uCapPaused;
    NoStringSet m_ssAcceptedCaps;
    NoStringSet m_ssPendingCaps;
    time_t m_lastCTCP;
    unsigned int m_uNumCTCP;
    static const time_t m_uCTCPFloodTime;
    static const unsigned int m_uCTCPFloodCount;
    NoStringMap m_mISupport;
    std::deque<NoString> m_vsSendQueue;
    short int m_iSendsAllowed;
    unsigned short int m_uFloodBurst;
    double m_fFloodRate;
    bool m_bFloodProtection;

    friend class NoIrcFloodTimer;
};

#endif // !NOIRCSOCK_H
