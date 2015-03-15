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

#include <znc/nochannel.h>
#include <znc/nonetwork.h>

using std::vector;

class CBuffExtras : public CModule
{
public:
    MODCONSTRUCTOR(CBuffExtras) {}

    virtual ~CBuffExtras() {}

    void AddBuffer(CChannel& Channel, const CString& sMessage)
    {
        // If they have AutoClearChanBuffer enabled, only add messages if no client is connected
        if (Channel.AutoClearChanBuffer() && GetNetwork()->IsUserOnline()) return;

        Channel.AddBuffer(":" + GetModNick() + "!" + GetModName() + "@znc.in PRIVMSG " + _NAMEDFMT(Channel.GetName()) + " :{text}",
                          sMessage);
    }

    void OnRawMode2(const CNick* pOpNick, CChannel& Channel, const CString& sModes, const CString& sArgs) override
    {
        const CString sNickMask = pOpNick ? pOpNick->GetNickMask() : "Server";
        AddBuffer(Channel, sNickMask + " set mode: " + sModes + " " + sArgs);
    }

    void OnKick(const CNick& OpNick, const CString& sKickedNick, CChannel& Channel, const CString& sMessage) override
    {
        AddBuffer(Channel, OpNick.GetNickMask() + " kicked " + sKickedNick + " Reason: [" + sMessage + "]");
    }

    void OnQuit(const CNick& Nick, const CString& sMessage, const vector<CChannel*>& vChans) override
    {
        vector<CChannel*>::const_iterator it;
        CString sMsg = Nick.GetNickMask() + " quit with message: [" + sMessage + "]";
        for (it = vChans.begin(); it != vChans.end(); ++it) {
            AddBuffer(**it, sMsg);
        }
    }

    void OnJoin(const CNick& Nick, CChannel& Channel) override { AddBuffer(Channel, Nick.GetNickMask() + " joined"); }

    void OnPart(const CNick& Nick, CChannel& Channel, const CString& sMessage) override
    {
        AddBuffer(Channel, Nick.GetNickMask() + " parted with message: [" + sMessage + "]");
    }

    void OnNick(const CNick& OldNick, const CString& sNewNick, const vector<CChannel*>& vChans) override
    {
        vector<CChannel*>::const_iterator it;
        CString sMsg = OldNick.GetNickMask() + " is now known as " + sNewNick;
        for (it = vChans.begin(); it != vChans.end(); ++it) {
            AddBuffer(**it, sMsg);
        }
    }

    EModRet OnTopic(CNick& Nick, CChannel& Channel, CString& sTopic) override
    {
        AddBuffer(Channel, Nick.GetNickMask() + " changed the topic to: " + sTopic);

        return CONTINUE;
    }
};

template <> void TModInfo<CBuffExtras>(CModInfo& Info)
{
    Info.SetWikiPage("buffextras");
    Info.AddType(CModInfo::NetworkModule);
}

USERMODULEDEFS(CBuffExtras, "Add joins, parts etc. to the playback buffer")
