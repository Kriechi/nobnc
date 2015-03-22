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

#include <no/nomodule.h>
#include <no/nochannel.h>
#include <no/nonetwork.h>
#include <no/noescape.h>
#include <no/nonick.h>

class NoBuffExtras : public NoModule
{
public:
    MODCONSTRUCTOR(NoBuffExtras) {}

    void AddBuffer(NoChannel& Channel, const NoString& sMessage)
    {
        // If they have AutoClearChanBuffer enabled, only add messages if no client is connected
        if (Channel.autoClearChanBuffer() && GetNetwork()->IsUserOnline()) return;

        Channel.addBuffer(":" + GetModNick() + "!" + GetModName() + "@znc.in PRIVMSG " + _NAMEDFMT(Channel.getName()) + " :{text}",
                          sMessage);
    }

    void OnRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs) override
    {
        const NoString sNickMask = pOpNick ? pOpNick->nickMask() : "Server";
        AddBuffer(Channel, sNickMask + " set mode: " + sModes + " " + sArgs);
    }

    void OnKick(const NoNick& OpNick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage) override
    {
        AddBuffer(Channel, OpNick.nickMask() + " kicked " + sKickedNick + " Reason: [" + sMessage + "]");
    }

    void OnQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans) override
    {
        std::vector<NoChannel*>::const_iterator it;
        NoString sMsg = Nick.nickMask() + " quit with message: [" + sMessage + "]";
        for (it = vChans.begin(); it != vChans.end(); ++it) {
            AddBuffer(**it, sMsg);
        }
    }

    void OnJoin(const NoNick& Nick, NoChannel& Channel) override { AddBuffer(Channel, Nick.nickMask() + " joined"); }

    void OnPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage) override
    {
        AddBuffer(Channel, Nick.nickMask() + " parted with message: [" + sMessage + "]");
    }

    void OnNick(const NoNick& OldNick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans) override
    {
        std::vector<NoChannel*>::const_iterator it;
        NoString sMsg = OldNick.nickMask() + " is now known as " + sNewNick;
        for (it = vChans.begin(); it != vChans.end(); ++it) {
            AddBuffer(**it, sMsg);
        }
    }

    ModRet OnTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic) override
    {
        AddBuffer(Channel, Nick.nickMask() + " changed the topic to: " + sTopic);

        return CONTINUE;
    }
};

template <> void no_moduleInfo<NoBuffExtras>(NoModuleInfo& Info)
{
    Info.SetWikiPage("buffextras");
    Info.AddType(No::NetworkModule);
}

USERMODULEDEFS(NoBuffExtras, "Add joins, parts etc. to the playback buffer")
