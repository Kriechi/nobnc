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

#include <no/nomodule.h>
#include <no/nochannel.h>
#include <no/nonetwork.h>
#include <no/noescape.h>
#include <no/nonick.h>

class NoBuffExtras : public NoModule
{
public:
    MODCONSTRUCTOR(NoBuffExtras)
    {
    }

    void AddBuffer(NoChannel& channel, const NoString& message)
    {
        // If they have AutoClearChanBuffer enabled, only add messages if no client is connected
        if (channel.autoClearChanBuffer() && network()->isUserOnline())
            return;

        channel.addBuffer(":" + moduleNick() + "!" + moduleName() + "@znc.in PRIVMSG " + _NAMEDFMT(channel.name()) +
                          " :{text}",
                          message);
    }

    void onRawMode2(const NoNick* opNick, NoChannel& channel, const NoString& modes, const NoString& args) override
    {
        const NoString sNickMask = opNick ? opNick->nickMask() : "Server";
        AddBuffer(channel, sNickMask + " set mode: " + modes + " " + args);
    }

    void onKick(const NoNick& opNick, const NoString& sKickedNick, NoChannel& channel, const NoString& message) override
    {
        AddBuffer(channel, opNick.nickMask() + " kicked " + sKickedNick + " Reason: [" + message + "]");
    }

    void onQuit(const NoNick& nick, const NoString& message, const std::vector<NoChannel*>& channels) override
    {
        std::vector<NoChannel*>::const_iterator it;
        NoString msg = nick.nickMask() + " quit with message: [" + message + "]";
        for (it = channels.begin(); it != channels.end(); ++it) {
            AddBuffer(**it, msg);
        }
    }

    void onJoin(const NoNick& nick, NoChannel& channel) override
    {
        AddBuffer(channel, nick.nickMask() + " joined");
    }

    void onPart(const NoNick& nick, NoChannel& channel, const NoString& message) override
    {
        AddBuffer(channel, nick.nickMask() + " parted with message: [" + message + "]");
    }

    void onNick(const NoNick& OldNick, const NoString& newNick, const std::vector<NoChannel*>& channels) override
    {
        std::vector<NoChannel*>::const_iterator it;
        NoString msg = OldNick.nickMask() + " is now known as " + newNick;
        for (it = channels.begin(); it != channels.end(); ++it) {
            AddBuffer(**it, msg);
        }
    }

    ModRet onTopic(NoNick& nick, NoChannel& channel, NoString& topic) override
    {
        AddBuffer(channel, nick.nickMask() + " changed the topic to: " + topic);

        return CONTINUE;
    }
};

template <>
void no_moduleInfo<NoBuffExtras>(NoModuleInfo& info)
{
    info.setWikiPage("buffextras");
    info.addType(No::NetworkModule);
}

USERMODULEDEFS(NoBuffExtras, "Add joins, parts etc. to the playback buffer")
