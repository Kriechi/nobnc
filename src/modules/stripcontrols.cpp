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

#include <nobnc/nomodule.h>
#include <nobnc/noutils.h>

class NoStripControlsMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoStripControlsMod)
    {
    }

    Return onPrivateCtcp(NoHostMask& nick, NoString& message) override
    {
        message = No::stripControls(message);
        return Continue;
    }

    Return onChannelCtcp(NoNick& nick, NoChannel* channel, NoString& message) override
    {
        message = No::stripControls(message);
        return Continue;
    }

    Return onPrivateNotice(NoHostMask& nick, NoString& message) override
    {
        message = No::stripControls(message);
        return Continue;
    }

    Return onChannelNotice(NoNick& nick, NoChannel* channel, NoString& message) override
    {
        message = No::stripControls(message);
        return Continue;
    }

    Return onPrivateMessage(NoHostMask& nick, NoString& message) override
    {
        message = No::stripControls(message);
        return Continue;
    }

    Return onChannelMessage(NoNick& nick, NoChannel* channel, NoString& message) override
    {
        message = No::stripControls(message);
        return Continue;
    }
};

template <>
void no_moduleInfo<NoStripControlsMod>(NoModuleInfo& info)
{
    info.setWikiPage("stripcontrols");
    info.addType(No::UserModule);
}

NETWORKMODULEDEFS(NoStripControlsMod, "Strips control codes (Colors, Bold, ..) from channel and private messages.")
