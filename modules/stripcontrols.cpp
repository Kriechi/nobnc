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

#include <znc/nomodules.h>

class NoStripControlsMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoStripControlsMod) {}

    EModRet OnPrivCTCP(NoNick& Nick, NoString& sMessage) override
    {
        sMessage.StripControls();
        return CONTINUE;
    }

    EModRet OnChanCTCP(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        sMessage.StripControls();
        return CONTINUE;
    }

    EModRet OnPrivNotice(NoNick& Nick, NoString& sMessage) override
    {
        sMessage.StripControls();
        return CONTINUE;
    }

    EModRet OnChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        sMessage.StripControls();
        return CONTINUE;
    }

    EModRet OnPrivMsg(NoNick& Nick, NoString& sMessage) override
    {
        sMessage.StripControls();
        return CONTINUE;
    }

    EModRet OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        sMessage.StripControls();
        return CONTINUE;
    }
};

template <> void TModInfo<NoStripControlsMod>(NoModInfo& Info)
{
    Info.SetWikiPage("stripcontrols");
    Info.AddType(NoModInfo::UserModule);
}

NETWORKMODULEDEFS(NoStripControlsMod, "Strips control codes (Colors, Bold, ..) from channel and private messages.")
