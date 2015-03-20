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
#include <no/noutils.h>

class NoStripControlsMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoStripControlsMod) {}

    ModRet OnPrivCTCP(NoNick& Nick, NoString& sMessage) override
    {
        sMessage = No::stripControls(sMessage);
        return CONTINUE;
    }

    ModRet OnChanCTCP(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        sMessage = No::stripControls(sMessage);
        return CONTINUE;
    }

    ModRet OnPrivNotice(NoNick& Nick, NoString& sMessage) override
    {
        sMessage = No::stripControls(sMessage);
        return CONTINUE;
    }

    ModRet OnChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        sMessage = No::stripControls(sMessage);
        return CONTINUE;
    }

    ModRet OnPrivMsg(NoNick& Nick, NoString& sMessage) override
    {
        sMessage = No::stripControls(sMessage);
        return CONTINUE;
    }

    ModRet OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        sMessage = No::stripControls(sMessage);
        return CONTINUE;
    }
};

template <> void no_moduleInfo<NoStripControlsMod>(NoModuleInfo& Info)
{
    Info.SetWikiPage("stripcontrols");
    Info.AddType(No::UserModule);
}

NETWORKMODULEDEFS(NoStripControlsMod, "Strips control codes (Colors, Bold, ..) from channel and private messages.")
