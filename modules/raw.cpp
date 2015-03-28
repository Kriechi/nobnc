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

class NoRawMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoRawMod) {}

    ModRet onRaw(NoString& sLine) override
    {
        putModule("IRC -> [" + sLine + "]");
        return CONTINUE;
    }

    void onModCommand(const NoString& sCommand) override { putIrc(sCommand); }

    ModRet onUserRaw(NoString& sLine) override
    {
        putModule("YOU -> [" + sLine + "]");
        return CONTINUE;
    }
};

template <> void no_moduleInfo<NoRawMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("raw");
    Info.addType(No::UserModule);
}

NETWORKMODULEDEFS(NoRawMod, "View all of the raw traffic")
