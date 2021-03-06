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

class NoRawMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoRawMod)
    {
    }

    Return onRaw(NoString& line) override
    {
        putModule("IRC -> [" + line + "]");
        return Continue;
    }

    void onModuleCommand(const NoString& command) override
    {
        putIrc(command);
    }

    Return onUserRaw(NoString& line) override
    {
        putModule("YOU -> [" + line + "]");
        return Continue;
    }
};

template <>
void no_moduleInfo<NoRawMod>(NoModuleInfo& info)
{
    info.setWikiPage("raw");
    info.addType(No::UserModule);
}

NETWORKMODULEDEFS(NoRawMod, "View all of the raw traffic")
