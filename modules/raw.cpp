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

class NoRawMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoRawMod) {}
    virtual ~NoRawMod() {}

    ModRet OnRaw(NoString& sLine) override
    {
        PutModule("IRC -> [" + sLine + "]");
        return CONTINUE;
    }

    void OnModCommand(const NoString& sCommand) override { PutIRC(sCommand); }

    ModRet OnUserRaw(NoString& sLine) override
    {
        PutModule("YOU -> [" + sLine + "]");
        return CONTINUE;
    }
};

template <> void TModInfo<NoRawMod>(NoModInfo& Info)
{
    Info.SetWikiPage("raw");
    Info.AddType(NoModInfo::UserModule);
}

NETWORKMODULEDEFS(NoRawMod, "View all of the raw traffic")
