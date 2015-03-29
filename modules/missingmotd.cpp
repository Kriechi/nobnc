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

class NoMissingMotd : public NoModule
{
public:
    MODCONSTRUCTOR(NoMissingMotd)
    {
    }

    void onClientLogin() override
    {
        putUser(":irc.znc.in 422 :MOTD File is missing");
    }
};

template <>
void no_moduleInfo<NoMissingMotd>(NoModuleInfo& Info)
{
    Info.setWikiPage("missingmotd");
    Info.setHasArgs(false);
}

USERMODULEDEFS(NoMissingMotd, "Sends 422 to clients when they login")
