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
#include <nobnc/nouser.h>
#include <nobnc/noapp.h>
#include <nobnc/noregistry.h>
#include <nobnc/notable.h>

class NoLastSeenMod : public NoModule
{
private:
    time_t GetTime(const NoUser* user)
    {
        return NoRegistry(this).value(user->userName()).toULong();
    }

    void SetTime(const NoUser* user)
    {
        NoRegistry(this).setValue(user->userName(), NoString(time(nullptr)));
    }

    const NoString FormatLastSeen(const NoUser* user, const char* sDefault = "")
    {
        time_t last = GetTime(user);
        if (last < 1) {
            return sDefault;
        } else {
            char buf[1024];
            strftime(buf, sizeof(buf) - 1, "%c", localtime(&last));
            return buf;
        }
    }

    typedef std::multimap<time_t, NoUser*> MTimeMulti;
    typedef std::map<NoString, NoUser*> MUsers;

    void ShowCommand(const NoString& line)
    {
        if (!user()->isAdmin()) {
            putModule("Access denied");
            return;
        }

        const MUsers& mUsers = noApp->userMap();
        MUsers::const_iterator it;
        NoTable Table;

        Table.addColumn("User");
        Table.addColumn("Last Seen");

        for (it = mUsers.begin(); it != mUsers.end(); ++it) {
            Table.addRow();
            Table.setValue("User", it->first);
            Table.setValue("Last Seen", FormatLastSeen(it->second, "never"));
        }

        putModule(Table);
    }

public:
    MODCONSTRUCTOR(NoLastSeenMod)
    {
        addHelpCommand();
        addCommand("Show", static_cast<NoModule::CommandFunction>(&NoLastSeenMod::ShowCommand));
    }

    // Event stuff:

    void onClientLogin() override
    {
        SetTime(user());
    }

    void onClientDisconnect() override
    {
        SetTime(user());
    }

    Return onDeleteUser(NoUser* user) override
    {
        NoRegistry registry(this);
        registry.remove(user->userName());
        return Continue;
    }
};

template <>
void no_moduleInfo<NoLastSeenMod>(NoModuleInfo& info)
{
    info.setWikiPage("lastseen");
}

GLOBALMODULEDEFS(NoLastSeenMod, "Collects data about when a user last logged in.")
