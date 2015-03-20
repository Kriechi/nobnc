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
#include <no/nouser.h>
#include <no/noapp.h>
#include <no/notemplate.h>
#include <no/nowebsocket.h>
#include <no/nowebsession.h>

class NoLastSeenMod : public NoModule
{
private:
    time_t GetTime(const NoUser* pUser) { return GetNV(pUser->GetUserName()).toULong(); }

    void SetTime(const NoUser* pUser) { SetNV(pUser->GetUserName(), NoString(time(nullptr))); }

    const NoString FormatLastSeen(const NoUser* pUser, const char* sDefault = "")
    {
        time_t last = GetTime(pUser);
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

    void ShowCommand(const NoString& sLine)
    {
        if (!GetUser()->IsAdmin()) {
            PutModule("Access denied");
            return;
        }

        const MUsers& mUsers = NoApp::Get().GetUserMap();
        MUsers::const_iterator it;
        NoTable Table;

        Table.AddColumn("User");
        Table.AddColumn("Last Seen");

        for (it = mUsers.begin(); it != mUsers.end(); ++it) {
            Table.AddRow();
            Table.SetCell("User", it->first);
            Table.SetCell("Last Seen", FormatLastSeen(it->second, "never"));
        }

        PutModule(Table);
    }

public:
    MODCONSTRUCTOR(NoLastSeenMod)
    {
        AddHelpCommand();
        AddCommand("Show", static_cast<NoModuleCommand::ModCmdFunc>(&NoLastSeenMod::ShowCommand));
    }

    // Event stuff:

    void OnClientLogin() override { SetTime(GetUser()); }

    void OnClientDisconnect() override { SetTime(GetUser()); }

    ModRet OnDeleteUser(NoUser& User) override
    {
        DelNV(User.GetUserName());
        return CONTINUE;
    }

    // Web stuff:

    bool WebRequiresAdmin() override { return true; }
    NoString GetWebMenuTitle() override { return "Last Seen"; }

    bool OnWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "index") {
            NoModules& GModules = NoApp::Get().GetModules();
            Tmpl["WebAdminLoaded"] = NoString(GModules.FindModule("webadmin") != nullptr);

            MTimeMulti mmSorted;
            const MUsers& mUsers = NoApp::Get().GetUserMap();

            for (MUsers::const_iterator uit = mUsers.begin(); uit != mUsers.end(); ++uit) {
                mmSorted.insert(std::pair<time_t, NoUser*>(GetTime(uit->second), uit->second));
            }

            for (MTimeMulti::const_iterator it = mmSorted.begin(); it != mmSorted.end(); ++it) {
                NoUser* pUser = it->second;
                NoTemplate& Row = Tmpl.AddRow("UserLoop");

                Row["Username"] = pUser->GetUserName();
                Row["IsSelf"] = NoString(pUser == WebSock.GetSession()->GetUser());
                Row["LastSeen"] = FormatLastSeen(pUser, "never");
            }

            return true;
        }

        return false;
    }

    bool OnEmbeddedWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "webadmin/user" && WebSock.GetSession()->IsAdmin()) {
            NoUser* pUser = NoApp::Get().FindUser(Tmpl["Username"]);
            if (pUser) {
                Tmpl["LastSeen"] = FormatLastSeen(pUser);
            }
            return true;
        }

        return false;
    }
};

template <> void no_moduleInfo<NoLastSeenMod>(NoModuleInfo& Info) { Info.SetWikiPage("lastseen"); }

GLOBALMODULEDEFS(NoLastSeenMod, "Collects data about when a user last logged in.")
