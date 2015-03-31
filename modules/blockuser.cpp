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
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/noclient.h>
#include <no/noapp.h>
#include <no/noauthenticator.h>
#include <no/nowebsocket.h>
#include <no/nowebsession.h>
#include <no/noregistry.h>

#define MESSAGE "Your account has been disabled. Contact your administrator."

class NoBlockUser : public NoModule
{
public:
    MODCONSTRUCTOR(NoBlockUser)
    {
        addHelpCommand();
        addCommand("List",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoBlockUser::OnListCommand),
                   "",
                   "List blocked users");
        addCommand("Block",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoBlockUser::OnBlockCommand),
                   "<user>",
                   "Block a user");
        addCommand("Unblock",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoBlockUser::OnUnblockCommand),
                   "<user>",
                   "Unblock a user");
    }

    bool onLoad(const NoString& sArgs, NoString& sMessage) override
    {
        NoStringVector::iterator it;

        // Load saved settings
        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            // Ignore errors
            Block(key);
        }

        // Parse arguments, each argument is a user name to block
        NoStringVector vArgs = sArgs.split(" ", No::SkipEmptyParts);

        for (it = vArgs.begin(); it != vArgs.end(); ++it) {
            if (!Block(*it)) {
                sMessage = "Could not block [" + *it + "]";
                return false;
            }
        }

        return true;
    }

    ModRet onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth) override
    {
        if (IsBlocked(Auth->username())) {
            Auth->refuseLogin(MESSAGE);
            return HALT;
        }

        return CONTINUE;
    }

    void onModCommand(const NoString& sCommand) override
    {
        if (!user()->isAdmin()) {
            putModule("Access denied");
        } else {
            handleCommand(sCommand);
        }
    }

    void OnListCommand(const NoString& sCommand)
    {
        NoTable Table;
        NoStringMap::iterator it;

        Table.addColumn("Blocked user");

        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            Table.addRow();
            Table.setValue("Blocked user", key);
        }

        if (putModule(Table) == 0)
            putModule("No users blocked");
    }

    void OnBlockCommand(const NoString& sCommand)
    {
        NoString sUser = No::tokens(sCommand, 1);

        if (sUser.empty()) {
            putModule("Usage: Block <user>");
            return;
        }

        if (user()->userName().equals(sUser)) {
            putModule("You can't block yourself");
            return;
        }

        if (Block(sUser))
            putModule("Blocked [" + sUser + "]");
        else
            putModule("Could not block [" + sUser + "] (misspelled?)");
    }

    void OnUnblockCommand(const NoString& sCommand)
    {
        NoString sUser = No::tokens(sCommand, 1);

        if (sUser.empty()) {
            putModule("Usage: Unblock <user>");
            return;
        }

        NoRegistry registry(this);
        if (registry.contains(sUser)) {
            registry.remove(sUser);
            putModule("Unblocked [" + sUser + "]");
        } else {
            putModule("This user is not blocked");
        }
    }

    bool onEmbeddedWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "webadmin/user" && WebSock.session()->isAdmin()) {
            NoString sAction = Tmpl["WebadminAction"];
            if (sAction == "display") {
                Tmpl["Blocked"] = NoString(IsBlocked(Tmpl["Username"]));
                Tmpl["Self"] = NoString(Tmpl["Username"].equals(WebSock.session()->user()->userName()));
                return true;
            }
            if (sAction == "change" && WebSock.param("embed_blockuser_presented").toBool()) {
                if (Tmpl["Username"].equals(WebSock.session()->user()->userName()) &&
                    WebSock.param("embed_blockuser_block").toBool()) {
                    WebSock.session()->addError("You can't block yourself");
                } else if (WebSock.param("embed_blockuser_block").toBool()) {
                    if (!WebSock.param("embed_blockuser_old").toBool()) {
                        if (Block(Tmpl["Username"])) {
                            WebSock.session()->addSuccess("Blocked [" + Tmpl["Username"] + "]");
                        } else {
                            WebSock.session()->addError("Couldn't block [" + Tmpl["Username"] + "]");
                        }
                    }
                } else if (WebSock.param("embed_blockuser_old").toBool()) {
                    NoRegistry registry(this);
                    if (registry.contains(Tmpl["Username"])) {
                        registry.remove(Tmpl["Username"]);
                        WebSock.session()->addSuccess("Unblocked [" + Tmpl["Username"] + "]");
                    } else {
                        WebSock.session()->addError("User [" + Tmpl["Username"] + "is not blocked");
                    }
                }
                return true;
            }
        }
        return false;
    }

private:
    bool IsBlocked(const NoString& sUser)
    {
        return NoRegistry(this).contains(sUser);
    }

    bool Block(const NoString& sUser)
    {
        NoUser* pUser = noApp->findUser(sUser);

        if (!pUser)
            return false;

        // Disconnect all clients
        std::vector<NoClient*> vpClients = pUser->allClients();
        std::vector<NoClient*>::iterator it;
        for (it = vpClients.begin(); it != vpClients.end(); ++it) {
            (*it)->putStatusNotice(MESSAGE);
            (*it)->socket()->close(NoSocket::CloseAfterWrite);
        }

        // Disconnect all networks from irc
        std::vector<NoNetwork*> vNetworks = pUser->networks();
        for (std::vector<NoNetwork*>::iterator it2 = vNetworks.begin(); it2 != vNetworks.end(); ++it2) {
            (*it2)->setEnabled(false);
        }

        NoRegistry registry(this);
        registry.setValue(pUser->userName(), "");
        return true;
    }
};

template <>
void no_moduleInfo<NoBlockUser>(NoModuleInfo& Info)
{
    Info.setWikiPage("blockuser");
    Info.setHasArgs(true);
    Info.setArgsHelpText("Enter one or more user names. Separate them by spaces.");
}

GLOBALMODULEDEFS(NoBlockUser, "Block certain users from logging in.")
