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
#include <nobnc/nonetwork.h>
#include <nobnc/noclient.h>
#include <nobnc/noapp.h>
#include <nobnc/noauthenticator.h>
#include <nobnc/noregistry.h>
#include <nobnc/notable.h>
#include <nobnc/nosocket.h>

#define MESSAGE "Your account has been disabled. Contact your administrator."

class NoBlockUser : public NoModule
{
public:
    MODCONSTRUCTOR(NoBlockUser)
    {
        addHelpCommand();
        addCommand("List",
                   static_cast<NoModule::CommandFunction>(&NoBlockUser::OnListCommand),
                   "",
                   "List blocked users");
        addCommand("Block",
                   static_cast<NoModule::CommandFunction>(&NoBlockUser::OnBlockCommand),
                   "<user>",
                   "Block a user");
        addCommand("Unblock",
                   static_cast<NoModule::CommandFunction>(&NoBlockUser::OnUnblockCommand),
                   "<user>",
                   "Unblock a user");
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        NoStringVector::iterator it;

        // Load saved settings
        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            // Ignore errors
            Block(key);
        }

        // Parse arguments, each argument is a user name to block
        NoStringVector vArgs = args.split(" ", No::SkipEmptyParts);

        for (it = vArgs.begin(); it != vArgs.end(); ++it) {
            if (!Block(*it)) {
                message = "Could not block [" + *it + "]";
                return false;
            }
        }

        return true;
    }

    Return onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth) override
    {
        if (IsBlocked(Auth->username())) {
            Auth->refuseLogin(MESSAGE);
            return Halt;
        }

        return Continue;
    }

    void onModuleCommand(const NoString& command) override
    {
        if (!user()->isAdmin()) {
            putModule("Access denied");
        } else {
            NoModule::onModuleCommand(command);
        }
    }

    void OnListCommand(const NoString& command)
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

    void OnBlockCommand(const NoString& command)
    {
        NoString sUser = No::tokens(command, 1);

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

    void OnUnblockCommand(const NoString& command)
    {
        NoString sUser = No::tokens(command, 1);

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

private:
    bool IsBlocked(const NoString& sUser)
    {
        return NoRegistry(this).contains(sUser);
    }

    bool Block(const NoString& sUser)
    {
        NoUser* user = noApp->findUser(sUser);

        if (!user)
            return false;

        // Disconnect all clients
        std::vector<NoClient*> vpClients = user->allClients();
        std::vector<NoClient*>::iterator it;
        for (it = vpClients.begin(); it != vpClients.end(); ++it) {
            (*it)->putStatusNotice(MESSAGE);
            (*it)->socket()->close(NoSocket::CloseAfterWrite);
        }

        // Disconnect all networks from irc
        std::vector<NoNetwork*> vNetworks = user->networks();
        for (std::vector<NoNetwork*>::iterator it2 = vNetworks.begin(); it2 != vNetworks.end(); ++it2) {
            (*it2)->setEnabled(false);
        }

        NoRegistry registry(this);
        registry.setValue(user->userName(), "");
        return true;
    }
};

template <>
void no_moduleInfo<NoBlockUser>(NoModuleInfo& info)
{
    info.setWikiPage("blockuser");
    info.setHasArgs(true);
    info.setArgsHelpText("Enter one or more user names. Separate them by spaces.");
}

GLOBALMODULEDEFS(NoBlockUser, "Block certain users from logging in.")
