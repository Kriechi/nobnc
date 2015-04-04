/*
 * Copyright (C) 2015 NoBNC
 * Copyright (C) 2004-2015 ZNC, see the NOTICE file for details.
 * Copyright (C) 2008 Heiko Hund <heiko@ist.eigentlich.net>
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

/**
 * @class NoSaslAuthMod
 * @author Heiko Hund <heiko@ist.eigentlich.net>
 * @brief SASL authentication module for znc.
 */

#define REQUIRESASL

#include <nobnc/nomodule.h>
#include <nobnc/noapp.h>
#include <nobnc/nouser.h>
#include <nobnc/nodebug.h>
#include <nobnc/noclient.h>
#include <nobnc/noauthenticator.h>
#include <nobnc/noregistry.h>

#include <sasl/sasl.h>

class NoSaslAuthMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoSaslAuthMod)
    {
        m_Cache.setExpiration(60000 /*ms*/);

        addHelpCommand();
        addCommand("CreateUser",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSaslAuthMod::CreateUserCommand),
                   "[yes|no]");
        addCommand("CloneUser",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSaslAuthMod::CloneUserCommand),
                   "[username]");
        addCommand("DisableCloneUser", static_cast<NoModuleCommand::ModCmdFunc>(&NoSaslAuthMod::DisableCloneUserCommand));
    }

    virtual ~NoSaslAuthMod()
    {
        sasl_done();
    }

    void onModCommand(const NoString& command) override
    {
        if (user()->isAdmin()) {
            handleCommand(command);
        } else {
            putModule("Access denied");
        }
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        NoStringVector::const_iterator it;
        NoStringVector vsArgs = args.split(" ", No::SkipEmptyParts);

        for (it = vsArgs.begin(); it != vsArgs.end(); ++it) {
            if (it->equals("saslauthd") || it->equals("auxprop")) {
                m_sMethod += *it + " ";
            } else {
                No::printError("Ignoring invalid SASL pwcheck method: " + *it);
                message = "Ignored invalid SASL pwcheck method";
            }
        }

        m_sMethod.trimRight();

        if (m_sMethod.empty()) {
            message = "Need a pwcheck method as argument (saslauthd, auxprop)";
            return false;
        }

        if (sasl_server_init(nullptr, nullptr) != SASL_OK) {
            message = "SASL Could Not Be Initialized - Halting Startup";
            return false;
        }

        m_cbs[0].id = SASL_CB_GETOPT;
        m_cbs[0].proc = reinterpret_cast<int (*)()>(NoSaslAuthMod::getopt);
        m_cbs[0].context = this;
        m_cbs[1].id = SASL_CB_LIST_END;
        m_cbs[1].proc = nullptr;
        m_cbs[1].context = nullptr;

        return true;
    }

    ModRet onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth) override
    {
        const NoString& username = Auth->username();
        const NoString& sPassword = Auth->password();
        NoUser* user(noApp->findUser(username));
        sasl_conn_t* sasl_conn(nullptr);
        bool success = false;

        if (!user && !CreateUser()) {
            return CONTINUE;
        }

        const NoString sCacheKey(No::md5(username + ":" + sPassword));
        if (m_Cache.contains(sCacheKey)) {
            success = true;
            NO_DEBUG("saslauth: Found [" + username + "] in cache");
        } else if (sasl_server_new("znc", nullptr, nullptr, nullptr, nullptr, m_cbs, 0, &sasl_conn) == SASL_OK &&
                   sasl_checkpass(sasl_conn, username.c_str(), username.size(), sPassword.c_str(), sPassword.size()) == SASL_OK) {
            m_Cache.insert(sCacheKey);

            NO_DEBUG("saslauth: Successful SASL authentication [" + username + "]");

            success = true;
        }

        sasl_dispose(&sasl_conn);

        if (success) {
            if (!user) {
                NoString sErr;
                user = new NoUser(username);

                if (ShouldCloneUser()) {
                    NoUser* pBaseUser = noApp->findUser(CloneUser());

                    if (!pBaseUser) {
                        NO_DEBUG("saslauth: Clone User [" << CloneUser() << "] User not found");
                        delete user;
                        user = nullptr;
                    }

                    if (user && !user->clone(pBaseUser, sErr)) {
                        NO_DEBUG("saslauth: Clone User [" << CloneUser() << "] failed: " << sErr);
                        delete user;
                        user = nullptr;
                    }
                }

                if (user) {
                    // "::" is an invalid hash, so user won't be able to login by usual method
                    user->setPassword("::"); // XXX TODO
                }

                if (user && !noApp->addUser(user, sErr)) {
                    NO_DEBUG("saslauth: Add user [" << username << "] failed: " << sErr);
                    delete user;
                    user = nullptr;
                }
            }

            if (user) {
                Auth->acceptLogin(user);
                return HALT;
            }
        }

        return CONTINUE;
    }

    const NoString& GetMethod() const
    {
        return m_sMethod;
    }

    void CreateUserCommand(const NoString& line)
    {
        NoString sCreate = No::token(line, 1);

        if (!sCreate.empty()) {
            NoRegistry registry(this);
            registry.setValue("CreateUser", sCreate);
        }

        if (CreateUser()) {
            putModule("We will create users on their first login");
        } else {
            putModule("We will not create users on their first login");
        }
    }

    void CloneUserCommand(const NoString& line)
    {
        NoString username = No::token(line, 1);

        if (!username.empty()) {
            NoRegistry registry(this);
            registry.setValue("CloneUser", username);
        }

        if (ShouldCloneUser()) {
            putModule("We will clone [" + CloneUser() + "]");
        } else {
            putModule("We will not clone a user");
        }
    }

    void DisableCloneUserCommand(const NoString& line)
    {
        NoRegistry registry(this);
        registry.remove("CloneUser");
        putModule("Clone user disabled");
    }

    bool CreateUser() const
    {
        return NoRegistry(this).value("CreateUser").toBool();
    }

    NoString CloneUser() const
    {
        return NoRegistry(this).value("CloneUser");
    }

    bool ShouldCloneUser()
    {
        return !NoRegistry(this).value("CloneUser").empty();
    }

protected:
    NoCacheMap<NoString> m_Cache;

    sasl_callback_t m_cbs[2];
    NoString m_sMethod;

    static int getopt(void* context, const char* plugin_name, const char* option, const char** result, unsigned* len)
    {
        if (NoString(option).equals("pwcheck_method")) {
            *result = ((NoSaslAuthMod*)context)->GetMethod().c_str();
            return SASL_OK;
        }

        return SASL_CONTINUE;
    }
};

template <>
void no_moduleInfo<NoSaslAuthMod>(NoModuleInfo& info)
{
    info.setWikiPage("cyrusauth");
    info.setHasArgs(true);
    info.setArgsHelpText(
    "This global module takes up to two arguments - the methods of authentication - auxprop and saslauthd");
}

GLOBALMODULEDEFS(NoSaslAuthMod, "Allow users to authenticate via SASL password verification method")
