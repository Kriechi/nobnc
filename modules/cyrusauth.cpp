/*
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

#define REQUIRECYRUS

#include <no/noapp.h>
#include <no/nouser.h>
#include <no/nodebug.h>

#include <sasl/sasl.h>

class NoSaslAuthMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoSaslAuthMod)
    {
        m_Cache.SetTTL(60000 /*ms*/);

        AddHelpCommand();
        AddCommand("CreateUser", static_cast<NoModCommand::ModCmdFunc>(&NoSaslAuthMod::CreateUserCommand), "[yes|no]");
        AddCommand("CloneUser", static_cast<NoModCommand::ModCmdFunc>(&NoSaslAuthMod::CloneUserCommand), "[username]");
        AddCommand("DisableCloneUser", static_cast<NoModCommand::ModCmdFunc>(&NoSaslAuthMod::DisableCloneUserCommand));
    }

    virtual ~NoSaslAuthMod() { sasl_done(); }

    void OnModCommand(const NoString& sCommand) override
    {
        if (GetUser()->IsAdmin()) {
            HandleCommand(sCommand);
        } else {
            PutModule("Access denied");
        }
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        NoStringVector vsArgs;
        NoStringVector::const_iterator it;
        sArgs.Split(" ", vsArgs, false);

        for (it = vsArgs.begin(); it != vsArgs.end(); ++it) {
            if (it->Equals("saslauthd") || it->Equals("auxprop")) {
                m_sMethod += *it + " ";
            } else {
                NoUtils::PrintError("Ignoring invalid SASL pwcheck method: " + *it);
                sMessage = "Ignored invalid SASL pwcheck method";
            }
        }

        m_sMethod.TrimRight();

        if (m_sMethod.empty()) {
            sMessage = "Need a pwcheck method as argument (saslauthd, auxprop)";
            return false;
        }

        if (sasl_server_init(nullptr, nullptr) != SASL_OK) {
            sMessage = "SASL Could Not Be Initialized - Halting Startup";
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

    EModRet OnLoginAttempt(std::shared_ptr<NoAuthBase> Auth) override
    {
        const NoString& sUsername = Auth->GetUsername();
        const NoString& sPassword = Auth->GetPassword();
        NoUser* pUser(NoApp::Get().FindUser(sUsername));
        sasl_conn_t* sasl_conn(nullptr);
        bool bSuccess = false;

        if (!pUser && !CreateUser()) {
            return CONTINUE;
        }

        const NoString sCacheKey(NoUtils::MD5(sUsername + ":" + sPassword));
        if (m_Cache.HasItem(sCacheKey)) {
            bSuccess = true;
            DEBUG("saslauth: Found [" + sUsername + "] in cache");
        } else if (sasl_server_new("znc", nullptr, nullptr, nullptr, nullptr, m_cbs, 0, &sasl_conn) == SASL_OK &&
                   sasl_checkpass(sasl_conn, sUsername.c_str(), sUsername.size(), sPassword.c_str(), sPassword.size()) == SASL_OK) {
            m_Cache.AddItem(sCacheKey);

            DEBUG("saslauth: Successful SASL authentication [" + sUsername + "]");

            bSuccess = true;
        }

        sasl_dispose(&sasl_conn);

        if (bSuccess) {
            if (!pUser) {
                NoString sErr;
                pUser = new NoUser(sUsername);

                if (ShouldCloneUser()) {
                    NoUser* pBaseUser = NoApp::Get().FindUser(CloneUser());

                    if (!pBaseUser) {
                        DEBUG("saslauth: Clone User [" << CloneUser() << "] User not found");
                        delete pUser;
                        pUser = nullptr;
                    }

                    if (pUser && !pUser->Clone(*pBaseUser, sErr)) {
                        DEBUG("saslauth: Clone User [" << CloneUser() << "] failed: " << sErr);
                        delete pUser;
                        pUser = nullptr;
                    }
                }

                if (pUser) {
                    // "::" is an invalid MD5 hash, so user won't be able to login by usual method
                    pUser->SetPass("::", NoUser::HASH_MD5, "::");
                }

                if (pUser && !NoApp::Get().AddUser(pUser, sErr)) {
                    DEBUG("saslauth: Add user [" << sUsername << "] failed: " << sErr);
                    delete pUser;
                    pUser = nullptr;
                }
            }

            if (pUser) {
                Auth->AcceptLogin(*pUser);
                return HALT;
            }
        }

        return CONTINUE;
    }

    const NoString& GetMethod() const { return m_sMethod; }

    void CreateUserCommand(const NoString& sLine)
    {
        NoString sCreate = sLine.Token(1);

        if (!sCreate.empty()) {
            SetNV("CreateUser", sCreate);
        }

        if (CreateUser()) {
            PutModule("We will create users on their first login");
        } else {
            PutModule("We will not create users on their first login");
        }
    }

    void CloneUserCommand(const NoString& sLine)
    {
        NoString sUsername = sLine.Token(1);

        if (!sUsername.empty()) {
            SetNV("CloneUser", sUsername);
        }

        if (ShouldCloneUser()) {
            PutModule("We will clone [" + CloneUser() + "]");
        } else {
            PutModule("We will not clone a user");
        }
    }

    void DisableCloneUserCommand(const NoString& sLine)
    {
        DelNV("CloneUser");
        PutModule("Clone user disabled");
    }

    bool CreateUser() const { return GetNV("CreateUser").ToBool(); }

    NoString CloneUser() const { return GetNV("CloneUser"); }

    bool ShouldCloneUser() { return !GetNV("CloneUser").empty(); }

protected:
    NoCacheMap<NoString> m_Cache;

    sasl_callback_t m_cbs[2];
    NoString m_sMethod;

    static int getopt(void* context, const char* plugin_name, const char* option, const char** result, unsigned* len)
    {
        if (NoString(option).Equals("pwcheck_method")) {
            *result = ((NoSaslAuthMod*)context)->GetMethod().c_str();
            return SASL_OK;
        }

        return SASL_CONTINUE;
    }
};

template <> void TModInfo<NoSaslAuthMod>(NoModInfo& Info)
{
    Info.SetWikiPage("cyrusauth");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText(
    "This global module takes up to two arguments - the methods of authentication - auxprop and saslauthd");
}

GLOBALMODULEDEFS(NoSaslAuthMod, "Allow users to authenticate via SASL password verification method")
