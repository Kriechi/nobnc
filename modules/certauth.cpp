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

#define REQUIRESSL

#include <no/nomodule.h>
#include <no/nouser.h>
#include <no/noapp.h>
#include <no/nodebug.h>
#include <no/noclient.h>
#include <no/noauthenticator.h>
#include <no/nowebsocket.h>
#include <no/nowebsession.h>
#include <no/nolistener.h>
#include <no/noregistry.h>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#endif

class NoSslClientCertMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoSslClientCertMod)
    {
        addHelpCommand();
        addCommand("Add",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSslClientCertMod::HandleaddCommand),
                   "[pubkey]",
                   "If pubkey is not provided will use the current key");
        addCommand("Del", static_cast<NoModuleCommand::ModCmdFunc>(&NoSslClientCertMod::HandleDelCommand), "id");
        addCommand("List", static_cast<NoModuleCommand::ModCmdFunc>(&NoSslClientCertMod::HandleListCommand));
        addCommand("Show",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSslClientCertMod::HandleShowCommand),
                   "",
                   "Print your current key");
    }

    bool onBoot() override
    {
        const std::vector<NoListener*>& vListeners = NoApp::Get().GetListeners();
        std::vector<NoListener*>::const_iterator it;

        // We need the SSL_VERIFY_PEER flag on all listeners, or else
        // the client doesn't send a ssl cert
        for (it = vListeners.begin(); it != vListeners.end(); ++it)
            (*it)->socket()->setRequireClientCertFlags(SSL_VERIFY_PEER);

        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            if (NoApp::Get().FindUser(key) == nullptr) {
                NO_DEBUG("Unknown user in saved data [" + key + "]");
                continue;
            }

            NoStringVector vsKeys = registry.value(key).split(" ", No::SkipEmptyParts);
            for (NoStringVector::const_iterator it2 = vsKeys.begin(); it2 != vsKeys.end(); ++it2) {
                m_PubKeys[key].insert(it2->toLower());
            }
        }

        return true;
    }

    void onPostRehash() override
    {
        onBoot();
    }

    bool onLoad(const NoString& sArgs, NoString& sMessage) override
    {
        onBoot();

        return true;
    }

    bool Save()
    {
        NoRegistry registry(this);
        registry.clear();
        for (MNoStringSet::const_iterator it = m_PubKeys.begin(); it != m_PubKeys.end(); ++it) {
            NoString sVal;
            for (NoStringSet::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
                sVal += *it2 + " ";
            }

            if (!sVal.empty())
                registry.setValue(it->first, sVal);
        }

        return registry.save();
    }

    bool AddKey(NoUser* pUser, const NoString& sKey)
    {
        const std::pair<NoStringSet::const_iterator, bool> pair = m_PubKeys[pUser->userName()].insert(sKey.toLower());

        if (pair.second) {
            Save();
        }

        return pair.second;
    }

    ModRet onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth) override
    {
        const NoString sUser = Auth->username();
        NoSocket* pSock = Auth->socket();
        NoUser* pUser = NoApp::Get().FindUser(sUser);

        if (pSock == nullptr || pUser == nullptr)
            return CONTINUE;

        const NoString sPubKey = GetKey(pSock);
        NO_DEBUG("User: " << sUser << " Key: " << sPubKey);

        if (sPubKey.empty()) {
            NO_DEBUG("Peer got no public key, ignoring");
            return CONTINUE;
        }

        MNoStringSet::const_iterator it = m_PubKeys.find(sUser);
        if (it == m_PubKeys.end()) {
            NO_DEBUG("No saved pubkeys for this client");
            return CONTINUE;
        }

        NoStringSet::const_iterator it2 = it->second.find(sPubKey);
        if (it2 == it->second.end()) {
            NO_DEBUG("Invalid pubkey");
            return CONTINUE;
        }

        // This client uses a valid pubkey for this user, let them in
        NO_DEBUG("Accepted pubkey auth");
        Auth->acceptLogin(pUser);

        return HALT;
    }

    void HandleShowCommand(const NoString& sLine)
    {
        const NoString sPubKey = GetKey(client()->socket());

        if (sPubKey.empty()) {
            putModule("You are not connected with any valid public key");
        } else {
            putModule("Your current public key is: " + sPubKey);
        }
    }

    void HandleaddCommand(const NoString& sLine)
    {
        NoString sPubKey = No::token(sLine, 1);

        if (sPubKey.empty()) {
            sPubKey = GetKey(client()->socket());
        }

        if (sPubKey.empty()) {
            putModule("You did not supply a public key or connect with one.");
        } else {
            if (AddKey(user(), sPubKey)) {
                putModule("'" + sPubKey + "' added.");
            } else {
                putModule("The key '" + sPubKey + "' is already added.");
            }
        }
    }

    void HandleListCommand(const NoString& sLine)
    {
        NoTable Table;

        Table.addColumn("Id");
        Table.addColumn("Key");

        MNoStringSet::const_iterator it = m_PubKeys.find(user()->userName());
        if (it == m_PubKeys.end()) {
            putModule("No keys set for your user");
            return;
        }

        uint id = 1;
        for (NoStringSet::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
            Table.addRow();
            Table.setValue("Id", NoString(id++));
            Table.setValue("Key", *it2);
        }

        if (putModule(Table) == 0) {
            // This double check is necessary, because the
            // set could be empty.
            putModule("No keys set for your user");
        }
    }

    void HandleDelCommand(const NoString& sLine)
    {
        uint id = No::tokens(sLine, 1).toUInt();
        MNoStringSet::iterator it = m_PubKeys.find(user()->userName());

        if (it == m_PubKeys.end()) {
            putModule("No keys set for your user");
            return;
        }

        if (id == 0 || id > it->second.size()) {
            putModule("Invalid #, check \"list\"");
            return;
        }

        NoStringSet::const_iterator it2 = it->second.begin();
        while (id > 1) {
            ++it2;
            id--;
        }

        it->second.erase(it2);
        if (it->second.size() == 0)
            m_PubKeys.erase(it);
        putModule("Removed");

        Save();
    }

    NoString GetKey(NoSocket* pSock)
    {
        NoString sRes;
        long int res = pSock->peerFingerprint(sRes);

        NO_DEBUG("GetKey() returned status " << res << " with key " << sRes);

        // This is 'inspired' by charybdis' libratbox
        switch (res) {
        case X509_V_OK:
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            return sRes.toLower();
        default:
            return "";
        }
    }

    NoString webMenuTitle() override
    {
        return "certauth";
    }

    bool onWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        NoUser* pUser = WebSock.session()->user();

        if (sPageName == "index") {
            MNoStringSet::const_iterator it = m_PubKeys.find(pUser->userName());
            if (it != m_PubKeys.end()) {
                for (NoStringSet::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
                    NoTemplate& row = Tmpl.addRow("KeyLoop");
                    row["Key"] = *it2;
                }
            }

            return true;
        } else if (sPageName == "add") {
            AddKey(pUser, WebSock.param("key"));
            WebSock.redirect(webPath());
            return true;
        } else if (sPageName == "delete") {
            MNoStringSet::iterator it = m_PubKeys.find(pUser->userName());
            if (it != m_PubKeys.end()) {
                if (it->second.erase(WebSock.param("key", false))) {
                    if (it->second.size() == 0) {
                        m_PubKeys.erase(it);
                    }

                    Save();
                }
            }

            WebSock.redirect(webPath());
            return true;
        }

        return false;
    }

private:
    // Maps user names to a list of allowed pubkeys
    typedef std::map<NoString, std::set<NoString>> MNoStringSet;
    MNoStringSet m_PubKeys;
};

template <>
void no_moduleInfo<NoSslClientCertMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("certauth");
}

GLOBALMODULEDEFS(NoSslClientCertMod, "Allow users to authenticate via SSL client certificates.")
