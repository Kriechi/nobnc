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

#define REQUIRESSL

#include <no/nomodule.h>
#include <no/nouser.h>
#include <no/noapp.h>
#include <no/nodebug.h>
#include <no/noclient.h>
#include <no/noauthenticator.h>

class NoSslClientCertMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoSslClientCertMod)
    {
        AddHelpCommand();
        AddCommand("Add",
                   static_cast<NoModCommand::ModCmdFunc>(&NoSslClientCertMod::HandleAddCommand),
                   "[pubkey]",
                   "If pubkey is not provided will use the current key");
        AddCommand("Del", static_cast<NoModCommand::ModCmdFunc>(&NoSslClientCertMod::HandleDelCommand), "id");
        AddCommand("List", static_cast<NoModCommand::ModCmdFunc>(&NoSslClientCertMod::HandleListCommand));
        AddCommand("Show",
                   static_cast<NoModCommand::ModCmdFunc>(&NoSslClientCertMod::HandleShowCommand),
                   "",
                   "Print your current key");
    }

    bool OnBoot() override
    {
        const std::vector<NoListener*>& vListeners = NoApp::Get().GetListeners();
        std::vector<NoListener*>::const_iterator it;

        // We need the SSL_VERIFY_PEER flag on all listeners, or else
        // the client doesn't send a ssl cert
        for (it = vListeners.begin(); it != vListeners.end(); ++it)
            (*it)->GetSocket()->SetRequireClientCertFlags(SSL_VERIFY_PEER);

        for (NoStringMap::const_iterator it1 = BeginNV(); it1 != EndNV(); ++it1) {
            if (NoApp::Get().FindUser(it1->first) == nullptr) {
                NO_DEBUG("Unknown user in saved data [" + it1->first + "]");
                continue;
            }

            NoStringVector vsKeys = it1->second.split(" ", No::SkipEmptyParts);
            for (NoStringVector::const_iterator it2 = vsKeys.begin(); it2 != vsKeys.end(); ++it2) {
                m_PubKeys[it1->first].insert(it2->toLower());
            }
        }

        return true;
    }

    void OnPostRehash() override { OnBoot(); }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        OnBoot();

        return true;
    }

    bool Save()
    {
        ClearNV(false);
        for (MNoStringSet::const_iterator it = m_PubKeys.begin(); it != m_PubKeys.end(); ++it) {
            NoString sVal;
            for (NoStringSet::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
                sVal += *it2 + " ";
            }

            if (!sVal.empty()) SetNV(it->first, sVal, false);
        }

        return SaveRegistry();
    }

    bool AddKey(NoUser* pUser, const NoString& sKey)
    {
        const std::pair<NoStringSet::const_iterator, bool> pair = m_PubKeys[pUser->GetUserName()].insert(sKey.toLower());

        if (pair.second) {
            Save();
        }

        return pair.second;
    }

    ModRet OnLoginAttempt(std::shared_ptr<NoAuthBase> Auth) override
    {
        const NoString sUser = Auth->GetUsername();
        NoSocket* pSock = Auth->GetSocket();
        NoUser* pUser = NoApp::Get().FindUser(sUser);

        if (pSock == nullptr || pUser == nullptr) return CONTINUE;

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
        Auth->AcceptLogin(*pUser);

        return HALT;
    }

    void HandleShowCommand(const NoString& sLine)
    {
        const NoString sPubKey = GetKey(GetClient());

        if (sPubKey.empty()) {
            PutModule("You are not connected with any valid public key");
        } else {
            PutModule("Your current public key is: " + sPubKey);
        }
    }

    void HandleAddCommand(const NoString& sLine)
    {
        NoString sPubKey = sLine.token(1);

        if (sPubKey.empty()) {
            sPubKey = GetKey(GetClient());
        }

        if (sPubKey.empty()) {
            PutModule("You did not supply a public key or connect with one.");
        } else {
            if (AddKey(GetUser(), sPubKey)) {
                PutModule("'" + sPubKey + "' added.");
            } else {
                PutModule("The key '" + sPubKey + "' is already added.");
            }
        }
    }

    void HandleListCommand(const NoString& sLine)
    {
        NoTable Table;

        Table.AddColumn("Id");
        Table.AddColumn("Key");

        MNoStringSet::const_iterator it = m_PubKeys.find(GetUser()->GetUserName());
        if (it == m_PubKeys.end()) {
            PutModule("No keys set for your user");
            return;
        }

        uint id = 1;
        for (NoStringSet::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
            Table.AddRow();
            Table.SetCell("Id", NoString(id++));
            Table.SetCell("Key", *it2);
        }

        if (PutModule(Table) == 0) {
            // This double check is necessary, because the
            // set could be empty.
            PutModule("No keys set for your user");
        }
    }

    void HandleDelCommand(const NoString& sLine)
    {
        uint id = sLine.tokens(1).toUInt();
        MNoStringSet::iterator it = m_PubKeys.find(GetUser()->GetUserName());

        if (it == m_PubKeys.end()) {
            PutModule("No keys set for your user");
            return;
        }

        if (id == 0 || id > it->second.size()) {
            PutModule("Invalid #, check \"list\"");
            return;
        }

        NoStringSet::const_iterator it2 = it->second.begin();
        while (id > 1) {
            ++it2;
            id--;
        }

        it->second.erase(it2);
        if (it->second.size() == 0) m_PubKeys.erase(it);
        PutModule("Removed");

        Save();
    }

    NoString GetKey(NoSocket* pSock)
    {
        NoString sRes;
        long int res = pSock->GetPeerFingerprint(sRes);

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

    NoString GetWebMenuTitle() override { return "certauth"; }

    bool OnWebRequest(NoWebSock& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        NoUser* pUser = WebSock.GetSession()->GetUser();

        if (sPageName == "index") {
            MNoStringSet::const_iterator it = m_PubKeys.find(pUser->GetUserName());
            if (it != m_PubKeys.end()) {
                for (NoStringSet::const_iterator it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
                    NoTemplate& row = Tmpl.AddRow("KeyLoop");
                    row["Key"] = *it2;
                }
            }

            return true;
        } else if (sPageName == "add") {
            AddKey(pUser, WebSock.GetParam("key"));
            WebSock.Redirect(GetWebPath());
            return true;
        } else if (sPageName == "delete") {
            MNoStringSet::iterator it = m_PubKeys.find(pUser->GetUserName());
            if (it != m_PubKeys.end()) {
                if (it->second.erase(WebSock.GetParam("key", false))) {
                    if (it->second.size() == 0) {
                        m_PubKeys.erase(it);
                    }

                    Save();
                }
            }

            WebSock.Redirect(GetWebPath());
            return true;
        }

        return false;
    }

private:
    // Maps user names to a list of allowed pubkeys
    typedef std::map<NoString, std::set<NoString>> MNoStringSet;
    MNoStringSet m_PubKeys;
};

template <> void TModInfo<NoSslClientCertMod>(NoModInfo& Info) { Info.SetWikiPage("certauth"); }

GLOBALMODULEDEFS(NoSslClientCertMod, "Allow users to authenticate via SSL client certificates.")
