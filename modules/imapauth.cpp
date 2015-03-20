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
#include <no/noapp.h>
#include <no/nodebug.h>
#include <no/noclient.h>
#include <no/noauthenticator.h>

class NoImapAuthMod;

class NoImapSock : public NoModuleSocket
{
public:
    NoImapSock(NoImapAuthMod* pModule, std::shared_ptr<NoAuthenticator> Auth) : NoModuleSocket((NoModule*)pModule), m_spAuth(Auth)
    {
        m_pIMAPMod = pModule;
        m_bSentReply = false;
        m_bSentLogin = false;
        EnableReadLine();
    }

    virtual ~NoImapSock()
    {
        if (!m_bSentReply) {
            m_spAuth->RefuseLogin("IMAP server is down, please try again later");
        }
    }

    void ReadLineImpl(const NoString& sLine) override;

private:
protected:
    NoImapAuthMod* m_pIMAPMod;
    bool m_bSentLogin;
    bool m_bSentReply;
    std::shared_ptr<NoAuthenticator> m_spAuth;
};


class NoImapAuthMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoImapAuthMod)
    {
        m_Cache.SetTTL(60000);
        m_sServer = "localhost";
        m_uPort = 143;
        m_bSSL = false;
    }

    bool OnBoot() override { return true; }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        if (sArgs.trim_n().empty()) {
            return true; // use defaults
        }

        m_sServer = sArgs.token(0);
        NoString sPort = sArgs.token(1);
        m_sUserFormat = sArgs.token(2);

        if (sPort.left(1) == "+") {
            m_bSSL = true;
            sPort.leftChomp(1);
        }

        ushort uPort = sPort.toUShort();

        if (uPort) {
            m_uPort = uPort;
        }

        return true;
    }

    ModRet OnLoginAttempt(std::shared_ptr<NoAuthenticator> Auth) override
    {
        NoUser* pUser = NoApp::Get().FindUser(Auth->GetUsername());

        if (!pUser) { // @todo Will want to do some sort of && !m_bAllowCreate in the future
            Auth->RefuseLogin("Invalid User - Halting IMAP Lookup");
            return HALT;
        }

        if (pUser && m_Cache.HasItem(NoUtils::MD5(Auth->GetUsername() + ":" + Auth->GetPassword()))) {
            NO_DEBUG("+++ Found in cache");
            Auth->AcceptLogin(*pUser);
            return HALT;
        }

        NoImapSock* pSock = new NoImapSock(this, Auth);
        pSock->Connect(m_sServer, m_uPort, m_bSSL, 20);

        return HALT;
    }

    void OnModCommand(const NoString& sLine) override {}

    void CacheLogin(const NoString& sLogin) { m_Cache.AddItem(sLogin); }

    // Getters
    const NoString& GetUserFormat() const { return m_sUserFormat; }
    // !Getters
private:
    // Settings
    NoString m_sServer;
    ushort m_uPort;
    bool m_bSSL;
    NoString m_sUserFormat;
    // !Settings

    NoCacheMap<NoString> m_Cache;
};

void NoImapSock::ReadLineImpl(const NoString& sLine)
{
    if (!m_bSentLogin) {
        NoString sUsername = m_spAuth->GetUsername();
        m_bSentLogin = true;

        const NoString& sFormat = m_pIMAPMod->GetUserFormat();

        if (!sFormat.empty()) {
            if (sFormat.find('%') != NoString::npos) {
                sUsername = sFormat.replace_n("%", sUsername);
            } else {
                sUsername += sFormat;
            }
        }

        Write("AUTH LOGIN " + sUsername + " " + m_spAuth->GetPassword() + "\r\n");
    } else if (sLine.left(5) == "AUTH ") {
        NoUser* pUser = NoApp::Get().FindUser(m_spAuth->GetUsername());

        if (pUser && sLine.startsWith("AUTH OK")) {
            m_spAuth->AcceptLogin(*pUser);
            // Use MD5 so passes don't sit in memory in plain text
            m_pIMAPMod->CacheLogin(NoUtils::MD5(m_spAuth->GetUsername() + ":" + m_spAuth->GetPassword()));
            NO_DEBUG("+++ Successful IMAP lookup");
        } else {
            m_spAuth->RefuseLogin("Invalid Password");
            NO_DEBUG("--- FAILED IMAP lookup");
        }

        m_bSentReply = true;
        Close();
    }
}

template <> void no_moduleInfo<NoImapAuthMod>(NoModInfo& Info)
{
    Info.SetWikiPage("imapauth");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("[ server [+]port [ UserFormatString ] ]");
}

GLOBALMODULEDEFS(NoImapAuthMod, "Allow users to authenticate via IMAP.")
