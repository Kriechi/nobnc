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
#include <no/noapp.h>
#include <no/nodebug.h>
#include <no/noclient.h>
#include <no/noauthenticator.h>
#include <no/nomodulesocket.h>

class NoImapAuthMod;

class NoImapSock : public NoModuleSocket
{
public:
    NoImapSock(NoImapAuthMod* module, std::shared_ptr<NoAuthenticator> Auth)
        : NoModuleSocket((NoModule*)module), m_spAuth(Auth)
    {
        m_pIMAPMod = module;
        m_bSentReply = false;
        m_bSentLogin = false;
        enableReadLine();
    }

    virtual ~NoImapSock()
    {
        if (!m_bSentReply) {
            m_spAuth->refuseLogin("IMAP server is down, please try again later");
        }
    }

    void readLine(const NoString& line) override;

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
        m_Cache.setExpiration(60000);
        m_sServer = "localhost";
        m_uPort = 143;
        m_bSSL = false;
    }

    bool onBoot() override
    {
        return true;
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        if (args.trim_n().empty()) {
            return true; // use defaults
        }

        m_sServer = No::token(args, 0);
        NoString sPort = No::token(args, 1);
        m_sUserFormat = No::token(args, 2);

        if (sPort.left(1) == "+") {
            m_bSSL = true;
            sPort.leftChomp(1);
        }

        ushort port = sPort.toUShort();

        if (port) {
            m_uPort = port;
        }

        return true;
    }

    ModRet onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth) override
    {
        NoUser* user = noApp->findUser(Auth->username());

        if (!user) { // @todo Will want to do some sort of && !m_bAllowCreate in the future
            Auth->refuseLogin("Invalid User - Halting IMAP Lookup");
            return HALT;
        }

        if (user && m_Cache.contains(No::md5(Auth->username() + ":" + Auth->password()))) {
            NO_DEBUG("+++ Found in cache");
            Auth->acceptLogin(user);
            return HALT;
        }

        NoImapSock* socket = new NoImapSock(this, Auth);
        socket->connect(m_sServer, m_uPort, m_bSSL, 20);

        return HALT;
    }

    void onModCommand(const NoString& line) override
    {
    }

    void CacheLogin(const NoString& sLogin)
    {
        m_Cache.insert(sLogin);
    }

    // Getters
    const NoString& GetUserFormat() const
    {
        return m_sUserFormat;
    }
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

void NoImapSock::readLine(const NoString& line)
{
    if (!m_bSentLogin) {
        NoString username = m_spAuth->username();
        m_bSentLogin = true;

        const NoString& format = m_pIMAPMod->GetUserFormat();

        if (!format.empty()) {
            if (format.contains('%')) {
                username = format.replace_n("%", username);
            } else {
                username += format;
            }
        }

        write("AUTH LOGIN " + username + " " + m_spAuth->password() + "\r\n");
    } else if (line.left(5) == "AUTH ") {
        NoUser* user = noApp->findUser(m_spAuth->username());

        if (user && line.startsWith("AUTH OK")) {
            m_spAuth->acceptLogin(user);
            // Use MD5 so passes don't sit in memory in plain text
            m_pIMAPMod->CacheLogin(No::md5(m_spAuth->username() + ":" + m_spAuth->password()));
            NO_DEBUG("+++ Successful IMAP lookup");
        } else {
            m_spAuth->refuseLogin("Invalid Password");
            NO_DEBUG("--- FAILED IMAP lookup");
        }

        m_bSentReply = true;
        close();
    }
}

template <>
void no_moduleInfo<NoImapAuthMod>(NoModuleInfo& info)
{
    info.setWikiPage("imapauth");
    info.setHasArgs(true);
    info.setArgsHelpText("[ server [+]port [ UserFormatString ] ]");
}

GLOBALMODULEDEFS(NoImapAuthMod, "Allow users to authenticate via IMAP.")
