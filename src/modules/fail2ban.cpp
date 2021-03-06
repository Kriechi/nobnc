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
#include <nobnc/noapp.h>
#include <nobnc/noclient.h>
#include <nobnc/noauthenticator.h>
#include <nobnc/nosocket.h>

class NoFailToBanMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoFailToBanMod)
    {
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        NoString sTimeout = No::token(args, 0);
        NoString sAttempts = No::token(args, 1);
        uint timeout = sTimeout.toUInt();

        if (sAttempts.empty())
            m_uiAllowedFailed = 2;
        else
            m_uiAllowedFailed = sAttempts.toUInt();
        ;

        if (args.empty()) {
            timeout = 1;
        } else if (timeout == 0 || m_uiAllowedFailed == 0 || !No::tokens(args, 2).empty()) {
            message = "Invalid argument, must be the number of minutes "
                       "IPs are blocked after a failed login and can be "
                       "followed by number of allowed failed login attempts";
            return false;
        }

        // SetTTL() wants milliseconds
        m_Cache.setExpiration(timeout * 60 * 1000);

        return true;
    }

    void onPostRehash() override
    {
        m_Cache.clear();
    }

    void Add(const NoString& host, uint count)
    {
        m_Cache.insert(host, count);
    }

    void onModuleCommand(const NoString& command) override
    {
        putModule("This module can only be configured through its arguments.");
        putModule("The module argument is the number of minutes an IP");
        putModule("is blocked after a failed login.");
    }

    void onClientConnect(NoSocket* client, const NoString& host, ushort port) override
    {
        uint* pCount = m_Cache.value(host);
        if (host.empty() || pCount == nullptr || *pCount < m_uiAllowedFailed) {
            return;
        }

        // refresh their ban
        Add(host, *pCount);

        client->write("ERROR :Closing link [Please try again later - reconnecting too fast]\r\n");
        client->close(NoSocket::CloseAfterWrite);
    }

    void onFailedLogin(const NoString& username, const NoString& sRemoteIP) override
    {
        uint* pCount = m_Cache.value(sRemoteIP);
        if (pCount)
            Add(sRemoteIP, *pCount + 1);
        else
            Add(sRemoteIP, 1);
    }

    Return onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth) override
    {
        // e.g. webadmin ends up here
        const NoString& sRemoteIP = Auth->socket()->remoteAddress();

        if (sRemoteIP.empty())
            return Continue;

        uint* pCount = m_Cache.value(sRemoteIP);
        if (pCount && *pCount >= m_uiAllowedFailed) {
            // onFailedLogin() will refresh their ban
            Auth->refuseLogin("Please try again later - reconnecting too fast");
            return Halt;
        }

        return Continue;
    }

private:
    NoCacheMap<NoString, uint> m_Cache;
    uint m_uiAllowedFailed;
};

template <>
void no_moduleInfo<NoFailToBanMod>(NoModuleInfo& info)
{
    info.setWikiPage("fail2ban");
    info.setHasArgs(true);
    info.setArgsHelpText("You might enter the time in minutes for the IP banning and the number of failed logins "
                         "before any action is taken.");
}

GLOBALMODULEDEFS(NoFailToBanMod, "Block IPs for some time after a failed login.")
