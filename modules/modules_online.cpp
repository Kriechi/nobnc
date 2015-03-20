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
#include <no/nonetwork.h>
#include <no/noapp.h>
#include <no/noclient.h>

class NoFakeOnlineModule : public NoModule
{
public:
    MODCONSTRUCTOR(NoFakeOnlineModule) {}
    virtual ~NoFakeOnlineModule() {}

    bool IsOnlineModNick(const NoString& sNick)
    {
        const NoString& sPrefix = GetUser()->GetStatusPrefix();
        if (!sNick.StartsWith(sPrefix)) return false;

        NoString sModNick = sNick.substr(sPrefix.length());
        if (sModNick.Equals("status") || GetNetwork()->GetModules().FindModule(sModNick) ||
            GetUser()->GetModules().FindModule(sModNick) || NoApp::Get().GetModules().FindModule(sModNick))
            return true;
        return false;
    }

    ModRet OnUserRaw(NoString& sLine) override
    {
        // Handle ISON
        if (sLine.Token(0).Equals("ison")) {
            NoStringVector::const_iterator it;

            // Get the list of nicks which are being asked for
            NoStringVector vsNicks = sLine.Tokens(1).TrimLeft_n(":").Split(" ", No::SkipEmptyParts);

            NoString sBNNoNicks;
            for (it = vsNicks.begin(); it != vsNicks.end(); ++it) {
                if (IsOnlineModNick(*it)) {
                    sBNNoNicks += " " + *it;
                }
            }
            // Remove the leading space
            sBNNoNicks.LeftChomp(1);

            if (!GetNetwork()->GetIRCSock()) {
                // if we are not connected to any IRC server, send
                // an empty or module-nick filled response.
                PutUser(":irc.znc.in 303 " + GetClient()->GetNick() + " :" + sBNNoNicks);
            } else {
                // We let the server handle this request and then act on
                // the 303 response from the IRC server.
                m_ISONRequests.push_back(sBNNoNicks);
            }
        }

        // Handle WHOIS
        if (sLine.Token(0).Equals("whois")) {
            NoString sNick = sLine.Token(1);

            if (IsOnlineModNick(sNick)) {
                NoNetwork* pNetwork = GetNetwork();
                PutUser(":znc.in 311 " + pNetwork->GetCurNick() + " " + sNick + " " + sNick + " znc.in * :" + sNick);
                PutUser(":znc.in 312 " + pNetwork->GetCurNick() + " " + sNick + " *.znc.in :Bouncer");
                PutUser(":znc.in 318 " + pNetwork->GetCurNick() + " " + sNick + " :End of /WHOIS list.");

                return HALT;
            }
        }

        return CONTINUE;
    }

    ModRet OnRaw(NoString& sLine) override
    {
        // Handle 303 reply if m_Requests is not empty
        if (sLine.Token(1) == "303" && !m_ISONRequests.empty()) {
            NoStringVector::iterator it = m_ISONRequests.begin();

            sLine.Trim();

            // Only append a space if this isn't an empty reply
            if (sLine.Right(1) != ":") {
                sLine += " ";
            }

            // add BNC nicks to the reply
            sLine += *it;
            m_ISONRequests.erase(it);
        }

        return CONTINUE;
    }

private:
    NoStringVector m_ISONRequests;
};

template <> void TModInfo<NoFakeOnlineModule>(NoModInfo& Info) { Info.SetWikiPage("modules_online"); }

NETWORKMODULEDEFS(NoFakeOnlineModule, "Make ZNC's *modules to be \"online\".")
