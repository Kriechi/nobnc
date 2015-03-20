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
#include <no/nonetwork.h>
#include <no/noircconnection.h>
#include <no/nodebug.h>

static const struct
{
    const char* szName;
    const char* szDescription;
    const bool bDefault;
} SupportedMechanisms[] = { { "EXTERNAL", "TLS certificate, for use with the *cert module", false },
                            { "PLAIN", "Plain text negotiation, this should work always if the network supports SASL", true },
                            { nullptr, nullptr, false } };

#define NV_REQUIRE_AUTH "require_auth"
#define NV_MECHANISMS "mechanisms"

class Mechanisms : public NoStringVector
{
public:
    Mechanisms& operator=(const NoStringVector& other) { *this = other; return *this; }

    void SetIndex(uint uiIndex) { m_uiIndex = uiIndex; }

    uint GetIndex() const { return m_uiIndex; }

    bool HasNext() const { return size() > (m_uiIndex + 1); }

    void IncrementIndex() { m_uiIndex++; }

    NoString GetCurrent() const { return at(m_uiIndex); }

    NoString GetNext() const
    {
        if (HasNext()) {
            return at(m_uiIndex + 1);
        }

        return "";
    }

private:
    uint m_uiIndex;
};

class NoSaslMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoSaslMod)
    {
        AddCommand("Help",
                   static_cast<NoModCommand::ModCmdFunc>(&NoSaslMod::PrintHelp),
                   "search",
                   "Generate this output");
        AddCommand("Set",
                   static_cast<NoModCommand::ModCmdFunc>(&NoSaslMod::Set),
                   "<username> [<password>]",
                   "Set username and password for the mechanisms that need them. Password is optional");
        AddCommand("Mechanism",
                   static_cast<NoModCommand::ModCmdFunc>(&NoSaslMod::SetMechanismCommand),
                   "[mechanism[ ...]]",
                   "Set the mechanisms to be attempted (in order)");
        AddCommand("RequireAuth",
                   static_cast<NoModCommand::ModCmdFunc>(&NoSaslMod::RequireAuthCommand),
                   "[yes|no]",
                   "Don't connect unless SASL authentication succeeds");

        m_bAuthenticated = false;
    }

    void PrintHelp(const NoString& sLine)
    {
        HandleHelpCommand(sLine);

        NoTable Mechanisms;
        Mechanisms.AddColumn("Mechanism");
        Mechanisms.AddColumn("Description");

        for (size_t i = 0; SupportedMechanisms[i].szName != nullptr; i++) {
            Mechanisms.AddRow();
            Mechanisms.SetCell("Mechanism", SupportedMechanisms[i].szName);
            Mechanisms.SetCell("Description", SupportedMechanisms[i].szDescription);
        }

        PutModule("The following mechanisms are available:");
        PutModule(Mechanisms);
    }

    void Set(const NoString& sLine)
    {
        SetNV("username", sLine.token(1));
        SetNV("password", sLine.token(2));

        PutModule("Username has been set to [" + GetNV("username") + "]");
        PutModule("Password has been set to [" + GetNV("password") + "]");
    }

    void SetMechanismCommand(const NoString& sLine)
    {
        NoString sMechanisms = sLine.tokens(1).toUpper();

        if (!sMechanisms.empty()) {
            NoStringVector vsMechanisms = sMechanisms.split(" ");

            for (NoStringVector::const_iterator it = vsMechanisms.begin(); it != vsMechanisms.end(); ++it) {
                if (!SupportsMechanism(*it)) {
                    PutModule("Unsupported mechanism: " + *it);
                    return;
                }
            }

            SetNV(NV_MECHANISMS, sMechanisms);
        }

        PutModule("Current mechanisms set: " + GetMechanismsString());
    }

    void RequireAuthCommand(const NoString& sLine)
    {
        if (!sLine.token(1).empty()) {
            SetNV(NV_REQUIRE_AUTH, sLine.token(1));
        }

        if (GetNV(NV_REQUIRE_AUTH).toBool()) {
            PutModule("We require SASL negotiation to connect");
        } else {
            PutModule("We will connect even if SASL fails");
        }
    }

    bool SupportsMechanism(const NoString& sMechanism) const
    {
        for (size_t i = 0; SupportedMechanisms[i].szName != nullptr; i++) {
            if (sMechanism.equals(SupportedMechanisms[i].szName)) {
                return true;
            }
        }

        return false;
    }

    NoString GetMechanismsString() const
    {
        if (GetNV(NV_MECHANISMS).empty()) {
            NoString sDefaults = "";

            for (size_t i = 0; SupportedMechanisms[i].szName != nullptr; i++) {
                if (SupportedMechanisms[i].bDefault) {
                    if (!sDefaults.empty()) {
                        sDefaults += " ";
                    }

                    sDefaults += SupportedMechanisms[i].szName;
                }
            }

            return sDefaults;
        }

        return GetNV(NV_MECHANISMS);
    }

    bool CheckRequireAuth()
    {
        if (!m_bAuthenticated && GetNV(NV_REQUIRE_AUTH).toBool()) {
            GetNetwork()->SetIRCConnectEnabled(false);
            PutModule("Disabling network, we require authentication.");
            PutModule("Use 'RequireAuth no' to disable.");
            return true;
        }

        return false;
    }

    void Authenticate(const NoString& sLine)
    {
        if (m_Mechanisms.GetCurrent().equals("PLAIN") && sLine.equals("+")) {
            NoString sAuthLine = GetNV("username") + '\0' + GetNV("username") + '\0' + GetNV("password");
            sAuthLine = sAuthLine.toBase64();
            PutIRC("AUTHENTICATE " + sAuthLine);
        } else {
            /* Send blank authenticate for other mechanisms (like EXTERNAL). */
            PutIRC("AUTHENTICATE +");
        }
    }

    bool OnServerCapAvailable(const NoString& sCap) override { return sCap.equals("sasl"); }

    void OnServerCapResult(const NoString& sCap, bool bSuccess) override
    {
        if (sCap.equals("sasl")) {
            if (bSuccess) {
                m_Mechanisms = GetMechanismsString().split(" ");

                if (m_Mechanisms.empty()) {
                    CheckRequireAuth();
                    return;
                }

                GetNetwork()->GetIRCSock()->PauseCap();

                m_Mechanisms.SetIndex(0);
                PutIRC("AUTHENTICATE " + m_Mechanisms.GetCurrent());
            } else {
                CheckRequireAuth();
            }
        }
    }

    ModRet OnRaw(NoString& sLine) override
    {
        if (sLine.token(0).equals("AUTHENTICATE")) {
            Authenticate(sLine.tokens(1));
        } else if (sLine.token(1).equals("903")) {
            /* SASL success! */
            GetNetwork()->GetIRCSock()->ResumeCap();
            m_bAuthenticated = true;
            NO_DEBUG("sasl: Authenticated with mechanism [" << m_Mechanisms.GetCurrent() << "]");
        } else if (sLine.token(1).equals("904") || sLine.token(1).equals("905")) {
            NO_DEBUG("sasl: Mechanism [" << m_Mechanisms.GetCurrent() << "] failed.");
            PutModule(m_Mechanisms.GetCurrent() + " mechanism failed.");

            if (m_Mechanisms.HasNext()) {
                m_Mechanisms.IncrementIndex();
                PutIRC("AUTHENTICATE " + m_Mechanisms.GetCurrent());
            } else {
                CheckRequireAuth();
                GetNetwork()->GetIRCSock()->ResumeCap();
            }
        } else if (sLine.token(1).equals("906")) {
            /* CAP wasn't paused? */
            NO_DEBUG("sasl: Reached 906.");
            CheckRequireAuth();
        } else if (sLine.token(1).equals("907")) {
            m_bAuthenticated = true;
            GetNetwork()->GetIRCSock()->ResumeCap();
            NO_DEBUG("sasl: Received 907 -- We are already registered");
        } else {
            return CONTINUE;
        }

        return HALT;
    }

    void OnIRCConnected() override
    {
        /* Just incase something slipped through, perhaps the server doesn't
         * respond to our CAP negotiation. */

        CheckRequireAuth();
    }

    void OnIRCDisconnected() override { m_bAuthenticated = false; }

private:
    Mechanisms m_Mechanisms;
    bool m_bAuthenticated;
};

template <> void no_moduleInfo<NoSaslMod>(NoModInfo& Info) { Info.SetWikiPage("sasl"); }

NETWORKMODULEDEFS(NoSaslMod, "Adds support for sasl authentication capability to authenticate to an IRC server")
