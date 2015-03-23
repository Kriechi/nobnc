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
#include <no/nonetwork.h>
#include <no/noircsocket.h>
#include <no/nodebug.h>
#include <no/noregistry.h>

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
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSaslMod::PrintHelp),
                   "search",
                   "Generate this output");
        AddCommand("Set",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSaslMod::Set),
                   "<username> [<password>]",
                   "Set username and password for the mechanisms that need them. Password is optional");
        AddCommand("Mechanism",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSaslMod::SetMechanismCommand),
                   "[mechanism[ ...]]",
                   "Set the mechanisms to be attempted (in order)");
        AddCommand("RequireAuth",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSaslMod::RequireAuthCommand),
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
        NoRegistry registry(this);
        registry.setValue("username", No::token(sLine, 1));
        registry.setValue("password", No::token(sLine, 2));

        PutModule("Username has been set to [" + registry.value("username") + "]");
        PutModule("Password has been set to [" + registry.value("password") + "]");
    }

    void SetMechanismCommand(const NoString& sLine)
    {
        NoString sMechanisms = No::tokens(sLine, 1).toUpper();

        if (!sMechanisms.empty()) {
            NoStringVector vsMechanisms = sMechanisms.split(" ");

            for (NoStringVector::const_iterator it = vsMechanisms.begin(); it != vsMechanisms.end(); ++it) {
                if (!SupportsMechanism(*it)) {
                    PutModule("Unsupported mechanism: " + *it);
                    return;
                }
            }

            NoRegistry registry(this);
            registry.setValue(NV_MECHANISMS, sMechanisms);
        }

        PutModule("Current mechanisms set: " + GetMechanismsString());
    }

    void RequireAuthCommand(const NoString& sLine)
    {
        NoRegistry registry(this);
        if (!No::token(sLine, 1).empty()) {
            registry.setValue(NV_REQUIRE_AUTH, No::token(sLine, 1));
        }

        if (registry.value(NV_REQUIRE_AUTH).toBool()) {
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
        NoRegistry registry(this);
        if (!registry.contains(NV_MECHANISMS)) {
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

        return registry.value(NV_MECHANISMS);
    }

    bool CheckRequireAuth()
    {
        NoRegistry registry(this);
        if (!m_bAuthenticated && registry.value(NV_REQUIRE_AUTH).toBool()) {
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
            NoRegistry registry(this);
            NoString sAuthLine = registry.value("username") + '\0' + registry.value("username") + '\0' + registry.value("password");
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
        if (No::token(sLine, 0).equals("AUTHENTICATE")) {
            Authenticate(No::tokens(sLine, 1));
        } else if (No::token(sLine, 1).equals("903")) {
            /* SASL success! */
            GetNetwork()->GetIRCSock()->ResumeCap();
            m_bAuthenticated = true;
            NO_DEBUG("sasl: Authenticated with mechanism [" << m_Mechanisms.GetCurrent() << "]");
        } else if (No::token(sLine, 1).equals("904") || No::token(sLine, 1).equals("905")) {
            NO_DEBUG("sasl: Mechanism [" << m_Mechanisms.GetCurrent() << "] failed.");
            PutModule(m_Mechanisms.GetCurrent() + " mechanism failed.");

            if (m_Mechanisms.HasNext()) {
                m_Mechanisms.IncrementIndex();
                PutIRC("AUTHENTICATE " + m_Mechanisms.GetCurrent());
            } else {
                CheckRequireAuth();
                GetNetwork()->GetIRCSock()->ResumeCap();
            }
        } else if (No::token(sLine, 1).equals("906")) {
            /* CAP wasn't paused? */
            NO_DEBUG("sasl: Reached 906.");
            CheckRequireAuth();
        } else if (No::token(sLine, 1).equals("907")) {
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

template <> void no_moduleInfo<NoSaslMod>(NoModuleInfo& Info) { Info.SetWikiPage("sasl"); }

NETWORKMODULEDEFS(NoSaslMod, "Adds support for sasl authentication capability to authenticate to an IRC server")
