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

#include <no/nonetwork.h>
#include <no/noircconnection.h>

class NoKeepNickMod;

class NoKeepNickTimer : public NoTimer
{
public:
    NoKeepNickTimer(NoKeepNickMod* pMod);
    ~NoKeepNickTimer() {}

    void RunJob() override;

private:
    NoKeepNickMod* m_pMod;
};

class NoKeepNickMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoKeepNickMod)
    {
        AddHelpCommand();
        AddCommand("Enable",
                   static_cast<NoModCommand::ModCmdFunc>(&NoKeepNickMod::OnEnableCommand),
                   "",
                   "Try to get your primary nick");
        AddCommand("Disable",
                   static_cast<NoModCommand::ModCmdFunc>(&NoKeepNickMod::OnDisableCommand),
                   "",
                   "No longer trying to get your primary nick");
        AddCommand("State",
                   static_cast<NoModCommand::ModCmdFunc>(&NoKeepNickMod::OnStateCommand),
                   "",
                   "Show the current state");
    }

    ~NoKeepNickMod() {}

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        m_pTimer = nullptr;

        // Check if we need to start the timer
        if (GetNetwork()->IsIRCConnected()) OnIRCConnected();

        return true;
    }

    void KeepNick()
    {
        if (!m_pTimer)
            // No timer means we are turned off
            return;

        NoIrcConnection* pIRCSock = GetNetwork()->GetIRCSock();

        if (!pIRCSock) return;

        // Do we already have the nick we want?
        if (pIRCSock->GetNick().Equals(GetNick())) return;

        PutIRC("NICK " + GetNick());
    }

    NoString GetNick()
    {
        NoString sConfNick = GetNetwork()->GetNick();
        NoIrcConnection* pIRCSock = GetNetwork()->GetIRCSock();

        if (pIRCSock) sConfNick = sConfNick.Left(pIRCSock->GetMaxNickLen());

        return sConfNick;
    }

    void OnNick(const NoNick& Nick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans) override
    {
        if (sNewNick == GetNetwork()->GetIRCSock()->GetNick()) {
            // We are changing our own nick
            if (Nick.equals(GetNick())) {
                // We are changing our nick away from the conf setting.
                // Let's assume the user wants this and disable
                // this module (to avoid fighting nickserv).
                Disable();
            } else if (sNewNick.Equals(GetNick())) {
                // We are changing our nick to the conf setting,
                // so we don't need that timer anymore.
                Disable();
            }
            return;
        }

        // If the nick we want is free now, be fast and get the nick
        if (Nick.equals(GetNick())) {
            KeepNick();
        }
    }

    void OnQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans) override
    {
        // If someone with the nick we want quits, be fast and get the nick
        if (Nick.equals(GetNick())) {
            KeepNick();
        }
    }

    void OnIRCDisconnected() override
    {
        // No way we can do something if we aren't connected to IRC.
        Disable();
    }

    void OnIRCConnected() override
    {
        if (!GetNetwork()->GetIRCSock()->GetNick().Equals(GetNick())) {
            // We don't have the nick we want, try to get it
            Enable();
        }
    }

    void Enable()
    {
        if (m_pTimer) return;

        m_pTimer = new NoKeepNickTimer(this);
        AddTimer(m_pTimer);
    }

    void Disable()
    {
        if (!m_pTimer) return;

        m_pTimer->Stop();
        RemTimer(m_pTimer);
        m_pTimer = nullptr;
    }

    EModRet OnUserRaw(NoString& sLine) override
    {
        // We dont care if we are not connected to IRC
        if (!GetNetwork()->IsIRCConnected()) return CONTINUE;

        // We are trying to get the config nick and this is a /nick?
        if (!m_pTimer || !sLine.Token(0).Equals("NICK")) return CONTINUE;

        // Is the nick change for the nick we are trying to get?
        NoString sNick = sLine.Token(1);

        // Don't even think of using spaces in your nick!
        if (sNick.Left(1) == ":") sNick.LeftChomp(1);

        if (!sNick.Equals(GetNick())) return CONTINUE;

        // Indeed trying to change to this nick, generate a 433 for it.
        // This way we can *always* block incoming 433s from the server.
        PutUser(":" + GetNetwork()->GetIRNoServer() + " 433 " + GetNetwork()->GetIRNoNick().nick() + " " + sNick +
                " :ZNC is already trying to get this nickname");
        return CONTINUE;
    }

    EModRet OnRaw(NoString& sLine) override
    {
        // Are we trying to get our primary nick and we caused this error?
        // :irc.server.net 433 mynick badnick :Nickname is already in use.
        if (m_pTimer && sLine.Token(1) == "433" && sLine.Token(3).Equals(GetNick())) return HALT;

        return CONTINUE;
    }

    void OnEnableCommand(const NoString& sCommand)
    {
        Enable();
        PutModule("Trying to get your primary nick");
    }

    void OnDisableCommand(const NoString& sCommand)
    {
        Disable();
        PutModule("No longer trying to get your primary nick");
    }

    void OnStateCommand(const NoString& sCommand)
    {
        if (m_pTimer)
            PutModule("Currently trying to get your primary nick");
        else
            PutModule("Currently disabled, try 'enable'");
    }

private:
    // If this is nullptr, we are turned off for some reason
    NoKeepNickTimer* m_pTimer;
};

NoKeepNickTimer::NoKeepNickTimer(NoKeepNickMod* pMod)
    : NoTimer(pMod, 30, 0, "KeepNickTimer", "Tries to acquire this user's primary nick")
{
    m_pMod = pMod;
}

void NoKeepNickTimer::RunJob() { m_pMod->KeepNick(); }

template <> void TModInfo<NoKeepNickMod>(NoModInfo& Info) { Info.SetWikiPage("keepnick"); }

NETWORKMODULEDEFS(NoKeepNickMod, "Keep trying for your primary nick")
