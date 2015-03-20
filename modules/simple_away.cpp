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

#define SIMPLE_AWAY_DEFAULT_REASON "Auto away at %s"
#define SIMPLE_AWAY_DEFAULT_TIME 60


class NoSimpleAway;

class NoSimpleAwayJob : public NoTimer
{
public:
    NoSimpleAwayJob(NoModule* pModule, uint uInterval, uint uCycles, const NoString& sLabel, const NoString& sDescription)
        : NoTimer(pModule, uInterval, uCycles, sLabel, sDescription)
    {
    }

protected:
    void RunJob() override;
};

class NoSimpleAway : public NoModule
{
private:
    NoString m_sReason;
    uint m_iAwayWait;
    bool m_bClientSetAway;
    bool m_bWeSetAway;

public:
    MODCONSTRUCTOR(NoSimpleAway)
    {
        m_sReason = SIMPLE_AWAY_DEFAULT_REASON;
        m_iAwayWait = SIMPLE_AWAY_DEFAULT_TIME;
        m_bClientSetAway = false;
        m_bWeSetAway = false;

        AddHelpCommand();
        AddCommand("Reason",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSimpleAway::OnReasonCommand),
                   "[<text>]",
                   "Prints or sets the away reason (%s is replaced with the time you were set away)");
        AddCommand("Timer",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSimpleAway::OnTimerCommand),
                   "",
                   "Prints the current time to wait before setting you away");
        AddCommand("SetTimer",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSimpleAway::OnSetTimerCommand),
                   "<seconds>",
                   "Sets the time to wait before setting you away");
        AddCommand("DisableTimer",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSimpleAway::OnDisableTimerCommand),
                   "",
                   "Disables the wait time before setting you away");
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        NoString sReasonArg;

        // Load AwayWait
        NoString sFirstArg = sArgs.token(0);
        if (sFirstArg.equals("-notimer")) {
            SetAwayWait(0);
            sReasonArg = sArgs.tokens(1);
        } else if (sFirstArg.equals("-timer")) {
            SetAwayWait(sArgs.token(1).toUInt());
            sReasonArg = sArgs.tokens(2);
        } else {
            NoString sAwayWait = GetNV("awaywait");
            if (!sAwayWait.empty()) SetAwayWait(sAwayWait.toUInt(), false);
            sReasonArg = sArgs;
        }

        // Load Reason
        if (!sReasonArg.empty()) {
            SetReason(sReasonArg);
        } else {
            NoString sSavedReason = GetNV("reason");
            if (!sSavedReason.empty()) SetReason(sSavedReason, false);
        }

        // Set away on load, required if loaded via webadmin
        if (GetNetwork()->IsIRCConnected() && !GetNetwork()->IsUserAttached()) SetAway(false);

        return true;
    }

    void OnIRCConnected() override
    {
        if (GetNetwork()->IsUserAttached())
            SetBack();
        else
            SetAway(false);
    }

    void OnClientLogin() override { SetBack(); }

    void OnClientDisconnect() override
    {
        /* There might still be other clients */
        if (!GetNetwork()->IsUserAttached()) SetAway();
    }

    void OnReasonCommand(const NoString& sLine)
    {
        NoString sReason = sLine.tokens(1);

        if (!sReason.empty()) {
            SetReason(sReason);
            PutModule("Away reason set");
        } else {
            PutModule("Away reason: " + m_sReason);
            PutModule("Current away reason would be: " + ExpandReason());
        }
    }

    void OnTimerCommand(const NoString& sLine)
    {
        PutModule("Current timer setting: " + NoString(m_iAwayWait) + " seconds");
    }

    void OnSetTimerCommand(const NoString& sLine)
    {
        SetAwayWait(sLine.token(1).toUInt());

        if (m_iAwayWait == 0)
            PutModule("Timer disabled");
        else
            PutModule("Timer set to " + NoString(m_iAwayWait) + " seconds");
    }

    void OnDisableTimerCommand(const NoString& sLine)
    {
        SetAwayWait(0);
        PutModule("Timer disabled");
    }

    ModRet OnUserRaw(NoString& sLine) override
    {
        if (!sLine.token(0).equals("AWAY")) return CONTINUE;

        // If a client set us away, we don't touch that away message
        const NoString sArg = sLine.tokens(1).trim_n(" ");
        if (sArg.empty() || sArg == ":")
            m_bClientSetAway = false;
        else
            m_bClientSetAway = true;

        m_bWeSetAway = false;

        return CONTINUE;
    }

    void SetAway(bool bTimer = true)
    {
        if (bTimer) {
            RemTimer("simple_away");
            AddTimer(new NoSimpleAwayJob(this, m_iAwayWait, 1, "simple_away", "Sets you away after detach"));
        } else {
            if (!m_bClientSetAway) {
                PutIRC("AWAY :" + ExpandReason());
                m_bWeSetAway = true;
            }
        }
    }

    void SetBack()
    {
        RemTimer("simple_away");
        if (m_bWeSetAway) {
            PutIRC("AWAY");
            m_bWeSetAway = false;
        }
    }

private:
    NoString ExpandReason()
    {
        NoString sReason = m_sReason;
        if (sReason.empty()) sReason = SIMPLE_AWAY_DEFAULT_REASON;

        time_t iTime = time(nullptr);
        NoString sTime = NoUtils::cTime(iTime, GetUser()->GetTimezone());
        sReason.replace("%s", sTime);

        return sReason;
    }

    /* Settings */
    void SetReason(NoString& sReason, bool bSave = true)
    {
        if (bSave) SetNV("reason", sReason);
        m_sReason = sReason;
    }

    void SetAwayWait(uint iAwayWait, bool bSave = true)
    {
        if (bSave) SetNV("awaywait", NoString(iAwayWait));
        m_iAwayWait = iAwayWait;
    }
};

void NoSimpleAwayJob::RunJob() { ((NoSimpleAway*)module())->SetAway(false); }

template <> void no_moduleInfo<NoSimpleAway>(NoModuleInfo& Info)
{
    Info.SetWikiPage("simple_away");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("You might enter up to 3 arguments, like -notimer awaymessage or -timer 5 awaymessage.");
}

NETWORKMODULEDEFS(NoSimpleAway,
                  "This module will automatically set you away on IRC while you are disconnected from the bouncer.")
