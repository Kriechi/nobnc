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
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/noregistry.h>

#define SIMPLE_AWAY_DEFAULT_REASON "Auto away at %s"
#define SIMPLE_AWAY_DEFAULT_TIME 60


class NoSimpleAway;

class NoSimpleAwayJob : public NoTimer
{
public:
    NoSimpleAwayJob(NoModule* pModule) : NoTimer(pModule)
    {
        setName("simple_away");
        setDescription("Sets you away after detach");
    }

protected:
    void run() override;
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

        addHelpCommand();
        addCommand("Reason",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSimpleAway::OnReasonCommand),
                   "[<text>]",
                   "Prints or sets the away reason (%s is replaced with the time you were set away)");
        addCommand("Timer",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSimpleAway::OnTimerCommand),
                   "",
                   "Prints the current time to wait before setting you away");
        addCommand("SetTimer",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSimpleAway::OnSetTimerCommand),
                   "<seconds>",
                   "Sets the time to wait before setting you away");
        addCommand("DisableTimer",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSimpleAway::OnDisableTimerCommand),
                   "",
                   "Disables the wait time before setting you away");
    }

    bool onLoad(const NoString& sArgs, NoString& sMessage) override
    {
        NoString sReasonArg;

        // Load AwayWait
        NoString sFirstArg = No::token(sArgs, 0);
        if (sFirstArg.equals("-notimer")) {
            SetAwayWait(0);
            sReasonArg = No::tokens(sArgs, 1);
        } else if (sFirstArg.equals("-timer")) {
            SetAwayWait(No::token(sArgs, 1).toUInt());
            sReasonArg = No::tokens(sArgs, 2);
        } else {
            NoString sAwayWait = NoRegistry(this).value("awaywait");
            if (!sAwayWait.empty()) SetAwayWait(sAwayWait.toUInt(), false);
            sReasonArg = sArgs;
        }

        // Load Reason
        if (!sReasonArg.empty()) {
            SetReason(sReasonArg);
        } else {
            NoString sSavedReason = NoRegistry(this).value("reason");
            if (!sSavedReason.empty()) SetReason(sSavedReason, false);
        }

        // Set away on load, required if loaded via webadmin
        if (network()->isIrcConnected() && !network()->isUserAttached()) SetAway(false);

        return true;
    }

    void onIrcConnected() override
    {
        if (network()->isUserAttached())
            SetBack();
        else
            SetAway(false);
    }

    void onClientLogin() override { SetBack(); }

    void onClientDisconnect() override
    {
        /* There might still be other clients */
        if (!network()->isUserAttached()) SetAway();
    }

    void OnReasonCommand(const NoString& sLine)
    {
        NoString sReason = No::tokens(sLine, 1);

        if (!sReason.empty()) {
            SetReason(sReason);
            putModule("Away reason set");
        } else {
            putModule("Away reason: " + m_sReason);
            putModule("Current away reason would be: " + ExpandReason());
        }
    }

    void OnTimerCommand(const NoString& sLine)
    {
        putModule("Current timer setting: " + NoString(m_iAwayWait) + " seconds");
    }

    void OnSetTimerCommand(const NoString& sLine)
    {
        SetAwayWait(No::token(sLine, 1).toUInt());

        if (m_iAwayWait == 0)
            putModule("Timer disabled");
        else
            putModule("Timer set to " + NoString(m_iAwayWait) + " seconds");
    }

    void OnDisableTimerCommand(const NoString& sLine)
    {
        SetAwayWait(0);
        putModule("Timer disabled");
    }

    ModRet onUserRaw(NoString& sLine) override
    {
        if (!No::token(sLine, 0).equals("AWAY")) return CONTINUE;

        // If a client set us away, we don't touch that away message
        const NoString sArg = No::tokens(sLine, 1).trim_n(" ");
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
            delete findTimer("simple_away");
            NoSimpleAwayJob* timer = new NoSimpleAwayJob(this);
            timer->setSingleShot(true);
            timer->start(m_iAwayWait);
        } else {
            if (!m_bClientSetAway) {
                putIrc("AWAY :" + ExpandReason());
                m_bWeSetAway = true;
            }
        }
    }

    void SetBack()
    {
        delete findTimer("simple_away");
        if (m_bWeSetAway) {
            putIrc("AWAY");
            m_bWeSetAway = false;
        }
    }

private:
    NoString ExpandReason()
    {
        NoString sReason = m_sReason;
        if (sReason.empty()) sReason = SIMPLE_AWAY_DEFAULT_REASON;

        time_t iTime = time(nullptr);
        NoString sTime = No::cTime(iTime, user()->timezone());
        sReason.replace("%s", sTime);

        return sReason;
    }

    /* Settings */
    void SetReason(NoString& sReason, bool bSave = true)
    {
        if (bSave) {
            NoRegistry registry(this);
            registry.setValue("reason", sReason);
        }
        m_sReason = sReason;
    }

    void SetAwayWait(uint iAwayWait, bool bSave = true)
    {
        if (bSave) {
            NoRegistry registry(this);
            registry.setValue("awaywait", NoString(iAwayWait));
        }
        m_iAwayWait = iAwayWait;
    }
};

void NoSimpleAwayJob::run() { ((NoSimpleAway*)module())->SetAway(false); }

template <> void no_moduleInfo<NoSimpleAway>(NoModuleInfo& Info)
{
    Info.setWikiPage("simple_away");
    Info.setHasArgs(true);
    Info.setArgsHelpText("You might enter up to 3 arguments, like -notimer awaymessage or -timer 5 awaymessage.");
}

NETWORKMODULEDEFS(NoSimpleAway,
                  "This module will automatically set you away on IRC while you are disconnected from the bouncer.")
