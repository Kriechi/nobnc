/*
 * Copyright (C) 2004-2015 ZNC, see the NOTICE file for details.
 * This was originally written by cycomate.
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

/*
 * Autorejoin module
 * rejoin channel (after a delay) when kicked
 * Usage: LoadModule = rejoin [delay]
 *
 */

#include <no/nomodule.h>
#include <no/nochannel.h>
#include <no/nonetwork.h>

class NoRejoinJob : public NoTimer
{
public:
    NoRejoinJob(NoModule* pModule, uint uInterval, uint uCycles, const NoString& sLabel, const NoString& sDescription)
        : NoTimer(pModule, uInterval, uCycles, sLabel, sDescription)
    {
    }

protected:
    void RunJob() override
    {
        NoNetwork* pNetwork = module()->GetNetwork();
        NoChannel* pChan = pNetwork->FindChan(GetName().Tokens(1));

        if (pChan) {
            pChan->enable();
            module()->PutIRC("JOIN " + pChan->getName() + " " + pChan->getKey());
        }
    }
};

class NoRejoinMod : public NoModule
{
private:
    uint delay;

public:
    MODCONSTRUCTOR(NoRejoinMod)
    {
        AddHelpCommand();
        AddCommand("SetDelay",
                   static_cast<NoModCommand::ModCmdFunc>(&NoRejoinMod::OnSetDelayCommand),
                   "<secs>",
                   "Set the rejoin delay");
        AddCommand("ShowDelay",
                   static_cast<NoModCommand::ModCmdFunc>(&NoRejoinMod::OnShowDelayCommand),
                   "",
                   "Show the rejoin delay");
    }

    bool OnLoad(const NoString& sArgs, NoString& sErrorMsg) override
    {
        if (sArgs.empty()) {
            NoString sDelay = GetNV("delay");

            if (sDelay.empty())
                delay = 10;
            else
                delay = sDelay.ToUInt();
        } else {
            int i = sArgs.ToInt();
            if ((i == 0 && sArgs == "0") || i > 0)
                delay = i;
            else {
                sErrorMsg = "Illegal argument, "
                            "must be a positive number or 0";
                return false;
            }
        }

        return true;
    }

    void OnSetDelayCommand(const NoString& sCommand)
    {
        int i;
        i = sCommand.Token(1).ToInt();

        if (i < 0) {
            PutModule("Negative delays don't make any sense!");
            return;
        }

        delay = i;
        SetNV("delay", NoString(delay));

        if (delay)
            PutModule("Rejoin delay set to " + NoString(delay) + " seconds");
        else
            PutModule("Rejoin delay disabled");
    }

    void OnShowDelayCommand(const NoString& sCommand)
    {
        if (delay)
            PutModule("Rejoin delay enabled, " + NoString(delay) + " seconds");
        else
            PutModule("Rejoin delay disabled");
    }

    void OnKick(const NoNick& OpNick, const NoString& sKickedNick, NoChannel& pChan, const NoString& sMessage) override
    {
        if (GetNetwork()->GetCurNick().Equals(sKickedNick)) {
            if (!delay) {
                PutIRC("JOIN " + pChan.getName() + " " + pChan.getKey());
                pChan.enable();
                return;
            }
            AddTimer(new NoRejoinJob(this, delay, 1, "Rejoin " + pChan.getName(), "Rejoin channel after a delay"));
        }
    }
};

template <> void TModInfo<NoRejoinMod>(NoModInfo& Info)
{
    Info.SetWikiPage("kickrejoin");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("You might enter the number of seconds to wait before rejoining.");
}

NETWORKMODULEDEFS(NoRejoinMod, "Autorejoin on kick")
