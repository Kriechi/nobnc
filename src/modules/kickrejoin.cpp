/*
 * Copyright (C) 2015 NoBNC
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

#include <nobnc/nomodule.h>
#include <nobnc/nochannel.h>
#include <nobnc/nonetwork.h>
#include <nobnc/noregistry.h>
#include <nobnc/notimer.h>
#include <nobnc/noutils.h>

class NoRejoinJob : public NoTimer
{
public:
    NoRejoinJob(NoModule* module, const NoString& sChan) : NoTimer(module)
    {
        setName("Rejoin " + sChan);
        setDescription("Rejoin channel after a delay");
    }

protected:
    void run() override
    {
        NoNetwork* network = module()->network();
        NoChannel* channel = network->findChannel(No::tokens(name(), 1));

        if (channel) {
            channel->enable();
            module()->putIrc("JOIN " + channel->name() + " " + channel->key());
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
        addHelpCommand();
        addCommand("SetDelay",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoRejoinMod::OnSetDelayCommand),
                   "<secs>",
                   "Set the rejoin delay");
        addCommand("ShowDelay",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoRejoinMod::OnShowDelayCommand),
                   "",
                   "Show the rejoin delay");
    }

    bool onLoad(const NoString& args, NoString& sErrorMsg) override
    {
        if (args.empty()) {
            NoRegistry registry(this);
            NoString sDelay = registry.value("delay");

            if (sDelay.empty())
                delay = 10;
            else
                delay = sDelay.toUInt();
        } else {
            int i = args.toInt();
            if ((i == 0 && args == "0") || i > 0)
                delay = i;
            else {
                sErrorMsg = "Illegal argument, "
                            "must be a positive number or 0";
                return false;
            }
        }

        return true;
    }

    void OnSetDelayCommand(const NoString& command)
    {
        int i;
        i = No::token(command, 1).toInt();

        if (i < 0) {
            putModule("Negative delays don't make any sense!");
            return;
        }

        delay = i;
        NoRegistry registry(this);
        registry.setValue("delay", NoString(delay));

        if (delay)
            putModule("Rejoin delay set to " + NoString(delay) + " seconds");
        else
            putModule("Rejoin delay disabled");
    }

    void OnShowDelayCommand(const NoString& command)
    {
        if (delay)
            putModule("Rejoin delay enabled, " + NoString(delay) + " seconds");
        else
            putModule("Rejoin delay disabled");
    }

    void onKick(const NoNick& opNick, const NoString& sKickedNick, NoChannel* channel, const NoString& message) override
    {
        if (network()->currentNick().equals(sKickedNick)) {
            if (!delay) {
                putIrc("JOIN " + channel->name() + " " + channel->key());
                channel->enable();
                return;
            }
            NoRejoinJob* timer = new NoRejoinJob(this, channel->name());
            timer->setSingleShot(true);
            timer->start(delay);
        }
    }
};

template <>
void no_moduleInfo<NoRejoinMod>(NoModuleInfo& info)
{
    info.setWikiPage("kickrejoin");
    info.setHasArgs(true);
    info.setArgsHelpText("You might enter the number of seconds to wait before rejoining.");
}

NETWORKMODULEDEFS(NoRejoinMod, "Autorejoin on kick")
