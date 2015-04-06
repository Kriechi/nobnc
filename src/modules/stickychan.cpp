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
#include <nobnc/nochannel.h>
#include <nobnc/nonetwork.h>
#include <nobnc/noregistry.h>
#include <nobnc/noutils.h>
#include <nobnc/notimer.h>

class NoStickyChan : public NoModule
{
public:
    MODCONSTRUCTOR(NoStickyChan)
    {
        addHelpCommand();
        addCommand("Stick", static_cast<NoModule::CommandFunction>(&NoStickyChan::OnStickCommand), "<#channel> [key]", "Sticks a channel");
        addCommand("Unstick", static_cast<NoModule::CommandFunction>(&NoStickyChan::OnUnstickCommand), "<#channel>", "Unsticks a channel");
        addCommand("List",
                   static_cast<NoModule::CommandFunction>(&NoStickyChan::OnListCommand),
                   "",
                   "Lists sticky channels");
    }

    bool onLoad(const NoString& args, NoString& message) override;

    Return onUserPart(NoString& channel, NoString& message) override
    {
        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            if (channel.equals(key)) {
                NoChannel* chan = network()->findChannel(channel);

                if (chan) {
                    chan->joinUser();
                    return Halt;
                }
            }
        }

        return Continue;
    }

    virtual void onMode(const NoNick* opNick, NoChannel* channel, char mode, const NoString& arg, bool added, bool noChange) override
    {
        if (mode == NoChannel::M_Key) {
            if (added) {
                // We ignore channel key "*" because of some broken nets.
                if (arg != "*") {
                    NoRegistry registry(this);
                    registry.setValue(channel->name(), arg);
                }
            } else {
                NoRegistry registry(this);
                registry.setValue(channel->name(), "");
            }
        }
    }

    void OnStickCommand(const NoString& command)
    {
        NoString channel = No::token(command, 1).toLower();
        if (channel.empty()) {
            putModule("Usage: Stick <#channel> [key]");
            return;
        }
        NoRegistry registry(this);
        registry.setValue(channel, No::token(command, 2));
        putModule("Stuck " + channel);
    }

    void OnUnstickCommand(const NoString& command)
    {
        NoString channel = No::token(command, 1);
        if (channel.empty()) {
            putModule("Usage: Unstick <#channel>");
            return;
        }
        NoRegistry registry(this);
        registry.remove(channel);
        putModule("Unstuck " + channel);
    }

    void OnListCommand(const NoString& command)
    {
        int i = 1;
        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            NoString value = registry.value(key);
            if (value.empty())
                putModule(NoString(i) + ": " + key);
            else
                putModule(NoString(i) + ": " + key + " (" + value + ")");
        }
        putModule(" -- End of List");
    }
};

class NoStickyTimer : public NoTimer
{
public:
    NoStickyTimer(NoModule* module) : NoTimer(module)
    {
        setName("StickyChanTimer");
    }

protected:
    void run() override
    {
        NoModule* mod = module();
        if (!mod)
            return;

        NoNetwork* network = mod->network();
        if (!network->ircSocket())
            return;

        NoRegistry registry(module());
        for (const NoString& key : registry.keys()) {
            NoChannel* channel = network->findChannel(key);
            if (!channel) {
                channel = new NoChannel(key, network, true);
                if (!registry.value(key).empty())
                    channel->setKey(registry.value(key));
                if (!network->addChannel(channel)) {
                    /* addChannel() deleted that channel */
                    mod->putModule("Could not join [" + key + "] (# prefix missing?)");
                    continue;
                }
            }
            if (!channel->isOn() && network->isIrcConnected()) {
                mod->putModule("Joining [" + channel->name() + "]");
                mod->putIrc("JOIN " + channel->name() + (channel->key().empty() ? "" : " " + channel->key()));
            }
        }
    }
};

bool NoStickyChan::onLoad(const NoString& args, NoString& message)
{
    NoStringVector vsChans = args.split(",", No::SkipEmptyParts);
    NoStringVector::iterator it;

    for (it = vsChans.begin(); it != vsChans.end(); ++it) {
        NoString sChan = No::token(*it, 0);
        NoString key = No::tokens(*it, 1);
        NoRegistry registry(this);
        registry.setValue(sChan, key);
    }

    // Since we now have these channels added, clear the argument list
    setArgs("");

    NoStickyTimer* timer = new NoStickyTimer(this);
    timer->start(15);
    return (true);
}

template <>
void no_moduleInfo<NoStickyChan>(NoModuleInfo& info)
{
    info.setWikiPage("stickychan");
    info.setHasArgs(true);
    info.setArgsHelpText("List of channels, separated by comma.");
}

NETWORKMODULEDEFS(NoStickyChan, "configless sticky chans, keeps you there very stickily even")
