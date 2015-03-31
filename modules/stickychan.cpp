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
#include <no/nochannel.h>
#include <no/nonetwork.h>
#include <no/nowebsocket.h>
#include <no/nowebsession.h>
#include <no/noregistry.h>

class NoStickyChan : public NoModule
{
public:
    MODCONSTRUCTOR(NoStickyChan)
    {
        addHelpCommand();
        addCommand("Stick", static_cast<NoModuleCommand::ModCmdFunc>(&NoStickyChan::OnStickCommand), "<#channel> [key]", "Sticks a channel");
        addCommand("Unstick", static_cast<NoModuleCommand::ModCmdFunc>(&NoStickyChan::OnUnstickCommand), "<#channel>", "Unsticks a channel");
        addCommand("List",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoStickyChan::OnListCommand),
                   "",
                   "Lists sticky channels");
    }

    bool onLoad(const NoString& args, NoString& sMessage) override;

    ModRet onUserPart(NoString& sChannel, NoString& sMessage) override
    {
        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            if (sChannel.equals(key)) {
                NoChannel* channel = network()->findChannel(sChannel);

                if (channel) {
                    channel->joinUser();
                    return HALT;
                }
            }
        }

        return CONTINUE;
    }

    virtual void onMode(const NoNick& pOpNick, NoChannel& Channel, char uMode, const NoString& arg, bool bAdded, bool bNoChange) override
    {
        if (uMode == NoChannel::M_Key) {
            if (bAdded) {
                // We ignore channel key "*" because of some broken nets.
                if (arg != "*") {
                    NoRegistry registry(this);
                    registry.setValue(Channel.name(), arg);
                }
            } else {
                NoRegistry registry(this);
                registry.setValue(Channel.name(), "");
            }
        }
    }

    void OnStickCommand(const NoString& command)
    {
        NoString sChannel = No::token(command, 1).toLower();
        if (sChannel.empty()) {
            putModule("Usage: Stick <#channel> [key]");
            return;
        }
        NoRegistry registry(this);
        registry.setValue(sChannel, No::token(command, 2));
        putModule("Stuck " + sChannel);
    }

    void OnUnstickCommand(const NoString& command)
    {
        NoString sChannel = No::token(command, 1);
        if (sChannel.empty()) {
            putModule("Usage: Unstick <#channel>");
            return;
        }
        NoRegistry registry(this);
        registry.remove(sChannel);
        putModule("Unstuck " + sChannel);
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

    NoString webMenuTitle() override
    {
        return "Sticky Chans";
    }

    bool onWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "index") {
            bool bSubmitted = (WebSock.param("submitted").toInt() != 0);

            NoRegistry registry(this);
            const std::vector<NoChannel*>& Channels = network()->channels();
            for (uint c = 0; c < Channels.size(); c++) {
                const NoString sChan = Channels[c]->name();
                bool bStick = registry.contains(sChan);

                if (bSubmitted) {
                    bool bNewStick = WebSock.param("stick_" + sChan).toBool();
                    if (bNewStick && !bStick)
                        registry.setValue(sChan, ""); // no password support for now unless chansaver is active too
                    else if (!bNewStick && bStick) {
                        registry.remove(sChan);
                    }
                    bStick = bNewStick;
                }

                NoTemplate& Row = Tmpl.addRow("ChannelLoop");
                Row["Name"] = sChan;
                Row["Sticky"] = NoString(bStick);
            }

            if (bSubmitted) {
                WebSock.session()->addSuccess("Changes have been saved!");
            }

            return true;
        }

        return false;
    }

    bool onEmbeddedWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "webadmin/channel") {
            NoString sChan = Tmpl["ChanName"];
            NoRegistry registry(this);
            bool bStick = registry.contains(sChan);
            if (Tmpl["WebadminAction"].equals("display")) {
                Tmpl["Sticky"] = NoString(bStick);
            } else if (WebSock.param("embed_stickychan_presented").toBool()) {
                bool bNewStick = WebSock.param("embed_stickychan_sticky").toBool();
                if (bNewStick && !bStick) {
                    registry.setValue(sChan, ""); // no password support for now unless chansaver is active too
                    WebSock.session()->addSuccess("Channel become sticky!");
                } else if (!bNewStick && bStick) {
                    registry.remove(sChan);
                    WebSock.session()->addSuccess("Channel stopped being sticky!");
                }
            }
            return true;
        }
        return false;
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

bool NoStickyChan::onLoad(const NoString& args, NoString& sMessage)
{
    NoStringVector vsChans = args.split(",", No::SkipEmptyParts);
    NoStringVector::iterator it;

    for (it = vsChans.begin(); it != vsChans.end(); ++it) {
        NoString sChan = No::token(*it, 0);
        NoString sKey = No::tokens(*it, 1);
        NoRegistry registry(this);
        registry.setValue(sChan, sKey);
    }

    // Since we now have these channels added, clear the argument list
    setArgs("");

    NoStickyTimer* timer = new NoStickyTimer(this);
    timer->start(15);
    return (true);
}

template <>
void no_moduleInfo<NoStickyChan>(NoModuleInfo& Info)
{
    Info.setWikiPage("stickychan");
    Info.setHasArgs(true);
    Info.setArgsHelpText("List of channels, separated by comma.");
}

NETWORKMODULEDEFS(NoStickyChan, "configless sticky chans, keeps you there very stickily even")
