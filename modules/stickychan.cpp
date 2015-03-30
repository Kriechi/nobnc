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

    bool onLoad(const NoString& sArgs, NoString& sMessage) override;

    ModRet onUserPart(NoString& sChannel, NoString& sMessage) override
    {
        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            if (sChannel.equals(key)) {
                NoChannel* pChan = network()->findChannel(sChannel);

                if (pChan) {
                    pChan->joinUser();
                    return HALT;
                }
            }
        }

        return CONTINUE;
    }

    virtual void onMode(const NoNick& pOpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange) override
    {
        if (uMode == NoChannel::M_Key) {
            if (bAdded) {
                // We ignore channel key "*" because of some broken nets.
                if (sArg != "*") {
                    NoRegistry registry(this);
                    registry.setValue(Channel.name(), sArg);
                }
            } else {
                NoRegistry registry(this);
                registry.setValue(Channel.name(), "");
            }
        }
    }

    void OnStickCommand(const NoString& sCommand)
    {
        NoString sChannel = No::token(sCommand, 1).toLower();
        if (sChannel.empty()) {
            putModule("Usage: Stick <#channel> [key]");
            return;
        }
        NoRegistry registry(this);
        registry.setValue(sChannel, No::token(sCommand, 2));
        putModule("Stuck " + sChannel);
    }

    void OnUnstickCommand(const NoString& sCommand)
    {
        NoString sChannel = No::token(sCommand, 1);
        if (sChannel.empty()) {
            putModule("Usage: Unstick <#channel>");
            return;
        }
        NoRegistry registry(this);
        registry.remove(sChannel);
        putModule("Unstuck " + sChannel);
    }

    void OnListCommand(const NoString& sCommand)
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
                WebSock.GetSession()->addSuccess("Changes have been saved!");
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
                    WebSock.GetSession()->addSuccess("Channel become sticky!");
                } else if (!bNewStick && bStick) {
                    registry.remove(sChan);
                    WebSock.GetSession()->addSuccess("Channel stopped being sticky!");
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

        NoNetwork* pNetwork = mod->network();
        if (!pNetwork->ircSocket())
            return;

        NoRegistry registry(module());
        for (const NoString& key : registry.keys()) {
            NoChannel* pChan = pNetwork->findChannel(key);
            if (!pChan) {
                pChan = new NoChannel(key, pNetwork, true);
                if (!registry.value(key).empty())
                    pChan->setKey(registry.value(key));
                if (!pNetwork->addChannel(pChan)) {
                    /* addChannel() deleted that channel */
                    mod->putModule("Could not join [" + key + "] (# prefix missing?)");
                    continue;
                }
            }
            if (!pChan->isOn() && pNetwork->isIrcConnected()) {
                mod->putModule("Joining [" + pChan->name() + "]");
                mod->putIrc("JOIN " + pChan->name() + (pChan->key().empty() ? "" : " " + pChan->key()));
            }
        }
    }
};

bool NoStickyChan::onLoad(const NoString& sArgs, NoString& sMessage)
{
    NoStringVector vsChans = sArgs.split(",", No::SkipEmptyParts);
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
