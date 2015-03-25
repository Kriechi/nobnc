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
        AddHelpCommand();
        AddCommand("Stick",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoStickyChan::OnStickCommand),
                   "<#channel> [key]",
                   "Sticks a channel");
        AddCommand("Unstick",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoStickyChan::OnUnstickCommand),
                   "<#channel>",
                   "Unsticks a channel");
        AddCommand("List",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoStickyChan::OnListCommand),
                   "",
                   "Lists sticky channels");
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override;

    ModRet onUserPart(NoString& sChannel, NoString& sMessage) override
    {
        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            if (sChannel.equals(key)) {
                NoChannel* pChan = GetNetwork()->FindChan(sChannel);

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
                    registry.setValue(Channel.getName(), sArg);
                }
            } else {
                NoRegistry registry(this);
                registry.setValue(Channel.getName(), "");
            }
        }
    }

    void OnStickCommand(const NoString& sCommand)
    {
        NoString sChannel = No::token(sCommand, 1).toLower();
        if (sChannel.empty()) {
            PutModule("Usage: Stick <#channel> [key]");
            return;
        }
        NoRegistry registry(this);
        registry.setValue(sChannel, No::token(sCommand, 2));
        PutModule("Stuck " + sChannel);
    }

    void OnUnstickCommand(const NoString& sCommand)
    {
        NoString sChannel = No::token(sCommand, 1);
        if (sChannel.empty()) {
            PutModule("Usage: Unstick <#channel>");
            return;
        }
        NoRegistry registry(this);
        registry.remove(sChannel);
        PutModule("Unstuck " + sChannel);
    }

    void OnListCommand(const NoString& sCommand)
    {
        int i = 1;
        NoRegistry registry(this);
        for (const NoString& key : registry.keys()) {
            NoString value = registry.value(key);
            if (value.empty())
                PutModule(NoString(i) + ": " + key);
            else
                PutModule(NoString(i) + ": " + key + " (" + value + ")");
        }
        PutModule(" -- End of List");
    }

    NoString GetWebMenuTitle() override { return "Sticky Chans"; }

    bool OnWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "index") {
            bool bSubmitted = (WebSock.GetParam("submitted").toInt() != 0);

            NoRegistry registry(this);
            const std::vector<NoChannel*>& Channels = GetNetwork()->GetChans();
            for (uint c = 0; c < Channels.size(); c++) {
                const NoString sChan = Channels[c]->getName();
                bool bStick = registry.contains(sChan);

                if (bSubmitted) {
                    bool bNewStick = WebSock.GetParam("stick_" + sChan).toBool();
                    if (bNewStick && !bStick)
                        registry.setValue(sChan, ""); // no password support for now unless chansaver is active too
                    else if (!bNewStick && bStick) {
                        registry.remove(sChan);
                    }
                    bStick = bNewStick;
                }

                NoTemplate& Row = Tmpl.AddRow("ChannelLoop");
                Row["Name"] = sChan;
                Row["Sticky"] = NoString(bStick);
            }

            if (bSubmitted) {
                WebSock.GetSession()->AddSuccess("Changes have been saved!");
            }

            return true;
        }

        return false;
    }

    bool OnEmbeddedWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "webadmin/channel") {
            NoString sChan = Tmpl["ChanName"];
            NoRegistry registry(this);
            bool bStick = registry.contains(sChan);
            if (Tmpl["WebadminAction"].equals("display")) {
                Tmpl["Sticky"] = NoString(bStick);
            } else if (WebSock.GetParam("embed_stickychan_presented").toBool()) {
                bool bNewStick = WebSock.GetParam("embed_stickychan_sticky").toBool();
                if (bNewStick && !bStick) {
                    registry.setValue(sChan, ""); // no password support for now unless chansaver is active too
                    WebSock.GetSession()->AddSuccess("Channel become sticky!");
                } else if (!bNewStick && bStick) {
                    registry.remove(sChan);
                    WebSock.GetSession()->AddSuccess("Channel stopped being sticky!");
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

        NoNetwork* pNetwork = mod->GetNetwork();
        if (!pNetwork->GetIRCSock())
            return;

        NoRegistry registry(module());
        for (const NoString& key : registry.keys()) {
            NoChannel* pChan = pNetwork->FindChan(key);
            if (!pChan) {
                pChan = new NoChannel(key, pNetwork, true);
                if (!registry.value(key).empty())
                    pChan->setKey(registry.value(key));
                if (!pNetwork->AddChan(pChan)) {
                    /* AddChan() deleted that channel */
                    mod->PutModule("Could not join [" + key + "] (# prefix missing?)");
                    continue;
                }
            }
            if (!pChan->isOn() && pNetwork->IsIRCConnected()) {
                mod->PutModule("Joining [" + pChan->getName() + "]");
                mod->PutIRC("JOIN " + pChan->getName() + (pChan->getKey().empty() ? "" : " " + pChan->getKey()));
            }
        }
    }
};

bool NoStickyChan::OnLoad(const NoString& sArgs, NoString& sMessage)
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
    SetArgs("");

    NoStickyTimer* timer = new NoStickyTimer(this);
    timer->start(15);
    return (true);
}

template <> void no_moduleInfo<NoStickyChan>(NoModuleInfo& Info)
{
    Info.SetWikiPage("stickychan");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("List of channels, separated by comma.");
}

NETWORKMODULEDEFS(NoStickyChan, "configless sticky chans, keeps you there very stickily even")
