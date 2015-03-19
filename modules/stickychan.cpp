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

#include <no/nochannel.h>
#include <no/nonetwork.h>

class NoStickyChan : public NoModule
{
public:
    MODCONSTRUCTOR(NoStickyChan)
    {
        AddHelpCommand();
        AddCommand("Stick",
                   static_cast<NoModCommand::ModCmdFunc>(&NoStickyChan::OnStickCommand),
                   "<#channel> [key]",
                   "Sticks a channel");
        AddCommand("Unstick",
                   static_cast<NoModCommand::ModCmdFunc>(&NoStickyChan::OnUnstickCommand),
                   "<#channel>",
                   "Unsticks a channel");
        AddCommand("List",
                   static_cast<NoModCommand::ModCmdFunc>(&NoStickyChan::OnListCommand),
                   "",
                   "Lists sticky channels");
    }
    virtual ~NoStickyChan() {}

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override;

    EModRet OnUserPart(NoString& sChannel, NoString& sMessage) override
    {
        for (NoStringMap::iterator it = BeginNV(); it != EndNV(); ++it) {
            if (sChannel.Equals(it->first)) {
                NoChannel* pChan = GetNetwork()->FindChan(sChannel);

                if (pChan) {
                    pChan->joinUser();
                    return HALT;
                }
            }
        }

        return CONTINUE;
    }

    virtual void OnMode(const NoNick& pOpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange) override
    {
        if (uMode == NoChannel::M_Key) {
            if (bAdded) {
                // We ignore channel key "*" because of some broken nets.
                if (sArg != "*") {
                    SetNV(Channel.getName(), sArg, true);
                }
            } else {
                SetNV(Channel.getName(), "", true);
            }
        }
    }

    void OnStickCommand(const NoString& sCommand)
    {
        NoString sChannel = sCommand.Token(1).AsLower();
        if (sChannel.empty()) {
            PutModule("Usage: Stick <#channel> [key]");
            return;
        }
        SetNV(sChannel, sCommand.Token(2), true);
        PutModule("Stuck " + sChannel);
    }

    void OnUnstickCommand(const NoString& sCommand)
    {
        NoString sChannel = sCommand.Token(1);
        if (sChannel.empty()) {
            PutModule("Usage: Unstick <#channel>");
            return;
        }
        DelNV(sChannel, true);
        PutModule("Unstuck " + sChannel);
    }

    void OnListCommand(const NoString& sCommand)
    {
        int i = 1;
        for (NoStringMap::iterator it = BeginNV(); it != EndNV(); ++it, i++) {
            if (it->second.empty())
                PutModule(NoString(i) + ": " + it->first);
            else
                PutModule(NoString(i) + ": " + it->first + " (" + it->second + ")");
        }
        PutModule(" -- End of List");
    }

    void RunJob()
    {
        NoNetwork* pNetwork = GetNetwork();
        if (!pNetwork->GetIRCSock()) return;

        for (NoStringMap::iterator it = BeginNV(); it != EndNV(); ++it) {
            NoChannel* pChan = pNetwork->FindChan(it->first);
            if (!pChan) {
                pChan = new NoChannel(it->first, pNetwork, true);
                if (!it->second.empty()) pChan->setKey(it->second);
                if (!pNetwork->AddChan(pChan)) {
                    /* AddChan() deleted that channel */
                    PutModule("Could not join [" + it->first + "] (# prefix missing?)");
                    continue;
                }
            }
            if (!pChan->isOn() && pNetwork->IsIRCConnected()) {
                PutModule("Joining [" + pChan->getName() + "]");
                PutIRC("JOIN " + pChan->getName() + (pChan->getKey().empty() ? "" : " " + pChan->getKey()));
            }
        }
    }

    NoString GetWebMenuTitle() override { return "Sticky Chans"; }

    bool OnWebRequest(NoWebSock& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "index") {
            bool bSubmitted = (WebSock.GetParam("submitted").ToInt() != 0);

            const std::vector<NoChannel*>& Channels = GetNetwork()->GetChans();
            for (uint c = 0; c < Channels.size(); c++) {
                const NoString sChan = Channels[c]->getName();
                bool bStick = FindNV(sChan) != EndNV();

                if (bSubmitted) {
                    bool bNewStick = WebSock.GetParam("stick_" + sChan).ToBool();
                    if (bNewStick && !bStick)
                        SetNV(sChan, ""); // no password support for now unless chansaver is active too
                    else if (!bNewStick && bStick) {
                        NoStringMap::iterator it = FindNV(sChan);
                        if (it != EndNV()) DelNV(it);
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

    bool OnEmbeddedWebRequest(NoWebSock& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "webadmin/channel") {
            NoString sChan = Tmpl["ChanName"];
            bool bStick = FindNV(sChan) != EndNV();
            if (Tmpl["WebadminAction"].Equals("display")) {
                Tmpl["Sticky"] = NoString(bStick);
            } else if (WebSock.GetParam("embed_stickychan_presented").ToBool()) {
                bool bNewStick = WebSock.GetParam("embed_stickychan_sticky").ToBool();
                if (bNewStick && !bStick) {
                    SetNV(sChan, ""); // no password support for now unless chansaver is active too
                    WebSock.GetSession()->AddSuccess("Channel become sticky!");
                } else if (!bNewStick && bStick) {
                    DelNV(sChan);
                    WebSock.GetSession()->AddSuccess("Channel stopped being sticky!");
                }
            }
            return true;
        }
        return false;
    }
};


static void RunTimer(NoModule* pModule, NoTimer* pTimer) { ((NoStickyChan*)pModule)->RunJob(); }

bool NoStickyChan::OnLoad(const NoString& sArgs, NoString& sMessage)
{
    NoStringVector vsChans = sArgs.Split(",", No::SkipEmptyParts);
    NoStringVector::iterator it;

    for (it = vsChans.begin(); it != vsChans.end(); ++it) {
        NoString sChan = it->Token(0);
        NoString sKey = it->Token(1, true);
        SetNV(sChan, sKey);
    }

    // Since we now have these channels added, clear the argument list
    SetArgs("");

    AddTimer(RunTimer, "StickyChanTimer", 15);
    return (true);
}

template <> void TModInfo<NoStickyChan>(NoModInfo& Info)
{
    Info.SetWikiPage("stickychan");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("List of channels, separated by comma.");
}

NETWORKMODULEDEFS(NoStickyChan, "configless sticky chans, keeps you there very stickily even")
