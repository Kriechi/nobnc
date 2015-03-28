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
#include <no/noutils.h>
#include <no/nouser.h>
#include <no/nonick.h>
#include <no/noregistry.h>

class NoNickServ : public NoModule
{
    void DoNickCommand(const NoString& sCmd, const NoString& sNick)
    {
        NoStringMap msValues;
        msValues["nickname"] = sNick;
        NoRegistry registry(this);
        msValues["password"] = registry.value("Password");
        PutIRC(No::namedFormat(registry.value(sCmd), msValues));
    }

public:
    void SetCommand(const NoString& sLine)
    {
        NoRegistry registry(this);
        registry.setValue("Password", No::tokens(sLine, 1));
        PutModule("Password set");
    }

    void ClearCommand(const NoString& sLine) { NoRegistry(this).remove("Password"); }

    void SetNSNameCommand(const NoString& sLine)
    {
        NoRegistry registry(this);
        registry.setValue("NickServName", No::tokens(sLine, 1));
        PutModule("NickServ name set");
    }

    void ClearNSNameCommand(const NoString& sLine) { NoRegistry(this).remove("NickServName"); }

    void ViewCommandsCommand(const NoString& sLine) { PutModule("IDENTIFY " + NoRegistry(this).value("IdentifyCmd")); }

    void SetCommandCommand(const NoString& sLine)
    {
        NoString sCmd = No::token(sLine, 1);
        NoString sNewCmd = No::tokens(sLine, 2);
        if (sCmd.equals("IDENTIFY")) {
            NoRegistry registry(this);
            registry.setValue("IdentifyCmd", sNewCmd);
        } else {
            PutModule("No such editable command. See ViewCommands for list.");
            return;
        }
        PutModule("Ok");
    }

    MODCONSTRUCTOR(NoNickServ)
    {
        AddHelpCommand();
        AddCommand("Set", static_cast<NoModuleCommand::ModCmdFunc>(&NoNickServ::SetCommand), "password");
        AddCommand("Clear",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoNickServ::ClearCommand),
                   "",
                   "Clear your nickserv password");
        AddCommand("SetNSName",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoNickServ::SetNSNameCommand),
                   "nickname",
                   "Set NickServ name (Useful on networks like EpiKnet, where NickServ is named Themis)");
        AddCommand("ClearNSName",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoNickServ::ClearNSNameCommand),
                   "",
                   "Reset NickServ name to default (NickServ)");
        AddCommand("ViewCommands",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoNickServ::ViewCommandsCommand),
                   "",
                   "Show patterns for lines, which are being sent to NickServ");
        AddCommand("SetCommand", static_cast<NoModuleCommand::ModCmdFunc>(&NoNickServ::SetCommandCommand), "cmd new-pattern", "Set pattern for commands");
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        NoRegistry registry(this);
        if (!sArgs.empty() && sArgs != "<hidden>") {
            registry.setValue("Password", sArgs);
            SetArgs("<hidden>");
        }

        if (registry.value("IdentifyCmd").empty()) {
            registry.setValue("IdentifyCmd", "NICKSERV IDENTIFY {password}");
        }

        return true;
    }

    void HandleMessage(NoNick& Nick, const NoString& sMessage)
    {
        NoRegistry registry(this);
        NoString sNickServName = (!registry.value("NickServName").empty()) ? registry.value("NickServName") : "NickServ";
        if (!registry.value("Password").empty() && Nick.equals(sNickServName) &&
            (sMessage.contains("msg") || sMessage.contains("authenticate") ||
             sMessage.contains("choose a different nickname") ||
             sMessage.contains("please choose a different nick") ||
             sMessage.contains("If this is your nick, identify yourself with") ||
             sMessage.contains("If this is your nick, type") ||
             sMessage.contains("This is a registered nickname, please identify") ||
             No::stripControls(sMessage).find("type /NickServ IDENTIFY password") ||
             No::stripControls(sMessage).find("type /msg NickServ IDENTIFY password")) &&
            sMessage.toUpper().contains("IDENTIFY") && sMessage.contains("help")) {
            NoStringMap msValues;
            msValues["password"] = registry.value("Password");
            PutIRC(No::namedFormat(registry.value("IdentifyCmd"), msValues));
        }
    }

    ModRet onPrivMsg(NoNick& Nick, NoString& sMessage) override
    {
        HandleMessage(Nick, sMessage);
        return CONTINUE;
    }

    ModRet onPrivNotice(NoNick& Nick, NoString& sMessage) override
    {
        HandleMessage(Nick, sMessage);
        return CONTINUE;
    }
};

template <> void no_moduleInfo<NoNickServ>(NoModuleInfo& Info)
{
    Info.setWikiPage("nickserv");
    Info.setHasArgs(true);
    Info.setArgsHelpText("Please enter your nickserv password.");
}

NETWORKMODULEDEFS(NoNickServ, "Auths you with NickServ")
