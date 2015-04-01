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
#include <nobnc/noutils.h>
#include <nobnc/nouser.h>
#include <nobnc/nonick.h>
#include <nobnc/noregistry.h>

class NoNickServ : public NoModule
{
    void DoNickCommand(const NoString& cmd, const NoString& nick)
    {
        NoStringMap msValues;
        msValues["nickname"] = nick;
        NoRegistry registry(this);
        msValues["password"] = registry.value("Password");
        putIrc(No::namedFormat(registry.value(cmd), msValues));
    }

public:
    void SetCommand(const NoString& line)
    {
        NoRegistry registry(this);
        registry.setValue("Password", No::tokens(line, 1));
        putModule("Password set");
    }

    void ClearCommand(const NoString& line)
    {
        NoRegistry(this).remove("Password");
    }

    void SetNSNameCommand(const NoString& line)
    {
        NoRegistry registry(this);
        registry.setValue("NickServName", No::tokens(line, 1));
        putModule("NickServ name set");
    }

    void ClearNSNameCommand(const NoString& line)
    {
        NoRegistry(this).remove("NickServName");
    }

    void ViewCommandsCommand(const NoString& line)
    {
        putModule("IDENTIFY " + NoRegistry(this).value("IdentifyCmd"));
    }

    void SetCommandCommand(const NoString& line)
    {
        NoString cmd = No::token(line, 1);
        NoString sNewCmd = No::tokens(line, 2);
        if (cmd.equals("IDENTIFY")) {
            NoRegistry registry(this);
            registry.setValue("IdentifyCmd", sNewCmd);
        } else {
            putModule("No such editable command. See ViewCommands for list.");
            return;
        }
        putModule("Ok");
    }

    MODCONSTRUCTOR(NoNickServ)
    {
        addHelpCommand();
        addCommand("Set", static_cast<NoModuleCommand::ModCmdFunc>(&NoNickServ::SetCommand), "password");
        addCommand("Clear",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoNickServ::ClearCommand),
                   "",
                   "Clear your nickserv password");
        addCommand("SetNSName",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoNickServ::SetNSNameCommand),
                   "nickname",
                   "Set NickServ name (Useful on networks like EpiKnet, where NickServ is named Themis)");
        addCommand("ClearNSName",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoNickServ::ClearNSNameCommand),
                   "",
                   "Reset NickServ name to default (NickServ)");
        addCommand("ViewCommands",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoNickServ::ViewCommandsCommand),
                   "",
                   "Show patterns for lines, which are being sent to NickServ");
        addCommand("SetCommand",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoNickServ::SetCommandCommand),
                   "cmd new-pattern",
                   "Set pattern for commands");
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        NoRegistry registry(this);
        if (!args.empty() && args != "<hidden>") {
            registry.setValue("Password", args);
            setArgs("<hidden>");
        }

        if (registry.value("IdentifyCmd").empty()) {
            registry.setValue("IdentifyCmd", "NICKSERV IDENTIFY {password}");
        }

        return true;
    }

    void HandleMessage(NoNick& nick, const NoString& message)
    {
        NoRegistry registry(this);
        NoString sNickServName =
        (!registry.value("NickServName").empty()) ? registry.value("NickServName") : "NickServ";
        if (!registry.value("Password").empty() && nick.equals(sNickServName) &&
            (message.contains("msg") || message.contains("authenticate") ||
             message.contains("choose a different nickname") || message.contains("please choose a different nick") ||
             message.contains("If this is your nick, identify yourself with") ||
             message.contains("If this is your nick, type") ||
             message.contains("This is a registered nickname, please identify") ||
             No::stripControls(message).find("type /NickServ IDENTIFY password") ||
             No::stripControls(message).find("type /msg NickServ IDENTIFY password")) &&
            message.toUpper().contains("IDENTIFY") && message.contains("help")) {
            NoStringMap msValues;
            msValues["password"] = registry.value("Password");
            putIrc(No::namedFormat(registry.value("IdentifyCmd"), msValues));
        }
    }

    ModRet onPrivMsg(NoNick& nick, NoString& message) override
    {
        HandleMessage(nick, message);
        return CONTINUE;
    }

    ModRet onPrivNotice(NoNick& nick, NoString& message) override
    {
        HandleMessage(nick, message);
        return CONTINUE;
    }
};

template <>
void no_moduleInfo<NoNickServ>(NoModuleInfo& info)
{
    info.setWikiPage("nickserv");
    info.setHasArgs(true);
    info.setArgsHelpText("Please enter your nickserv password.");
}

NETWORKMODULEDEFS(NoNickServ, "Auths you with NickServ")
