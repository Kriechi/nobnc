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

#include <no/nomodules.h>
#include <no/noutils.h>
#include <no/nouser.h>

class NoNickServ : public NoModule
{
    void DoNickCommand(const NoString& sCmd, const NoString& sNick)
    {
        NoStringMap msValues;
        msValues["nickname"] = sNick;
        msValues["password"] = GetNV("Password");
        PutIRC(NoUtils::NamedFormat(GetNV(sCmd), msValues));
    }

public:
    void SetCommand(const NoString& sLine)
    {
        SetNV("Password", sLine.Token(1, true));
        PutModule("Password set");
    }

    void ClearCommand(const NoString& sLine) { DelNV("Password"); }

    void SetNSNameCommand(const NoString& sLine)
    {
        SetNV("NickServName", sLine.Token(1, true));
        PutModule("NickServ name set");
    }

    void ClearNSNameCommand(const NoString& sLine) { DelNV("NickServName"); }

    void ViewCommandsCommand(const NoString& sLine) { PutModule("IDENTIFY " + GetNV("IdentifyCmd")); }

    void SetCommandCommand(const NoString& sLine)
    {
        NoString sCmd = sLine.Token(1);
        NoString sNewCmd = sLine.Token(2, true);
        if (sCmd.Equals("IDENTIFY")) {
            SetNV("IdentifyCmd", sNewCmd);
        } else {
            PutModule("No such editable command. See ViewCommands for list.");
            return;
        }
        PutModule("Ok");
    }

    MODCONSTRUCTOR(NoNickServ)
    {
        AddHelpCommand();
        AddCommand("Set", static_cast<NoModCommand::ModCmdFunc>(&NoNickServ::SetCommand), "password");
        AddCommand("Clear",
                   static_cast<NoModCommand::ModCmdFunc>(&NoNickServ::ClearCommand),
                   "",
                   "Clear your nickserv password");
        AddCommand("SetNSName",
                   static_cast<NoModCommand::ModCmdFunc>(&NoNickServ::SetNSNameCommand),
                   "nickname",
                   "Set NickServ name (Useful on networks like EpiKnet, where NickServ is named Themis)");
        AddCommand("ClearNSName",
                   static_cast<NoModCommand::ModCmdFunc>(&NoNickServ::ClearNSNameCommand),
                   "",
                   "Reset NickServ name to default (NickServ)");
        AddCommand("ViewCommands",
                   static_cast<NoModCommand::ModCmdFunc>(&NoNickServ::ViewCommandsCommand),
                   "",
                   "Show patterns for lines, which are being sent to NickServ");
        AddCommand("SetCommand", static_cast<NoModCommand::ModCmdFunc>(&NoNickServ::SetCommandCommand), "cmd new-pattern", "Set pattern for commands");
    }

    virtual ~NoNickServ() {}

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        if (!sArgs.empty() && sArgs != "<hidden>") {
            SetNV("Password", sArgs);
            SetArgs("<hidden>");
        }

        if (GetNV("IdentifyCmd").empty()) {
            SetNV("IdentifyCmd", "NICKSERV IDENTIFY {password}");
        }

        return true;
    }

    void HandleMessage(NoNick& Nick, const NoString& sMessage)
    {
        NoString sNickServName = (!GetNV("NickServName").empty()) ? GetNV("NickServName") : "NickServ";
        if (!GetNV("Password").empty() && Nick.equals(sNickServName) &&
            (sMessage.find("msg") != NoString::npos || sMessage.find("authenticate") != NoString::npos ||
             sMessage.find("choose a different nickname") != NoString::npos ||
             sMessage.find("please choose a different nick") != NoString::npos ||
             sMessage.find("If this is your nick, identify yourself with") != NoString::npos ||
             sMessage.find("If this is your nick, type") != NoString::npos ||
             sMessage.find("This is a registered nickname, please identify") != NoString::npos ||
             NoUtils::StripControls(sMessage).find("type /NickServ IDENTIFY password") != NoString::npos ||
             NoUtils::StripControls(sMessage).find("type /msg NickServ IDENTIFY password") != NoString::npos) &&
            sMessage.AsUpper().find("IDENTIFY") != NoString::npos && sMessage.find("help") == NoString::npos) {
            NoStringMap msValues;
            msValues["password"] = GetNV("Password");
            PutIRC(NoUtils::NamedFormat(GetNV("IdentifyCmd"), msValues));
        }
    }

    EModRet OnPrivMsg(NoNick& Nick, NoString& sMessage) override
    {
        HandleMessage(Nick, sMessage);
        return CONTINUE;
    }

    EModRet OnPrivNotice(NoNick& Nick, NoString& sMessage) override
    {
        HandleMessage(Nick, sMessage);
        return CONTINUE;
    }
};

template <> void TModInfo<NoNickServ>(NoModInfo& Info)
{
    Info.SetWikiPage("nickserv");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("Please enter your nickserv password.");
}

NETWORKMODULEDEFS(NoNickServ, "Auths you with NickServ")
