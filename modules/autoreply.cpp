/*
 * Copyright (C) 2015 NoBNC
 * Copyright (C) 2004-2015 ZNC, see the NOTICE file for details.
 * Copyright (C) 2008 Michael "Svedrin" Ziegler diese-addy@funzt-halt.net
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
#include <no/nonetwork.h>
#include <no/noircsocket.h>
#include <no/nocachemap.h>
#include <no/noregistry.h>
#include <no/nonick.h>

class NoAutoReplyMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoAutoReplyMod)
    {
        AddHelpCommand();
        AddCommand("Set",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoReplyMod::OnSetCommand),
                   "<reply>",
                   "Sets a new reply");
        AddCommand("Show",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoReplyMod::OnShowCommand),
                   "",
                   "Displays the current query reply");
        m_Messaged.setTtl(1000 * 120);
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        if (!sArgs.empty()) {
            SetReply(sArgs);
        }

        return true;
    }

    void SetReply(const NoString& sReply) { NoRegistry(this).setValue("Reply", sReply); }

    NoString GetReply()
    {
        NoString sReply = NoRegistry(this).value("Reply");
        if (sReply.empty()) {
            sReply = "%nick% is currently away, try again later";
            SetReply(sReply);
        }

        return ExpandString(sReply);
    }

    void Handle(const NoString& sNick)
    {
        NoIrcSocket* pIRCSock = GetNetwork()->GetIRCSock();
        if (!pIRCSock)
            // WTF?
            return;
        if (sNick == pIRCSock->GetNick()) return;
        if (m_Messaged.contains(sNick)) return;

        if (GetNetwork()->IsUserAttached()) return;

        m_Messaged.insert(sNick);
        PutIRC("NOTICE " + sNick + " :" + GetReply());
    }

    ModRet onPrivMsg(NoNick& Nick, NoString& sMessage) override
    {
        Handle(Nick.nick());
        return CONTINUE;
    }

    void OnShowCommand(const NoString& sCommand)
    {
        PutModule("Current reply is: " + NoRegistry(this).value("Reply") + " (" + GetReply() + ")");
    }

    void OnSetCommand(const NoString& sCommand)
    {
        SetReply(No::tokens(sCommand, 1));
        PutModule("New reply set");
    }

private:
    NoCacheMap<NoString> m_Messaged;
};

template <> void no_moduleInfo<NoAutoReplyMod>(NoModuleInfo& Info)
{
    Info.SetWikiPage("autoreply");
    Info.AddType(No::NetworkModule);
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("You might specify a reply text. It is used when automatically answering queries, if you are "
                         "not connected to ZNC.");
}

USERMODULEDEFS(NoAutoReplyMod, "Reply to queries when you are away")
