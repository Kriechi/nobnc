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

#include <nobnc/nomodule.h>
#include <nobnc/nonetwork.h>
#include <nobnc/noircsocket.h>
#include <nobnc/nocachemap.h>
#include <nobnc/noregistry.h>
#include <nobnc/nonick.h>
#include <nobnc/nohostmask.h>

class NoAutoReplyMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoAutoReplyMod)
    {
        addHelpCommand();
        addCommand("Set",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoReplyMod::OnSetCommand),
                   "<reply>",
                   "Sets a new reply");
        addCommand("Show",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAutoReplyMod::OnShowCommand),
                   "",
                   "Displays the current query reply");
        m_Messaged.setExpiration(1000 * 120);
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        if (!args.empty()) {
            SetReply(args);
        }

        return true;
    }

    void SetReply(const NoString& reply)
    {
        NoRegistry(this).setValue("Reply", reply);
    }

    NoString GetReply()
    {
        NoString reply = NoRegistry(this).value("Reply");
        if (reply.empty()) {
            reply = "%nick% is currently away, try again later";
            SetReply(reply);
        }

        return expandString(reply);
    }

    void Handle(const NoString& nick)
    {
        NoIrcSocket* socket = network()->ircSocket();
        if (!socket)
            // WTF?
            return;
        if (nick == socket->nick())
            return;
        if (m_Messaged.contains(nick))
            return;

        if (network()->isUserAttached())
            return;

        m_Messaged.insert(nick);
        putIrc("NOTICE " + nick + " :" + GetReply());
    }

    ModRet onPrivMsg(NoHostMask& nick, NoString& message) override
    {
        Handle(nick.nick());
        return CONTINUE;
    }

    void OnShowCommand(const NoString& command)
    {
        putModule("Current reply is: " + NoRegistry(this).value("Reply") + " (" + GetReply() + ")");
    }

    void OnSetCommand(const NoString& command)
    {
        SetReply(No::tokens(command, 1));
        putModule("New reply set");
    }

private:
    NoCacheMap<NoString> m_Messaged;
};

template <>
void no_moduleInfo<NoAutoReplyMod>(NoModuleInfo& info)
{
    info.setWikiPage("autoreply");
    info.addType(No::NetworkModule);
    info.setHasArgs(true);
    info.setArgsHelpText("You might specify a reply text. It is used when automatically answering queries, if you are "
                         "not connected to ZNC.");
}

USERMODULEDEFS(NoAutoReplyMod, "Reply to queries when you are away")
