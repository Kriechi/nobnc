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

//! @author prozac@rottenboy.com
//
// The encryption here was designed to be compatible with mircryption's CBC mode.
//
// TODO:
//
// 1) Encrypt key storage file
// 2) Secure key exchange using pub/priv keys and the DH algorithm
// 3) Some way of notifying the user that the current channel is in "encryption mode" verses plain text
// 4) Temporarily disable a target (nick/chan)
//
// NOTE: This module is currently NOT intended to secure you from your shell admin.
//       The keys are currently stored in plain text, so anyone with access to your account (or root) can obtain them.
//       It is strongly suggested that you enable SSL between znc and your client otherwise the encryption stops at znc
//       and gets sent to your client in plain text.
//

#include <nobnc/nomodule.h>
#include <nobnc/nochannel.h>
#include <nobnc/nouser.h>
#include <nobnc/nonetwork.h>
#include <nobnc/noregistry.h>
#include <nobnc/nonick.h>
#include <nobnc/nohostmask.h>
#include <nobnc/noutils.h>
#include <nobnc/notable.h>

#define REQUIRESSL 1
#define NICK_PREFIX_KEY "[nick-prefix]"

class NoCryptMod : public NoModule
{
    NoString NickPrefix()
    {
        NoRegistry registry(this);
        if (!registry.contains(NICK_PREFIX_KEY))
            return "*";
        return registry.value(NICK_PREFIX_KEY);
    }

public:
    MODCONSTRUCTOR(NoCryptMod)
    {
        addHelpCommand();
        addCommand("DelKey",
                   static_cast<NoModule::CommandFunction>(&NoCryptMod::OnDelKeyCommand),
                   "<#chan|nick>",
                   "Remove a key for nick or channel");
        addCommand("SetKey",
                   static_cast<NoModule::CommandFunction>(&NoCryptMod::OnSetKeyCommand),
                   "<#chan|nick> <Key>",
                   "Set a key for nick or channel");
        addCommand("ListKeys",
                   static_cast<NoModule::CommandFunction>(&NoCryptMod::OnListKeysCommand),
                   "",
                   "List all keys");
    }

    Return onUserMessage(NoString& target, NoString& message) override
    {
        target.trimLeft(NickPrefix());

        if (message.left(2) == "``") {
            message.leftChomp(2);
            return Continue;
        }

        NoRegistry registry(this);
        if (registry.contains(target.toLower())) {
            NoChannel* channel = network()->findChannel(target);
            NoString sNickMask = network()->ircNick().hostMask();
            if (channel) {
                if (!channel->autoClearChanBuffer())
                    channel->addBuffer(":" + NickPrefix() + _NAMEDFMT(sNickMask) + " PRIVMSG " + _NAMEDFMT(target) +
                                     " :{text}",
                                     message);
                user()->putUser(":" + NickPrefix() + sNickMask + " PRIVMSG " + target + " :" + message, nullptr, client());
            }

            NoString msg = MakeIvec() + message;
            msg = No::encrypt(msg, registry.value(target.toLower()));
            msg = msg.toBase64();
            msg = "+OK *" + msg;

            putIrc("PRIVMSG " + target + " :" + msg);
            return HaltCore;
        }

        return Continue;
    }

    Return onPrivateMessage(NoHostMask& mask, NoString& message) override
    {
        NoNick nick(mask.toString()); // TODO: cleanup
        FilterIncoming(nick.nick(), nick, message);
        mask.setNick(nick.nick()); // TODO: cleanup
        return Continue;
    }

    Return onChannelMessage(NoNick& nick, NoChannel* channel, NoString& message) override
    {
        FilterIncoming(channel->name(), nick, message);
        return Continue;
    }

    void FilterIncoming(const NoString& target, NoNick& nick, NoString& message)
    {
        if (message.left(5) == "+OK *") {
            NoRegistry registry(this);
            if (registry.contains(target.toLower())) {
                message.leftChomp(5);
                message = NoString::fromBase64(message);
                message = No::decrypt(message, registry.value(target.toLower()));
                message.leftChomp(8);
                message = message.c_str();
                nick.setNick(NickPrefix() + nick.nick());
            }
        }
    }

    void OnDelKeyCommand(const NoString& command)
    {
        NoString target = No::token(command, 1);

        if (!target.empty()) {
            NoRegistry registry(this);
            if (registry.contains(target.toLower())) {
                registry.remove(target.toLower());
                putModule("Target [" + target + "] deleted");
            } else {
                putModule("Target [" + target + "] not found");
            }
        } else {
            putModule("Usage DelKey <#chan|nick>");
        }
    }

    void OnSetKeyCommand(const NoString& command)
    {
        NoString target = No::token(command, 1);
        NoString key = No::tokens(command, 2);

        // Strip "cbc:" from beginning of string incase someone pastes directly from mircryption
        key.trimPrefix("cbc:");

        if (!key.empty()) {
            NoRegistry registry(this);
            registry.setValue(target.toLower(), key);
            putModule("Set encryption key for [" + target + "] to [" + key + "]");
        } else {
            putModule("Usage: SetKey <#chan|nick> <Key>");
        }
    }

    void OnListKeysCommand(const NoString& command)
    {
        NoRegistry registry(this);
        if (registry.isEmpty()) {
            putModule("You have no encryption keys set.");
        } else {
            NoTable Table;
            Table.addColumn("Target");
            Table.addColumn("Key");

            NoRegistry registry(this);
            for (const NoString& key : registry.keys()) {
                Table.addRow();
                Table.setValue("Target", key);
                Table.setValue("Key", registry.value(key));
            }

            if (!registry.contains(NICK_PREFIX_KEY)) {
                Table.addRow();
                Table.setValue("Target", NICK_PREFIX_KEY);
                Table.setValue("Key", NickPrefix());
            }

            putModule(Table);
        }
    }

    NoString MakeIvec()
    {
        NoString ret;
        time_t t;
        time(&t);
        int r = rand();
        ret.append((char*)&t, 4);
        ret.append((char*)&r, 4);

        return ret;
    }
};

template <>
void no_moduleInfo<NoCryptMod>(NoModuleInfo& info)
{
    info.setWikiPage("crypt");
}

NETWORKMODULEDEFS(NoCryptMod, "Encryption for channel/private messages")
