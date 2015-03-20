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

#include <no/nomodule.h>
#include <no/nochannel.h>
#include <no/nouser.h>
#include <no/nonetwork.h>

#define REQUIRESSL 1
#define NICK_PREFIX_KEY "[nick-prefix]"

class NoCryptMod : public NoModule
{
    NoString NickPrefix()
    {
        NoStringMap::iterator it = FindNV(NICK_PREFIX_KEY);
        return it != EndNV() ? it->second : "*";
    }

public:
    MODCONSTRUCTOR(NoCryptMod)
    {
        AddHelpCommand();
        AddCommand("DelKey",
                   static_cast<NoModCommand::ModCmdFunc>(&NoCryptMod::OnDelKeyCommand),
                   "<#chan|Nick>",
                   "Remove a key for nick or channel");
        AddCommand("SetKey", static_cast<NoModCommand::ModCmdFunc>(&NoCryptMod::OnSetKeyCommand), "<#chan|Nick> <Key>", "Set a key for nick or channel");
        AddCommand("ListKeys",
                   static_cast<NoModCommand::ModCmdFunc>(&NoCryptMod::OnListKeysCommand),
                   "",
                   "List all keys");
    }

    virtual ~NoCryptMod() {}

    ModRet OnUserMsg(NoString& sTarget, NoString& sMessage) override
    {
        sTarget.TrimLeft(NickPrefix());

        if (sMessage.Left(2) == "``") {
            sMessage.LeftChomp(2);
            return CONTINUE;
        }

        NoStringMap::iterator it = FindNV(sTarget.AsLower());

        if (it != EndNV()) {
            NoChannel* pChan = GetNetwork()->FindChan(sTarget);
            NoString sNickMask = GetNetwork()->GetIRCNick().nickMask();
            if (pChan) {
                if (!pChan->autoClearChanBuffer())
                    pChan->addBuffer(":" + NickPrefix() + _NAMEDFMT(sNickMask) + " PRIVMSG " + _NAMEDFMT(sTarget) +
                                     " :{text}",
                                     sMessage);
                GetUser()->PutUser(":" + NickPrefix() + sNickMask + " PRIVMSG " + sTarget + " :" + sMessage, nullptr, GetClient());
            }

            NoString sMsg = MakeIvec() + sMessage;
            sMsg = NoUtils::Encrypt(sMsg, it->second);
            sMsg = sMsg.ToBase64();
            sMsg = "+OK *" + sMsg;

            PutIRC("PRIVMSG " + sTarget + " :" + sMsg);
            return HALTCORE;
        }

        return CONTINUE;
    }

    ModRet OnPrivMsg(NoNick& Nick, NoString& sMessage) override
    {
        FilterIncoming(Nick.nick(), Nick, sMessage);
        return CONTINUE;
    }

    ModRet OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        FilterIncoming(Channel.getName(), Nick, sMessage);
        return CONTINUE;
    }

    void FilterIncoming(const NoString& sTarget, NoNick& Nick, NoString& sMessage)
    {
        if (sMessage.Left(5) == "+OK *") {
            NoStringMap::iterator it = FindNV(sTarget.AsLower());

            if (it != EndNV()) {
                sMessage.LeftChomp(5);
                sMessage = NoString::FromBase64(sMessage);
                sMessage = NoUtils::Decrypt(sMessage, it->second);
                sMessage.LeftChomp(8);
                sMessage = sMessage.c_str();
                Nick.setNick(NickPrefix() + Nick.nick());
            }
        }
    }

    void OnDelKeyCommand(const NoString& sCommand)
    {
        NoString sTarget = sCommand.Token(1);

        if (!sTarget.empty()) {
            if (DelNV(sTarget.AsLower())) {
                PutModule("Target [" + sTarget + "] deleted");
            } else {
                PutModule("Target [" + sTarget + "] not found");
            }
        } else {
            PutModule("Usage DelKey <#chan|Nick>");
        }
    }

    void OnSetKeyCommand(const NoString& sCommand)
    {
        NoString sTarget = sCommand.Token(1);
        NoString sKey = sCommand.Tokens(2);

        // Strip "cbc:" from beginning of string incase someone pastes directly from mircryption
        sKey.TrimPrefix("cbc:");

        if (!sKey.empty()) {
            SetNV(sTarget.AsLower(), sKey);
            PutModule("Set encryption key for [" + sTarget + "] to [" + sKey + "]");
        } else {
            PutModule("Usage: SetKey <#chan|Nick> <Key>");
        }
    }

    void OnListKeysCommand(const NoString& sCommand)
    {
        if (BeginNV() == EndNV()) {
            PutModule("You have no encryption keys set.");
        } else {
            NoTable Table;
            Table.AddColumn("Target");
            Table.AddColumn("Key");

            for (NoStringMap::iterator it = BeginNV(); it != EndNV(); ++it) {
                Table.AddRow();
                Table.SetCell("Target", it->first);
                Table.SetCell("Key", it->second);
            }

            NoStringMap::iterator it = FindNV(NICK_PREFIX_KEY);
            if (it == EndNV()) {
                Table.AddRow();
                Table.SetCell("Target", NICK_PREFIX_KEY);
                Table.SetCell("Key", NickPrefix());
            }

            PutModule(Table);
        }
    }

    NoString MakeIvec()
    {
        NoString sRet;
        time_t t;
        time(&t);
        int r = rand();
        sRet.append((char*)&t, 4);
        sRet.append((char*)&r, 4);

        return sRet;
    }
};

template <> void TModInfo<NoCryptMod>(NoModInfo& Info) { Info.SetWikiPage("crypt"); }

NETWORKMODULEDEFS(NoCryptMod, "Encryption for channel/private messages")
