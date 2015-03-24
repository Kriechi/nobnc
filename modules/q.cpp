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
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/noircsocket.h>
#include <no/nochannel.h>
#include <no/nowebsocket.h>
#include <no/nowebsession.h>
#include <no/noregistry.h>
#include <no/nonick.h>

#ifndef Q_DEBUG_COMMUNICATION
#define Q_DEBUG_COMMUNICATION 0
#endif

class NoQModule : public NoModule
{
public:
    MODCONSTRUCTOR(NoQModule) {}

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        NoRegistry registry(this);
        if (!sArgs.empty()) {
            SetUsername(No::token(sArgs, 0));
            SetPassword(No::token(sArgs, 1));
        } else {
            m_sUsername = registry.value("Username");
            m_sPassword = registry.value("Password");
        }

        NoString sTmp;
        m_bUseCloakedHost = (sTmp = registry.value("UseCloakedHost")).empty() ? true : sTmp.toBool();
        m_bUseChallenge = (sTmp = registry.value("UseChallenge")).empty() ? true : sTmp.toBool();
        m_bRequestPerms = registry.value("RequestPerms").toBool();
        m_bJoinOnInvite = (sTmp = registry.value("JoinOnInvite")).empty() ? true : sTmp.toBool();
        m_bJoinAfterCloaked = (sTmp = registry.value("JoinAfterCloaked")).empty() ? true : sTmp.toBool();

        // Make sure NVs are stored in config. Note: SetUseCloakedHost() is called further down.
        SetUseChallenge(m_bUseChallenge);
        SetRequestPerms(m_bRequestPerms);
        SetJoinOnInvite(m_bJoinOnInvite);
        SetJoinAfterCloaked(m_bJoinAfterCloaked);

        OnIRCDisconnected(); // reset module's state

        if (IsIRCConnected()) {
            // check for usermode +x if we are already connected
            std::set<uchar> scUserModes = GetNetwork()->GetIRCSock()->GetUserModes();
            if (scUserModes.find('x') != scUserModes.end()) m_bCloaked = true;

            // This will only happen once, and only if the user loads the module after connecting to IRC.
            // Also don't notify the user in case he already had mode +x set.
            if (registry.value("UseCloakedHost").empty()) {
                if (!m_bCloaked)
                    PutModule("Notice: Your host will be cloaked the next time you reconnect to IRC. "
                              "If you want to cloak your host now, /msg *q Cloak. You can set your preference "
                              "with /msg *q Set UseCloakedHost true/false.");
                m_bUseCloakedHost = true;
                SetUseCloakedHost(m_bUseCloakedHost);
                m_bJoinAfterCloaked = true;
                SetJoinAfterCloaked(m_bJoinAfterCloaked);
            } else if (m_bUseChallenge) {
                Cloak();
            }
            WhoAmI();
        } else {
            SetUseCloakedHost(m_bUseCloakedHost);
        }

        return true;
    }

    void OnIRCDisconnected() override
    {
        m_bCloaked = false;
        m_bAuthed = false;
        m_bRequestedWhoami = false;
        m_bRequestedChallenge = false;
        m_bCatchResponse = false;
    }

    void OnIRCConnected() override
    {
        if (m_bUseCloakedHost) Cloak();
        WhoAmI();
    }

    void OnModCommand(const NoString& sLine) override
    {
        NoString sCommand = No::token(sLine, 0).toLower();

        if (sCommand == "help") {
            PutModule("The following commands are available:");
            NoTable Table;
            Table.addColumn("Command");
            Table.addColumn("Description");
            Table.addRow();
            Table.setValue("Command", "Auth [<username> <password>]");
            Table.setValue("Description", "Tries to authenticate you with Q. Both parameters are optional.");
            Table.addRow();
            Table.setValue("Command", "Cloak");
            Table.setValue("Description", "Tries to set usermode +x to hide your real hostname.");
            Table.addRow();
            Table.setValue("Command", "Status");
            Table.setValue("Description", "Prints the current status of the module.");
            Table.addRow();
            Table.setValue("Command", "Update");
            Table.setValue("Description", "Re-requests the current user information from Q.");
            Table.addRow();
            Table.setValue("Command", "Set <setting> <value>");
            Table.setValue("Description", "Changes the value of the given setting. See the list of settings below.");
            Table.addRow();
            Table.setValue("Command", "Get");
            Table.setValue("Description", "Prints out the current configuration. See the list of settings below.");
            PutModule(Table);

            PutModule("The following settings are available:");
            NoTable Table2;
            Table2.addColumn("Setting");
            Table2.addColumn("Type");
            Table2.addColumn("Description");
            Table2.addRow();
            Table2.setValue("Setting", "Username");
            Table2.setValue("Type", "String");
            Table2.setValue("Description", "Your Q username.");
            Table2.addRow();
            Table2.setValue("Setting", "Password");
            Table2.setValue("Type", "String");
            Table2.setValue("Description", "Your Q password.");
            Table2.addRow();
            Table2.setValue("Setting", "UseCloakedHost");
            Table2.setValue("Type", "Boolean");
            Table2.setValue("Description", "Whether to cloak your hostname (+x) automatically on connect.");
            Table2.addRow();
            Table2.setValue("Setting", "UseChallenge");
            Table2.setValue("Type", "Boolean");
            Table2.setValue("Description",
                           "Whether to use the CHALLENGEAUTH mechanism to avoid sending passwords in cleartext.");
            Table2.addRow();
            Table2.setValue("Setting", "RequestPerms");
            Table2.setValue("Type", "Boolean");
            Table2.setValue("Description", "Whether to request voice/op from Q on join/devoice/deop.");
            Table2.addRow();
            Table2.setValue("Setting", "JoinOnInvite");
            Table2.setValue("Type", "Boolean");
            Table2.setValue("Description", "Whether to join channels when Q invites you.");
            Table2.addRow();
            Table2.setValue("Setting", "JoinAfterCloaked");
            Table2.setValue("Type", "Boolean");
            Table2.setValue("Description", "Whether to delay joining channels until after you are cloaked.");
            PutModule(Table2);

            PutModule("This module takes 2 optional parameters: <username> <password>");
            PutModule("Module settings are stored between restarts.");

        } else if (sCommand == "set") {
            NoString sSetting = No::token(sLine, 1).toLower();
            NoString sValue = No::token(sLine, 2);
            if (sSetting.empty() || sValue.empty()) {
                PutModule("Syntax: Set <setting> <value>");
            } else if (sSetting == "username") {
                SetUsername(sValue);
                PutModule("Username set");
            } else if (sSetting == "password") {
                SetPassword(sValue);
                PutModule("Password set");
            } else if (sSetting == "usecloakedhost") {
                SetUseCloakedHost(sValue.toBool());
                PutModule("UseCloakedHost set");
            } else if (sSetting == "usechallenge") {
                SetUseChallenge(sValue.toBool());
                PutModule("UseChallenge set");
            } else if (sSetting == "requestperms") {
                SetRequestPerms(sValue.toBool());
                PutModule("RequestPerms set");
            } else if (sSetting == "joinoninvite") {
                SetJoinOnInvite(sValue.toBool());
                PutModule("JoinOnInvite set");
            } else if (sSetting == "joinaftercloaked") {
                SetJoinAfterCloaked(sValue.toBool());
                PutModule("JoinAfterCloaked set");
            } else
                PutModule("Unknown setting: " + sSetting);

        } else if (sCommand == "get" || sCommand == "list") {
            NoTable Table;
            Table.addColumn("Setting");
            Table.addColumn("Value");
            Table.addRow();
            Table.setValue("Setting", "Username");
            Table.setValue("Value", m_sUsername);
            Table.addRow();
            Table.setValue("Setting", "Password");
            Table.setValue("Value", "*****"); // m_sPassword
            Table.addRow();
            Table.setValue("Setting", "UseCloakedHost");
            Table.setValue("Value", NoString(m_bUseCloakedHost));
            Table.addRow();
            Table.setValue("Setting", "UseChallenge");
            Table.setValue("Value", NoString(m_bUseChallenge));
            Table.addRow();
            Table.setValue("Setting", "RequestPerms");
            Table.setValue("Value", NoString(m_bRequestPerms));
            Table.addRow();
            Table.setValue("Setting", "JoinOnInvite");
            Table.setValue("Value", NoString(m_bJoinOnInvite));
            Table.addRow();
            Table.setValue("Setting", "JoinAfterCloaked");
            Table.setValue("Value", NoString(m_bJoinAfterCloaked));
            PutModule(Table);

        } else if (sCommand == "status") {
            PutModule("Connected: " + NoString(IsIRCConnected() ? "yes" : "no"));
            PutModule("Cloaked: " + NoString(m_bCloaked ? "yes" : "no"));
            PutModule("Authed: " + NoString(m_bAuthed ? "yes" : "no"));

        } else {
            // The following commands require an IRC connection.
            if (!IsIRCConnected()) {
                PutModule("Error: You are not connected to IRC.");
                return;
            }

            if (sCommand == "cloak") {
                if (!m_bCloaked)
                    Cloak();
                else
                    PutModule("Error: You are already cloaked!");

            } else if (sCommand == "auth") {
                if (!m_bAuthed)
                    Auth(No::token(sLine, 1), No::token(sLine, 2));
                else
                    PutModule("Error: You are already authed!");

            } else if (sCommand == "update") {
                WhoAmI();
                PutModule("Update requested.");

            } else {
                PutModule("Unknown command. Try 'help'.");
            }
        }
    }

    ModRet OnRaw(NoString& sLine) override
    {
        // use OnRaw because OnUserMode is not defined (yet?)
        if (No::token(sLine, 1) == "396" && No::token(sLine, 3).contains("users.quakenet.org")) {
            m_bCloaked = true;
            PutModule("Cloak successful: Your hostname is now cloaked.");

            // Join channels immediately after our spoof is set, but only if
            // both UseCloakedHost and JoinAfterCloaked is enabled. See #602.
            if (m_bJoinAfterCloaked) {
                GetNetwork()->JoinChans();
            }
        }
        return CONTINUE;
    }

    ModRet OnPrivMsg(NoNick& Nick, NoString& sMessage) override { return HandleMessage(Nick, sMessage); }

    ModRet OnPrivNotice(NoNick& Nick, NoString& sMessage) override { return HandleMessage(Nick, sMessage); }

    ModRet OnJoining(NoChannel& Channel) override
    {
        // Halt if are not already cloaked, but the user requres that we delay
        // channel join till after we are cloaked.
        if (!m_bCloaked && m_bUseCloakedHost && m_bJoinAfterCloaked) return HALT;

        return CONTINUE;
    }

    void OnJoin(const NoNick& Nick, NoChannel& Channel) override
    {
        if (m_bRequestPerms && IsSelf(Nick)) HandleNeed(Channel, "ov");
    }

    void OnDeop2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override
    {
        if (m_bRequestPerms && IsSelf(Nick) && (!pOpNick || !IsSelf(*pOpNick))) HandleNeed(Channel, "o");
    }

    void OnDevoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override
    {
        if (m_bRequestPerms && IsSelf(Nick) && (!pOpNick || !IsSelf(*pOpNick))) HandleNeed(Channel, "v");
    }

    ModRet OnInvite(const NoNick& Nick, const NoString& sChan) override
    {
        if (!Nick.equals("Q") || !Nick.host().equals("CServe.quakenet.org")) return CONTINUE;
        if (m_bJoinOnInvite) GetNetwork()->AddChan(sChan, false);
        return CONTINUE;
    }

    NoString GetWebMenuTitle() override { return "Q"; }

    bool OnWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "index") {
            bool bSubmitted = (WebSock.GetParam("submitted").toInt() != 0);

            if (bSubmitted) {
                NoString FormUsername = WebSock.GetParam("user");
                if (!FormUsername.empty()) SetUsername(FormUsername);

                NoString FormPassword = WebSock.GetParam("password");
                if (!FormPassword.empty()) SetPassword(FormPassword);

                SetUseCloakedHost(WebSock.GetParam("usecloakedhost").toBool());
                SetUseChallenge(WebSock.GetParam("usechallenge").toBool());
                SetRequestPerms(WebSock.GetParam("requestperms").toBool());
                SetJoinOnInvite(WebSock.GetParam("joinoninvite").toBool());
                SetJoinAfterCloaked(WebSock.GetParam("joinaftercloaked").toBool());
            }

            Tmpl["Username"] = m_sUsername;

            NoTemplate& o1 = Tmpl.AddRow("OptionLoop");
            o1["Name"] = "usecloakedhost";
            o1["DisplayName"] = "UseCloakedHost";
            o1["Tooltip"] = "Whether to cloak your hostname (+x) automatically on connect.";
            o1["Checked"] = NoString(m_bUseCloakedHost);

            NoTemplate& o2 = Tmpl.AddRow("OptionLoop");
            o2["Name"] = "usechallenge";
            o2["DisplayName"] = "UseChallenge";
            o2["Tooltip"] = "Whether to use the CHALLENGEAUTH mechanism to avoid sending passwords in cleartext.";
            o2["Checked"] = NoString(m_bUseChallenge);

            NoTemplate& o3 = Tmpl.AddRow("OptionLoop");
            o3["Name"] = "requestperms";
            o3["DisplayName"] = "RequestPerms";
            o3["Tooltip"] = "Whether to request voice/op from Q on join/devoice/deop.";
            o3["Checked"] = NoString(m_bRequestPerms);

            NoTemplate& o4 = Tmpl.AddRow("OptionLoop");
            o4["Name"] = "joinoninvite";
            o4["DisplayName"] = "JoinOnInvite";
            o4["Tooltip"] = "Whether to join channels when Q invites you.";
            o4["Checked"] = NoString(m_bJoinOnInvite);

            NoTemplate& o5 = Tmpl.AddRow("OptionLoop");
            o5["Name"] = "joinaftercloaked";
            o5["DisplayName"] = "JoinAfterCloaked";
            o5["Tooltip"] = "Whether to delay joining channels until after you are cloaked.";
            o5["Checked"] = NoString(m_bJoinAfterCloaked);

            if (bSubmitted) {
                WebSock.GetSession()->AddSuccess("Changes have been saved!");
            }

            return true;
        }

        return false;
    }

private:
    bool m_bCloaked;
    bool m_bAuthed;
    bool m_bRequestedWhoami;
    bool m_bRequestedChallenge;
    bool m_bCatchResponse;
    NoStringMap m_msChanModes;

    void PutQ(const NoString& sMessage)
    {
        PutIRC("PRIVMSG Q@CServe.quakenet.org :" + sMessage);
#if Q_DEBUG_COMMUNICATION
        PutModule("[ZNC --> Q] " + sMessage);
#endif
    }

    void Cloak()
    {
        if (m_bCloaked) return;

        PutModule("Cloak: Trying to cloak your hostname, setting +x...");
        PutIRC("MODE " + GetNetwork()->GetIRCSock()->GetNick() + " +x");
    }

    void WhoAmI()
    {
        m_bRequestedWhoami = true;
        PutQ("WHOAMI");
    }

    void Auth(const NoString& sUsername = "", const NoString& sPassword = "")
    {
        if (m_bAuthed) return;

        if (!sUsername.empty()) SetUsername(sUsername);
        if (!sPassword.empty()) SetPassword(sPassword);

        if (m_sUsername.empty() || m_sPassword.empty()) {
            PutModule("You have to set a username and password to use this module! See 'help' for details.");
            return;
        }

        if (m_bUseChallenge) {
            PutModule("Auth: Requesting CHALLENGE...");
            m_bRequestedChallenge = true;
            PutQ("CHALLENGE");
        } else {
            PutModule("Auth: Sending AUTH request...");
            PutQ("AUTH " + m_sUsername + " " + m_sPassword);
        }
    }

    void ChallengeAuth(NoString sChallenge)
    {
        if (m_bAuthed) return;

        NoString sUsername = m_sUsername.toLower().replace_n("[", "{").replace_n("]", "}").replace_n("\\", "|");
        NoString sPasswordHash = No::sha256(m_sPassword.left(10));
        NoString sKey = No::sha256(sUsername + ":" + sPasswordHash);
        NoString sResponse = HMAC_SHA256(sKey, sChallenge);

        PutModule("Auth: Received challenge, sending CHALLENGEAUTH request...");
        PutQ("CHALLENGEAUTH " + m_sUsername + " " + sResponse + " HMAC-SHA-256");
    }

    ModRet HandleMessage(const NoNick& Nick, NoString sMessage)
    {
        if (!Nick.equals("Q") || !Nick.host().equals("CServe.quakenet.org")) return CONTINUE;

        sMessage.trim();

#if Q_DEBUG_COMMUNICATION
        PutModule("[ZNC <-- Q] " + sMessage);
#endif

        // WHOAMI
        if (sMessage.contains("WHOAMI is only available to authed users")) {
            m_bAuthed = false;
            Auth();
            m_bCatchResponse = m_bRequestedWhoami;
        } else if (sMessage.contains("Information for user")) {
            m_bAuthed = true;
            m_msChanModes.clear();
            m_bCatchResponse = m_bRequestedWhoami;
            m_bRequestedWhoami = true;
        } else if (m_bRequestedWhoami && No::wildCmp(sMessage, "#*")) {
            NoString sChannel = No::token(sMessage, 0);
            NoString sFlags = No::tokens(sMessage, 1).trim_n().trimLeft_n("+");
            m_msChanModes[sChannel] = sFlags;
        } else if (m_bRequestedWhoami && m_bCatchResponse &&
                   (sMessage.equals("End of list.") || sMessage.equals("account, or HELLO to create an account."))) {
            m_bRequestedWhoami = m_bCatchResponse = false;
            return HALT;
        }

        // AUTH
        else if (sMessage.equals("Username or password incorrect.")) {
            m_bAuthed = false;
            PutModule("Auth failed: " + sMessage);
            return HALT;
        } else if (No::wildCmp(sMessage, "You are now logged in as *.")) {
            m_bAuthed = true;
            PutModule("Auth successful: " + sMessage);
            WhoAmI();
            return HALT;
        } else if (m_bRequestedChallenge && No::token(sMessage, 0).equals("CHALLENGE")) {
            m_bRequestedChallenge = false;
            if (sMessage.contains("not available once you have authed")) {
                m_bAuthed = true;
            } else {
                if (sMessage.contains("HMAC-SHA-256")) {
                    ChallengeAuth(No::token(sMessage, 1));
                } else {
                    PutModule(
                    "Auth failed: Q does not support HMAC-SHA-256 for CHALLENGEAUTH, falling back to standard AUTH.");
                    SetUseChallenge(false);
                    Auth();
                }
            }
            return HALT;
        }

        // prevent buffering of Q's responses
        return !m_bCatchResponse && GetUser()->IsUserAttached() ? CONTINUE : HALT;
    }

    void HandleNeed(const NoChannel& Channel, const NoString& sPerms)
    {
        NoStringMap::iterator it = m_msChanModes.find(Channel.getName());
        if (it == m_msChanModes.end()) return;
        NoString sModes = it->second;

        bool bMaster = sModes.contains("m") || sModes.contains("n");

        if (sPerms.contains("o")) {
            bool bOp = sModes.contains("o");
            bool bAutoOp = sModes.contains("a");
            if (bMaster || bOp) {
                if (!bAutoOp) {
                    PutModule("RequestPerms: Requesting op on " + Channel.getName());
                    PutQ("OP " + Channel.getName());
                }
                return;
            }
        }

        if (sPerms.contains("v")) {
            bool bVoice = sModes.contains("v");
            bool bAutoVoice = sModes.contains("g");
            if (bMaster || bVoice) {
                if (!bAutoVoice) {
                    PutModule("RequestPerms: Requesting voice on " + Channel.getName());
                    PutQ("VOICE " + Channel.getName());
                }
                return;
            }
        }
    }


    /* Utility Functions */
    bool IsIRCConnected()
    {
        NoIrcSocket* pIRCSock = GetNetwork()->GetIRCSock();
        return pIRCSock && pIRCSock->IsAuthed();
    }

    bool IsSelf(const NoNick& Nick) { return Nick.equals(GetNetwork()->GetCurNick()); }

    bool PackHex(const NoString& sHex, NoString& sPackedHex)
    {
        if (sHex.length() % 2) return false;

        sPackedHex.clear();

        NoString::size_type len = sHex.length() / 2;
        for (NoString::size_type i = 0; i < len; i++) {
            uint value;
            int n = sscanf(&sHex[i * 2], "%02x", &value);
            if (n != 1 || value > 0xff) return false;
            sPackedHex += (uchar)value;
        }

        return true;
    }

    NoString HMAC_SHA256(const NoString& sKey, const NoString& sData)
    {
        NoString sRealKey;
        if (sKey.length() > 64)
            PackHex(No::sha256(sKey), sRealKey);
        else
            sRealKey = sKey;

        NoString sOuterKey, sInnerKey;
        NoString::size_type iKeyLength = sRealKey.length();
        for (uint i = 0; i < 64; i++) {
            char r = (i < iKeyLength ? sRealKey[i] : '\0');
            sOuterKey += r ^ 0x5c;
            sInnerKey += r ^ 0x36;
        }

        NoString sInnerHash;
        PackHex(No::sha256(sInnerKey + sData), sInnerHash);
        return No::sha256(sOuterKey + sInnerHash);
    }

    /* Settings */
    NoString m_sUsername;
    NoString m_sPassword;
    bool m_bUseCloakedHost;
    bool m_bUseChallenge;
    bool m_bRequestPerms;
    bool m_bJoinOnInvite;
    bool m_bJoinAfterCloaked;

    void SetUsername(const NoString& sUsername)
    {
        NoRegistry registry(this);
        registry.setValue("Username", sUsername);
        m_sUsername = sUsername;
    }

    void SetPassword(const NoString& sPassword)
    {
        NoRegistry registry(this);
        registry.setValue("Password", sPassword);
        m_sPassword = sPassword;
    }

    void SetUseCloakedHost(const bool bUseCloakedHost)
    {
        NoRegistry registry(this);
        registry.setValue("UseCloakedHost", NoString(bUseCloakedHost));
        m_bUseCloakedHost = bUseCloakedHost;

        if (!m_bCloaked && m_bUseCloakedHost && IsIRCConnected()) Cloak();
    }

    void SetUseChallenge(const bool bUseChallenge)
    {
        NoRegistry registry(this);
        registry.setValue("UseChallenge", NoString(bUseChallenge));
        m_bUseChallenge = bUseChallenge;
    }

    void SetRequestPerms(const bool bRequestPerms)
    {
        NoRegistry registry(this);
        registry.setValue("RequestPerms", NoString(bRequestPerms));
        m_bRequestPerms = bRequestPerms;
    }

    void SetJoinOnInvite(const bool bJoinOnInvite)
    {
        NoRegistry registry(this);
        registry.setValue("JoinOnInvite", NoString(bJoinOnInvite));
        m_bJoinOnInvite = bJoinOnInvite;
    }

    void SetJoinAfterCloaked(const bool bJoinAfterCloaked)
    {
        NoRegistry registry(this);
        registry.setValue("JoinAfterCloaked", NoString(bJoinAfterCloaked));
        m_bJoinAfterCloaked = bJoinAfterCloaked;
    }
};

template <> void no_moduleInfo<NoQModule>(NoModuleInfo& Info)
{
    Info.SetWikiPage("Q");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("Please provide your username and password for Q.");
}

NETWORKMODULEDEFS(NoQModule, "Auths you with QuakeNet's Q bot.")
