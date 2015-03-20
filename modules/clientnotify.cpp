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

#include <no/nomodule.h>
#include <no/noapp.h>
#include <no/nouser.h>
#include <no/noclient.h>

class NoClientNotifyMod : public NoModule
{
protected:
    NoString m_sMethod;
    bool m_bNewOnly;
    bool m_bOnDisconnect;

    std::set<NoString> m_sClientsSeen;

    void SaveSettings()
    {
        SetNV("method", m_sMethod);
        SetNV("newonly", m_bNewOnly ? "1" : "0");
        SetNV("ondisconnect", m_bOnDisconnect ? "1" : "0");
    }

    void SendNotification(const NoString& sMessage)
    {
        if (m_sMethod == "message") {
            GetUser()->PutStatus(sMessage, nullptr, GetClient());
        } else if (m_sMethod == "notice") {
            GetUser()->PutStatusNotice(sMessage, nullptr, GetClient());
        }
    }

public:
    MODCONSTRUCTOR(NoClientNotifyMod)
    {
        AddHelpCommand();
        AddCommand("Method",
                   static_cast<NoModCommand::ModCmdFunc>(&NoClientNotifyMod::OnMethodCommand),
                   "<message|notice|off>",
                   "Sets the notify method");
        AddCommand("NewOnly",
                   static_cast<NoModCommand::ModCmdFunc>(&NoClientNotifyMod::OnNewOnlyCommand),
                   "<on|off>",
                   "Turns notifies for unseen IP addresses only on or off");
        AddCommand("OnDisconnect",
                   static_cast<NoModCommand::ModCmdFunc>(&NoClientNotifyMod::OnDisconnectCommand),
                   "<on|off>",
                   "Turns notifies on disconnecting clients on or off");
        AddCommand("Show",
                   static_cast<NoModCommand::ModCmdFunc>(&NoClientNotifyMod::OnShowCommand),
                   "",
                   "Show the current settings");
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        m_sMethod = GetNV("method");

        if (m_sMethod != "notice" && m_sMethod != "message" && m_sMethod != "off") {
            m_sMethod = "message";
        }

        // default = off for these:

        m_bNewOnly = (GetNV("newonly") == "1");
        m_bOnDisconnect = (GetNV("ondisconnect") == "1");

        return true;
    }

    void OnClientLogin() override
    {
        NoString sRemoteIP = GetClient()->GetRemoteIP();
        if (!m_bNewOnly || m_sClientsSeen.find(sRemoteIP) == m_sClientsSeen.end()) {
            SendNotification("Another client authenticated as your user. "
                             "Use the 'ListClients' command to see all " +
                             NoString(GetUser()->GetAllClients().size()) + " clients.");

            // the std::set<> will automatically disregard duplicates:
            m_sClientsSeen.insert(sRemoteIP);
        }
    }

    void OnClientDisconnect() override
    {
        if (m_bOnDisconnect) {
            SendNotification("A client disconnected from your user. "
                             "Use the 'ListClients' command to see the " +
                             NoString(GetUser()->GetAllClients().size()) + " remaining client(s).");
        }
    }

    void OnMethodCommand(const NoString& sCommand)
    {
        const NoString& sArg = sCommand.tokens(1).toLower();

        if (sArg != "notice" && sArg != "message" && sArg != "off") {
            PutModule("Usage: Method <message|notice|off>");
            return;
        }

        m_sMethod = sArg;
        SaveSettings();
        PutModule("Saved.");
    }

    void OnNewOnlyCommand(const NoString& sCommand)
    {
        const NoString& sArg = sCommand.tokens(1).toLower();

        if (sArg.empty()) {
            PutModule("Usage: NewOnly <on|off>");
            return;
        }

        m_bNewOnly = sArg.toBool();
        SaveSettings();
        PutModule("Saved.");
    }

    void OnDisconnectCommand(const NoString& sCommand)
    {
        const NoString& sArg = sCommand.tokens(1).toLower();

        if (sArg.empty()) {
            PutModule("Usage: OnDisconnect <on|off>");
            return;
        }

        m_bOnDisconnect = sArg.toBool();
        SaveSettings();
        PutModule("Saved.");
    }

    void OnShowCommand(const NoString& sLine)
    {
        PutModule("Current settings: Method: " + m_sMethod + ", for unseen IP addresses only: " + NoString(m_bNewOnly) +
                  ", notify on disconnecting clients: " + NoString(m_bOnDisconnect));
    }
};

template <> void no_moduleInfo<NoClientNotifyMod>(NoModuleInfo& Info) { Info.SetWikiPage("clientnotify"); }

USERMODULEDEFS(NoClientNotifyMod, "Notifies you when another IRC client logs into or out of your account. Configurable.")
