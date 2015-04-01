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
#include <no/noapp.h>
#include <no/nouser.h>
#include <no/noclient.h>
#include <no/noregistry.h>
#include <no/nosocket.h>

class NoClientNotifyMod : public NoModule
{
protected:
    NoString m_sMethod;
    bool m_bNewOnly;
    bool m_bOnDisconnect;

    std::set<NoString> m_sClientsSeen;

    void SaveSettings()
    {
        NoRegistry registry(this);
        registry.setValue("method", m_sMethod);
        registry.setValue("newonly", m_bNewOnly ? "1" : "0");
        registry.setValue("ondisconnect", m_bOnDisconnect ? "1" : "0");
    }

    void SendNotification(const NoString& message)
    {
        if (m_sMethod == "message") {
            user()->putStatus(message, nullptr, client());
        } else if (m_sMethod == "notice") {
            user()->putStatusNotice(message, nullptr, client());
        }
    }

public:
    MODCONSTRUCTOR(NoClientNotifyMod)
    {
        addHelpCommand();
        addCommand("Method",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoClientNotifyMod::OnMethodCommand),
                   "<message|notice|off>",
                   "Sets the notify method");
        addCommand("NewOnly",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoClientNotifyMod::OnNewOnlyCommand),
                   "<on|off>",
                   "Turns notifies for unseen IP addresses only on or off");
        addCommand("OnDisconnect",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoClientNotifyMod::OnDisconnectCommand),
                   "<on|off>",
                   "Turns notifies on disconnecting clients on or off");
        addCommand("Show",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoClientNotifyMod::OnShowCommand),
                   "",
                   "Show the current settings");
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        NoRegistry registry(this);
        m_sMethod = registry.value("method");

        if (m_sMethod != "notice" && m_sMethod != "message" && m_sMethod != "off") {
            m_sMethod = "message";
        }

        // default = off for these:

        m_bNewOnly = (registry.value("newonly") == "1");
        m_bOnDisconnect = (registry.value("ondisconnect") == "1");

        return true;
    }

    void onClientLogin() override
    {
        NoString sRemoteIP = client()->socket()->remoteAddress();
        if (!m_bNewOnly || m_sClientsSeen.find(sRemoteIP) == m_sClientsSeen.end()) {
            SendNotification("Another client authenticated as your user. "
                             "Use the 'ListClients' command to see all " +
                             NoString(user()->allClients().size()) + " clients.");

            // the std::set<> will automatically disregard duplicates:
            m_sClientsSeen.insert(sRemoteIP);
        }
    }

    void onClientDisconnect() override
    {
        if (m_bOnDisconnect) {
            SendNotification("A client disconnected from your user. "
                             "Use the 'ListClients' command to see the " +
                             NoString(user()->allClients().size()) + " remaining client(s).");
        }
    }

    void OnMethodCommand(const NoString& command)
    {
        const NoString& arg = No::tokens(command, 1).toLower();

        if (arg != "notice" && arg != "message" && arg != "off") {
            putModule("Usage: Method <message|notice|off>");
            return;
        }

        m_sMethod = arg;
        SaveSettings();
        putModule("Saved.");
    }

    void OnNewOnlyCommand(const NoString& command)
    {
        const NoString& arg = No::tokens(command, 1).toLower();

        if (arg.empty()) {
            putModule("Usage: NewOnly <on|off>");
            return;
        }

        m_bNewOnly = arg.toBool();
        SaveSettings();
        putModule("Saved.");
    }

    void OnDisconnectCommand(const NoString& command)
    {
        const NoString& arg = No::tokens(command, 1).toLower();

        if (arg.empty()) {
            putModule("Usage: OnDisconnect <on|off>");
            return;
        }

        m_bOnDisconnect = arg.toBool();
        SaveSettings();
        putModule("Saved.");
    }

    void OnShowCommand(const NoString& line)
    {
        putModule("Current settings: Method: " + m_sMethod + ", for unseen IP addresses only: " + NoString(m_bNewOnly) +
                  ", notify on disconnecting clients: " + NoString(m_bOnDisconnect));
    }
};

template <>
void no_moduleInfo<NoClientNotifyMod>(NoModuleInfo& info)
{
    info.setWikiPage("clientnotify");
}

USERMODULEDEFS(NoClientNotifyMod,
               "Notifies you when another IRC client logs into or out of your account. Configurable.")
