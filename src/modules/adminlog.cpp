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
#include <nobnc/nofile.h>
#include <nobnc/noserverinfo.h>
#include <nobnc/nonetwork.h>
#include <nobnc/nouser.h>
#include <nobnc/nodebug.h>
#include <nobnc/noclient.h>
#include <nobnc/noregistry.h>
#include <nobnc/nosocket.h>
#include <nobnc/noutils.h>

#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>

class NoAdminLogMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoAdminLogMod)
    {
        addHelpCommand();
        addCommand("Show",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminLogMod::OnShowCommand),
                   "",
                   "Show the logging target");
        addCommand("Target",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAdminLogMod::OnTargetCommand),
                   "<file|syslog|both>",
                   "Set the logging target");
        openlog("znc", LOG_PID, LOG_DAEMON);
    }

    virtual ~NoAdminLogMod()
    {
        Log("Logging ended.");
        closelog();
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        NoRegistry registry(this);
        NoString target = registry.value("target");
        if (target.equals("syslog"))
            m_eLogMode = LOG_TO_SYSLOG;
        else if (target.equals("both"))
            m_eLogMode = LOG_TO_BOTH;
        else if (target.equals("file"))
            m_eLogMode = LOG_TO_FILE;
        else
            m_eLogMode = LOG_TO_FILE;

        m_sLogFile = savePath() + "/znc.log";

        Log("Logging started. ZNC PID[" + NoString(getpid()) + "] UID/GID[" + NoString(getuid()) + ":" + NoString(getgid()) + "]");
        return true;
    }

    void onIrcConnected() override
    {
        Log("[" + user()->userName() + "/" + network()->name() + "] connected to IRC: " + network()->currentServer()->host());
    }

    void onIrcDisconnected() override
    {
        Log("[" + user()->userName() + "/" + network()->name() + "] disconnected from IRC");
    }

    ModRet onRaw(NoString& line) override
    {
        if (line.startsWith("ERROR ")) {
            // ERROR :Closing Link: nick[24.24.24.24] (Excess Flood)
            // ERROR :Closing Link: nick[24.24.24.24] Killer (Local kill by Killer (reason))
            NoString error(line.substr(6));
            if (error.left(1) == ":")
                error.leftChomp(1);
            Log("[" + user()->userName() + "/" + network()->name() + "] disconnected from IRC: " +
                network()->currentServer()->host() + " [" + error + "]",
                LOG_NOTICE);
        }
        return CONTINUE;
    }

    void onClientLogin() override
    {
        Log("[" + user()->userName() + "] connected to ZNC from " + client()->socket()->remoteAddress());
    }

    void onClientDisconnect() override
    {
        Log("[" + user()->userName() + "] disconnected from ZNC from " + client()->socket()->remoteAddress());
    }

    void onFailedLogin(const NoString& username, const NoString& sRemoteIP) override
    {
        Log("[" + username + "] failed to login from " + sRemoteIP, LOG_WARNING);
    }

    void Log(NoString line, int iPrio = LOG_INFO)
    {
        if (m_eLogMode & LOG_TO_SYSLOG)
            syslog(iPrio, "%s", line.c_str());

        if (m_eLogMode & LOG_TO_FILE) {
            time_t curtime;
            tm* timeinfo;
            char buf[23];

            time(&curtime);
            timeinfo = localtime(&curtime);
            strftime(buf, sizeof(buf), "[%Y-%m-%d %H:%M:%S] ", timeinfo);

            NoFile LogFile(m_sLogFile);

            if (LogFile.Open(O_WRONLY | O_APPEND | O_CREAT))
                LogFile.Write(buf + line + "\n");
            else
                NO_DEBUG("Failed to write to [" << m_sLogFile << "]: " << strerror(errno));
        }
    }

    void onModCommand(const NoString& command) override
    {
        if (!user()->isAdmin()) {
            putModule("Access denied");
        } else {
            handleCommand(command);
        }
    }

    void OnTargetCommand(const NoString& command)
    {
        NoString arg = No::tokens(command, 1);
        NoString target;
        NoString message;
        LogMode mode;

        if (arg.equals("file")) {
            target = "file";
            message = "Now only logging to file";
            mode = LOG_TO_FILE;
        } else if (arg.equals("syslog")) {
            target = "syslog";
            message = "Now only logging to syslog";
            mode = LOG_TO_SYSLOG;
        } else if (arg.equals("both")) {
            target = "both";
            message = "Now logging to file and syslog";
            mode = LOG_TO_BOTH;
        } else {
            if (arg.empty()) {
                putModule("Usage: Target <file|syslog|both>");
            } else {
                putModule("Unknown target");
            }
            return;
        }

        Log(message);
        NoRegistry registry(this);
        registry.setValue("target", target);
        m_eLogMode = mode;
        putModule(message);
    }

    void OnShowCommand(const NoString& command)
    {
        NoString target;

        switch (m_eLogMode) {
        case LOG_TO_FILE:
            target = "file";
            break;
        case LOG_TO_SYSLOG:
            target = "syslog";
            break;
        case LOG_TO_BOTH:
            target = "both, file and syslog";
            break;
        }

        putModule("Logging is enabled for " + target);
        if (m_eLogMode != LOG_TO_SYSLOG)
            putModule("Log file will be written to [" + m_sLogFile + "]");
    }

private:
    enum LogMode { LOG_TO_FILE = 1 << 0, LOG_TO_SYSLOG = 1 << 1, LOG_TO_BOTH = LOG_TO_FILE | LOG_TO_SYSLOG };
    LogMode m_eLogMode;
    NoString m_sLogFile;
};

template <>
void no_moduleInfo<NoAdminLogMod>(NoModuleInfo& info)
{
    info.setWikiPage("adminlog");
}

GLOBALMODULEDEFS(NoAdminLogMod, "Log ZNC events to file and/or syslog.")
