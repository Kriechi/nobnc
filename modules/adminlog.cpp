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
#include <no/nofile.h>
#include <no/noserverinfo.h>
#include <no/nonetwork.h>
#include <no/nouser.h>
#include <no/nodebug.h>
#include <no/noclient.h>
#include <no/noregistry.h>
#include <no/nosocket.h>

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

    bool onLoad(const NoString& sArgs, NoString& sMessage) override
    {
        NoRegistry registry(this);
        NoString sTarget = registry.value("target");
        if (sTarget.equals("syslog"))
            m_eLogMode = LOG_TO_SYSLOG;
        else if (sTarget.equals("both"))
            m_eLogMode = LOG_TO_BOTH;
        else if (sTarget.equals("file"))
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

    ModRet onRaw(NoString& sLine) override
    {
        if (sLine.startsWith("ERROR ")) {
            // ERROR :Closing Link: nick[24.24.24.24] (Excess Flood)
            // ERROR :Closing Link: nick[24.24.24.24] Killer (Local kill by Killer (reason))
            NoString sError(sLine.substr(6));
            if (sError.left(1) == ":")
                sError.leftChomp(1);
            Log("[" + user()->userName() + "/" + network()->name() + "] disconnected from IRC: " +
                network()->currentServer()->host() + " [" + sError + "]",
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

    void onFailedLogin(const NoString& sUsername, const NoString& sRemoteIP) override
    {
        Log("[" + sUsername + "] failed to login from " + sRemoteIP, LOG_WARNING);
    }

    void Log(NoString sLine, int iPrio = LOG_INFO)
    {
        if (m_eLogMode & LOG_TO_SYSLOG)
            syslog(iPrio, "%s", sLine.c_str());

        if (m_eLogMode & LOG_TO_FILE) {
            time_t curtime;
            tm* timeinfo;
            char buf[23];

            time(&curtime);
            timeinfo = localtime(&curtime);
            strftime(buf, sizeof(buf), "[%Y-%m-%d %H:%M:%S] ", timeinfo);

            NoFile LogFile(m_sLogFile);

            if (LogFile.Open(O_WRONLY | O_APPEND | O_CREAT))
                LogFile.Write(buf + sLine + "\n");
            else
                NO_DEBUG("Failed to write to [" << m_sLogFile << "]: " << strerror(errno));
        }
    }

    void onModCommand(const NoString& sCommand) override
    {
        if (!user()->isAdmin()) {
            putModule("Access denied");
        } else {
            handleCommand(sCommand);
        }
    }

    void OnTargetCommand(const NoString& sCommand)
    {
        NoString sArg = No::tokens(sCommand, 1);
        NoString sTarget;
        NoString sMessage;
        LogMode mode;

        if (sArg.equals("file")) {
            sTarget = "file";
            sMessage = "Now only logging to file";
            mode = LOG_TO_FILE;
        } else if (sArg.equals("syslog")) {
            sTarget = "syslog";
            sMessage = "Now only logging to syslog";
            mode = LOG_TO_SYSLOG;
        } else if (sArg.equals("both")) {
            sTarget = "both";
            sMessage = "Now logging to file and syslog";
            mode = LOG_TO_BOTH;
        } else {
            if (sArg.empty()) {
                putModule("Usage: Target <file|syslog|both>");
            } else {
                putModule("Unknown target");
            }
            return;
        }

        Log(sMessage);
        NoRegistry registry(this);
        registry.setValue("target", sTarget);
        m_eLogMode = mode;
        putModule(sMessage);
    }

    void OnShowCommand(const NoString& sCommand)
    {
        NoString sTarget;

        switch (m_eLogMode) {
        case LOG_TO_FILE:
            sTarget = "file";
            break;
        case LOG_TO_SYSLOG:
            sTarget = "syslog";
            break;
        case LOG_TO_BOTH:
            sTarget = "both, file and syslog";
            break;
        }

        putModule("Logging is enabled for " + sTarget);
        if (m_eLogMode != LOG_TO_SYSLOG)
            putModule("Log file will be written to [" + m_sLogFile + "]");
    }

private:
    enum LogMode { LOG_TO_FILE = 1 << 0, LOG_TO_SYSLOG = 1 << 1, LOG_TO_BOTH = LOG_TO_FILE | LOG_TO_SYSLOG };
    LogMode m_eLogMode;
    NoString m_sLogFile;
};

template <>
void no_moduleInfo<NoAdminLogMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("adminlog");
}

GLOBALMODULEDEFS(NoAdminLogMod, "Log ZNC events to file and/or syslog.")
