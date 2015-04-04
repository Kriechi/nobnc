/*
 * Copyright (C) 2015 NoBNC
 * Copyright (C) 2004-2015 ZNC, see the NOTICE file for details.
 * Author: imaginos <imaginos@imaginos.net>
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

/*
 * Quiet Away and message logger
 *
 * I originally wrote this module for when I had multiple clients connected to ZNC. I would leave work and forget to
 *close my client, arriving at home
 * and re-attaching there someone may have messaged me in commute and I wouldn't know it until I would arrive back at
 *work the next day. I wrote it such that
 * my xchat client would monitor desktop activity and ping the module to let it know I was active. Within a few minutes
 *of inactivity the pinging stops and
 * the away module sets the user as away and logging commences.
 */

#define REQUIRESSL

#include <nobnc/nomodule.h>
#include <nobnc/nouser.h>
#include <nobnc/nonetwork.h>
#include <nobnc/nofile.h>
#include <nobnc/noutils.h>
#include <nobnc/noclient.h>
#include <nobnc/nonick.h>
#include <nobnc/nohostmask.h>
#include <nobnc/notimer.h>

#define CRYPT_VERIFICATION_TOKEN "::__:AWAY:__::"

class NoAway;

class NoAwayJob : public NoTimer
{
public:
    NoAwayJob(NoModule* module) : NoTimer(module)
    {
        setName("AwayJob");
        setDescription("Checks for idle and saves messages every 1 minute");
    }

protected:
    void run() override;
};

class NoAway : public NoModule
{
    void AwayCommand(const NoString& command)
    {
        NoString reason;
        time_t curtime;
        time(&curtime);

        if (No::token(command, 1) != "-quiet") {
            reason = No::formatTime(curtime, No::tokens(command, 1), user()->timezone());
            putModuleNotice("You have been marked as away");
        } else {
            reason = No::formatTime(curtime, No::tokens(command, 2), user()->timezone());
        }

        Away(false, reason);
    }

    void BackCommand(const NoString& command)
    {
        if ((m_vMessages.empty()) && (No::token(command, 1) != "-quiet"))
            putModuleNotice("Welcome Back!");
        Ping();
        Back();
    }

    void MessagesCommand(const NoString& command)
    {
        for (u_int a = 0; a < m_vMessages.size(); a++)
            putModule(m_vMessages[a]);
    }

    void ReplayCommand(const NoString& command)
    {
        NoString nick = client()->nick();
        for (u_int a = 0; a < m_vMessages.size(); a++) {
            NoString sWhom = No::token(m_vMessages[a], 1, ":");
            NoString message = No::tokens(m_vMessages[a], 2, ":");
            putUser(":" + sWhom + " PRIVMSG " + nick + " :" + message);
        }
    }

    void DeleteCommand(const NoString& command)
    {
        NoString sWhich = No::token(command, 1);
        if (sWhich == "all") {
            putModuleNotice("Deleted " + NoString(m_vMessages.size()) + " Messages.");
            for (u_int a = 0; a < m_vMessages.size(); a++)
                m_vMessages.erase(m_vMessages.begin() + a--);
        } else if (sWhich.empty()) {
            putModuleNotice("USAGE: delete <num|all>");
            return;
        } else {
            u_int iNum = sWhich.toUInt();
            if (iNum >= m_vMessages.size()) {
                putModuleNotice("Illegal Message # Requested");
                return;
            } else {
                m_vMessages.erase(m_vMessages.begin() + iNum);
                putModuleNotice("Message Erased.");
            }
            SaveBufferToDisk();
        }
    }

    void SaveCommand(const NoString& command)
    {
        if (m_saveMessages) {
            SaveBufferToDisk();
            putModuleNotice("Messages saved to disk.");
        } else {
            putModuleNotice("There are no messages to save.");
        }
    }

    void PingCommand(const NoString& command)
    {
        Ping();
        if (m_bIsAway)
            Back();
    }

    void PassCommand(const NoString& command)
    {
        m_sPassword = No::token(command, 1);
        putModuleNotice("Password Updated to [" + m_sPassword + "]");
    }

    void ShowCommand(const NoString& command)
    {
        std::map<NoString, std::vector<NoString>> msvOutput;
        for (u_int a = 0; a < m_vMessages.size(); a++) {
            NoString sTime = No::token(m_vMessages[a], 0);
            NoString sWhom = No::token(m_vMessages[a], 1);
            NoString message = No::tokens(m_vMessages[a], 2);

            if ((sTime.empty()) || (sWhom.empty()) || (message.empty())) {
                // illegal format
                putModule("Corrupt message! [" + m_vMessages[a] + "]");
                m_vMessages.erase(m_vMessages.begin() + a--);
                continue;
            }

            time_t iTime = sTime.toULong();
            char szFormat[64];
            struct tm t;
            localtime_r(&iTime, &t);
            size_t iCount = strftime(szFormat, 64, "%F %T", &t);

            if (iCount <= 0) {
                putModule("Corrupt time stamp! [" + m_vMessages[a] + "]");
                m_vMessages.erase(m_vMessages.begin() + a--);
                continue;
            }

            NoString sTmp = "    " + NoString(a) + ") [";
            sTmp.append(szFormat, iCount);
            sTmp += "] ";
            sTmp += message;
            msvOutput[sWhom].push_back(sTmp);
        }

        for (std::map<NoString, std::vector<NoString>>::iterator it = msvOutput.begin(); it != msvOutput.end(); ++it) {
            putModule(it->first);
            for (u_int a = 0; a < it->second.size(); a++)
                putModule(it->second[a]);
        }

        putModule("#--- End Messages");
    }

    void EnableTimerCommand(const NoString& command)
    {
        SetAwayTime(300);
        putModule("Timer set to 300 seconds");
    }

    void DisableTimerCommand(const NoString& command)
    {
        SetAwayTime(0);
        putModule("Timer disabled");
    }

    void SetTimerCommand(const NoString& command)
    {
        int iSetting = No::token(command, 1).toInt();

        SetAwayTime(iSetting);

        if (iSetting == 0)
            putModule("Timer disabled");
        else
            putModule("Timer set to " + NoString(iSetting) + " seconds");
    }

    void TimerCommand(const NoString& command)
    {
        putModule("Current timer setting: " + NoString(GetAwayTime()) + " seconds");
    }

public:
    MODCONSTRUCTOR(NoAway)
    {
        Ping();
        m_bIsAway = false;
        m_bBootError = false;
        m_saveMessages = true;
        SetAwayTime(300);
        NoAwayJob* timer = new NoAwayJob(this);
        timer->start(60);

        addHelpCommand();
        addCommand("Away", static_cast<NoModuleCommand::ModCmdFunc>(&NoAway::AwayCommand), "[-quiet]");
        addCommand("Back", static_cast<NoModuleCommand::ModCmdFunc>(&NoAway::BackCommand), "[-quiet]");
        addCommand("Messages", static_cast<NoModuleCommand::ModCmdFunc>(&NoAway::BackCommand));
        addCommand("Delete", static_cast<NoModuleCommand::ModCmdFunc>(&NoAway::DeleteCommand), "delete <num|all>");
        addCommand("Save", static_cast<NoModuleCommand::ModCmdFunc>(&NoAway::SaveCommand));
        addCommand("Ping", static_cast<NoModuleCommand::ModCmdFunc>(&NoAway::PingCommand));
        addCommand("Pass", static_cast<NoModuleCommand::ModCmdFunc>(&NoAway::PassCommand));
        addCommand("Show", static_cast<NoModuleCommand::ModCmdFunc>(&NoAway::ShowCommand));
        addCommand("Replay", static_cast<NoModuleCommand::ModCmdFunc>(&NoAway::ReplayCommand));
        addCommand("EnableTimer", static_cast<NoModuleCommand::ModCmdFunc>(&NoAway::EnableTimerCommand));
        addCommand("DisableTimer", static_cast<NoModuleCommand::ModCmdFunc>(&NoAway::DisableTimerCommand));
        addCommand("SetTimer", static_cast<NoModuleCommand::ModCmdFunc>(&NoAway::SetTimerCommand), "<secs>");
        addCommand("Timer", static_cast<NoModuleCommand::ModCmdFunc>(&NoAway::TimerCommand));
    }

    virtual ~NoAway()
    {
        if (!m_bBootError)
            SaveBufferToDisk();
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        NoString sMyArgs = args;
        size_t uIndex = 0;
        if (No::token(sMyArgs, 0) == "-nostore") {
            uIndex++;
            m_saveMessages = false;
        }
        if (No::token(sMyArgs, uIndex) == "-notimer") {
            SetAwayTime(0);
            sMyArgs = No::tokens(sMyArgs, uIndex + 1);
        } else if (No::token(sMyArgs, uIndex) == "-timer") {
            SetAwayTime(No::token(sMyArgs, uIndex + 1).toInt());
            sMyArgs = No::tokens(sMyArgs, uIndex + 2);
        }
        if (m_saveMessages) {
            if (!sMyArgs.empty()) {
                m_sPassword = No::md5(sMyArgs);
            } else {
                message = "This module needs as an argument a keyphrase used for encryption";
                return false;
            }

            if (!BootStrap()) {
                message = "Failed to decrypt your saved messages - "
                           "Did you give the right encryption key as an argument to this module?";
                m_bBootError = true;
                return false;
            }
        }

        return true;
    }

    void onIrcConnected() override
    {
        if (m_bIsAway)
            Away(true); // reset away if we are reconnected
        else
            Back(); // ircd seems to remember your away if you killed the client and came back
    }

    bool BootStrap()
    {
        NoString sFile;
        if (DecryptMessages(sFile)) {
            NoStringVector::iterator it;

            NoStringVector vsLines = sFile.split("\n");

            for (it = vsLines.begin(); it != vsLines.end(); ++it) {
                NoString line(*it);
                line.trim();
                AddMessage(line);
            }
        } else {
            m_sPassword = "";
            No::printError("[" + moduleName() + ".so] Failed to Decrypt Messages");
            return (false);
        }

        return (true);
    }

    void SaveBufferToDisk()
    {
        if (!m_sPassword.empty()) {
            NoString sFile = CRYPT_VERIFICATION_TOKEN;

            for (u_int b = 0; b < m_vMessages.size(); b++)
                sFile += m_vMessages[b] + "\n";

            sFile = No::encrypt(sFile, m_sPassword);
            NoString path = GetPath();
            if (!path.empty()) {
                NoFile File(path);
                if (File.Open(O_WRONLY | O_CREAT | O_TRUNC, 0600)) {
                    File.Chmod(0600);
                    File.Write(sFile);
                }
                File.Close();
            }
        }
    }

    void onClientLogin() override
    {
        Back(true);
    }
    void onClientDisconnect() override
    {
        Away();
    }

    NoString GetPath()
    {
        NoString sBuffer = user()->userName();
        NoString ret = savePath();
        ret += "/.znc-away-" + No::md5(sBuffer);
        return (ret);
    }

    void Away(bool force = false, const NoString& reason = "")
    {
        if ((!m_bIsAway) || (force)) {
            if (!force)
                m_sReason = reason;
            else if (!reason.empty())
                m_sReason = reason;

            time_t iTime = time(nullptr);
            char* pTime = ctime(&iTime);
            NoString sTime;
            if (pTime) {
                sTime = pTime;
                sTime.trim();
            }
            if (m_sReason.empty())
                m_sReason = "Auto Away at " + sTime;
            putIrc("AWAY :" + m_sReason);
            m_bIsAway = true;
        }
    }

    void Back(bool bUsePrivMessage = false)
    {
        putIrc("away");
        m_bIsAway = false;
        if (!m_vMessages.empty()) {
            if (bUsePrivMessage) {
                putModule("Welcome Back!");
                putModule("You have " + NoString(m_vMessages.size()) + " messages!");
            } else {
                putModuleNotice("Welcome Back!");
                putModuleNotice("You have " + NoString(m_vMessages.size()) + " messages!");
            }
        }
        m_sReason = "";
    }

    ModRet onPrivateMessage(NoHostMask& nick, NoString& message) override
    {
        if (m_bIsAway)
            AddMessage(time(nullptr), nick, message);
        return (CONTINUE);
    }

    ModRet onPrivateAction(NoHostMask& nick, NoString& message) override
    {
        if (m_bIsAway) {
            AddMessage(time(nullptr), nick, "* " + message);
        }
        return (CONTINUE);
    }

    ModRet onUserNotice(NoString& target, NoString& message) override
    {
        Ping();
        if (m_bIsAway)
            Back();

        return (CONTINUE);
    }

    ModRet onUserMessage(NoString& target, NoString& message) override
    {
        Ping();
        if (m_bIsAway)
            Back();

        return (CONTINUE);
    }

    ModRet onUserAction(NoString& target, NoString& message) override
    {
        Ping();
        if (m_bIsAway)
            Back();

        return (CONTINUE);
    }

    time_t GetTimeStamp() const
    {
        return (m_iLastSentData);
    }
    void Ping()
    {
        m_iLastSentData = time(nullptr);
    }
    time_t GetAwayTime()
    {
        return m_iAutoAway;
    }
    void SetAwayTime(time_t u)
    {
        m_iAutoAway = u;
    }

    bool IsAway()
    {
        return (m_bIsAway);
    }

private:
    NoString m_sPassword;
    bool m_bBootError;
    bool DecryptMessages(NoString& sBuffer)
    {
        NoString sMessages = GetPath();
        NoString sFile;
        sBuffer = "";

        NoFile File(sMessages);

        if (sMessages.empty() || !File.Open() || !File.ReadFile(sFile)) {
            putModule("Unable to find buffer");
            return (true); // gonna be successful here
        }

        File.Close();

        if (!sFile.empty()) {
            sBuffer = No::decrypt(sFile, m_sPassword);

            if (sBuffer.left(strlen(CRYPT_VERIFICATION_TOKEN)) != CRYPT_VERIFICATION_TOKEN) {
                // failed to decode :(
                putModule("Unable to decode Encrypted messages");
                return (false);
            }
            sBuffer.erase(0, strlen(CRYPT_VERIFICATION_TOKEN));
        }
        return (true);
    }

    void AddMessage(time_t iTime, const NoHostMask& nick, const NoString& message)
    {
        if (nick.nick() == network()->ircNick().nick())
            return; // ignore messages from self
        AddMessage(NoString(iTime) + " " + nick.toString() + " " + message);
    }

    void AddMessage(const NoString& text)
    {
        if (m_saveMessages) {
            m_vMessages.push_back(text);
        }
    }

    time_t m_iLastSentData;
    bool m_bIsAway;
    time_t m_iAutoAway;
    std::vector<NoString> m_vMessages;
    NoString m_sReason;
    bool m_saveMessages;
};


void NoAwayJob::run()
{
    NoAway* p = (NoAway*)module();
    p->SaveBufferToDisk();

    if (!p->IsAway()) {
        time_t iNow = time(nullptr);

        if ((iNow - p->GetTimeStamp()) > p->GetAwayTime() && p->GetAwayTime() != 0)
            p->Away();
    }
}

template <>
void no_moduleInfo<NoAway>(NoModuleInfo& info)
{
    info.setWikiPage("awaystore");
    info.setHasArgs(true);
    info.setArgsHelpText("[ -notimer | -timer N ]  passw0rd . N is number of seconds, 600 by default.");
}

NETWORKMODULEDEFS(NoAway, "Adds auto-away with logging, useful when you use ZNC from different locations");
