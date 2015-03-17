/*
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

#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/nofile.h>
#include <no/noblowfish.h>

#define CRYPT_VERIFICATION_TOKEN "::__:AWAY:__::"

class NoAway;

class NoAwayJob : public NoTimer
{
public:
    NoAwayJob(NoModule* pModule, uint uInterval, uint uCycles, const NoString& sLabel, const NoString& sDescription)
        : NoTimer(pModule, uInterval, uCycles, sLabel, sDescription)
    {
    }

    virtual ~NoAwayJob() {}

protected:
    void RunJob() override;
};

class NoAway : public NoModule
{
    void AwayCommand(const NoString& sCommand)
    {
        NoString sReason;
        time_t curtime;
        time(&curtime);

        if (sCommand.Token(1) != "-quiet") {
            sReason = NoUtils::FormatTime(curtime, sCommand.Token(1, true), GetUser()->GetTimezone());
            PutModNotice("You have been marked as away");
        } else {
            sReason = NoUtils::FormatTime(curtime, sCommand.Token(2, true), GetUser()->GetTimezone());
        }

        Away(false, sReason);
    }

    void BackCommand(const NoString& sCommand)
    {
        if ((m_vMessages.empty()) && (sCommand.Token(1) != "-quiet")) PutModNotice("Welcome Back!");
        Ping();
        Back();
    }

    void MessagesCommand(const NoString& sCommand)
    {
        for (u_int a = 0; a < m_vMessages.size(); a++) PutModule(m_vMessages[a]);
    }

    void ReplayCommand(const NoString& sCommand)
    {
        NoString nick = GetClient()->GetNick();
        for (u_int a = 0; a < m_vMessages.size(); a++) {
            NoString sWhom = m_vMessages[a].Token(1, false, ":");
            NoString sMessage = m_vMessages[a].Token(2, true, ":");
            PutUser(":" + sWhom + " PRIVMSG " + nick + " :" + sMessage);
        }
    }

    void DeleteCommand(const NoString& sCommand)
    {
        NoString sWhich = sCommand.Token(1);
        if (sWhich == "all") {
            PutModNotice("Deleted " + NoString(m_vMessages.size()) + " Messages.");
            for (u_int a = 0; a < m_vMessages.size(); a++) m_vMessages.erase(m_vMessages.begin() + a--);
        } else if (sWhich.empty()) {
            PutModNotice("USAGE: delete <num|all>");
            return;
        } else {
            u_int iNum = sWhich.ToUInt();
            if (iNum >= m_vMessages.size()) {
                PutModNotice("Illegal Message # Requested");
                return;
            } else {
                m_vMessages.erase(m_vMessages.begin() + iNum);
                PutModNotice("Message Erased.");
            }
            SaveBufferToDisk();
        }
    }

    void SaveCommand(const NoString& sCommand)
    {
        if (m_saveMessages) {
            SaveBufferToDisk();
            PutModNotice("Messages saved to disk.");
        } else {
            PutModNotice("There are no messages to save.");
        }
    }

    void PingCommand(const NoString& sCommand)
    {
        Ping();
        if (m_bIsAway) Back();
    }

    void PassCommand(const NoString& sCommand)
    {
        m_sPassword = sCommand.Token(1);
        PutModNotice("Password Updated to [" + m_sPassword + "]");
    }

    void ShowCommand(const NoString& sCommand)
    {
        std::map<NoString, std::vector<NoString>> msvOutput;
        for (u_int a = 0; a < m_vMessages.size(); a++) {
            NoString sTime = m_vMessages[a].Token(0, false);
            NoString sWhom = m_vMessages[a].Token(1, false);
            NoString sMessage = m_vMessages[a].Token(2, true);

            if ((sTime.empty()) || (sWhom.empty()) || (sMessage.empty())) {
                // illegal format
                PutModule("Corrupt message! [" + m_vMessages[a] + "]");
                m_vMessages.erase(m_vMessages.begin() + a--);
                continue;
            }

            time_t iTime = sTime.ToULong();
            char szFormat[64];
            struct tm t;
            localtime_r(&iTime, &t);
            size_t iCount = strftime(szFormat, 64, "%F %T", &t);

            if (iCount <= 0) {
                PutModule("Corrupt time stamp! [" + m_vMessages[a] + "]");
                m_vMessages.erase(m_vMessages.begin() + a--);
                continue;
            }

            NoString sTmp = "    " + NoString(a) + ") [";
            sTmp.append(szFormat, iCount);
            sTmp += "] ";
            sTmp += sMessage;
            msvOutput[sWhom].push_back(sTmp);
        }

        for (std::map<NoString, std::vector<NoString>>::iterator it = msvOutput.begin(); it != msvOutput.end(); ++it) {
            PutModule(it->first);
            for (u_int a = 0; a < it->second.size(); a++) PutModule(it->second[a]);
        }

        PutModule("#--- End Messages");
    }

    void EnableTimerCommand(const NoString& sCommand)
    {
        SetAwayTime(300);
        PutModule("Timer set to 300 seconds");
    }

    void DisableTimerCommand(const NoString& sCommand)
    {
        SetAwayTime(0);
        PutModule("Timer disabled");
    }

    void SetTimerCommand(const NoString& sCommand)
    {
        int iSetting = sCommand.Token(1).ToInt();

        SetAwayTime(iSetting);

        if (iSetting == 0)
            PutModule("Timer disabled");
        else
            PutModule("Timer set to " + NoString(iSetting) + " seconds");
    }

    void TimerCommand(const NoString& sCommand)
    {
        PutModule("Current timer setting: " + NoString(GetAwayTime()) + " seconds");
    }

public:
    MODCONSTRUCTOR(NoAway)
    {
        Ping();
        m_bIsAway = false;
        m_bBootError = false;
        m_saveMessages = true;
        SetAwayTime(300);
        AddTimer(new NoAwayJob(this, 60, 0, "AwayJob", "Checks for idle and saves messages every 1 minute"));

        AddHelpCommand();
        AddCommand("Away", static_cast<NoModCommand::ModCmdFunc>(&NoAway::AwayCommand), "[-quiet]");
        AddCommand("Back", static_cast<NoModCommand::ModCmdFunc>(&NoAway::BackCommand), "[-quiet]");
        AddCommand("Messages", static_cast<NoModCommand::ModCmdFunc>(&NoAway::BackCommand));
        AddCommand("Delete", static_cast<NoModCommand::ModCmdFunc>(&NoAway::DeleteCommand), "delete <num|all>");
        AddCommand("Save", static_cast<NoModCommand::ModCmdFunc>(&NoAway::SaveCommand));
        AddCommand("Ping", static_cast<NoModCommand::ModCmdFunc>(&NoAway::PingCommand));
        AddCommand("Pass", static_cast<NoModCommand::ModCmdFunc>(&NoAway::PassCommand));
        AddCommand("Show", static_cast<NoModCommand::ModCmdFunc>(&NoAway::ShowCommand));
        AddCommand("Replay", static_cast<NoModCommand::ModCmdFunc>(&NoAway::ReplayCommand));
        AddCommand("EnableTimer", static_cast<NoModCommand::ModCmdFunc>(&NoAway::EnableTimerCommand));
        AddCommand("DisableTimer", static_cast<NoModCommand::ModCmdFunc>(&NoAway::DisableTimerCommand));
        AddCommand("SetTimer", static_cast<NoModCommand::ModCmdFunc>(&NoAway::SetTimerCommand), "<secs>");
        AddCommand("Timer", static_cast<NoModCommand::ModCmdFunc>(&NoAway::TimerCommand));
    }

    virtual ~NoAway()
    {
        if (!m_bBootError) SaveBufferToDisk();
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        NoString sMyArgs = sArgs;
        size_t uIndex = 0;
        if (sMyArgs.Token(0) == "-nostore") {
            uIndex++;
            m_saveMessages = false;
        }
        if (sMyArgs.Token(uIndex) == "-notimer") {
            SetAwayTime(0);
            sMyArgs = sMyArgs.Token(uIndex + 1, true);
        } else if (sMyArgs.Token(uIndex) == "-timer") {
            SetAwayTime(sMyArgs.Token(uIndex + 1).ToInt());
            sMyArgs = sMyArgs.Token(uIndex + 2, true);
        }
        if (m_saveMessages) {
            if (!sMyArgs.empty()) {
                m_sPassword = NoBlowfish::MD5(sMyArgs);
            } else {
                sMessage = "This module needs as an argument a keyphrase used for encryption";
                return false;
            }

            if (!BootStrap()) {
                sMessage = "Failed to decrypt your saved messages - "
                           "Did you give the right encryption key as an argument to this module?";
                m_bBootError = true;
                return false;
            }
        }

        return true;
    }

    void OnIRCConnected() override
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
            NoStringVector vsLines;
            NoStringVector::iterator it;

            sFile.Split("\n", vsLines);

            for (it = vsLines.begin(); it != vsLines.end(); ++it) {
                NoString sLine(*it);
                sLine.Trim();
                AddMessage(sLine);
            }
        } else {
            m_sPassword = "";
            NoUtils::PrintError("[" + GetModName() + ".so] Failed to Decrypt Messages");
            return (false);
        }

        return (true);
    }

    void SaveBufferToDisk()
    {
        if (!m_sPassword.empty()) {
            NoString sFile = CRYPT_VERIFICATION_TOKEN;

            for (u_int b = 0; b < m_vMessages.size(); b++) sFile += m_vMessages[b] + "\n";

            NoBlowfish c(m_sPassword, BF_ENCRYPT);
            sFile = c.Crypt(sFile);
            NoString sPath = GetPath();
            if (!sPath.empty()) {
                NoFile File(sPath);
                if (File.Open(O_WRONLY | O_CREAT | O_TRUNC, 0600)) {
                    File.Chmod(0600);
                    File.Write(sFile);
                }
                File.Close();
            }
        }
    }

    void OnClientLogin() override { Back(true); }
    void OnClientDisconnect() override { Away(); }

    NoString GetPath()
    {
        NoString sBuffer = GetUser()->GetUserName();
        NoString sRet = GetSavePath();
        sRet += "/.znc-away-" + NoBlowfish::MD5(sBuffer, true);
        return (sRet);
    }

    void Away(bool bForce = false, const NoString& sReason = "")
    {
        if ((!m_bIsAway) || (bForce)) {
            if (!bForce)
                m_sReason = sReason;
            else if (!sReason.empty())
                m_sReason = sReason;

            time_t iTime = time(nullptr);
            char* pTime = ctime(&iTime);
            NoString sTime;
            if (pTime) {
                sTime = pTime;
                sTime.Trim();
            }
            if (m_sReason.empty()) m_sReason = "Auto Away at " + sTime;
            PutIRC("AWAY :" + m_sReason);
            m_bIsAway = true;
        }
    }

    void Back(bool bUsePrivMessage = false)
    {
        PutIRC("away");
        m_bIsAway = false;
        if (!m_vMessages.empty()) {
            if (bUsePrivMessage) {
                PutModule("Welcome Back!");
                PutModule("You have " + NoString(m_vMessages.size()) + " messages!");
            } else {
                PutModNotice("Welcome Back!");
                PutModNotice("You have " + NoString(m_vMessages.size()) + " messages!");
            }
        }
        m_sReason = "";
    }

    EModRet OnPrivMsg(NoNick& Nick, NoString& sMessage) override
    {
        if (m_bIsAway) AddMessage(time(nullptr), Nick, sMessage);
        return (CONTINUE);
    }

    EModRet OnPrivAction(NoNick& Nick, NoString& sMessage) override
    {
        if (m_bIsAway) {
            AddMessage(time(nullptr), Nick, "* " + sMessage);
        }
        return (CONTINUE);
    }

    EModRet OnUserNotice(NoString& sTarget, NoString& sMessage) override
    {
        Ping();
        if (m_bIsAway) Back();

        return (CONTINUE);
    }

    EModRet OnUserMsg(NoString& sTarget, NoString& sMessage) override
    {
        Ping();
        if (m_bIsAway) Back();

        return (CONTINUE);
    }

    EModRet OnUserAction(NoString& sTarget, NoString& sMessage) override
    {
        Ping();
        if (m_bIsAway) Back();

        return (CONTINUE);
    }

    time_t GetTimeStamp() const { return (m_iLastSentData); }
    void Ping() { m_iLastSentData = time(nullptr); }
    time_t GetAwayTime() { return m_iAutoAway; }
    void SetAwayTime(time_t u) { m_iAutoAway = u; }

    bool IsAway() { return (m_bIsAway); }

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
            PutModule("Unable to find buffer");
            return (true); // gonna be successful here
        }

        File.Close();

        if (!sFile.empty()) {
            NoBlowfish c(m_sPassword, BF_DECRYPT);
            sBuffer = c.Crypt(sFile);

            if (sBuffer.Left(strlen(CRYPT_VERIFICATION_TOKEN)) != CRYPT_VERIFICATION_TOKEN) {
                // failed to decode :(
                PutModule("Unable to decode Encrypted messages");
                return (false);
            }
            sBuffer.erase(0, strlen(CRYPT_VERIFICATION_TOKEN));
        }
        return (true);
    }

    void AddMessage(time_t iTime, const NoNick& Nick, const NoString& sMessage)
    {
        if (Nick.GetNick() == GetNetwork()->GetIRNoNick().GetNick()) return; // ignore messages from self
        AddMessage(NoString(iTime) + " " + Nick.GetNickMask() + " " + sMessage);
    }

    void AddMessage(const NoString& sText)
    {
        if (m_saveMessages) {
            m_vMessages.push_back(sText);
        }
    }

    time_t m_iLastSentData;
    bool m_bIsAway;
    time_t m_iAutoAway;
    std::vector<NoString> m_vMessages;
    NoString m_sReason;
    bool m_saveMessages;
};


void NoAwayJob::RunJob()
{
    NoAway* p = (NoAway*)module();
    p->SaveBufferToDisk();

    if (!p->IsAway()) {
        time_t iNow = time(nullptr);

        if ((iNow - p->GetTimeStamp()) > p->GetAwayTime() && p->GetAwayTime() != 0) p->Away();
    }
}

template <> void TModInfo<NoAway>(NoModInfo& Info)
{
    Info.SetWikiPage("awaystore");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("[ -notimer | -timer N ]  passw0rd . N is number of seconds, 600 by default.");
}

NETWORKMODULEDEFS(NoAway, "Adds auto-away with logging, useful when you use ZNC from different locations");
