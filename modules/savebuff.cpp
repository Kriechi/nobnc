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
 * Buffer Saving thing, incase your shit goes out while your out
 *
 * Its only as secure as your shell, the encryption only offers a slightly
 * better solution then plain text.
 */

#define REQUIRESSL

#include <no/nomodule.h>
#include <no/nochannel.h>
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/nofile.h>
#include <no/nodir.h>
#include <no/noquery.h>
#include <no/noblowfish.h>
#include <no/noescape.h>
#include <no/nomessage.h>

#define LEGACY_VERIFICATION_TOKEN "::__:SAVEBUFF:__::"
#define CHAN_VERIFICATION_TOKEN "::__:CHANBUFF:__::"
#define QUERY_VERIFICATION_TOKEN "::__:QUERYBUFF:__::"
// this is basically plain text, but so is having the pass in the command line so *shrug*
// you could at least do something kind of cool like a bunch of unprintable text
#define CRYPT_LAME_PASS "::__:NOPASS:__::"
#define CRYPT_ASK_PASS "--ask-pass"

class NoSaveBuff;

class NoSaveBuffJob : public NoTimer
{
public:
    NoSaveBuffJob(NoModule* pModule) : NoTimer(pModule)
    {
        setName("SaveBuff");
        setDescription("Saves the current buffer to disk every 1 minute");
    }

protected:
    void run() override;
};

class NoSaveBuff : public NoModule
{
public:
    MODCONSTRUCTOR(NoSaveBuff)
    {
        m_bBootError = false;

        AddHelpCommand();
        AddCommand("SetPass",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSaveBuff::OnSetPassCommand),
                   "<password>",
                   "Sets the password");
        AddCommand("Replay",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSaveBuff::OnReplayCommand),
                   "<buffer>",
                   "Replays the buffer");
        AddCommand("Save", static_cast<NoModuleCommand::ModCmdFunc>(&NoSaveBuff::OnSaveCommand), "", "Saves all buffers");
    }
    virtual ~NoSaveBuff()
    {
        if (!m_bBootError) {
            SaveBuffersToDisk();
        }
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        if (sArgs == CRYPT_ASK_PASS) {
            char* pPass = getpass("Enter pass for savebuff: ");
            if (pPass)
                m_sPassword = No::md5(pPass);
            else {
                m_bBootError = true;
                sMessage = "Nothing retrieved from console. aborting";
            }
        } else if (sArgs.empty())
            m_sPassword = No::md5(CRYPT_LAME_PASS);
        else
            m_sPassword = No::md5(sArgs);

        NoSaveBuffJob* timer = new NoSaveBuffJob(this);
        timer->start(60);

        return (!m_bBootError);
    }

    bool OnBoot() override
    {
        NoDir saveDir(GetSavePath());
        for (NoFile* pFile : saveDir) {
            NoString sName;
            NoString sBuffer;

            BufferType eType = DecryptBuffer(pFile->GetLongName(), sBuffer, sName);
            switch (eType) {
            case InvalidBuffer:
                m_sPassword = "";
                No::printError("[" + GetModName() + ".so] Failed to Decrypt [" + pFile->GetLongName() + "]");
                if (!sName.empty()) {
                    PutUser(":***!znc@znc.in PRIVMSG " + sName +
                            " :Failed to decrypt this buffer, did you change the encryption pass?");
                }
                break;
            case ChanBuffer:
                if (NoChannel* pChan = GetNetwork()->FindChan(sName)) {
                    BootStrap(pChan, sBuffer);
                }
                break;
            case QueryBuffer:
                if (NoQuery* pQuery = GetNetwork()->AddQuery(sName)) {
                    BootStrap(pQuery, sBuffer);
                }
                break;
            default:
                break;
            }
        }
        return true;
    }

    template <typename T> void BootStrap(T* pTarget, const NoString& sContent)
    {
        if (!pTarget->getBuffer().isEmpty()) return; // in this case the module was probably reloaded

        NoStringVector::iterator it;

        NoStringVector vsLines = sContent.split("\n");

        for (it = vsLines.begin(); it != vsLines.end(); ++it) {
            NoString sLine(*it);
            sLine.trim();
            if (sLine[0] == '@' && it + 1 != vsLines.end()) {
                NoString sTimestamp = No::token(sLine, 0);
                sTimestamp.trimLeft("@");
                timeval ts;
                ts.tv_sec = No::token(sTimestamp, 0, ",").toLongLong();
                ts.tv_usec = No::token(sTimestamp, 1, ",").toLong();

                NoString sFormat = No::tokens(sLine, 1);

                NoString sText(*++it);
                sText.trim();

                pTarget->addBuffer(sFormat, sText, &ts);
            } else {
                // Old format, escape the line and use as is.
                pTarget->addBuffer(_NAMEDFMT(sLine));
            }
        }
    }

    void SaveBufferToDisk(const NoBuffer& Buffer, const NoString& sPath, const NoString& sHeader)
    {
        NoFile File(sPath);
        NoString sContent = sHeader + "\n";

        size_t uSize = Buffer.size();
        for (uint uIdx = 0; uIdx < uSize; uIdx++) {
            const NoMessage& Line = Buffer.getMessage(uIdx);
            timeval ts = Line.GetTime();
            sContent +=
            "@" + NoString(ts.tv_sec) + "," + NoString(ts.tv_usec) + " " + Line.GetFormat() + "\n" + Line.GetText() + "\n";
        }

        sContent = NoBlowfish::encrypt(sContent, m_sPassword);

        if (File.Open(O_WRONLY | O_CREAT | O_TRUNC, 0600)) {
            File.Chmod(0600);
            File.Write(sContent);
        }
        File.Close();
    }

    void SaveBuffersToDisk()
    {
        if (!m_sPassword.empty()) {
            std::set<NoString> ssPaths;

            const std::vector<NoChannel*>& vChans = GetNetwork()->GetChans();
            for (NoChannel* pChan : vChans) {
                NoString sPath = GetPath(pChan->getName());
                SaveBufferToDisk(pChan->getBuffer(), sPath, CHAN_VERIFICATION_TOKEN + pChan->getName());
                ssPaths.insert(sPath);
            }

            const std::vector<NoQuery*>& vQueries = GetNetwork()->GetQueries();
            for (NoQuery* pQuery : vQueries) {
                NoString sPath = GetPath(pQuery->getName());
                SaveBufferToDisk(pQuery->getBuffer(), sPath, QUERY_VERIFICATION_TOKEN + pQuery->getName());
                ssPaths.insert(sPath);
            }

            // cleanup leftovers ie. cleared buffers
            NoDir saveDir(GetSavePath());
            for (NoFile* pFile : saveDir) {
                if (ssPaths.count(pFile->GetLongName()) == 0) {
                    pFile->Delete();
                }
            }
        } else {
            PutModule("Password is unset usually meaning the decryption failed. You can setpass to the appropriate "
                      "pass and things should start working, or setpass to a new pass and save to reinstantiate");
        }
    }

    void OnSetPassCommand(const NoString& sCmdLine)
    {
        NoString sArgs = No::tokens(sCmdLine, 1);

        if (sArgs.empty()) sArgs = CRYPT_LAME_PASS;

        PutModule("Password set to [" + sArgs + "]");
        m_sPassword = No::md5(sArgs);
    }

    void OnModCommand(const NoString& sCmdLine) override
    {
        NoString sCommand = No::token(sCmdLine, 0);
        NoString sArgs = No::tokens(sCmdLine, 1);

        if (sCommand.equals("dumpbuff")) {
            // for testing purposes - hidden from help
            NoString sFile;
            NoString sName;
            if (DecryptBuffer(GetPath(sArgs), sFile, sName)) {
                NoStringVector vsLines = sFile.split("\n");
                NoStringVector::iterator it;

                for (it = vsLines.begin(); it != vsLines.end(); ++it) {
                    NoString sLine(*it);
                    sLine.trim();
                    PutModule("[" + sLine + "]");
                }
            }
            PutModule("//!-- EOF " + sArgs);
        } else {
            HandleCommand(sCmdLine);
        }
    }

    void OnReplayCommand(const NoString& sCmdLine)
    {
        NoString sArgs = No::tokens(sCmdLine, 1);

        Replay(sArgs);
        PutModule("Replayed " + sArgs);
    }

    void OnSaveCommand(const NoString& sCmdLine)
    {
        SaveBuffersToDisk();
        PutModule("Done.");
    }

    void Replay(const NoString& sBuffer)
    {
        NoString sFile;
        NoString sName;
        PutUser(":***!znc@znc.in PRIVMSG " + sBuffer + " :Buffer Playback...");
        if (DecryptBuffer(GetPath(sBuffer), sFile, sName)) {
            NoStringVector vsLines = sFile.split("\n");
            NoStringVector::iterator it;

            for (it = vsLines.begin(); it != vsLines.end(); ++it) {
                NoString sLine(*it);
                sLine.trim();
                PutUser(sLine);
            }
        }
        PutUser(":***!znc@znc.in PRIVMSG " + sBuffer + " :Playback Complete.");
    }

    NoString GetPath(const NoString& sTarget) const
    {
        NoString sBuffer = GetUser()->GetUserName() + sTarget.toLower();
        NoString sRet = GetSavePath();
        sRet += "/" + No::md5(sBuffer);
        return (sRet);
    }

    NoString FindLegacyBufferName(const NoString& sPath) const
    {
        const std::vector<NoChannel*>& vChans = GetNetwork()->GetChans();
        for (NoChannel* pChan : vChans) {
            const NoString& sName = pChan->getName();
            if (GetPath(sName).equals(sPath)) {
                return sName;
            }
        }
        return NoString();
    }

#ifdef LEGACY_SAVEBUFF /* event logging is deprecated now in savebuf. Use buffextras module along side of this */
    NoString SpoofChanMsg(const NoString& sChannel, const NoString& sMesg)
    {
        NoString sReturn = ":*" + GetModName() + "!znc@znc.in PRIVMSG " + sChannel + " :" + NoString(time(nullptr)) + " " + sMesg;
        return (sReturn);
    }

    void AddBuffer(NoChannel& chan, const NoString& sLine)
    {
        // If they have AutoClearChanBuffer enabled, only add messages if no client is connected
        if (chan.AutoClearChanBuffer() && GetNetwork()->IsUserAttached()) return;
        chan.AddBuffer(sLine);
    }

    void OnRawMode(const NoNick& cOpNick, NoChannel& cChannel, const NoString& sModes, const NoString& sArgs) override
    {
        AddBuffer(cChannel, SpoofChanMsg(cChannel.GetName(), cOpNick.GetNickMask() + " MODE " + sModes + " " + sArgs));
    }
    void OnQuit(const NoNick& cNick, const NoString& sMessage, const std::vector<NoChannel*>& vChans) override
    {
        for (size_t a = 0; a < vChans.size(); a++) {
            AddBuffer(*vChans[a], SpoofChanMsg(vChans[a]->GetName(), cNick.GetNickMask() + " QUIT " + sMessage));
        }
        if (cNick.NickEquals(GetUser()->GetNick())) SaveBuffersToDisk(); // need to force a save here to see this!
    }

    void OnNick(const NoNick& cNick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans) override
    {
        for (size_t a = 0; a < vChans.size(); a++) {
            AddBuffer(*vChans[a], SpoofChanMsg(vChans[a]->GetName(), cNick.GetNickMask() + " NICK " + sNewNick));
        }
    }
    void OnKick(const NoNick& cNick, const NoString& sOpNick, NoChannel& cChannel, const NoString& sMessage) override
    {
        AddBuffer(cChannel, SpoofChanMsg(cChannel.GetName(), sOpNick + " KICK " + cNick.GetNickMask() + " " + sMessage));
    }
    void OnJoin(const NoNick& cNick, NoChannel& cChannel) override
    {
        if (cNick.NickEquals(GetUser()->GetNick()) && cChannel.GetBuffer().empty()) {
            BootStrap((NoChannel*)&cChannel);
            if (!cChannel.GetBuffer().empty()) Replay(cChannel.GetName());
        }
        AddBuffer(cChannel, SpoofChanMsg(cChannel.GetName(), cNick.GetNickMask() + " JOIN"));
    }
    void OnPart(const NoNick& cNick, NoChannel& cChannel) override
    {
        AddBuffer(cChannel, SpoofChanMsg(cChannel.GetName(), cNick.GetNickMask() + " PART"));
        if (cNick.NickEquals(GetUser()->GetNick())) SaveBuffersToDisk(); // need to force a save here to see this!
    }
#endif /* LEGACY_SAVEBUFF */

private:
    bool m_bBootError;
    NoString m_sPassword;

    enum BufferType { InvalidBuffer = 0, EmptyBuffer, ChanBuffer, QueryBuffer };

    BufferType DecryptBuffer(const NoString& sPath, NoString& sBuffer, NoString& sName)
    {
        NoString sContent;
        sBuffer = "";

        NoFile File(sPath);

        if (sPath.empty() || !File.Open() || !File.ReadFile(sContent)) return EmptyBuffer;

        File.Close();

        if (!sContent.empty()) {
            sBuffer = NoBlowfish::decrypt(sContent, m_sPassword);

            if (sBuffer.trimPrefix(LEGACY_VERIFICATION_TOKEN)) {
                sName = FindLegacyBufferName(sPath);
                return ChanBuffer;
            } else if (sBuffer.trimPrefix(CHAN_VERIFICATION_TOKEN)) {
                sName = No::firstLine(sBuffer);
                if (sBuffer.trimLeft(sName + "\n")) return ChanBuffer;
            } else if (sBuffer.trimPrefix(QUERY_VERIFICATION_TOKEN)) {
                sName = No::firstLine(sBuffer);
                if (sBuffer.trimLeft(sName + "\n")) return QueryBuffer;
            }

            PutModule("Unable to decode Encrypted file [" + sPath + "]");
            return InvalidBuffer;
        }
        return EmptyBuffer;
    }
};


void NoSaveBuffJob::run()
{
    static_cast<NoSaveBuff*>(module())->SaveBuffersToDisk();
}

template <> void no_moduleInfo<NoSaveBuff>(NoModuleInfo& Info)
{
    Info.SetWikiPage("savebuff");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("This user module takes up to one arguments. Either --ask-pass or the password itself (which "
                         "may contain spaces) or nothing");
}

NETWORKMODULEDEFS(NoSaveBuff, "Stores channel and query buffers to disk, encrypted")
