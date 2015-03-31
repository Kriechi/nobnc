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
#include <no/noutils.h>
#include <no/noescape.h>
#include <no/nomessage.h>
#include <no/nobuffer.h>

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

        addHelpCommand();
        addCommand("SetPass",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSaveBuff::OnSetPassCommand),
                   "<password>",
                   "Sets the password");
        addCommand("Replay",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSaveBuff::OnReplayCommand),
                   "<buffer>",
                   "Replays the buffer");
        addCommand("Save",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoSaveBuff::OnSaveCommand),
                   "",
                   "Saves all buffers");
    }
    virtual ~NoSaveBuff()
    {
        if (!m_bBootError) {
            SaveBuffersToDisk();
        }
    }

    bool onLoad(const NoString& args, NoString& sMessage) override
    {
        if (args == CRYPT_ASK_PASS) {
            char* pPass = getpass("Enter pass for savebuff: ");
            if (pPass)
                m_sPassword = No::md5(pPass);
            else {
                m_bBootError = true;
                sMessage = "Nothing retrieved from console. aborting";
            }
        } else if (args.empty())
            m_sPassword = No::md5(CRYPT_LAME_PASS);
        else
            m_sPassword = No::md5(args);

        NoSaveBuffJob* timer = new NoSaveBuffJob(this);
        timer->start(60);

        return (!m_bBootError);
    }

    bool onBoot() override
    {
        NoDir saveDir(savePath());
        for (NoFile* pFile : saveDir.files()) {
            NoString name;
            NoString sBuffer;

            BufferType eType = DecryptBuffer(pFile->GetLongName(), sBuffer, name);
            switch (eType) {
            case InvalidBuffer:
                m_sPassword = "";
                No::printError("[" + moduleName() + ".so] Failed to Decrypt [" + pFile->GetLongName() + "]");
                if (!name.empty()) {
                    putUser(":***!znc@znc.in PRIVMSG " + name +
                            " :Failed to decrypt this buffer, did you change the encryption pass?");
                }
                break;
            case ChanBuffer:
                if (NoChannel* channel = network()->findChannel(name)) {
                    BootStrap(channel, sBuffer);
                }
                break;
            case QueryBuffer:
                if (NoQuery* query = network()->addQuery(name)) {
                    BootStrap(query, sBuffer);
                }
                break;
            default:
                break;
            }
        }
        return true;
    }

    template <typename T>
    void BootStrap(T* pTarget, const NoString& sContent)
    {
        if (!pTarget->buffer().isEmpty())
            return; // in this case the module was probably reloaded

        NoStringVector::iterator it;

        NoStringVector vsLines = sContent.split("\n");

        for (it = vsLines.begin(); it != vsLines.end(); ++it) {
            NoString line(*it);
            line.trim();
            if (line[0] == '@' && it + 1 != vsLines.end()) {
                NoString sTimestamp = No::token(line, 0);
                sTimestamp.trimLeft("@");
                timeval ts;
                ts.tv_sec = No::token(sTimestamp, 0, ",").toLongLong();
                ts.tv_usec = No::token(sTimestamp, 1, ",").toLong();

                NoString format = No::tokens(line, 1);

                NoString text(*++it);
                text.trim();

                pTarget->addBuffer(format, text, &ts);
            } else {
                // Old format, escape the line and use as is.
                pTarget->addBuffer(_NAMEDFMT(line));
            }
        }
    }

    void SaveBufferToDisk(const NoBuffer& Buffer, const NoString& sPath, const NoString& sHeader)
    {
        NoFile File(sPath);
        NoString sContent = sHeader + "\n";

        size_t uSize = Buffer.size();
        for (uint uIdx = 0; uIdx < uSize; uIdx++) {
            const NoMessage& Line = Buffer.message(uIdx);
            timeval ts = Line.timestamp();
            sContent += "@" + NoString(ts.tv_sec) + "," + NoString(ts.tv_usec) + " " + Line.format() + "\n" + Line.text() + "\n";
        }

        sContent = No::encrypt(sContent, m_sPassword);

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

            const std::vector<NoChannel*>& channels = network()->channels();
            for (NoChannel* channel : channels) {
                NoString sPath = GetPath(channel->name());
                SaveBufferToDisk(channel->buffer(), sPath, CHAN_VERIFICATION_TOKEN + channel->name());
                ssPaths.insert(sPath);
            }

            const std::vector<NoQuery*>& vQueries = network()->queries();
            for (NoQuery* query : vQueries) {
                NoString sPath = GetPath(query->name());
                SaveBufferToDisk(query->buffer(), sPath, QUERY_VERIFICATION_TOKEN + query->name());
                ssPaths.insert(sPath);
            }

            // cleanup leftovers ie. cleared buffers
            NoDir saveDir(savePath());
            for (NoFile* pFile : saveDir.files()) {
                if (ssPaths.count(pFile->GetLongName()) == 0) {
                    pFile->Delete();
                }
            }
        } else {
            putModule("Password is unset usually meaning the decryption failed. You can setpass to the appropriate "
                      "pass and things should start working, or setpass to a new pass and save to reinstantiate");
        }
    }

    void OnSetPassCommand(const NoString& sCmdLine)
    {
        NoString args = No::tokens(sCmdLine, 1);

        if (args.empty())
            args = CRYPT_LAME_PASS;

        putModule("Password set to [" + args + "]");
        m_sPassword = No::md5(args);
    }

    void onModCommand(const NoString& sCmdLine) override
    {
        NoString command = No::token(sCmdLine, 0);
        NoString args = No::tokens(sCmdLine, 1);

        if (command.equals("dumpbuff")) {
            // for testing purposes - hidden from help
            NoString sFile;
            NoString name;
            if (DecryptBuffer(GetPath(args), sFile, name)) {
                NoStringVector vsLines = sFile.split("\n");
                NoStringVector::iterator it;

                for (it = vsLines.begin(); it != vsLines.end(); ++it) {
                    NoString line(*it);
                    line.trim();
                    putModule("[" + line + "]");
                }
            }
            putModule("//!-- EOF " + args);
        } else {
            handleCommand(sCmdLine);
        }
    }

    void OnReplayCommand(const NoString& sCmdLine)
    {
        NoString args = No::tokens(sCmdLine, 1);

        Replay(args);
        putModule("Replayed " + args);
    }

    void OnSaveCommand(const NoString& sCmdLine)
    {
        SaveBuffersToDisk();
        putModule("Done.");
    }

    void Replay(const NoString& sBuffer)
    {
        NoString sFile;
        NoString name;
        putUser(":***!znc@znc.in PRIVMSG " + sBuffer + " :Buffer Playback...");
        if (DecryptBuffer(GetPath(sBuffer), sFile, name)) {
            NoStringVector vsLines = sFile.split("\n");
            NoStringVector::iterator it;

            for (it = vsLines.begin(); it != vsLines.end(); ++it) {
                NoString line(*it);
                line.trim();
                putUser(line);
            }
        }
        putUser(":***!znc@znc.in PRIVMSG " + sBuffer + " :Playback Complete.");
    }

    NoString GetPath(const NoString& sTarget) const
    {
        NoString sBuffer = user()->userName() + sTarget.toLower();
        NoString ret = savePath();
        ret += "/" + No::md5(sBuffer);
        return (ret);
    }

    NoString FindLegacyBufferName(const NoString& sPath) const
    {
        const std::vector<NoChannel*>& channels = network()->channels();
        for (NoChannel* channel : channels) {
            const NoString& name = channel->name();
            if (GetPath(name).equals(sPath)) {
                return name;
            }
        }
        return NoString();
    }

#ifdef LEGACY_SAVEBUFF /* event logging is deprecated now in savebuf. Use buffextras module along side of this */
    NoString SpoofChanMsg(const NoString& sChannel, const NoString& sMesg)
    {
        NoString sReturn = ":*" + moduleName() + "!znc@znc.in PRIVMSG " + sChannel + " :" + NoString(time(nullptr)) + " " + sMesg;
        return (sReturn);
    }

    void AddBuffer(NoChannel& chan, const NoString& line)
    {
        // If they have AutoClearChanBuffer enabled, only add messages if no client is connected
        if (chan.AutoClearChanBuffer() && network()->isUserAttached())
            return;
        chan.AddBuffer(line);
    }

    void onRawMode(const NoNick& cOpNick, NoChannel& cChannel, const NoString& sModes, const NoString& args) override
    {
        AddBuffer(cChannel, SpoofChanMsg(cChannel.GetName(), cOpNick.GetNickMask() + " MODE " + sModes + " " + args));
    }
    void onQuit(const NoNick& cNick, const NoString& sMessage, const std::vector<NoChannel*>& channels) override
    {
        for (size_t a = 0; a < channels.size(); a++) {
            AddBuffer(*channels[a], SpoofChanMsg(channels[a]->GetName(), cNick.GetNickMask() + " QUIT " + sMessage));
        }
        if (cNick.NickEquals(user()->nick()))
            SaveBuffersToDisk(); // need to force a save here to see this!
    }

    void onNick(const NoNick& cNick, const NoString& sNewNick, const std::vector<NoChannel*>& channels) override
    {
        for (size_t a = 0; a < channels.size(); a++) {
            AddBuffer(*channels[a], SpoofChanMsg(channels[a]->GetName(), cNick.GetNickMask() + " NICK " + sNewNick));
        }
    }
    void onKick(const NoNick& cNick, const NoString& sOpNick, NoChannel& cChannel, const NoString& sMessage) override
    {
        AddBuffer(cChannel, SpoofChanMsg(cChannel.GetName(), sOpNick + " KICK " + cNick.GetNickMask() + " " + sMessage));
    }
    void onJoin(const NoNick& cNick, NoChannel& cChannel) override
    {
        if (cNick.NickEquals(user()->nick()) && cChannel.GetBuffer().empty()) {
            BootStrap((NoChannel*)&cChannel);
            if (!cChannel.GetBuffer().empty())
                Replay(cChannel.GetName());
        }
        AddBuffer(cChannel, SpoofChanMsg(cChannel.GetName(), cNick.GetNickMask() + " JOIN"));
    }
    void onPart(const NoNick& cNick, NoChannel& cChannel) override
    {
        AddBuffer(cChannel, SpoofChanMsg(cChannel.GetName(), cNick.GetNickMask() + " PART"));
        if (cNick.NickEquals(user()->nick()))
            SaveBuffersToDisk(); // need to force a save here to see this!
    }
#endif /* LEGACY_SAVEBUFF */

private:
    bool m_bBootError;
    NoString m_sPassword;

    enum BufferType { InvalidBuffer = 0, EmptyBuffer, ChanBuffer, QueryBuffer };

    BufferType DecryptBuffer(const NoString& sPath, NoString& sBuffer, NoString& name)
    {
        NoString sContent;
        sBuffer = "";

        NoFile File(sPath);

        if (sPath.empty() || !File.Open() || !File.ReadFile(sContent))
            return EmptyBuffer;

        File.Close();

        if (!sContent.empty()) {
            sBuffer = No::decrypt(sContent, m_sPassword);

            if (sBuffer.trimPrefix(LEGACY_VERIFICATION_TOKEN)) {
                name = FindLegacyBufferName(sPath);
                return ChanBuffer;
            } else if (sBuffer.trimPrefix(CHAN_VERIFICATION_TOKEN)) {
                name = No::firstLine(sBuffer);
                if (sBuffer.trimLeft(name + "\n"))
                    return ChanBuffer;
            } else if (sBuffer.trimPrefix(QUERY_VERIFICATION_TOKEN)) {
                name = No::firstLine(sBuffer);
                if (sBuffer.trimLeft(name + "\n"))
                    return QueryBuffer;
            }

            putModule("Unable to decode Encrypted file [" + sPath + "]");
            return InvalidBuffer;
        }
        return EmptyBuffer;
    }
};


void NoSaveBuffJob::run()
{
    static_cast<NoSaveBuff*>(module())->SaveBuffersToDisk();
}

template <>
void no_moduleInfo<NoSaveBuff>(NoModuleInfo& Info)
{
    Info.setWikiPage("savebuff");
    Info.setHasArgs(true);
    Info.setArgsHelpText("This user module takes up to one arguments. Either --ask-pass or the password itself (which "
                         "may contain spaces) or nothing");
}

NETWORKMODULEDEFS(NoSaveBuff, "Stores channel and query buffers to disk, encrypted")
