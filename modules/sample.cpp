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
#include <no/noclient.h>
#include <no/nochannel.h>
#include <no/nomodulejob.h>
#include <no/nonick.h>
#include <unistd.h>

#ifdef HAVE_PTHREAD
class NoSampleJob : public NoModuleJob
{
public:
    NoSampleJob(NoModule* pModule) : NoModuleJob(pModule, "sample", "Message the user after a delay") {}

    ~NoSampleJob()
    {
        if (wasCancelled()) {
            GetModule()->PutModule("Sample job cancelled");
        } else {
            GetModule()->PutModule("Sample job destroyed");
        }
    }

    void runThread() override
    {
        // Cannot safely use GetModule() in here, because this runs in its
        // own thread and such an access would require synchronisation
        // between this thread and the main thread!

        for (int i = 0; i < 10; i++) {
            // Regularly check if we were cancelled
            if (wasCancelled()) return;
            sleep(1);
        }
    }

    void runMain() override { GetModule()->PutModule("Sample job done"); }
};
#endif

class NoSampleTimer : public NoTimer
{
public:
    NoSampleTimer(NoModule* pModule, uint uInterval, const NoString& sLabel, const NoString& sDescription)
        : NoTimer(pModule)
    {
        setName(sLabel);
        setDescription(sDescription);

        start(uInterval);
    }

protected:
    void run() override { module()->PutModule("TEST!!!!"); }
};

class NoSampleMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoSampleMod) {}

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        PutModule("I'm being loaded with the arguments: [" + sArgs + "]");
// AddTimer(new NoSampleTimer(this, 300, 0, "Sample", "Sample timer for sample things."));
// AddTimer(new NoSampleTimer(this, 5, 20, "Another", "Another sample timer."));
// AddTimer(new NoSampleTimer(this, 25000, 5, "Third", "A third sample timer."));
#ifdef HAVE_PTHREAD
        AddJob(new NoSampleJob(this));
#endif
        return true;
    }

    virtual ~NoSampleMod() { PutModule("I'm being unloaded!"); }

    bool OnBoot() override
    {
        // This is called when the app starts up (only modules that are loaded in the config will get this event)
        return true;
    }

    void OnIRCConnected() override { PutModule("You got connected BoyOh."); }

    void OnIRCDisconnected() override { PutModule("You got disconnected BoyOh."); }

    ModRet OnIRCRegistration(NoString& sPass, NoString& sNick, NoString& sIdent, NoString& sRealName) override
    {
        sRealName += " - ZNC";
        return CONTINUE;
    }

    ModRet OnBroadcast(NoString& sMessage) override
    {
        PutModule("------ [" + sMessage + "]");
        sMessage = "======== [" + sMessage + "] ========";
        return CONTINUE;
    }

    void OnChanPermission(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange) override
    {
        PutModule(((bNoChange) ? "[0] [" : "[1] [") + OpNick.nick() + "] set mode [" + Channel.getName() +
                  ((bAdded) ? "] +" : "] -") + NoString(uMode) + " " + Nick.nick());
    }

    void OnOp(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override
    {
        PutModule(((bNoChange) ? "[0] [" : "[1] [") + OpNick.nick() + "] opped [" + Nick.nick() + "] on [" +
                  Channel.getName() + "]");
    }

    void OnDeop(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override
    {
        PutModule(((bNoChange) ? "[0] [" : "[1] [") + OpNick.nick() + "] deopped [" + Nick.nick() + "] on [" +
                  Channel.getName() + "]");
    }

    void OnVoice(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override
    {
        PutModule(((bNoChange) ? "[0] [" : "[1] [") + OpNick.nick() + "] voiced [" + Nick.nick() + "] on [" +
                  Channel.getName() + "]");
    }

    void OnDevoice(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override
    {
        PutModule(((bNoChange) ? "[0] [" : "[1] [") + OpNick.nick() + "] devoiced [" + Nick.nick() + "] on [" +
                  Channel.getName() + "]");
    }

    void OnRawMode(const NoNick& OpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs) override
    {
        PutModule("* " + OpNick.nick() + " sets mode: " + sModes + " " + sArgs + " (" + Channel.getName() + ")");
    }

    ModRet OnRaw(NoString& sLine) override
    {
        // PutModule("OnRaw() [" + sLine + "]");
        return CONTINUE;
    }

    ModRet OnUserRaw(NoString& sLine) override
    {
        // PutModule("UserRaw() [" + sLine + "]");
        return CONTINUE;
    }

    void OnKick(const NoNick& OpNick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage) override
    {
        PutModule("[" + OpNick.nick() + "] kicked [" + sKickedNick + "] from [" + Channel.getName() +
                  "] with the msg [" + sMessage + "]");
    }

    void OnQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans) override
    {
        PutModule("* Quits: " + Nick.nick() + " (" + Nick.ident() + "!" + Nick.host() + ") (" + sMessage + ")");
    }

    ModRet OnTimerAutoJoin(NoChannel& Channel) override
    {
        PutModule("Attempting to join " + Channel.getName());
        return CONTINUE;
    }

    void OnJoin(const NoNick& Nick, NoChannel& Channel) override
    {
        PutModule("* Joins: " + Nick.nick() + " (" + Nick.ident() + "!" + Nick.host() + ")");
    }

    void OnPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage) override
    {
        PutModule("* Parts: " + Nick.nick() + " (" + Nick.ident() + "!" + Nick.host() + ")");
    }

    ModRet OnInvite(const NoNick& Nick, const NoString& sChan) override
    {
        if (sChan.equals("#test")) {
            PutModule(Nick.nick() + " invited us to " + sChan + ", ignoring invites to " + sChan);
            return HALT;
        }

        PutModule(Nick.nick() + " invited us to " + sChan);
        return CONTINUE;
    }

    void OnNick(const NoNick& OldNick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans) override
    {
        PutModule("* " + OldNick.nick() + " is now known as " + sNewNick);
    }

    ModRet OnUserCTCPReply(NoString& sTarget, NoString& sMessage) override
    {
        PutModule("[" + sTarget + "] userctcpreply [" + sMessage + "]");
        sMessage = "\037" + sMessage + "\037";

        return CONTINUE;
    }

    ModRet OnCTCPReply(NoNick& Nick, NoString& sMessage) override
    {
        PutModule("[" + Nick.nick() + "] ctcpreply [" + sMessage + "]");

        return CONTINUE;
    }

    ModRet OnUserCTCP(NoString& sTarget, NoString& sMessage) override
    {
        PutModule("[" + sTarget + "] userctcp [" + sMessage + "]");

        return CONTINUE;
    }

    ModRet OnPrivCTCP(NoNick& Nick, NoString& sMessage) override
    {
        PutModule("[" + Nick.nick() + "] privctcp [" + sMessage + "]");
        sMessage = "\002" + sMessage + "\002";

        return CONTINUE;
    }

    ModRet OnChanCTCP(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        PutModule("[" + Nick.nick() + "] chanctcp [" + sMessage + "] to [" + Channel.getName() + "]");
        sMessage = "\00311,5 " + sMessage + " \003";

        return CONTINUE;
    }

    ModRet OnUserNotice(NoString& sTarget, NoString& sMessage) override
    {
        PutModule("[" + sTarget + "] usernotice [" + sMessage + "]");
        sMessage = "\037" + sMessage + "\037";

        return CONTINUE;
    }

    ModRet OnPrivNotice(NoNick& Nick, NoString& sMessage) override
    {
        PutModule("[" + Nick.nick() + "] privnotice [" + sMessage + "]");
        sMessage = "\002" + sMessage + "\002";

        return CONTINUE;
    }

    ModRet OnChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        PutModule("[" + Nick.nick() + "] channotice [" + sMessage + "] to [" + Channel.getName() + "]");
        sMessage = "\00311,5 " + sMessage + " \003";

        return CONTINUE;
    }

    ModRet OnTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic) override
    {
        PutModule("* " + Nick.nick() + " changes topic on " + Channel.getName() + " to '" + sTopic + "'");

        return CONTINUE;
    }

    ModRet OnUserTopic(NoString& sTarget, NoString& sTopic) override
    {
        PutModule("* " + GetClient()->GetNick() + " changed topic on " + sTarget + " to '" + sTopic + "'");

        return CONTINUE;
    }

    ModRet OnUserMsg(NoString& sTarget, NoString& sMessage) override
    {
        PutModule("[" + sTarget + "] usermsg [" + sMessage + "]");
        sMessage = "Sample: \0034" + sMessage + "\003";

        return CONTINUE;
    }

    ModRet OnPrivMsg(NoNick& Nick, NoString& sMessage) override
    {
        PutModule("[" + Nick.nick() + "] privmsg [" + sMessage + "]");
        sMessage = "\002" + sMessage + "\002";

        return CONTINUE;
    }

    ModRet OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        if (sMessage == "!ping") {
            PutIRC("PRIVMSG " + Channel.getName() + " :PONG?");
        }

        sMessage = "x " + sMessage + " x";

        PutModule(sMessage);

        return CONTINUE;
    }

    void OnModCommand(const NoString& sCommand) override
    {
        if (sCommand.equals("TIMERS")) {
            ListTimers();
        }
    }

    ModRet OnStatusCommand(NoString& sCommand) override
    {
        if (sCommand.equals("SAMPLE")) {
            PutModule("Hi, I'm your friendly sample module.");
            return HALT;
        }

        return CONTINUE;
    }
};

template <> void no_moduleInfo<NoSampleMod>(NoModuleInfo& Info)
{
    Info.SetWikiPage("sample");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("Description of module arguments goes here.");
}

MODULEDEFS(NoSampleMod, "To be used as a sample for writing modules")
