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
#include <no/noclient.h>
#include <no/nochannel.h>
#include <no/nomodulejob.h>
#include <no/nonick.h>
#include <unistd.h>

#ifdef HAVE_PTHREAD
class NoSampleJob : public NoModuleJob
{
public:
    NoSampleJob(NoModule* pModule) : NoModuleJob(pModule, "sample", "Message the user after a delay")
    {
    }

    ~NoSampleJob()
    {
        if (wasCancelled()) {
            module()->putModule("Sample job cancelled");
        } else {
            module()->putModule("Sample job destroyed");
        }
    }

    void run() override
    {
        // Cannot safely use GetModule() in here, because this runs in its
        // own thread and such an access would require synchronisation
        // between this thread and the main thread!

        for (int i = 0; i < 10; i++) {
            // Regularly check if we were cancelled
            if (wasCancelled())
                return;
            sleep(1);
        }
    }

    void finished() override
    {
        module()->putModule("Sample job done");
    }
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
    void run() override
    {
        module()->putModule("TEST!!!!");
    }
};

class NoSampleMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoSampleMod)
    {
    }

    bool onLoad(const NoString& sArgs, NoString& sMessage) override
    {
        putModule("I'm being loaded with the arguments: [" + sArgs + "]");
// AddTimer(new NoSampleTimer(this, 300, 0, "Sample", "Sample timer for sample things."));
// AddTimer(new NoSampleTimer(this, 5, 20, "Another", "Another sample timer."));
// AddTimer(new NoSampleTimer(this, 25000, 5, "Third", "A third sample timer."));
#ifdef HAVE_PTHREAD
        addJob(new NoSampleJob(this));
#endif
        return true;
    }

    virtual ~NoSampleMod()
    {
        putModule("I'm being unloaded!");
    }

    bool onBoot() override
    {
        // This is called when the app starts up (only modules that are loaded in the config will get this event)
        return true;
    }

    void onIrcConnected() override
    {
        putModule("You got connected BoyOh.");
    }

    void onIrcDisconnected() override
    {
        putModule("You got disconnected BoyOh.");
    }

    ModRet onIrcRegistration(NoString& sPass, NoString& sNick, NoString& sIdent, NoString& sRealName) override
    {
        sRealName += " - ZNC";
        return CONTINUE;
    }

    ModRet onBroadcast(NoString& sMessage) override
    {
        putModule("------ [" + sMessage + "]");
        sMessage = "======== [" + sMessage + "] ========";
        return CONTINUE;
    }

    void onChanPermission(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, uchar uMode, bool bAdded, bool bNoChange) override
    {
        putModule(((bNoChange) ? "[0] [" : "[1] [") + OpNick.nick() + "] set mode [" + Channel.name() +
                  ((bAdded) ? "] +" : "] -") + NoString(uMode) + " " + Nick.nick());
    }

    void onOp(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override
    {
        putModule(((bNoChange) ? "[0] [" : "[1] [") + OpNick.nick() + "] opped [" + Nick.nick() + "] on [" + Channel.name() + "]");
    }

    void onDeop(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override
    {
        putModule(((bNoChange) ? "[0] [" : "[1] [") + OpNick.nick() + "] deopped [" + Nick.nick() + "] on [" + Channel.name() + "]");
    }

    void onVoice(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override
    {
        putModule(((bNoChange) ? "[0] [" : "[1] [") + OpNick.nick() + "] voiced [" + Nick.nick() + "] on [" + Channel.name() + "]");
    }

    void onDevoice(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange) override
    {
        putModule(((bNoChange) ? "[0] [" : "[1] [") + OpNick.nick() + "] devoiced [" + Nick.nick() + "] on [" + Channel.name() + "]");
    }

    void onRawMode(const NoNick& OpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs) override
    {
        putModule("* " + OpNick.nick() + " sets mode: " + sModes + " " + sArgs + " (" + Channel.name() + ")");
    }

    ModRet onRaw(NoString& sLine) override
    {
        // putModule("onRaw() [" + sLine + "]");
        return CONTINUE;
    }

    ModRet onUserRaw(NoString& sLine) override
    {
        // putModule("UserRaw() [" + sLine + "]");
        return CONTINUE;
    }

    void onKick(const NoNick& OpNick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage) override
    {
        putModule("[" + OpNick.nick() + "] kicked [" + sKickedNick + "] from [" + Channel.name() + "] with the msg [" + sMessage + "]");
    }

    void onQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans) override
    {
        putModule("* Quits: " + Nick.nick() + " (" + Nick.ident() + "!" + Nick.host() + ") (" + sMessage + ")");
    }

    ModRet onTimerAutoJoin(NoChannel& Channel) override
    {
        putModule("Attempting to join " + Channel.name());
        return CONTINUE;
    }

    void onJoin(const NoNick& Nick, NoChannel& Channel) override
    {
        putModule("* Joins: " + Nick.nick() + " (" + Nick.ident() + "!" + Nick.host() + ")");
    }

    void onPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage) override
    {
        putModule("* Parts: " + Nick.nick() + " (" + Nick.ident() + "!" + Nick.host() + ")");
    }

    ModRet onInvite(const NoNick& Nick, const NoString& sChan) override
    {
        if (sChan.equals("#test")) {
            putModule(Nick.nick() + " invited us to " + sChan + ", ignoring invites to " + sChan);
            return HALT;
        }

        putModule(Nick.nick() + " invited us to " + sChan);
        return CONTINUE;
    }

    void onNick(const NoNick& OldNick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans) override
    {
        putModule("* " + OldNick.nick() + " is now known as " + sNewNick);
    }

    ModRet onUserCtcpReply(NoString& sTarget, NoString& sMessage) override
    {
        putModule("[" + sTarget + "] userctcpreply [" + sMessage + "]");
        sMessage = "\037" + sMessage + "\037";

        return CONTINUE;
    }

    ModRet onCtcpReply(NoNick& Nick, NoString& sMessage) override
    {
        putModule("[" + Nick.nick() + "] ctcpreply [" + sMessage + "]");

        return CONTINUE;
    }

    ModRet onUserCtcp(NoString& sTarget, NoString& sMessage) override
    {
        putModule("[" + sTarget + "] userctcp [" + sMessage + "]");

        return CONTINUE;
    }

    ModRet onPrivCtcp(NoNick& Nick, NoString& sMessage) override
    {
        putModule("[" + Nick.nick() + "] privctcp [" + sMessage + "]");
        sMessage = "\002" + sMessage + "\002";

        return CONTINUE;
    }

    ModRet onChanCtcp(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        putModule("[" + Nick.nick() + "] chanctcp [" + sMessage + "] to [" + Channel.name() + "]");
        sMessage = "\00311,5 " + sMessage + " \003";

        return CONTINUE;
    }

    ModRet onUserNotice(NoString& sTarget, NoString& sMessage) override
    {
        putModule("[" + sTarget + "] usernotice [" + sMessage + "]");
        sMessage = "\037" + sMessage + "\037";

        return CONTINUE;
    }

    ModRet onPrivNotice(NoNick& Nick, NoString& sMessage) override
    {
        putModule("[" + Nick.nick() + "] privnotice [" + sMessage + "]");
        sMessage = "\002" + sMessage + "\002";

        return CONTINUE;
    }

    ModRet onChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        putModule("[" + Nick.nick() + "] channotice [" + sMessage + "] to [" + Channel.name() + "]");
        sMessage = "\00311,5 " + sMessage + " \003";

        return CONTINUE;
    }

    ModRet onTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic) override
    {
        putModule("* " + Nick.nick() + " changes topic on " + Channel.name() + " to '" + sTopic + "'");

        return CONTINUE;
    }

    ModRet onUserTopic(NoString& sTarget, NoString& sTopic) override
    {
        putModule("* " + client()->nick() + " changed topic on " + sTarget + " to '" + sTopic + "'");

        return CONTINUE;
    }

    ModRet onUserMsg(NoString& sTarget, NoString& sMessage) override
    {
        putModule("[" + sTarget + "] usermsg [" + sMessage + "]");
        sMessage = "Sample: \0034" + sMessage + "\003";

        return CONTINUE;
    }

    ModRet onPrivMsg(NoNick& Nick, NoString& sMessage) override
    {
        putModule("[" + Nick.nick() + "] privmsg [" + sMessage + "]");
        sMessage = "\002" + sMessage + "\002";

        return CONTINUE;
    }

    ModRet onChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        if (sMessage == "!ping") {
            putIrc("PRIVMSG " + Channel.name() + " :PONG?");
        }

        sMessage = "x " + sMessage + " x";

        putModule(sMessage);

        return CONTINUE;
    }

    void onModCommand(const NoString& sCommand) override
    {
        if (sCommand.equals("TIMERS")) {
            listTimers();
        }
    }

    ModRet onStatusCommand(NoString& sCommand) override
    {
        if (sCommand.equals("SAMPLE")) {
            putModule("Hi, I'm your friendly sample module.");
            return HALT;
        }

        return CONTINUE;
    }
};

template <>
void no_moduleInfo<NoSampleMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("sample");
    Info.setHasArgs(true);
    Info.setArgsHelpText("Description of module arguments goes here.");
}

MODULEDEFS(NoSampleMod, "To be used as a sample for writing modules")
