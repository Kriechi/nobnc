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
#include <nobnc/noclient.h>
#include <nobnc/nochannel.h>
#include <nobnc/nomodulejob.h>
#include <nobnc/nonick.h>
#include <unistd.h>

#ifdef HAVE_PTHREAD
class NoSampleJob : public NoModuleJob
{
public:
    NoSampleJob(NoModule* module) : NoModuleJob(module, "sample", "Message the user after a delay")
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
    NoSampleTimer(NoModule* module, uint uInterval, const NoString& label, const NoString& description)
        : NoTimer(module)
    {
        setName(label);
        setDescription(description);

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

    bool onLoad(const NoString& args, NoString& message) override
    {
        putModule("I'm being loaded with the arguments: [" + args + "]");
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

    ModRet onIrcRegistration(NoString& pass, NoString& nick, NoString& ident, NoString& realName) override
    {
        realName += " - ZNC";
        return CONTINUE;
    }

    ModRet onBroadcast(NoString& message) override
    {
        putModule("------ [" + message + "]");
        message = "======== [" + message + "] ========";
        return CONTINUE;
    }

    void onChanPermission(const NoNick& opNick, const NoNick& nick, NoChannel& channel, uchar mode, bool added, bool noChange) override
    {
        putModule(((noChange) ? "[0] [" : "[1] [") + opNick.nick() + "] set mode [" + channel.name() +
                  ((added) ? "] +" : "] -") + NoString(mode) + " " + nick.nick());
    }

    void onOp(const NoNick& opNick, const NoNick& nick, NoChannel& channel, bool noChange) override
    {
        putModule(((noChange) ? "[0] [" : "[1] [") + opNick.nick() + "] opped [" + nick.nick() + "] on [" + channel.name() + "]");
    }

    void onDeop(const NoNick& opNick, const NoNick& nick, NoChannel& channel, bool noChange) override
    {
        putModule(((noChange) ? "[0] [" : "[1] [") + opNick.nick() + "] deopped [" + nick.nick() + "] on [" + channel.name() + "]");
    }

    void onVoice(const NoNick& opNick, const NoNick& nick, NoChannel& channel, bool noChange) override
    {
        putModule(((noChange) ? "[0] [" : "[1] [") + opNick.nick() + "] voiced [" + nick.nick() + "] on [" + channel.name() + "]");
    }

    void onDevoice(const NoNick& opNick, const NoNick& nick, NoChannel& channel, bool noChange) override
    {
        putModule(((noChange) ? "[0] [" : "[1] [") + opNick.nick() + "] devoiced [" + nick.nick() + "] on [" + channel.name() + "]");
    }

    void onRawMode(const NoNick& opNick, NoChannel& channel, const NoString& modes, const NoString& args) override
    {
        putModule("* " + opNick.nick() + " sets mode: " + modes + " " + args + " (" + channel.name() + ")");
    }

    ModRet onRaw(NoString& line) override
    {
        // putModule("onRaw() [" + line + "]");
        return CONTINUE;
    }

    ModRet onUserRaw(NoString& line) override
    {
        // putModule("UserRaw() [" + line + "]");
        return CONTINUE;
    }

    void onKick(const NoNick& opNick, const NoString& sKickedNick, NoChannel& channel, const NoString& message) override
    {
        putModule("[" + opNick.nick() + "] kicked [" + sKickedNick + "] from [" + channel.name() + "] with the msg [" + message + "]");
    }

    void onQuit(const NoNick& nick, const NoString& message, const std::vector<NoChannel*>& channels) override
    {
        putModule("* Quits: " + nick.nick() + " (" + nick.ident() + "!" + nick.host() + ") (" + message + ")");
    }

    ModRet onTimerAutoJoin(NoChannel& channel) override
    {
        putModule("Attempting to join " + channel.name());
        return CONTINUE;
    }

    void onJoin(const NoNick& nick, NoChannel& channel) override
    {
        putModule("* Joins: " + nick.nick() + " (" + nick.ident() + "!" + nick.host() + ")");
    }

    void onPart(const NoNick& nick, NoChannel& channel, const NoString& message) override
    {
        putModule("* Parts: " + nick.nick() + " (" + nick.ident() + "!" + nick.host() + ")");
    }

    ModRet onInvite(const NoNick& nick, const NoString& sChan) override
    {
        if (sChan.equals("#test")) {
            putModule(nick.nick() + " invited us to " + sChan + ", ignoring invites to " + sChan);
            return HALT;
        }

        putModule(nick.nick() + " invited us to " + sChan);
        return CONTINUE;
    }

    void onNick(const NoNick& OldNick, const NoString& newNick, const std::vector<NoChannel*>& channels) override
    {
        putModule("* " + OldNick.nick() + " is now known as " + newNick);
    }

    ModRet onUserCtcpReply(NoString& target, NoString& message) override
    {
        putModule("[" + target + "] userctcpreply [" + message + "]");
        message = "\037" + message + "\037";

        return CONTINUE;
    }

    ModRet onCtcpReply(NoNick& nick, NoString& message) override
    {
        putModule("[" + nick.nick() + "] ctcpreply [" + message + "]");

        return CONTINUE;
    }

    ModRet onUserCtcp(NoString& target, NoString& message) override
    {
        putModule("[" + target + "] userctcp [" + message + "]");

        return CONTINUE;
    }

    ModRet onPrivCtcp(NoNick& nick, NoString& message) override
    {
        putModule("[" + nick.nick() + "] privctcp [" + message + "]");
        message = "\002" + message + "\002";

        return CONTINUE;
    }

    ModRet onChanCtcp(NoNick& nick, NoChannel& channel, NoString& message) override
    {
        putModule("[" + nick.nick() + "] chanctcp [" + message + "] to [" + channel.name() + "]");
        message = "\00311,5 " + message + " \003";

        return CONTINUE;
    }

    ModRet onUserNotice(NoString& target, NoString& message) override
    {
        putModule("[" + target + "] usernotice [" + message + "]");
        message = "\037" + message + "\037";

        return CONTINUE;
    }

    ModRet onPrivNotice(NoNick& nick, NoString& message) override
    {
        putModule("[" + nick.nick() + "] privnotice [" + message + "]");
        message = "\002" + message + "\002";

        return CONTINUE;
    }

    ModRet onChanNotice(NoNick& nick, NoChannel& channel, NoString& message) override
    {
        putModule("[" + nick.nick() + "] channotice [" + message + "] to [" + channel.name() + "]");
        message = "\00311,5 " + message + " \003";

        return CONTINUE;
    }

    ModRet onTopic(NoNick& nick, NoChannel& channel, NoString& topic) override
    {
        putModule("* " + nick.nick() + " changes topic on " + channel.name() + " to '" + topic + "'");

        return CONTINUE;
    }

    ModRet onUserTopic(NoString& target, NoString& topic) override
    {
        putModule("* " + client()->nick() + " changed topic on " + target + " to '" + topic + "'");

        return CONTINUE;
    }

    ModRet onUserMsg(NoString& target, NoString& message) override
    {
        putModule("[" + target + "] usermsg [" + message + "]");
        message = "Sample: \0034" + message + "\003";

        return CONTINUE;
    }

    ModRet onPrivMsg(NoNick& nick, NoString& message) override
    {
        putModule("[" + nick.nick() + "] privmsg [" + message + "]");
        message = "\002" + message + "\002";

        return CONTINUE;
    }

    ModRet onChanMsg(NoNick& nick, NoChannel& channel, NoString& message) override
    {
        if (message == "!ping") {
            putIrc("PRIVMSG " + channel.name() + " :PONG?");
        }

        message = "x " + message + " x";

        putModule(message);

        return CONTINUE;
    }

    void onModCommand(const NoString& command) override
    {
        if (command.equals("TIMERS")) {
            listTimers();
        }
    }

    ModRet onStatusCommand(NoString& command) override
    {
        if (command.equals("SAMPLE")) {
            putModule("Hi, I'm your friendly sample module.");
            return HALT;
        }

        return CONTINUE;
    }
};

template <>
void no_moduleInfo<NoSampleMod>(NoModuleInfo& info)
{
    info.setWikiPage("sample");
    info.setHasArgs(true);
    info.setArgsHelpText("Description of module arguments goes here.");
}

MODULEDEFS(NoSampleMod, "To be used as a sample for writing modules")
