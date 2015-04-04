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
#include <nobnc/nonetwork.h>
#include <nobnc/noircsocket.h>
#include <nobnc/nonick.h>
#include <nobnc/nohostmask.h>

class NoKeepNickTimer : public NoTimer
{
public:
    NoKeepNickTimer(NoModule* mod);

    void run() override;
};

class NoKeepNickMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoKeepNickMod)
    {
        addHelpCommand();
        addCommand("Enable",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoKeepNickMod::OnEnableCommand),
                   "",
                   "Try to get your primary nick");
        addCommand("Disable",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoKeepNickMod::OnDisableCommand),
                   "",
                   "No longer trying to get your primary nick");
        addCommand("State",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoKeepNickMod::OnStateCommand),
                   "",
                   "Show the current state");
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        m_pTimer = nullptr;

        // Check if we need to start the timer
        if (network()->isIrcConnected())
            onIrcConnected();

        return true;
    }

    void KeepNick()
    {
        if (!m_pTimer)
            // No timer means we are turned off
            return;

        NoIrcSocket* socket = network()->ircSocket();

        if (!socket)
            return;

        // Do we already have the nick we want?
        if (socket->nick().equals(GetNick()))
            return;

        putIrc("NICK " + GetNick());
    }

    NoString GetNick()
    {
        NoString sConfNick = network()->nick();
        NoIrcSocket* socket = network()->ircSocket();

        if (socket)
            sConfNick = sConfNick.left(socket->maxNickLen());

        return sConfNick;
    }

    void onNick(const NoHostMask& nick, const NoString& newNick) override
    {
        if (newNick == network()->ircSocket()->nick()) {
            // We are changing our own nick
            if (nick.nick().equals(GetNick())) {
                // We are changing our nick away from the conf setting.
                // Let's assume the user wants this and disable
                // this module (to avoid fighting nickserv).
                Disable();
            } else if (newNick.equals(GetNick())) {
                // We are changing our nick to the conf setting,
                // so we don't need that timer anymore.
                Disable();
            }
            return;
        }

        // If the nick we want is free now, be fast and get the nick
        if (nick.nick().equals(GetNick())) {
            KeepNick();
        }
    }

    void onQuit(const NoHostMask& nick, const NoString& message) override
    {
        // If someone with the nick we want quits, be fast and get the nick
        if (nick.nick().equals(GetNick())) {
            KeepNick();
        }
    }

    void onIrcDisconnected() override
    {
        // No way we can do something if we aren't connected to IRC.
        Disable();
    }

    void onIrcConnected() override
    {
        if (!network()->ircSocket()->nick().equals(GetNick())) {
            // We don't have the nick we want, try to get it
            Enable();
        }
    }

    void Enable()
    {
        if (m_pTimer)
            return;

        m_pTimer = new NoKeepNickTimer(this);
        m_pTimer->start(30);
    }

    void Disable()
    {
        if (!m_pTimer)
            return;

        m_pTimer->stop();
        delete m_pTimer;
        m_pTimer = nullptr;
    }

    ModRet onUserRaw(NoString& line) override
    {
        // We dont care if we are not connected to IRC
        if (!network()->isIrcConnected())
            return CONTINUE;

        // We are trying to get the config nick and this is a /nick?
        if (!m_pTimer || !No::token(line, 0).equals("NICK"))
            return CONTINUE;

        // Is the nick change for the nick we are trying to get?
        NoString nick = No::token(line, 1);

        // Don't even think of using spaces in your nick!
        if (nick.left(1) == ":")
            nick.leftChomp(1);

        if (!nick.equals(GetNick()))
            return CONTINUE;

        // Indeed trying to change to this nick, generate a 433 for it.
        // This way we can *always* block incoming 433s from the server.
        putUser(":" + network()->ircServer() + " 433 " + network()->ircNick().nick() + " " + nick +
                " :ZNC is already trying to get this nickname");
        return CONTINUE;
    }

    ModRet onRaw(NoString& line) override
    {
        // Are we trying to get our primary nick and we caused this error?
        // :irc.server.net 433 mynick badnick :Nickname is already in use.
        if (m_pTimer && No::token(line, 1) == "433" && No::token(line, 3).equals(GetNick()))
            return HALT;

        return CONTINUE;
    }

    void OnEnableCommand(const NoString& command)
    {
        Enable();
        putModule("Trying to get your primary nick");
    }

    void OnDisableCommand(const NoString& command)
    {
        Disable();
        putModule("No longer trying to get your primary nick");
    }

    void OnStateCommand(const NoString& command)
    {
        if (m_pTimer)
            putModule("Currently trying to get your primary nick");
        else
            putModule("Currently disabled, try 'enable'");
    }

private:
    // If this is nullptr, we are turned off for some reason
    NoKeepNickTimer* m_pTimer;
};

NoKeepNickTimer::NoKeepNickTimer(NoModule* mod) : NoTimer(mod)
{
    setName("KeepNickTimer");
    setDescription("Tries to acquire this user's primary nick");
}

void NoKeepNickTimer::run()
{
    static_cast<NoKeepNickMod*>(module())->KeepNick();
}

template <>
void no_moduleInfo<NoKeepNickMod>(NoModuleInfo& info)
{
    info.setWikiPage("keepnick");
}

NETWORKMODULEDEFS(NoKeepNickMod, "Keep trying for your primary nick")
