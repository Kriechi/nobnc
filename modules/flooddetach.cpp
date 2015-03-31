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
#include <no/nochannel.h>
#include <no/nonetwork.h>
#include <no/noregistry.h>

class NoFloodDetachMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoFloodDetachMod)
    {
        m_iThresholdSecs = 0;
        m_iThresholdMsgs = 0;

        addHelpCommand();
        addCommand("Show", static_cast<NoModuleCommand::ModCmdFunc>(&NoFloodDetachMod::ShowCommand), "");
        addCommand("Secs", static_cast<NoModuleCommand::ModCmdFunc>(&NoFloodDetachMod::SecsCommand), "[<limit>]");
        addCommand("Lines", static_cast<NoModuleCommand::ModCmdFunc>(&NoFloodDetachMod::LinesCommand), "[<limit>]");
        addCommand("Silent", static_cast<NoModuleCommand::ModCmdFunc>(&NoFloodDetachMod::SilentCommand), "[yes|no]");
    }

    void Save()
    {
        // We save the settings twice because the module arguments can
        // be more easily edited via webadmin, while the registry.setValue() stuff
        // survives e.g. /msg *status reloadmod ctcpflood.
        NoRegistry registry(this);
        registry.setValue("secs", NoString(m_iThresholdSecs));
        registry.setValue("msgs", NoString(m_iThresholdMsgs));

        setArgs(NoString(m_iThresholdMsgs) + " " + NoString(m_iThresholdSecs));
    }

    bool onLoad(const NoString& args, NoString& sMessage) override
    {
        m_iThresholdMsgs = No::token(args, 0).toUInt();
        m_iThresholdSecs = No::token(args, 1).toUInt();

        if (m_iThresholdMsgs == 0 || m_iThresholdSecs == 0) {
            NoRegistry registry(this);
            m_iThresholdMsgs = registry.value("msgs").toUInt();
            m_iThresholdSecs = registry.value("secs").toUInt();
        }

        if (m_iThresholdSecs == 0)
            m_iThresholdSecs = 2;
        if (m_iThresholdMsgs == 0)
            m_iThresholdMsgs = 5;

        Save();

        return true;
    }

    void onIrcDisconnected() override
    {
        m_chans.clear();
    }

    void Cleanup()
    {
        Limits::iterator it;
        time_t now = time(nullptr);

        for (it = m_chans.begin(); it != m_chans.end(); ++it) {
            // The timeout for this channel did not expire yet?
            if (it->second.first + (time_t)m_iThresholdSecs >= now)
                continue;

            NoChannel* channel = network()->findChannel(it->first);
            if (it->second.second >= m_iThresholdMsgs && channel && channel->isDetached()) {
                // The channel is detached and it is over the
                // messages limit. Since we only track those
                // limits for non-detached channels or for
                // channels which we detached, this means that
                // we detached because of a flood.

                NoRegistry registry(this);
                if (!registry.value("silent").toBool()) {
                    putModule("Flood in [" + channel->name() + "] is over, "
                                                             "re-attaching...");
                }
                // No buffer playback, makes sense, doesn't it?
                channel->clearBuffer();
                channel->attachUser();
            }

            Limits::iterator it2 = it++;
            m_chans.erase(it2);

            // Without this Bad Things (tm) could happen
            if (it == m_chans.end())
                break;
        }
    }

    void Message(NoChannel& Channel)
    {
        Limits::iterator it;
        time_t now = time(nullptr);

        // First: Clean up old entries and reattach where necessary
        Cleanup();

        it = m_chans.find(Channel.name());

        if (it == m_chans.end()) {
            // We don't track detached channels
            if (Channel.isDetached())
                return;

            // This is the first message for this channel, start a
            // new timeout.
            std::pair<time_t, uint> tmp(now, 1);
            m_chans[Channel.name()] = tmp;
            return;
        }

        // No need to check it->second.first (expiry time), since
        // Cleanup() would have removed it if it was expired.

        if (it->second.second >= m_iThresholdMsgs) {
            // The channel already hit the limit and we detached the
            // user, but it is still being flooded, reset the timeout
            it->second.first = now;
            it->second.second++;
            return;
        }

        it->second.second++;

        if (it->second.second < m_iThresholdMsgs)
            return;

        // The channel hit the limit, reset the timeout so that we keep
        // it detached for longer.
        it->second.first = now;

        Channel.detachUser();

        NoRegistry registry(this);
        if (!registry.value("silent").toBool()) {
            putModule("Channel [" + Channel.name() + "] was "
                                                     "flooded, you've been detached");
        }
    }

    ModRet onChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        Message(Channel);
        return CONTINUE;
    }

    // This also catches onChanAction()
    ModRet onChanCtcp(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        Message(Channel);
        return CONTINUE;
    }

    ModRet onChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        Message(Channel);
        return CONTINUE;
    }

    ModRet onTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic) override
    {
        Message(Channel);
        return CONTINUE;
    }

    void ShowCommand(const NoString& line)
    {
        putModule("Current limit is " + NoString(m_iThresholdMsgs) + " lines "
                                                                     "in " +
                  NoString(m_iThresholdSecs) + " secs.");
    }

    void SecsCommand(const NoString& line)
    {
        const NoString arg = No::tokens(line, 1);

        if (arg.empty()) {
            putModule("Seconds limit is [" + NoString(m_iThresholdSecs) + "]");
        } else {
            m_iThresholdSecs = arg.toUInt();
            if (m_iThresholdSecs == 0)
                m_iThresholdSecs = 1;

            putModule("Set seconds limit to [" + NoString(m_iThresholdSecs) + "]");
            Save();
        }
    }

    void LinesCommand(const NoString& line)
    {
        const NoString arg = No::tokens(line, 1);

        if (arg.empty()) {
            putModule("Lines limit is [" + NoString(m_iThresholdMsgs) + "]");
        } else {
            m_iThresholdMsgs = arg.toUInt();
            if (m_iThresholdMsgs == 0)
                m_iThresholdMsgs = 2;

            putModule("Set lines limit to [" + NoString(m_iThresholdMsgs) + "]");
            Save();
        }
    }

    void SilentCommand(const NoString& line)
    {
        const NoString arg = No::tokens(line, 1);

        NoRegistry registry(this);
        if (!arg.empty()) {
            registry.setValue("silent", NoString(arg.toBool()));
        }

        if (registry.value("silent").toBool()) {
            putModule("Module messages are disabled");
        } else {
            putModule("Module messages are enabled");
        }
    }

private:
    typedef std::map<NoString, std::pair<time_t, uint>> Limits;
    Limits m_chans;
    uint m_iThresholdSecs;
    uint m_iThresholdMsgs;
};

template <>
void no_moduleInfo<NoFloodDetachMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("flooddetach");
    Info.setHasArgs(true);
    Info.setArgsHelpText("This user module takes up to two arguments. Arguments are msgs and secs numbers.");
}

USERMODULEDEFS(NoFloodDetachMod, "Detach channels when flooded")
