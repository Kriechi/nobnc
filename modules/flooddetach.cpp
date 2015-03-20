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
#include <no/nochannel.h>
#include <no/nonetwork.h>

class NoFloodDetachMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoFloodDetachMod)
    {
        m_iThresholdSecs = 0;
        m_iThresholdMsgs = 0;

        AddHelpCommand();
        AddCommand("Show", static_cast<NoModCommand::ModCmdFunc>(&NoFloodDetachMod::ShowCommand), "");
        AddCommand("Secs", static_cast<NoModCommand::ModCmdFunc>(&NoFloodDetachMod::SecsCommand), "[<limit>]");
        AddCommand("Lines", static_cast<NoModCommand::ModCmdFunc>(&NoFloodDetachMod::LinesCommand), "[<limit>]");
        AddCommand("Silent", static_cast<NoModCommand::ModCmdFunc>(&NoFloodDetachMod::SilentCommand), "[yes|no]");
    }

    void Save()
    {
        // We save the settings twice because the module arguments can
        // be more easily edited via webadmin, while the SetNV() stuff
        // survives e.g. /msg *status reloadmod ctcpflood.
        SetNV("secs", NoString(m_iThresholdSecs));
        SetNV("msgs", NoString(m_iThresholdMsgs));

        SetArgs(NoString(m_iThresholdMsgs) + " " + NoString(m_iThresholdSecs));
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        m_iThresholdMsgs = sArgs.Token(0).ToUInt();
        m_iThresholdSecs = sArgs.Token(1).ToUInt();

        if (m_iThresholdMsgs == 0 || m_iThresholdSecs == 0) {
            m_iThresholdMsgs = GetNV("msgs").ToUInt();
            m_iThresholdSecs = GetNV("secs").ToUInt();
        }

        if (m_iThresholdSecs == 0) m_iThresholdSecs = 2;
        if (m_iThresholdMsgs == 0) m_iThresholdMsgs = 5;

        Save();

        return true;
    }

    void OnIRCDisconnected() override { m_chans.clear(); }

    void Cleanup()
    {
        Limits::iterator it;
        time_t now = time(nullptr);

        for (it = m_chans.begin(); it != m_chans.end(); ++it) {
            // The timeout for this channel did not expire yet?
            if (it->second.first + (time_t)m_iThresholdSecs >= now) continue;

            NoChannel* pChan = GetNetwork()->FindChan(it->first);
            if (it->second.second >= m_iThresholdMsgs && pChan && pChan->isDetached()) {
                // The channel is detached and it is over the
                // messages limit. Since we only track those
                // limits for non-detached channels or for
                // channels which we detached, this means that
                // we detached because of a flood.

                if (!GetNV("silent").ToBool()) {
                    PutModule("Flood in [" + pChan->getName() + "] is over, "
                                                                "re-attaching...");
                }
                // No buffer playback, makes sense, doesn't it?
                pChan->clearBuffer();
                pChan->attachUser();
            }

            Limits::iterator it2 = it++;
            m_chans.erase(it2);

            // Without this Bad Things (tm) could happen
            if (it == m_chans.end()) break;
        }
    }

    void Message(NoChannel& Channel)
    {
        Limits::iterator it;
        time_t now = time(nullptr);

        // First: Clean up old entries and reattach where necessary
        Cleanup();

        it = m_chans.find(Channel.getName());

        if (it == m_chans.end()) {
            // We don't track detached channels
            if (Channel.isDetached()) return;

            // This is the first message for this channel, start a
            // new timeout.
            std::pair<time_t, uint> tmp(now, 1);
            m_chans[Channel.getName()] = tmp;
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

        if (it->second.second < m_iThresholdMsgs) return;

        // The channel hit the limit, reset the timeout so that we keep
        // it detached for longer.
        it->second.first = now;

        Channel.detachUser();
        if (!GetNV("silent").ToBool()) {
            PutModule("Channel [" + Channel.getName() + "] was "
                                                        "flooded, you've been detached");
        }
    }

    ModRet OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        Message(Channel);
        return CONTINUE;
    }

    // This also catches OnChanAction()
    ModRet OnChanCTCP(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        Message(Channel);
        return CONTINUE;
    }

    ModRet OnChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        Message(Channel);
        return CONTINUE;
    }

    ModRet OnTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic) override
    {
        Message(Channel);
        return CONTINUE;
    }

    void ShowCommand(const NoString& sLine)
    {
        PutModule("Current limit is " + NoString(m_iThresholdMsgs) + " lines "
                                                                    "in " +
                  NoString(m_iThresholdSecs) + " secs.");
    }

    void SecsCommand(const NoString& sLine)
    {
        const NoString sArg = sLine.Tokens(1);

        if (sArg.empty()) {
            PutModule("Seconds limit is [" + NoString(m_iThresholdSecs) + "]");
        } else {
            m_iThresholdSecs = sArg.ToUInt();
            if (m_iThresholdSecs == 0) m_iThresholdSecs = 1;

            PutModule("Set seconds limit to [" + NoString(m_iThresholdSecs) + "]");
            Save();
        }
    }

    void LinesCommand(const NoString& sLine)
    {
        const NoString sArg = sLine.Tokens(1);

        if (sArg.empty()) {
            PutModule("Lines limit is [" + NoString(m_iThresholdMsgs) + "]");
        } else {
            m_iThresholdMsgs = sArg.ToUInt();
            if (m_iThresholdMsgs == 0) m_iThresholdMsgs = 2;

            PutModule("Set lines limit to [" + NoString(m_iThresholdMsgs) + "]");
            Save();
        }
    }

    void SilentCommand(const NoString& sLine)
    {
        const NoString sArg = sLine.Tokens(1);

        if (!sArg.empty()) {
            SetNV("silent", NoString(sArg.ToBool()));
        }

        if (GetNV("silent").ToBool()) {
            PutModule("Module messages are disabled");
        } else {
            PutModule("Module messages are enabled");
        }
    }

private:
    typedef std::map<NoString, std::pair<time_t, uint>> Limits;
    Limits m_chans;
    uint m_iThresholdSecs;
    uint m_iThresholdMsgs;
};

template <> void TModInfo<NoFloodDetachMod>(NoModInfo& Info)
{
    Info.SetWikiPage("flooddetach");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("This user module takes up to two arguments. Arguments are msgs and secs numbers.");
}

USERMODULEDEFS(NoFloodDetachMod, "Detach channels when flooded")
