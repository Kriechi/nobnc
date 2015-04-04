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
#include <nobnc/nochannel.h>
#include <nobnc/noregistry.h>
#include <nobnc/nonick.h>
#include <nobnc/nohostmask.h>
#include <nobnc/noutils.h>

class NoCtcpFloodMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoCtcpFloodMod)
    {
        m_tLastCTCP = 0;
        m_iNumCTCP = 0;

        addHelpCommand();
        addCommand("Secs",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoCtcpFloodMod::OnSecsCommand),
                   "<limit>",
                   "Set seconds limit");
        addCommand("Lines",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoCtcpFloodMod::OnLinesCommand),
                   "<limit>",
                   "Set lines limit");
        addCommand("Show",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoCtcpFloodMod::OnShowCommand),
                   "",
                   "Show the current limits");
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

    bool onLoad(const NoString& args, NoString& message) override
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
            m_iThresholdMsgs = 4;

        Save();

        return true;
    }

    ModRet Message(const NoString& hostMask, const NoString& message)
    {
        // We never block /me, because it doesn't cause a reply
        if (No::token(message, 0).equals("ACTION"))
            return CONTINUE;

        if (m_tLastCTCP + m_iThresholdSecs < time(nullptr)) {
            m_tLastCTCP = time(nullptr);
            m_iNumCTCP = 0;
        }

        m_iNumCTCP++;

        if (m_iNumCTCP < m_iThresholdMsgs)
            return CONTINUE;
        else if (m_iNumCTCP == m_iThresholdMsgs)
            putModule("Limit reached by [" + hostMask + "], blocking all CTCP");

        // Reset the timeout so that we continue blocking messages
        m_tLastCTCP = time(nullptr);

        return HALT;
    }

    ModRet onPrivCtcp(NoHostMask& nick, NoString& message) override
    {
        return Message(nick.toString(), message);
    }

    ModRet onChanCtcp(NoNick& nick, NoChannel* channel, NoString& message) override
    {
        return Message(nick.hostMask(), message);
    }

    void OnSecsCommand(const NoString& command)
    {
        const NoString& arg = No::tokens(command, 1);

        if (arg.empty()) {
            putModule("Usage: Secs <limit>");
            return;
        }

        m_iThresholdSecs = arg.toUInt();
        if (m_iThresholdSecs == 0)
            m_iThresholdSecs = 1;

        putModule("Set seconds limit to [" + NoString(m_iThresholdSecs) + "]");
        Save();
    }

    void OnLinesCommand(const NoString& command)
    {
        const NoString& arg = No::tokens(command, 1);

        if (arg.empty()) {
            putModule("Usage: Lines <limit>");
            return;
        }

        m_iThresholdMsgs = arg.toUInt();
        if (m_iThresholdMsgs == 0)
            m_iThresholdMsgs = 2;

        putModule("Set lines limit to [" + NoString(m_iThresholdMsgs) + "]");
        Save();
    }

    void OnShowCommand(const NoString& command)
    {
        putModule("Current limit is " + NoString(m_iThresholdMsgs) + " CTCPs "
                                                                     "in " +
                  NoString(m_iThresholdSecs) + " secs");
    }

private:
    time_t m_tLastCTCP;
    uint m_iNumCTCP;

    time_t m_iThresholdSecs;
    uint m_iThresholdMsgs;
};

template <>
void no_moduleInfo<NoCtcpFloodMod>(NoModuleInfo& info)
{
    info.setWikiPage("ctcpflood");
    info.setHasArgs(true);
    info.setArgsHelpText("This user module takes none to two arguments. The first argument is the number of lines "
                         "after which the flood-protection is triggered. The second argument is the time (s) to in "
                         "which the number of lines is reached. The default setting is 4 CTCPs in 2 seconds");
}

USERMODULEDEFS(NoCtcpFloodMod, "Don't forward CTCP floods to clients")
