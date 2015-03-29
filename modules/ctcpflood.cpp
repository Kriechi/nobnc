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
#include <no/noregistry.h>
#include <no/nonick.h>

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

    bool onLoad(const NoString& sArgs, NoString& sMessage) override
    {
        m_iThresholdMsgs = No::token(sArgs, 0).toUInt();
        m_iThresholdSecs = No::token(sArgs, 1).toUInt();

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

    ModRet Message(const NoNick& Nick, const NoString& sMessage)
    {
        // We never block /me, because it doesn't cause a reply
        if (No::token(sMessage, 0).equals("ACTION"))
            return CONTINUE;

        if (m_tLastCTCP + m_iThresholdSecs < time(nullptr)) {
            m_tLastCTCP = time(nullptr);
            m_iNumCTCP = 0;
        }

        m_iNumCTCP++;

        if (m_iNumCTCP < m_iThresholdMsgs)
            return CONTINUE;
        else if (m_iNumCTCP == m_iThresholdMsgs)
            putModule("Limit reached by [" + Nick.hostMask() + "], blocking all CTCP");

        // Reset the timeout so that we continue blocking messages
        m_tLastCTCP = time(nullptr);

        return HALT;
    }

    ModRet onPrivCtcp(NoNick& Nick, NoString& sMessage) override
    {
        return Message(Nick, sMessage);
    }

    ModRet onChanCtcp(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        return Message(Nick, sMessage);
    }

    void OnSecsCommand(const NoString& sCommand)
    {
        const NoString& sArg = No::tokens(sCommand, 1);

        if (sArg.empty()) {
            putModule("Usage: Secs <limit>");
            return;
        }

        m_iThresholdSecs = sArg.toUInt();
        if (m_iThresholdSecs == 0)
            m_iThresholdSecs = 1;

        putModule("Set seconds limit to [" + NoString(m_iThresholdSecs) + "]");
        Save();
    }

    void OnLinesCommand(const NoString& sCommand)
    {
        const NoString& sArg = No::tokens(sCommand, 1);

        if (sArg.empty()) {
            putModule("Usage: Lines <limit>");
            return;
        }

        m_iThresholdMsgs = sArg.toUInt();
        if (m_iThresholdMsgs == 0)
            m_iThresholdMsgs = 2;

        putModule("Set lines limit to [" + NoString(m_iThresholdMsgs) + "]");
        Save();
    }

    void OnShowCommand(const NoString& sCommand)
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
void no_moduleInfo<NoCtcpFloodMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("ctcpflood");
    Info.setHasArgs(true);
    Info.setArgsHelpText("This user module takes none to two arguments. The first argument is the number of lines "
                         "after which the flood-protection is triggered. The second argument is the time (s) to in "
                         "which the number of lines is reached. The default setting is 4 CTCPs in 2 seconds");
}

USERMODULEDEFS(NoCtcpFloodMod, "Don't forward CTCP floods to clients")
