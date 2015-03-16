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

#include <no/nomodules.h>
#include <no/nochannel.h>

class NoCtcpFloodMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoCtcpFloodMod)
    {
        m_tLastCTCP = 0;
        m_iNumCTCP = 0;

        AddHelpCommand();
        AddCommand("Secs",
                   static_cast<NoModCommand::ModCmdFunc>(&NoCtcpFloodMod::OnSecsCommand),
                   "<limit>",
                   "Set seconds limit");
        AddCommand("Lines",
                   static_cast<NoModCommand::ModCmdFunc>(&NoCtcpFloodMod::OnLinesCommand),
                   "<limit>",
                   "Set lines limit");
        AddCommand("Show",
                   static_cast<NoModCommand::ModCmdFunc>(&NoCtcpFloodMod::OnShowCommand),
                   "",
                   "Show the current limits");
    }

    ~NoCtcpFloodMod() {}

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
        if (m_iThresholdMsgs == 0) m_iThresholdMsgs = 4;

        Save();

        return true;
    }

    EModRet Message(const NoNick& Nick, const NoString& sMessage)
    {
        // We never block /me, because it doesn't cause a reply
        if (sMessage.Token(0).Equals("ACTION")) return CONTINUE;

        if (m_tLastCTCP + m_iThresholdSecs < time(nullptr)) {
            m_tLastCTCP = time(nullptr);
            m_iNumCTCP = 0;
        }

        m_iNumCTCP++;

        if (m_iNumCTCP < m_iThresholdMsgs)
            return CONTINUE;
        else if (m_iNumCTCP == m_iThresholdMsgs)
            PutModule("Limit reached by [" + Nick.GetHostMask() + "], blocking all CTCP");

        // Reset the timeout so that we continue blocking messages
        m_tLastCTCP = time(nullptr);

        return HALT;
    }

    EModRet OnPrivCTCP(NoNick& Nick, NoString& sMessage) override { return Message(Nick, sMessage); }

    EModRet OnChanCTCP(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override { return Message(Nick, sMessage); }

    void OnSecsCommand(const NoString& sCommand)
    {
        const NoString& sArg = sCommand.Token(1, true);

        if (sArg.empty()) {
            PutModule("Usage: Secs <limit>");
            return;
        }

        m_iThresholdSecs = sArg.ToUInt();
        if (m_iThresholdSecs == 0) m_iThresholdSecs = 1;

        PutModule("Set seconds limit to [" + NoString(m_iThresholdSecs) + "]");
        Save();
    }

    void OnLinesCommand(const NoString& sCommand)
    {
        const NoString& sArg = sCommand.Token(1, true);

        if (sArg.empty()) {
            PutModule("Usage: Lines <limit>");
            return;
        }

        m_iThresholdMsgs = sArg.ToUInt();
        if (m_iThresholdMsgs == 0) m_iThresholdMsgs = 2;

        PutModule("Set lines limit to [" + NoString(m_iThresholdMsgs) + "]");
        Save();
    }

    void OnShowCommand(const NoString& sCommand)
    {
        PutModule("Current limit is " + NoString(m_iThresholdMsgs) + " CTCPs "
                                                                    "in " +
                  NoString(m_iThresholdSecs) + " secs");
    }

private:
    time_t m_tLastCTCP;
    uint m_iNumCTCP;

    time_t m_iThresholdSecs;
    uint m_iThresholdMsgs;
};

template <> void TModInfo<NoCtcpFloodMod>(NoModInfo& Info)
{
    Info.SetWikiPage("ctcpflood");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("This user module takes none to two arguments. The first argument is the number of lines "
                         "after which the flood-protection is triggered. The second argument is the time (s) to in "
                         "which the number of lines is reached. The default setting is 4 CTCPs in 2 seconds");
}

USERMODULEDEFS(NoCtcpFloodMod, "Don't forward CTCP floods to clients")
