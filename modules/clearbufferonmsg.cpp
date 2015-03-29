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
#include <no/nonetwork.h>
#include <no/nouser.h>
#include <no/nochannel.h>
#include <no/noquery.h>

enum {
    RULE_MSG,
    RULE_CTCP,
    RULE_ACTION,
    RULE_NOTICE,
    RULE_PART,
    RULE_TOPIC,
    RULE_QUIT,
    RULE_MAX,
};

class NoClearBufferOnMsgMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoClearBufferOnMsgMod)
    {
        SetAllRules(true);
        // false for backward compatibility
        m_bRules[RULE_QUIT] = false;
    }

    void ClearAllBuffers()
    {
        NoNetwork* pNetwork = network();

        if (pNetwork) {
            const std::vector<NoChannel*>& vChans = pNetwork->channels();

            for (NoChannel* pChan : vChans) {
                // Skip detached channels, they weren't read yet
                if (pChan->isDetached())
                    continue;

                pChan->clearBuffer();
                // We deny AutoClearChanBuffer on all channels since this module
                // doesn't make any sense with it
                pChan->setAutoClearChanBuffer(false);
            }

            std::vector<NoQuery*> VQueries = pNetwork->queries();

            for (NoQuery* pQuery : VQueries) {
                pNetwork->removeQuery(pQuery->name());
            }

            // We deny autoclearQueryBuffer since this module
            // doesn't make any sense with it
            user()->setAutoclearQueryBuffer(false);
        }
    }

    ModRet onUserMsg(NoString& sTarget, NoString& sMessage) override
    {
        if (m_bRules[RULE_MSG])
            ClearAllBuffers();
        return CONTINUE;
    }

    ModRet onUserCtcp(NoString& sTarget, NoString& sMessage) override
    {
        if (m_bRules[RULE_CTCP])
            ClearAllBuffers();
        return CONTINUE;
    }

    ModRet onUserAction(NoString& sTarget, NoString& sMessage) override
    {
        if (m_bRules[RULE_ACTION])
            ClearAllBuffers();
        return CONTINUE;
    }

    ModRet onUserNotice(NoString& sTarget, NoString& sMessage) override
    {
        if (m_bRules[RULE_NOTICE])
            ClearAllBuffers();
        return CONTINUE;
    }

    ModRet onUserPart(NoString& sChannel, NoString& sMessage) override
    {
        if (m_bRules[RULE_PART])
            ClearAllBuffers();
        return CONTINUE;
    }

    ModRet onUserTopic(NoString& sChannel, NoString& sTopic) override
    {
        if (m_bRules[RULE_TOPIC])
            ClearAllBuffers();
        return CONTINUE;
    }

    ModRet onUserQuit(NoString& sMessage) override
    {
        if (m_bRules[RULE_QUIT])
            ClearAllBuffers();
        return CONTINUE;
    }

    void SetAllRules(bool bVal)
    {
        for (int i = 0; i < RULE_MAX; i++)
            m_bRules[i] = bVal;
    }

    void SetRule(const NoString& sOpt, bool bVal)
    {
        static const struct
        {
            NoString sName;
            int Index;
        } Names[RULE_MAX] = {
              { "msg", RULE_MSG },
              { "ctcp", RULE_CTCP },
              { "action", RULE_ACTION },
              { "notice", RULE_NOTICE },
              { "part", RULE_PART },
              { "topic", RULE_TOPIC },
              { "quit", RULE_QUIT },
          };

        if (sOpt.equals("all")) {
            SetAllRules(bVal);
        } else {
            for (int i = 0; i < RULE_MAX; i++) {
                if (sOpt.equals(Names[i].sName))
                    m_bRules[Names[i].Index] = bVal;
            }
        }
    }

    bool onLoad(const NoString& sArgs, NoString& sMessage) override
    {
        NoStringVector vsOpts = sArgs.split(" ", No::SkipEmptyParts);

        for (NoString& sOpt : vsOpts) {
            if (sOpt.startsWith("!"))
                SetRule(sOpt.substr(1), false);
            else if (!sOpt.empty())
                SetRule(sOpt, true);
        }

        return true;
    }

private:
    bool m_bRules[RULE_MAX];
};

template <>
void no_moduleInfo<NoClearBufferOnMsgMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("clearbufferonmsg");
    Info.setHasArgs(true);
    Info.setArgsHelpText("[ [!]<msg|ctcp|action|notice|part|topic|quit|all> ]");
}

USERMODULEDEFS(NoClearBufferOnMsgMod, "Clear all channel and query buffers whenever the user does something")
