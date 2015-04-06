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
#include <nobnc/noregistry.h>
#include <nobnc/noutils.h>
#include <nobnc/notable.h>

class NoPerform : public NoModule
{
    void Add(const NoString& command)
    {
        NoString sPerf = No::tokens(command, 1);

        if (sPerf.empty()) {
            putModule("Usage: add <command>");
            return;
        }

        m_vPerform.push_back(ParsePerform(sPerf));
        putModule("Added!");
        Save();
    }

    void Del(const NoString& command)
    {
        u_int iNum = No::tokens(command, 1).toUInt();

        if (iNum > m_vPerform.size() || iNum <= 0) {
            putModule("Illegal # Requested");
            return;
        } else {
            m_vPerform.erase(m_vPerform.begin() + iNum - 1);
            putModule("Command Erased.");
        }
        Save();
    }

    void List(const NoString& command)
    {
        NoTable Table;
        uint index = 1;

        Table.addColumn("Id");
        Table.addColumn("Perform");
        Table.addColumn("Expanded");

        for (NoStringVector::const_iterator it = m_vPerform.begin(); it != m_vPerform.end(); ++it, index++) {
            Table.addRow();
            Table.setValue("Id", NoString(index));
            Table.setValue("Perform", *it);

            NoString sExpanded = expandString(*it);

            if (sExpanded != *it) {
                Table.setValue("Expanded", sExpanded);
            }
        }

        if (putModule(Table) == 0) {
            putModule("No commands in your perform list.");
        }
    }

    void Execute(const NoString& command)
    {
        onIrcConnected();
        putModule("perform commands sent");
    }

    void Swap(const NoString& command)
    {
        u_int iNumA = No::token(command, 1).toUInt();
        u_int iNumB = No::token(command, 2).toUInt();

        if (iNumA > m_vPerform.size() || iNumA <= 0 || iNumB > m_vPerform.size() || iNumB <= 0) {
            putModule("Illegal # Requested");
        } else {
            std::iter_swap(m_vPerform.begin() + (iNumA - 1), m_vPerform.begin() + (iNumB - 1));
            putModule("Commands Swapped.");
            Save();
        }
    }

public:
    MODCONSTRUCTOR(NoPerform)
    {
        addHelpCommand();
        addCommand("Add", static_cast<NoModule::CommandFunction>(&NoPerform::Add), "<command>");
        addCommand("Del", static_cast<NoModule::CommandFunction>(&NoPerform::Del), "<nr>");
        addCommand("List", static_cast<NoModule::CommandFunction>(&NoPerform::List));
        addCommand("Execute", static_cast<NoModule::CommandFunction>(&NoPerform::Execute));
        addCommand("Swap", static_cast<NoModule::CommandFunction>(&NoPerform::Swap), "<nr> <nr>");
    }

    NoString ParsePerform(const NoString& arg) const
    {
        NoString sPerf = arg;

        if (sPerf.left(1) == "/")
            sPerf.leftChomp(1);

        if (No::token(sPerf, 0).equals("MSG")) {
            sPerf = "PRIVMSG " + No::tokens(sPerf, 1);
        }

        if ((No::token(sPerf, 0).equals("PRIVMSG") || No::token(sPerf, 0).equals("NOTICE")) && No::token(sPerf, 2).left(1) != ":") {
            sPerf = No::token(sPerf, 0) + " " + No::token(sPerf, 1) + " :" + No::tokens(sPerf, 2);
        }

        return sPerf;
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        m_vPerform = NoRegistry(this).value("Perform").split("\n", No::SkipEmptyParts);

        return true;
    }

    void onIrcConnected() override
    {
        for (NoStringVector::const_iterator it = m_vPerform.begin(); it != m_vPerform.end(); ++it) {
            putIrc(expandString(*it));
        }
    }

private:
    void Save()
    {
        NoString sBuffer = "";

        for (NoStringVector::const_iterator it = m_vPerform.begin(); it != m_vPerform.end(); ++it) {
            sBuffer += *it + "\n";
        }
        NoRegistry registry(this);
        registry.setValue("Perform", sBuffer);
    }

    NoStringVector m_vPerform;
};

template <>
void no_moduleInfo<NoPerform>(NoModuleInfo& info)
{
    info.addType(No::UserModule);
    info.setWikiPage("perform");
}

NETWORKMODULEDEFS(NoPerform, "Keeps a list of commands to be executed when ZNC connects to IRC.")
