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
#include <no/nowebsocket.h>
#include <no/noregistry.h>

class NoPerform : public NoModule
{
    void Add(const NoString& sCommand)
    {
        NoString sPerf = No::tokens(sCommand, 1);

        if (sPerf.empty()) {
            PutModule("Usage: add <command>");
            return;
        }

        m_vPerform.push_back(ParsePerform(sPerf));
        PutModule("Added!");
        Save();
    }

    void Del(const NoString& sCommand)
    {
        u_int iNum = No::tokens(sCommand, 1).toUInt();

        if (iNum > m_vPerform.size() || iNum <= 0) {
            PutModule("Illegal # Requested");
            return;
        } else {
            m_vPerform.erase(m_vPerform.begin() + iNum - 1);
            PutModule("Command Erased.");
        }
        Save();
    }

    void List(const NoString& sCommand)
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

            NoString sExpanded = ExpandString(*it);

            if (sExpanded != *it) {
                Table.setValue("Expanded", sExpanded);
            }
        }

        if (PutModule(Table) == 0) {
            PutModule("No commands in your perform list.");
        }
    }

    void Execute(const NoString& sCommand)
    {
        onIrcConnected();
        PutModule("perform commands sent");
    }

    void Swap(const NoString& sCommand)
    {
        u_int iNumA = No::token(sCommand, 1).toUInt();
        u_int iNumB = No::token(sCommand, 2).toUInt();

        if (iNumA > m_vPerform.size() || iNumA <= 0 || iNumB > m_vPerform.size() || iNumB <= 0) {
            PutModule("Illegal # Requested");
        } else {
            std::iter_swap(m_vPerform.begin() + (iNumA - 1), m_vPerform.begin() + (iNumB - 1));
            PutModule("Commands Swapped.");
            Save();
        }
    }

public:
    MODCONSTRUCTOR(NoPerform)
    {
        AddHelpCommand();
        AddCommand("Add", static_cast<NoModuleCommand::ModCmdFunc>(&NoPerform::Add), "<command>");
        AddCommand("Del", static_cast<NoModuleCommand::ModCmdFunc>(&NoPerform::Del), "<nr>");
        AddCommand("List", static_cast<NoModuleCommand::ModCmdFunc>(&NoPerform::List));
        AddCommand("Execute", static_cast<NoModuleCommand::ModCmdFunc>(&NoPerform::Execute));
        AddCommand("Swap", static_cast<NoModuleCommand::ModCmdFunc>(&NoPerform::Swap), "<nr> <nr>");
    }

    NoString ParsePerform(const NoString& sArg) const
    {
        NoString sPerf = sArg;

        if (sPerf.left(1) == "/") sPerf.leftChomp(1);

        if (No::token(sPerf, 0).equals("MSG")) {
            sPerf = "PRIVMSG " + No::tokens(sPerf, 1);
        }

        if ((No::token(sPerf, 0).equals("PRIVMSG") || No::token(sPerf, 0).equals("NOTICE")) && No::token(sPerf, 2).left(1) != ":") {
            sPerf = No::token(sPerf, 0) + " " + No::token(sPerf, 1) + " :" + No::tokens(sPerf, 2);
        }

        return sPerf;
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        m_vPerform = NoRegistry(this).value("Perform").split("\n", No::SkipEmptyParts);

        return true;
    }

    void onIrcConnected() override
    {
        for (NoStringVector::const_iterator it = m_vPerform.begin(); it != m_vPerform.end(); ++it) {
            PutIRC(ExpandString(*it));
        }
    }

    NoString GetWebMenuTitle() override { return "Perform"; }

    bool OnWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName != "index") {
            // only accept requests to index
            return false;
        }

        if (WebSock.IsPost()) {
            NoStringVector vsPerf = WebSock.GetRawParam("perform", true).split("\n", No::SkipEmptyParts);
            m_vPerform.clear();

            for (NoStringVector::const_iterator it = vsPerf.begin(); it != vsPerf.end(); ++it)
                m_vPerform.push_back(ParsePerform(*it));

            Save();
        }

        for (NoStringVector::const_iterator it = m_vPerform.begin(); it != m_vPerform.end(); ++it) {
            NoTemplate& Row = Tmpl.AddRow("PerformLoop");
            Row["Perform"] = *it;
        }

        return true;
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

template <> void no_moduleInfo<NoPerform>(NoModuleInfo& Info)
{
    Info.AddType(No::UserModule);
    Info.SetWikiPage("perform");
}

NETWORKMODULEDEFS(NoPerform, "Keeps a list of commands to be executed when ZNC connects to IRC.")
