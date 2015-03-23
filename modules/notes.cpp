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
#include <no/noapp.h>
#include <no/noclient.h>
#include <no/notemplate.h>
#include <no/nowebsocket.h>
#include <no/noregistry.h>

class NoNotesMod : public NoModule
{
    bool bShowNotesOnLogin;

    void ListCommand(const NoString& sLine) { ListNotes(); }

    void AddNoteCommand(const NoString& sLine)
    {
        NoString sKey(No::token(sLine, 1));
        NoString sValue(No::tokens(sLine, 2));

        NoRegistry registry(this);
        if (!registry.value(sKey).empty()) {
            PutModule("That note already exists.  Use MOD <key> <note> to overwrite.");
        } else if (AddNote(sKey, sValue)) {
            PutModule("Added note [" + sKey + "]");
        } else {
            PutModule("Unable to add note [" + sKey + "]");
        }
    }

    void ModCommand(const NoString& sLine)
    {
        NoString sKey(No::token(sLine, 1));
        NoString sValue(No::tokens(sLine, 2));

        if (AddNote(sKey, sValue)) {
            PutModule("Set note for [" + sKey + "]");
        } else {
            PutModule("Unable to add note [" + sKey + "]");
        }
    }

    void GetCommand(const NoString& sLine)
    {
        NoRegistry registry(this);
        NoString sNote = registry.value(No::tokens(sLine, 1));

        if (sNote.empty()) {
            PutModule("This note doesn't exist.");
        } else {
            PutModule(sNote);
        }
    }

    void DelCommand(const NoString& sLine)
    {
        NoString sKey(No::token(sLine, 1));

        if (DelNote(sKey)) {
            PutModule("Deleted note [" + sKey + "]");
        } else {
            PutModule("Unable to delete note [" + sKey + "]");
        }
    }

public:
    MODCONSTRUCTOR(NoNotesMod)
    {
        using std::placeholders::_1;
        AddHelpCommand();
        AddCommand("List", static_cast<NoModuleCommand::ModCmdFunc>(&NoNotesMod::ListCommand));
        AddCommand("Add", static_cast<NoModuleCommand::ModCmdFunc>(&NoNotesMod::AddNoteCommand), "<key> <note>");
        AddCommand("Del", static_cast<NoModuleCommand::ModCmdFunc>(&NoNotesMod::DelCommand), "<key>", "Delete a note");
        AddCommand("Mod", "<key> <note>", "Modify a note", std::bind(&NoNotesMod::ModCommand, this, _1));
        AddCommand("Get", "<key>", "", [this](const NoString& sLine) { GetCommand(sLine); });
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
        bShowNotesOnLogin = !sArgs.equals("-disableNotesOnLogin");
        return true;
    }

    NoString GetWebMenuTitle() override { return "Notes"; }

    void OnClientLogin() override
    {
        if (bShowNotesOnLogin) {
            ListNotes(true);
        }
    }

    ModRet OnUserRaw(NoString& sLine) override
    {
        if (sLine.left(1) != "#") {
            return CONTINUE;
        }

        NoString sKey;
        bool bOverwrite = false;

        if (sLine == "#?") {
            ListNotes(true);
            return HALT;
        } else if (sLine.left(2) == "#-") {
            sKey = No::token(sLine, 0).leftChomp_n(2);
            if (DelNote(sKey)) {
                PutModNotice("Deleted note [" + sKey + "]");
            } else {
                PutModNotice("Unable to delete note [" + sKey + "]");
            }
            return HALT;
        } else if (sLine.left(2) == "#+") {
            sKey = No::token(sLine, 0).leftChomp_n(2);
            bOverwrite = true;
        } else if (sLine.left(1) == "#") {
            sKey = No::token(sLine, 0).leftChomp_n(1);
        }

        NoString sValue(No::tokens(sLine, 1));

        if (!sKey.empty()) {
            if (!bOverwrite && NoRegistry(this).contains(sKey)) {
                PutModNotice("That note already exists.  Use /#+<key> <note> to overwrite.");
            } else if (AddNote(sKey, sValue)) {
                if (!bOverwrite) {
                    PutModNotice("Added note [" + sKey + "]");
                } else {
                    PutModNotice("Set note for [" + sKey + "]");
                }
            } else {
                PutModNotice("Unable to add note [" + sKey + "]");
            }
        }

        return HALT;
    }

    bool DelNote(const NoString& sKey)
    {
        NoRegistry registry(this);
        if (registry.contains(sKey)) {
            registry.remove(sKey);
            return true;
        }
        return false;
    }

    bool AddNote(const NoString& sKey, const NoString& sNote)
    {
        if (sKey.empty()) {
            return false;
        }

        NoRegistry registry(this);
        registry.setValue(sKey, sNote);
        return true;
    }

    void ListNotes(bool bNotice = false)
    {
        NoClient* pClient = GetClient();

        if (pClient) {
            NoTable Table;
            Table.AddColumn("Key");
            Table.AddColumn("Note");

            NoRegistry registry(this);
            for (const NoString& key : registry.keys()) {
                Table.AddRow();
                Table.SetCell("Key", key);
                Table.SetCell("Note", registry.value(key));
            }

            if (Table.size()) {
                uint idx = 0;
                NoString sLine;
                while (Table.GetLine(idx++, sLine)) {
                    if (bNotice) {
                        pClient->PutModNotice(GetModName(), sLine);
                    } else {
                        pClient->PutModule(GetModName(), sLine);
                    }
                }
            } else {
                if (bNotice) {
                    PutModNotice("You have no entries.");
                } else {
                    PutModule("You have no entries.");
                }
            }
        }
    }

    bool OnWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "index") {
            NoRegistry registry(this);
            for (const NoString& key : registry.keys()) {
                NoTemplate& Row = Tmpl.AddRow("NotesLoop");

                Row["Key"] = key;
                Row["Note"] = registry.value(key);
            }

            return true;
        } else if (sPageName == "delnote") {
            DelNote(WebSock.GetParam("key", false));
            WebSock.Redirect(GetWebPath());
            return true;
        } else if (sPageName == "addnote") {
            AddNote(WebSock.GetParam("key"), WebSock.GetParam("note"));
            WebSock.Redirect(GetWebPath());
            return true;
        }

        return false;
    }
};

template <> void no_moduleInfo<NoNotesMod>(NoModuleInfo& Info)
{
    Info.SetWikiPage("notes");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText(
    "This user module takes up to one arguments. It can be -disableNotesOnLogin not to show notes upon client login");
}

USERMODULEDEFS(NoNotesMod, "Keep and replay notes")
