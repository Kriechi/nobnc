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

    void ListCommand(const NoString& sLine)
    {
        ListNotes();
    }

    void AddNoteCommand(const NoString& sLine)
    {
        NoString sKey(No::token(sLine, 1));
        NoString sValue(No::tokens(sLine, 2));

        NoRegistry registry(this);
        if (!registry.value(sKey).empty()) {
            putModule("That note already exists.  Use MOD <key> <note> to overwrite.");
        } else if (AddNote(sKey, sValue)) {
            putModule("Added note [" + sKey + "]");
        } else {
            putModule("Unable to add note [" + sKey + "]");
        }
    }

    void ModCommand(const NoString& sLine)
    {
        NoString sKey(No::token(sLine, 1));
        NoString sValue(No::tokens(sLine, 2));

        if (AddNote(sKey, sValue)) {
            putModule("Set note for [" + sKey + "]");
        } else {
            putModule("Unable to add note [" + sKey + "]");
        }
    }

    void GetCommand(const NoString& sLine)
    {
        NoRegistry registry(this);
        NoString sNote = registry.value(No::tokens(sLine, 1));

        if (sNote.empty()) {
            putModule("This note doesn't exist.");
        } else {
            putModule(sNote);
        }
    }

    void DelCommand(const NoString& sLine)
    {
        NoString sKey(No::token(sLine, 1));

        if (DelNote(sKey)) {
            putModule("Deleted note [" + sKey + "]");
        } else {
            putModule("Unable to delete note [" + sKey + "]");
        }
    }

public:
    MODCONSTRUCTOR(NoNotesMod)
    {
        using std::placeholders::_1;
        addHelpCommand();
        addCommand("List", static_cast<NoModuleCommand::ModCmdFunc>(&NoNotesMod::ListCommand));
        addCommand("Add", static_cast<NoModuleCommand::ModCmdFunc>(&NoNotesMod::AddNoteCommand), "<key> <note>");
        addCommand("Del", static_cast<NoModuleCommand::ModCmdFunc>(&NoNotesMod::DelCommand), "<key>", "Delete a note");
        addCommand("Mod", "<key> <note>", "Modify a note", std::bind(&NoNotesMod::ModCommand, this, _1));
        addCommand("Get", "<key>", "", [this](const NoString& sLine) { GetCommand(sLine); });
    }

    bool onLoad(const NoString& sArgs, NoString& sMessage) override
    {
        bShowNotesOnLogin = !sArgs.equals("-disableNotesOnLogin");
        return true;
    }

    NoString webMenuTitle() override
    {
        return "Notes";
    }

    void onClientLogin() override
    {
        if (bShowNotesOnLogin) {
            ListNotes(true);
        }
    }

    ModRet onUserRaw(NoString& sLine) override
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
                putModuleNotice("Deleted note [" + sKey + "]");
            } else {
                putModuleNotice("Unable to delete note [" + sKey + "]");
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
                putModuleNotice("That note already exists.  Use /#+<key> <note> to overwrite.");
            } else if (AddNote(sKey, sValue)) {
                if (!bOverwrite) {
                    putModuleNotice("Added note [" + sKey + "]");
                } else {
                    putModuleNotice("Set note for [" + sKey + "]");
                }
            } else {
                putModuleNotice("Unable to add note [" + sKey + "]");
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
        NoClient* pClient = client();

        if (pClient) {
            NoTable Table;
            Table.addColumn("Key");
            Table.addColumn("Note");

            NoRegistry registry(this);
            for (const NoString& key : registry.keys()) {
                Table.addRow();
                Table.setValue("Key", key);
                Table.setValue("Note", registry.value(key));
            }

            if (!Table.isEmpty()) {
                for (const NoString& line : Table.toString()) {
                    if (bNotice)
                        pClient->putModuleNotice(moduleName(), line);
                    else
                        pClient->putModule(moduleName(), line);
                }
            } else {
                if (bNotice) {
                    putModuleNotice("You have no entries.");
                } else {
                    putModule("You have no entries.");
                }
            }
        }
    }

    bool onWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "index") {
            NoRegistry registry(this);
            for (const NoString& key : registry.keys()) {
                NoTemplate& Row = Tmpl.addRow("NotesLoop");

                Row["Key"] = key;
                Row["Note"] = registry.value(key);
            }

            return true;
        } else if (sPageName == "delnote") {
            DelNote(WebSock.param("key", false));
            WebSock.redirect(webPath());
            return true;
        } else if (sPageName == "addnote") {
            AddNote(WebSock.param("key"), WebSock.param("note"));
            WebSock.redirect(webPath());
            return true;
        }

        return false;
    }
};

template <>
void no_moduleInfo<NoNotesMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("notes");
    Info.setHasArgs(true);
    Info.setArgsHelpText(
    "This user module takes up to one arguments. It can be -disableNotesOnLogin not to show notes upon client login");
}

USERMODULEDEFS(NoNotesMod, "Keep and replay notes")
