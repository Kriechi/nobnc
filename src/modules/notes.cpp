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
#include <nobnc/noapp.h>
#include <nobnc/noclient.h>
#include <nobnc/notemplate.h>
#include <nobnc/nowebsocket.h>
#include <nobnc/noregistry.h>
#include <nobnc/notable.h>

class NoNotesMod : public NoModule
{
    bool bShowNotesOnLogin;

    void ListCommand(const NoString& line)
    {
        ListNotes();
    }

    void AddNoteCommand(const NoString& line)
    {
        NoString key(No::token(line, 1));
        NoString value(No::tokens(line, 2));

        NoRegistry registry(this);
        if (!registry.value(key).empty()) {
            putModule("That note already exists.  Use MOD <key> <note> to overwrite.");
        } else if (AddNote(key, value)) {
            putModule("Added note [" + key + "]");
        } else {
            putModule("Unable to add note [" + key + "]");
        }
    }

    void ModCommand(const NoString& line)
    {
        NoString key(No::token(line, 1));
        NoString value(No::tokens(line, 2));

        if (AddNote(key, value)) {
            putModule("Set note for [" + key + "]");
        } else {
            putModule("Unable to add note [" + key + "]");
        }
    }

    void GetCommand(const NoString& line)
    {
        NoRegistry registry(this);
        NoString sNote = registry.value(No::tokens(line, 1));

        if (sNote.empty()) {
            putModule("This note doesn't exist.");
        } else {
            putModule(sNote);
        }
    }

    void DelCommand(const NoString& line)
    {
        NoString key(No::token(line, 1));

        if (DelNote(key)) {
            putModule("Deleted note [" + key + "]");
        } else {
            putModule("Unable to delete note [" + key + "]");
        }
    }

public:
    MODCONSTRUCTOR(NoNotesMod)
    {
        addHelpCommand();
        addCommand("List", static_cast<NoModule::CommandFunction>(&NoNotesMod::ListCommand));
        addCommand("Add", static_cast<NoModule::CommandFunction>(&NoNotesMod::AddNoteCommand), "<key> <note>");
        addCommand("Del", static_cast<NoModule::CommandFunction>(&NoNotesMod::DelCommand), "<key>", "Delete a note");
        addCommand("Mod", static_cast<NoModule::CommandFunction>(&NoNotesMod::ModCommand), "<key> <note>", "Modify a note");
        addCommand("Get", static_cast<NoModule::CommandFunction>(&NoNotesMod::GetCommand), "<key>", "");
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
        bShowNotesOnLogin = !args.equals("-disableNotesOnLogin");
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

    Return onUserRaw(NoString& line) override
    {
        if (line.left(1) != "#") {
            return Continue;
        }

        NoString key;
        bool bOverwrite = false;

        if (line == "#?") {
            ListNotes(true);
            return Halt;
        } else if (line.left(2) == "#-") {
            key = No::token(line, 0).leftChomp_n(2);
            if (DelNote(key)) {
                putModuleNotice("Deleted note [" + key + "]");
            } else {
                putModuleNotice("Unable to delete note [" + key + "]");
            }
            return Halt;
        } else if (line.left(2) == "#+") {
            key = No::token(line, 0).leftChomp_n(2);
            bOverwrite = true;
        } else if (line.left(1) == "#") {
            key = No::token(line, 0).leftChomp_n(1);
        }

        NoString value(No::tokens(line, 1));

        if (!key.empty()) {
            if (!bOverwrite && NoRegistry(this).contains(key)) {
                putModuleNotice("That note already exists.  Use /#+<key> <note> to overwrite.");
            } else if (AddNote(key, value)) {
                if (!bOverwrite) {
                    putModuleNotice("Added note [" + key + "]");
                } else {
                    putModuleNotice("Set note for [" + key + "]");
                }
            } else {
                putModuleNotice("Unable to add note [" + key + "]");
            }
        }

        return Halt;
    }

    bool DelNote(const NoString& key)
    {
        NoRegistry registry(this);
        if (registry.contains(key)) {
            registry.remove(key);
            return true;
        }
        return false;
    }

    bool AddNote(const NoString& key, const NoString& sNote)
    {
        if (key.empty()) {
            return false;
        }

        NoRegistry registry(this);
        registry.setValue(key, sNote);
        return true;
    }

    void ListNotes(bool bNotice = false)
    {
        NoClient* client = NoModule::client();

        if (client) {
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
                        client->putModuleNotice(name(), line);
                    else
                        client->putModule(name(), line);
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

    bool onWebRequest(NoWebSocket* socket, const NoString& page, NoTemplate& tmpl) override
    {
        if (page == "index") {
            NoRegistry registry(this);
            for (const NoString& key : registry.keys()) {
                NoTemplate& Row = tmpl.addRow("NotesLoop");

                Row["Key"] = key;
                Row["Note"] = registry.value(key);
            }

            return true;
        } else if (page == "delnote") {
            DelNote(socket->param("key", false));
            socket->redirect(webPath());
            return true;
        } else if (page == "addnote") {
            AddNote(socket->param("key"), socket->param("note"));
            socket->redirect(webPath());
            return true;
        }

        return false;
    }
};

template <>
void no_moduleInfo<NoNotesMod>(NoModuleInfo& info)
{
    info.setWikiPage("notes");
    info.setHasArgs(true);
    info.setArgsHelpText(
    "This user module takes up to one arguments. It can be -disableNotesOnLogin not to show notes upon client login");
}

USERMODULEDEFS(NoNotesMod, "Keep and replay notes")
