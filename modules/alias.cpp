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
#include <no/noclient.h>
#include <no/nochannel.h>
#include <no/nonetwork.h>
#include <no/noregistry.h>

#include <sstream>
#include <stdexcept>

class NoAlias
{
private:
    NoModule* parent;
    NoString name;
    NoStringVector alias_cmds;

public:
    // getters/setters
    const NoString& GetName() const { return name; }

    // name should be a single, all uppercase word
    void SetName(const NoString& newname)
    {
        name = No::token(newname, 0, " ").toUpper();
    }

    // combined getter/setter for command list
    NoStringVector& AliasCmds() { return alias_cmds; }

    // check registry if alias exists
    static bool AliasExists(NoModule* module, NoString alias_name)
    {
        alias_name = No::token(alias_name, 0, " ").toUpper();
        return NoRegistry(module).contains(alias_name);
    }

    // populate alias from stored settings in registry, or return false if none exists
    static bool AliasGet(NoAlias& alias, NoModule* module, NoString line)
    {
        line = No::token(line, 0, " ").toUpper();
        NoRegistry registry(module);
        if (!registry.contains(line))
            return false;
        alias.parent = module;
        alias.name = line;
        alias.alias_cmds = registry.value(line).split("\n", No::SkipEmptyParts);
        return true;
    }

    // constructors
    NoAlias() : parent(nullptr) {}
    NoAlias(NoModule* new_parent, const NoString& new_name) : parent(new_parent) { SetName(new_name); }

    // produce a command string from this alias' command list
    NoString GetCommands() const { return NoString("\n").join(alias_cmds.begin(), alias_cmds.end()); }

    // write this alias to registry
    void Commit() const
    {
        if (!parent) return;
        NoRegistry registry(parent);
        registry.setValue(name, GetCommands());
    }

    // delete this alias from regisrty
    void Delete() const
    {
        if (!parent) return;
        NoRegistry registry(parent);
        registry.remove(name);
    }

private:
    // this function helps imprint out.  it checks if there is a substitution token at 'caret' in 'alias_data'
    // and if it finds one, pulls the appropriate token out of 'line' and appends it to 'output', and updates 'caret'.
    // 'skip' is updated based on the logic that we should skip the % at the caret if we fail to parse the token.
    static void ParseToken(const NoString& alias_data, const NoString& line, NoString& output, size_t& caret, size_t& skip)
    {
        bool optional = false;
        bool subsequent = false;
        size_t index = caret + 1;
        int token = -1;

        skip = 1;

        if (alias_data.length() > index && alias_data[index] == '?') {
            optional = true;
            ++index;
        } // try to read optional flag
        if (alias_data.length() > index && NoString(alias_data.substr(index)).convert(&token)) // try to read integer
        {
            while (alias_data.length() > index && alias_data[index] >= '0' && alias_data[index] <= '9')
                ++index; // skip any numeric digits in string
        } // (supposed to fail if whitespace precedes integer)
        else
            return; // token was malformed. leave caret unchanged, and flag first character for skipping
        if (alias_data.length() > index && alias_data[index] == '+') {
            subsequent = true;
            ++index;
        } // try to read subsequent flag
        if (alias_data.length() > index && alias_data[index] == '%') {
            ++index;
        } // try to read end-of-substitution marker
        else
            return;

        // if we get here, we're definitely dealing with a token, so
        // get the token's value
        NoString stok = subsequent ? No::tokens(line, token) : No::token(line, token);
        if (stok.empty() && !optional)
            throw std::invalid_argument(NoString("missing required parameter: ") +
                                        NoString(token)); // blow up if token is required and also empty
        output.append(stok); // write token value to output

        skip = 0; // since we're moving the cursor after the end of the token, skip no characters
        caret = index; // advance the cursor forward by the size of the token
    }

public:
    // read an IRC line and do token substitution
    // throws an exception if a required parameter is missing, and might also throw if you manage to make it bork
    NoString Imprint(NoString line) const
    {
        NoString output;
        NoString alias_data = GetCommands();
        alias_data = parent->ExpandString(alias_data);
        size_t lastfound = 0, skip = 0;

        // it would be very inefficient to attempt to blindly replace every possible token
        // so let's just parse the line and replace when we find them
        // token syntax:
        // %[?]n[+]%
        // adding ? makes the substitution optional (you'll get "" if there are insufficient tokens, otherwise the alias
        // will fail)
        // adding + makes the substitution contain all tokens from the nth to the end of the line
        while (true) {
            // if (found >= (int) alias_data.length()) break; 		// shouldn't be possible.
            size_t found = alias_data.find("%", lastfound + skip);
            if (found == NoString::npos) break; // if we found nothing, break
            output.append(alias_data.substr(lastfound, found - lastfound)); // capture everything between the last
            // stopping point and here
            ParseToken(alias_data, line, output, found, skip); // attempt to read a token, updates indices based on
            // success/failure
            lastfound = found;
        }

        output += alias_data.substr(lastfound); // append from the final
        return output;
    }
};

class NoAliasMod : public NoModule
{
private:
    bool sending_lines;

public:
    void CreateCommand(const NoString& sLine)
    {
        NoString name = No::token(sLine, 1, " ");
        if (!NoAlias::AliasExists(this, name)) {
            NoAlias na(this, name);
            na.Commit();
            PutModule("Created alias: " + na.GetName());
        } else
            PutModule("Alias already exists.");
    }

    void DeleteCommand(const NoString& sLine)
    {
        NoString name = No::token(sLine, 1, " ");
        NoAlias delete_alias;
        if (NoAlias::AliasGet(delete_alias, this, name)) {
            PutModule("Deleted alias: " + delete_alias.GetName());
            delete_alias.Delete();
        } else
            PutModule("Alias does not exist.");
    }

    void AddCmd(const NoString& sLine)
    {
        NoString name = No::token(sLine, 1, " ");
        NoAlias add_alias;
        if (NoAlias::AliasGet(add_alias, this, name)) {
            add_alias.AliasCmds().push_back(No::tokens(sLine, 2, " "));
            add_alias.Commit();
            PutModule("Modified alias.");
        } else
            PutModule("Alias does not exist.");
    }

    void InsertCommand(const NoString& sLine)
    {
        NoString name = No::token(sLine, 1, " ");
        NoAlias insert_alias;
        int index;
        if (NoAlias::AliasGet(insert_alias, this, name)) {
            // if Convert succeeds, then i has been successfully read from user input
            if (!No::token(sLine, 2, " ").convert(&index) || index < 0 || index > (int)insert_alias.AliasCmds().size()) {
                PutModule("Invalid index.");
                return;
            }

            insert_alias.AliasCmds().insert(insert_alias.AliasCmds().begin() + index, No::tokens(sLine, 3, " "));
            insert_alias.Commit();
            PutModule("Modified alias.");
        } else
            PutModule("Alias does not exist.");
    }

    void RemoveCommand(const NoString& sLine)
    {
        NoString name = No::token(sLine, 1, " ");
        NoAlias remove_alias;
        int index;
        if (NoAlias::AliasGet(remove_alias, this, name)) {
            if (!No::token(sLine, 2, " ").convert(&index) || index < 0 || index > (int)remove_alias.AliasCmds().size() - 1) {
                PutModule("Invalid index.");
                return;
            }

            remove_alias.AliasCmds().erase(remove_alias.AliasCmds().begin() + index);
            remove_alias.Commit();
            PutModule("Modified alias.");
        } else
            PutModule("Alias does not exist.");
    }

    void ClearCommand(const NoString& sLine)
    {
        NoString name = No::token(sLine, 1, " ");
        NoAlias clear_alias;
        if (NoAlias::AliasGet(clear_alias, this, name)) {
            clear_alias.AliasCmds().clear();
            clear_alias.Commit();
            PutModule("Modified alias.");
        } else
            PutModule("Alias does not exist.");
    }

    void ListCommand(const NoString& sLine)
    {
        NoString output = "The following aliases exist:";
        NoRegistry registry(this);
        NoStringVector aliases = registry.keys();
        if (!aliases.empty())
            output += NoString(" ").join(aliases.begin(), aliases.end());
        else
            output += " [none]";
        PutModule(output);
    }

    void InfoCommand(const NoString& sLine)
    {
        NoString name = No::token(sLine, 1, " ");
        NoAlias info_alias;
        if (NoAlias::AliasGet(info_alias, this, name)) {
            PutModule("Actions for alias " + info_alias.GetName() + ":");
            for (size_t i = 0; i < info_alias.AliasCmds().size(); ++i) {
                NoString num(i);
                NoString padding(4 - (num.length() > 3 ? 3 : num.length()), ' ');
                PutModule(num + padding + info_alias.AliasCmds()[i]);
            }
            PutModule("End of actions for alias " + info_alias.GetName() + ".");
        } else
            PutModule("Alias does not exist.");
    }

    MODCONSTRUCTOR(NoAliasMod), sending_lines(false)
    {
        AddHelpCommand();
        AddCommand("Create",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAliasMod::CreateCommand),
                   "<name>",
                   "Creates a new, blank alias called name.");
        AddCommand("Delete",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAliasMod::DeleteCommand),
                   "<name>",
                   "Deletes an existing alias.");
        AddCommand("Add",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAliasMod::AddCmd),
                   "<name> <action ...>",
                   "Adds a line to an existing alias.");
        AddCommand("Insert",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAliasMod::InsertCommand),
                   "<name> <pos> <action ...>",
                   "Inserts a line into an existing alias.");
        AddCommand("Remove",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAliasMod::RemoveCommand),
                   "<name> <linenum>",
                   "Removes a line from an existing alias.");
        AddCommand("Clear",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAliasMod::ClearCommand),
                   "<name>",
                   "Removes all line from an existing alias.");
        AddCommand("List",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAliasMod::ListCommand),
                   "",
                   "Lists all aliases by name.");
        AddCommand("Info",
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoAliasMod::InfoCommand),
                   "<name>",
                   "Reports the actions performed by an alias.");
    }

    ModRet onUserRaw(NoString& sLine) override
    {
        NoAlias current_alias;

        if (sending_lines) return CONTINUE;

        try {
            if (sLine.equals("ZNC-CLEAR-ALL-ALIASES!")) {
                ListCommand("");
                PutModule("Clearing all of them!");
                NoRegistry registry(this);
                registry.clear();
                return HALT;
            } else if (NoAlias::AliasGet(current_alias, this, sLine)) {
                NoStringVector rawLines = current_alias.Imprint(sLine).split("\n", No::SkipEmptyParts);
                sending_lines = true;

                for (size_t i = 0; i < rawLines.size(); ++i) {
                    GetClient()->ReadLine(rawLines[i]);
                }

                sending_lines = false;
                return HALT;
            }
        } catch (std::exception& e) {
            NoString my_nick = (GetNetwork() == nullptr ? "" : GetNetwork()->currentNick());
            if (my_nick.empty()) my_nick = "*";
            PutUser(NoString(":znc.in 461 " + my_nick + " " + current_alias.GetName() + " :ZNC alias error: ") + e.what());
            return HALTCORE;
        }

        return CONTINUE;
    }
};

template <> void no_moduleInfo<NoAliasMod>(NoModuleInfo& Info)
{
    Info.SetWikiPage("alias");
    Info.AddType(No::NetworkModule);
}

USERMODULEDEFS(NoAliasMod, "Provides bouncer-side command alias support.")
