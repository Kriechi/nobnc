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
#include <nobnc/noclient.h>
#include <nobnc/nochannel.h>
#include <nobnc/nonetwork.h>
#include <nobnc/noregistry.h>
#include <nobnc/noutils.h>

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
    const NoString& GetName() const
    {
        return name;
    }

    // name should be a single, all uppercase word
    void SetName(const NoString& newname)
    {
        name = No::token(newname, 0, " ").toUpper();
    }

    // combined getter/setter for command list
    NoStringVector& AliasCmds()
    {
        return alias_cmds;
    }

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
    NoAlias() : parent(nullptr)
    {
    }
    NoAlias(NoModule* new_parent, const NoString& new_name) : parent(new_parent)
    {
        SetName(new_name);
    }

    // produce a command string from this alias' command list
    NoString GetCommands() const
    {
        return NoString("\n").join(alias_cmds.begin(), alias_cmds.end());
    }

    // write this alias to registry
    void Commit() const
    {
        if (!parent)
            return;
        NoRegistry registry(parent);
        registry.setValue(name, GetCommands());
    }

    // delete this alias from regisrty
    void Delete() const
    {
        if (!parent)
            return;
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
        alias_data = parent->expandString(alias_data);
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
            if (found == NoString::npos)
                break; // if we found nothing, break
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
    void CreateCommand(const NoString& line)
    {
        NoString name = No::token(line, 1, " ");
        if (!NoAlias::AliasExists(this, name)) {
            NoAlias na(this, name);
            na.Commit();
            putModule("Created alias: " + na.GetName());
        } else
            putModule("Alias already exists.");
    }

    void DeleteCommand(const NoString& line)
    {
        NoString name = No::token(line, 1, " ");
        NoAlias delete_alias;
        if (NoAlias::AliasGet(delete_alias, this, name)) {
            putModule("Deleted alias: " + delete_alias.GetName());
            delete_alias.Delete();
        } else
            putModule("Alias does not exist.");
    }

    void AddCmd(const NoString& line)
    {
        NoString name = No::token(line, 1, " ");
        NoAlias add_alias;
        if (NoAlias::AliasGet(add_alias, this, name)) {
            add_alias.AliasCmds().push_back(No::tokens(line, 2, " "));
            add_alias.Commit();
            putModule("Modified alias.");
        } else
            putModule("Alias does not exist.");
    }

    void InsertCommand(const NoString& line)
    {
        NoString name = No::token(line, 1, " ");
        NoAlias insert_alias;
        int index;
        if (NoAlias::AliasGet(insert_alias, this, name)) {
            // if Convert succeeds, then i has been successfully read from user input
            if (!No::token(line, 2, " ").convert(&index) || index < 0 || index > (int)insert_alias.AliasCmds().size()) {
                putModule("Invalid index.");
                return;
            }

            insert_alias.AliasCmds().insert(insert_alias.AliasCmds().begin() + index, No::tokens(line, 3, " "));
            insert_alias.Commit();
            putModule("Modified alias.");
        } else
            putModule("Alias does not exist.");
    }

    void RemoveCommand(const NoString& line)
    {
        NoString name = No::token(line, 1, " ");
        NoAlias remove_alias;
        int index;
        if (NoAlias::AliasGet(remove_alias, this, name)) {
            if (!No::token(line, 2, " ").convert(&index) || index < 0 || index > (int)remove_alias.AliasCmds().size() - 1) {
                putModule("Invalid index.");
                return;
            }

            remove_alias.AliasCmds().erase(remove_alias.AliasCmds().begin() + index);
            remove_alias.Commit();
            putModule("Modified alias.");
        } else
            putModule("Alias does not exist.");
    }

    void ClearCommand(const NoString& line)
    {
        NoString name = No::token(line, 1, " ");
        NoAlias clear_alias;
        if (NoAlias::AliasGet(clear_alias, this, name)) {
            clear_alias.AliasCmds().clear();
            clear_alias.Commit();
            putModule("Modified alias.");
        } else
            putModule("Alias does not exist.");
    }

    void ListCommand(const NoString& line)
    {
        NoString output = "The following aliases exist:";
        NoRegistry registry(this);
        NoStringVector aliases = registry.keys();
        if (!aliases.empty())
            output += NoString(" ").join(aliases.begin(), aliases.end());
        else
            output += " [none]";
        putModule(output);
    }

    void InfoCommand(const NoString& line)
    {
        NoString name = No::token(line, 1, " ");
        NoAlias info_alias;
        if (NoAlias::AliasGet(info_alias, this, name)) {
            putModule("Actions for alias " + info_alias.GetName() + ":");
            for (size_t i = 0; i < info_alias.AliasCmds().size(); ++i) {
                NoString num(i);
                NoString padding(4 - (num.length() > 3 ? 3 : num.length()), ' ');
                putModule(num + padding + info_alias.AliasCmds()[i]);
            }
            putModule("End of actions for alias " + info_alias.GetName() + ".");
        } else
            putModule("Alias does not exist.");
    }

    MODCONSTRUCTOR(NoAliasMod), sending_lines(false)
    {
        addHelpCommand();
        addCommand("Create",
                   static_cast<NoModule::CommandFunction>(&NoAliasMod::CreateCommand),
                   "<name>",
                   "Creates a new, blank alias called name.");
        addCommand("Delete",
                   static_cast<NoModule::CommandFunction>(&NoAliasMod::DeleteCommand),
                   "<name>",
                   "Deletes an existing alias.");
        addCommand("Add",
                   static_cast<NoModule::CommandFunction>(&NoAliasMod::AddCmd),
                   "<name> <action ...>",
                   "Adds a line to an existing alias.");
        addCommand("Insert",
                   static_cast<NoModule::CommandFunction>(&NoAliasMod::InsertCommand),
                   "<name> <pos> <action ...>",
                   "Inserts a line into an existing alias.");
        addCommand("Remove", static_cast<NoModule::CommandFunction>(&NoAliasMod::RemoveCommand), "<name> <linenum>", "Removes a line from an existing alias.");
        addCommand("Clear",
                   static_cast<NoModule::CommandFunction>(&NoAliasMod::ClearCommand),
                   "<name>",
                   "Removes all line from an existing alias.");
        addCommand("List",
                   static_cast<NoModule::CommandFunction>(&NoAliasMod::ListCommand),
                   "",
                   "Lists all aliases by name.");
        addCommand("info",
                   static_cast<NoModule::CommandFunction>(&NoAliasMod::InfoCommand),
                   "<name>",
                   "Reports the actions performed by an alias.");
    }

    Return onUserRaw(NoString& line) override
    {
        NoAlias current_alias;

        if (sending_lines)
            return Continue;

        try {
            if (line.equals("ZNC-CLEAR-ALL-ALIASES!")) {
                ListCommand("");
                putModule("Clearing all of them!");
                NoRegistry registry(this);
                registry.clear();
                return Halt;
            } else if (NoAlias::AliasGet(current_alias, this, line)) {
                NoStringVector rawLines = current_alias.Imprint(line).split("\n", No::SkipEmptyParts);
                sending_lines = true;

                for (size_t i = 0; i < rawLines.size(); ++i) {
                    client()->readLine(rawLines[i]);
                }

                sending_lines = false;
                return Halt;
            }
        } catch (std::exception& e) {
            NoString my_nick = (network() == nullptr ? "" : network()->currentNick());
            if (my_nick.empty())
                my_nick = "*";
            putUser(NoString(":bnc.no 461 " + my_nick + " " + current_alias.GetName() + " :NoBNC alias error: ") + e.what());
            return HaltCore;
        }

        return Continue;
    }
};

template <>
void no_moduleInfo<NoAliasMod>(NoModuleInfo& info)
{
    info.setWikiPage("alias");
    info.addType(No::NetworkModule);
}

USERMODULEDEFS(NoAliasMod, "Provides bouncer-side command alias support.")
