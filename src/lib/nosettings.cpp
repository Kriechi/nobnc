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

#include "nosettings.h"
#include "nofile.h"
#include "noutils.h"
#include <stack>
#include <sstream>

struct ConfigStackEntry
{
    NoString tag;
    NoString name;
    NoSettings config;

    ConfigStackEntry(const NoString& tag, const NoString& name) : tag(tag), name(name)
    {
    }
};

NoSettingsEntry::NoSettingsEntry() : m_subConfig(nullptr)
{
}

NoSettingsEntry::NoSettingsEntry(const NoSettings& config) : m_subConfig(new NoSettings(config))
{
}

NoSettingsEntry::NoSettingsEntry(const NoSettingsEntry& other) : m_subConfig(nullptr)
{
    if (other.m_subConfig)
        m_subConfig = new NoSettings(*other.m_subConfig);
}

NoSettingsEntry::~NoSettingsEntry()
{
    delete m_subConfig;
}

NoSettingsEntry& NoSettingsEntry::operator=(const NoSettingsEntry& other)
{
    delete m_subConfig;
    if (other.m_subConfig)
        m_subConfig = new NoSettings(*other.m_subConfig);
    else
        m_subConfig = nullptr;
    return *this;
}

NoSettings::NoSettings() : m_entries(), m_subConfigs()
{
}

NoSettings::EntryMapIterator NoSettings::BeginEntries() const
{
    return m_entries.begin();
}

NoSettings::EntryMapIterator NoSettings::EndEntries() const
{
    return m_entries.end();
}

NoSettings::SubConfigMapIterator NoSettings::BeginSubConfigs() const
{
    return m_subConfigs.begin();
}

NoSettings::SubConfigMapIterator NoSettings::EndSubConfigs() const
{
    return m_subConfigs.end();
}

void NoSettings::AddKeyValuePair(const NoString& name, const NoString& value)
{
    if (name.empty() || value.empty()) {
        return;
    }

    m_entries[name].push_back(value);
}

bool NoSettings::AddSubConfig(const NoString& tag, const NoString& name, NoSettings config)
{
    SubConfig& conf = m_subConfigs[tag];
    SubConfig::const_iterator it = conf.find(name);

    if (it != conf.end()) {
        return false;
    }

    conf[name] = config;
    return true;
}

bool NoSettings::FindStringVector(const NoString& name, NoStringVector& lst, bool erase)
{
    EntryMap::iterator it = m_entries.find(name);
    lst.clear();
    if (it == m_entries.end())
        return false;
    lst = it->second;

    if (erase) {
        m_entries.erase(it);
    }

    return true;
}

bool NoSettings::FindStringEntry(const NoString& name, NoString& res, const NoString& defaultValue)
{
    EntryMap::iterator it = m_entries.find(name);
    res = defaultValue;
    if (it == m_entries.end() || it->second.empty())
        return false;
    res = it->second.front();
    it->second.erase(it->second.begin());
    if (it->second.empty())
        m_entries.erase(it);
    return true;
}

bool NoSettings::FindBoolEntry(const NoString& name, bool& res, bool defaultValue)
{
    NoString s;
    if (FindStringEntry(name, s)) {
        res = s.toBool();
        return true;
    }
    res = defaultValue;
    return false;
}

bool NoSettings::FindUIntEntry(const NoString& name, uint& res, uint defaultValue)
{
    NoString s;
    if (FindStringEntry(name, s)) {
        res = s.toUInt();
        return true;
    }
    res = defaultValue;
    return false;
}

bool NoSettings::FindUShortEntry(const NoString& name, ushort& res, ushort defaultValue)
{
    NoString s;
    if (FindStringEntry(name, s)) {
        res = s.toUShort();
        return true;
    }
    res = defaultValue;
    return false;
}

bool NoSettings::FindDoubleEntry(const NoString& name, double& res, double defaultValue)
{
    NoString s;
    if (FindStringEntry(name, s)) {
        res = s.toDouble();
        return true;
    }
    res = defaultValue;
    return false;
}

bool NoSettings::FindSubConfig(const NoString& name, NoSettings::SubConfig& config, bool erase)
{
    SubConfigMap::iterator it = m_subConfigs.find(name);
    if (it == m_subConfigs.end()) {
        config.clear();
        return false;
    }
    config = it->second;

    if (erase) {
        m_subConfigs.erase(it);
    }

    return true;
}

bool NoSettings::empty() const
{
    return m_entries.empty() && m_subConfigs.empty();
}

bool NoSettings::Parse(NoFile& file, NoString& error)
{
    NoString line;
    uint lineNum = 0;
    NoSettings* activeConfig = this;
    std::stack<ConfigStackEntry> configStack;
    bool commented = false; // support for /**/ style comments

    if (!file.Seek(0)) {
        error = "Could not seek to the beginning of the config.";
        return false;
    }

    while (file.ReadLine(line)) {
        lineNum++;

#define ERROR(arg)                                             \
    do {                                                       \
        std::stringstream stream;                              \
        stream << "Error on line " << lineNum << ": " << arg; \
        error = stream.str();                              \
        m_subConfigs.clear();                                  \
        m_entries.clear();                                     \
        return false;                                          \
    } while (0)

        // Remove all leading spaces and trailing line endings
        line.trimLeft();
        line.trimRight("\r\n");

        if (commented || line.left(2) == "/*") {
            /* Does this comment end on the same line again? */
            commented = (line.right(2) != "*/");

            continue;
        }

        if ((line.empty()) || (line[0] == '#') || (line.left(2) == "//")) {
            continue;
        }

        if ((line.left(1) == "<") && (line.right(1) == ">")) {
            line.leftChomp(1);
            line.rightChomp(1);
            line.trim();

            NoString tag = No::token(line, 0);
            NoString value = No::tokens(line, 1);

            tag.trim();
            value.trim();

            if (tag.left(1) == "/") {
                tag = tag.substr(1);

                if (!value.empty())
                    ERROR("Malformated closing tag. Expected \"</" << tag << ">\".");
                if (configStack.empty())
                    ERROR("Closing tag \"" << tag << "\" which is not open.");

                const struct ConfigStackEntry& entry = configStack.top();
                NoSettings myConfig(entry.config);
                NoString name(entry.name);

                if (!tag.equals(entry.tag))
                    ERROR("Closing tag \"" << tag << "\" which is not open.");

                // This breaks entry
                configStack.pop();

                if (configStack.empty())
                    activeConfig = this;
                else
                    activeConfig = &configStack.top().config;

                SubConfig& conf = activeConfig->m_subConfigs[tag.toLower()];
                SubConfig::const_iterator it = conf.find(name);

                if (it != conf.end())
                    ERROR("Duplicate entry for tag \"" << tag << "\" name \"" << name << "\".");

                conf[name] = NoSettingsEntry(myConfig);
            } else {
                if (value.empty())
                    ERROR("Empty block name at begin of block.");
                configStack.push(ConfigStackEntry(tag.toLower(), value));
                activeConfig = &configStack.top().config;
            }

            continue;
        }

        // If we have a regular line, figure out where it goes
        NoString name = No::token(line, 0, "=");
        NoString value = No::tokens(line, 1, "=");

        // Only remove the first space, people might want
        // leading spaces (e.g. in the MOTD).
        if (value.left(1) == " ")
            value.leftChomp(1);

        // We don't have any names with spaces, trim all
        // leading/trailing spaces.
        name.trim();

        if (name.empty() || value.empty())
            ERROR("Malformed line");

        NoString sNameLower = name.toLower();
        activeConfig->m_entries[sNameLower].push_back(value);
    }

    if (commented)
        ERROR("Comment not closed at end of file.");

    if (!configStack.empty()) {
        const NoString& tag = configStack.top().tag;
        ERROR("Not all tags are closed at the end of the file. Inner-most open tag is \"" << tag << "\".");
    }

    return true;
}

void NoSettings::Write(NoFile& file, uint indentation)
{
    NoString sIndentation = NoString(indentation, '\t');

    for (const auto& it : m_entries) {
        for (const NoString& value : it.second) {
            file.Write(sIndentation + it.first + " = " + value + "\n");
        }
    }

    for (const auto& it : m_subConfigs) {
        for (const auto& it2 : it.second) {
            file.Write("\n");

            file.Write(sIndentation + "<" + it.first + " " + it2.first + ">\n");
            it2.second.m_subConfig->Write(file, indentation + 1);
            file.Write(sIndentation + "</" + it.first + ">\n");
        }
    }
}
