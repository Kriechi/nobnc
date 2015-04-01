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
    NoString sTag;
    NoString name;
    NoSettings Config;

    ConfigStackEntry(const NoString& Tag, const NoString Name) : sTag(Tag), name(Name), Config()
    {
    }
};

NoSettingsEntry::NoSettingsEntry() : m_subConfig(nullptr)
{
}

NoSettingsEntry::NoSettingsEntry(const NoSettings& Config) : m_subConfig(new NoSettings(Config))
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

bool NoSettings::AddSubConfig(const NoString& sTag, const NoString& name, NoSettings Config)
{
    SubConfig& conf = m_subConfigs[sTag];
    SubConfig::const_iterator it = conf.find(name);

    if (it != conf.end()) {
        return false;
    }

    conf[name] = Config;
    return true;
}

bool NoSettings::FindStringVector(const NoString& name, NoStringVector& vsList, bool bErase)
{
    EntryMap::iterator it = m_entries.find(name);
    vsList.clear();
    if (it == m_entries.end())
        return false;
    vsList = it->second;

    if (bErase) {
        m_entries.erase(it);
    }

    return true;
}

bool NoSettings::FindStringEntry(const NoString& name, NoString& sRes, const NoString& sDefault)
{
    EntryMap::iterator it = m_entries.find(name);
    sRes = sDefault;
    if (it == m_entries.end() || it->second.empty())
        return false;
    sRes = it->second.front();
    it->second.erase(it->second.begin());
    if (it->second.empty())
        m_entries.erase(it);
    return true;
}

bool NoSettings::FindBoolEntry(const NoString& name, bool& bRes, bool bDefault)
{
    NoString s;
    if (FindStringEntry(name, s)) {
        bRes = s.toBool();
        return true;
    }
    bRes = bDefault;
    return false;
}

bool NoSettings::FindUIntEntry(const NoString& name, uint& uRes, uint uDefault)
{
    NoString s;
    if (FindStringEntry(name, s)) {
        uRes = s.toUInt();
        return true;
    }
    uRes = uDefault;
    return false;
}

bool NoSettings::FindUShortEntry(const NoString& name, ushort& uRes, ushort uDefault)
{
    NoString s;
    if (FindStringEntry(name, s)) {
        uRes = s.toUShort();
        return true;
    }
    uRes = uDefault;
    return false;
}

bool NoSettings::FindDoubleEntry(const NoString& name, double& fRes, double fDefault)
{
    NoString s;
    if (FindStringEntry(name, s)) {
        fRes = s.toDouble();
        return true;
    }
    fRes = fDefault;
    return false;
}

bool NoSettings::FindSubConfig(const NoString& name, NoSettings::SubConfig& Config, bool bErase)
{
    SubConfigMap::iterator it = m_subConfigs.find(name);
    if (it == m_subConfigs.end()) {
        Config.clear();
        return false;
    }
    Config = it->second;

    if (bErase) {
        m_subConfigs.erase(it);
    }

    return true;
}

bool NoSettings::empty() const
{
    return m_entries.empty() && m_subConfigs.empty();
}

bool NoSettings::Parse(NoFile& file, NoString& sErrorMsg)
{
    NoString line;
    uint uLineNum = 0;
    NoSettings* pActiveConfig = this;
    std::stack<ConfigStackEntry> ConfigStack;
    bool bCommented = false; // support for /**/ style comments

    if (!file.Seek(0)) {
        sErrorMsg = "Could not seek to the beginning of the config.";
        return false;
    }

    while (file.ReadLine(line)) {
        uLineNum++;

#define ERROR(arg)                                             \
    do {                                                       \
        std::stringstream stream;                              \
        stream << "Error on line " << uLineNum << ": " << arg; \
        sErrorMsg = stream.str();                              \
        m_subConfigs.clear();                                  \
        m_entries.clear();                                     \
        return false;                                          \
    } while (0)

        // Remove all leading spaces and trailing line endings
        line.trimLeft();
        line.trimRight("\r\n");

        if (bCommented || line.left(2) == "/*") {
            /* Does this comment end on the same line again? */
            bCommented = (line.right(2) != "*/");

            continue;
        }

        if ((line.empty()) || (line[0] == '#') || (line.left(2) == "//")) {
            continue;
        }

        if ((line.left(1) == "<") && (line.right(1) == ">")) {
            line.leftChomp(1);
            line.rightChomp(1);
            line.trim();

            NoString sTag = No::token(line, 0);
            NoString value = No::tokens(line, 1);

            sTag.trim();
            value.trim();

            if (sTag.left(1) == "/") {
                sTag = sTag.substr(1);

                if (!value.empty())
                    ERROR("Malformated closing tag. Expected \"</" << sTag << ">\".");
                if (ConfigStack.empty())
                    ERROR("Closing tag \"" << sTag << "\" which is not open.");

                const struct ConfigStackEntry& entry = ConfigStack.top();
                NoSettings myConfig(entry.Config);
                NoString name(entry.name);

                if (!sTag.equals(entry.sTag))
                    ERROR("Closing tag \"" << sTag << "\" which is not open.");

                // This breaks entry
                ConfigStack.pop();

                if (ConfigStack.empty())
                    pActiveConfig = this;
                else
                    pActiveConfig = &ConfigStack.top().Config;

                SubConfig& conf = pActiveConfig->m_subConfigs[sTag.toLower()];
                SubConfig::const_iterator it = conf.find(name);

                if (it != conf.end())
                    ERROR("Duplicate entry for tag \"" << sTag << "\" name \"" << name << "\".");

                conf[name] = NoSettingsEntry(myConfig);
            } else {
                if (value.empty())
                    ERROR("Empty block name at begin of block.");
                ConfigStack.push(ConfigStackEntry(sTag.toLower(), value));
                pActiveConfig = &ConfigStack.top().Config;
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
        pActiveConfig->m_entries[sNameLower].push_back(value);
    }

    if (bCommented)
        ERROR("Comment not closed at end of file.");

    if (!ConfigStack.empty()) {
        const NoString& sTag = ConfigStack.top().sTag;
        ERROR("Not all tags are closed at the end of the file. Inner-most open tag is \"" << sTag << "\".");
    }

    return true;
}

void NoSettings::Write(NoFile& File, uint iIndentation)
{
    NoString sIndentation = NoString(iIndentation, '\t');

    for (const auto& it : m_entries) {
        for (const NoString& value : it.second) {
            File.Write(sIndentation + it.first + " = " + value + "\n");
        }
    }

    for (const auto& it : m_subConfigs) {
        for (const auto& it2 : it.second) {
            File.Write("\n");

            File.Write(sIndentation + "<" + it.first + " " + it2.first + ">\n");
            it2.second.m_subConfig->Write(File, iIndentation + 1);
            File.Write(sIndentation + "</" + it.first + ">\n");
        }
    }
}
