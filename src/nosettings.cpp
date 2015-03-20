/*
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
    NoString sName;
    NoSettings Config;

    ConfigStackEntry(const NoString& Tag, const NoString Name) : sTag(Tag), sName(Name), Config() {}
};

NoSettingsEntry::NoSettingsEntry() : m_pSubConfig(nullptr) {}

NoSettingsEntry::NoSettingsEntry(const NoSettings& Config) : m_pSubConfig(new NoSettings(Config)) {}

NoSettingsEntry::NoSettingsEntry(const NoSettingsEntry& other) : m_pSubConfig(nullptr)
{
    if (other.m_pSubConfig) m_pSubConfig = new NoSettings(*other.m_pSubConfig);
}

NoSettingsEntry::~NoSettingsEntry() { delete m_pSubConfig; }

NoSettingsEntry& NoSettingsEntry::operator=(const NoSettingsEntry& other)
{
    delete m_pSubConfig;
    if (other.m_pSubConfig)
        m_pSubConfig = new NoSettings(*other.m_pSubConfig);
    else
        m_pSubConfig = nullptr;
    return *this;
}

NoSettings::NoSettings() : m_ConfigEntries(), m_SubConfigs() {}

NoSettings::EntryMapIterator NoSettings::BeginEntries() const { return m_ConfigEntries.begin(); }

NoSettings::EntryMapIterator NoSettings::EndEntries() const { return m_ConfigEntries.end(); }

NoSettings::SubConfigMapIterator NoSettings::BeginSubConfigs() const { return m_SubConfigs.begin(); }

NoSettings::SubConfigMapIterator NoSettings::EndSubConfigs() const { return m_SubConfigs.end(); }

void NoSettings::AddKeyValuePair(const NoString& sName, const NoString& sValue)
{
    if (sName.empty() || sValue.empty()) {
        return;
    }

    m_ConfigEntries[sName].push_back(sValue);
}

bool NoSettings::AddSubConfig(const NoString& sTag, const NoString& sName, NoSettings Config)
{
    SubConfig& conf = m_SubConfigs[sTag];
    SubConfig::const_iterator it = conf.find(sName);

    if (it != conf.end()) {
        return false;
    }

    conf[sName] = Config;
    return true;
}

bool NoSettings::FindStringVector(const NoString& sName, NoStringVector& vsList, bool bErase)
{
    EntryMap::iterator it = m_ConfigEntries.find(sName);
    vsList.clear();
    if (it == m_ConfigEntries.end()) return false;
    vsList = it->second;

    if (bErase) {
        m_ConfigEntries.erase(it);
    }

    return true;
}

bool NoSettings::FindStringEntry(const NoString& sName, NoString& sRes, const NoString& sDefault)
{
    EntryMap::iterator it = m_ConfigEntries.find(sName);
    sRes = sDefault;
    if (it == m_ConfigEntries.end() || it->second.empty()) return false;
    sRes = it->second.front();
    it->second.erase(it->second.begin());
    if (it->second.empty()) m_ConfigEntries.erase(it);
    return true;
}

bool NoSettings::FindBoolEntry(const NoString& sName, bool& bRes, bool bDefault)
{
    NoString s;
    if (FindStringEntry(sName, s)) {
        bRes = s.toBool();
        return true;
    }
    bRes = bDefault;
    return false;
}

bool NoSettings::FindUIntEntry(const NoString& sName, uint& uRes, uint uDefault)
{
    NoString s;
    if (FindStringEntry(sName, s)) {
        uRes = s.toUInt();
        return true;
    }
    uRes = uDefault;
    return false;
}

bool NoSettings::FindUShortEntry(const NoString& sName, ushort& uRes, ushort uDefault)
{
    NoString s;
    if (FindStringEntry(sName, s)) {
        uRes = s.toUShort();
        return true;
    }
    uRes = uDefault;
    return false;
}

bool NoSettings::FindDoubleEntry(const NoString& sName, double& fRes, double fDefault)
{
    NoString s;
    if (FindStringEntry(sName, s)) {
        fRes = s.toDouble();
        return true;
    }
    fRes = fDefault;
    return false;
}

bool NoSettings::FindSubConfig(const NoString& sName, NoSettings::SubConfig& Config, bool bErase)
{
    SubConfigMap::iterator it = m_SubConfigs.find(sName);
    if (it == m_SubConfigs.end()) {
        Config.clear();
        return false;
    }
    Config = it->second;

    if (bErase) {
        m_SubConfigs.erase(it);
    }

    return true;
}

bool NoSettings::empty() const { return m_ConfigEntries.empty() && m_SubConfigs.empty(); }

bool NoSettings::Parse(NoFile& file, NoString& sErrorMsg)
{
    NoString sLine;
    uint uLineNum = 0;
    NoSettings* pActiveConfig = this;
    std::stack<ConfigStackEntry> ConfigStack;
    bool bCommented = false; // support for /**/ style comments

    if (!file.Seek(0)) {
        sErrorMsg = "Could not seek to the beginning of the config.";
        return false;
    }

    while (file.ReadLine(sLine)) {
        uLineNum++;

#define ERROR(arg)                                             \
    do {                                                       \
        std::stringstream stream;                              \
        stream << "Error on line " << uLineNum << ": " << arg; \
        sErrorMsg = stream.str();                              \
        m_SubConfigs.clear();                                  \
        m_ConfigEntries.clear();                               \
        return false;                                          \
    } while (0)

        // Remove all leading spaces and trailing line endings
        sLine.trimLeft();
        sLine.trimRight("\r\n");

        if (bCommented || sLine.left(2) == "/*") {
            /* Does this comment end on the same line again? */
            bCommented = (sLine.right(2) != "*/");

            continue;
        }

        if ((sLine.empty()) || (sLine[0] == '#') || (sLine.left(2) == "//")) {
            continue;
        }

        if ((sLine.left(1) == "<") && (sLine.right(1) == ">")) {
            sLine.leftChomp(1);
            sLine.rightChomp(1);
            sLine.trim();

            NoString sTag = No::token(sLine, 0);
            NoString sValue = No::tokens(sLine, 1);

            sTag.trim();
            sValue.trim();

            if (sTag.left(1) == "/") {
                sTag = sTag.substr(1);

                if (!sValue.empty()) ERROR("Malformated closing tag. Expected \"</" << sTag << ">\".");
                if (ConfigStack.empty()) ERROR("Closing tag \"" << sTag << "\" which is not open.");

                const struct ConfigStackEntry& entry = ConfigStack.top();
                NoSettings myConfig(entry.Config);
                NoString sName(entry.sName);

                if (!sTag.equals(entry.sTag)) ERROR("Closing tag \"" << sTag << "\" which is not open.");

                // This breaks entry
                ConfigStack.pop();

                if (ConfigStack.empty())
                    pActiveConfig = this;
                else
                    pActiveConfig = &ConfigStack.top().Config;

                SubConfig& conf = pActiveConfig->m_SubConfigs[sTag.toLower()];
                SubConfig::const_iterator it = conf.find(sName);

                if (it != conf.end()) ERROR("Duplicate entry for tag \"" << sTag << "\" name \"" << sName << "\".");

                conf[sName] = NoSettingsEntry(myConfig);
            } else {
                if (sValue.empty()) ERROR("Empty block name at begin of block.");
                ConfigStack.push(ConfigStackEntry(sTag.toLower(), sValue));
                pActiveConfig = &ConfigStack.top().Config;
            }

            continue;
        }

        // If we have a regular line, figure out where it goes
        NoString sName = No::token(sLine, 0, "=");
        NoString sValue = No::tokens(sLine, 1, "=");

        // Only remove the first space, people might want
        // leading spaces (e.g. in the MOTD).
        if (sValue.left(1) == " ") sValue.leftChomp(1);

        // We don't have any names with spaces, trim all
        // leading/trailing spaces.
        sName.trim();

        if (sName.empty() || sValue.empty()) ERROR("Malformed line");

        NoString sNameLower = sName.toLower();
        pActiveConfig->m_ConfigEntries[sNameLower].push_back(sValue);
    }

    if (bCommented) ERROR("Comment not closed at end of file.");

    if (!ConfigStack.empty()) {
        const NoString& sTag = ConfigStack.top().sTag;
        ERROR("Not all tags are closed at the end of the file. Inner-most open tag is \"" << sTag << "\".");
    }

    return true;
}

void NoSettings::Write(NoFile& File, uint iIndentation)
{
    NoString sIndentation = NoString(iIndentation, '\t');

    for (const auto& it : m_ConfigEntries) {
        for (const NoString& sValue : it.second) {
            File.Write(sIndentation + it.first + " = " + sValue + "\n");
        }
    }

    for (const auto& it : m_SubConfigs) {
        for (const auto& it2 : it.second) {
            File.Write("\n");

            File.Write(sIndentation + "<" + it.first + " " + it2.first + ">\n");
            it2.second.m_pSubConfig->Write(File, iIndentation + 1);
            File.Write(sIndentation + "</" + it.first + ">\n");
        }
    }
}
