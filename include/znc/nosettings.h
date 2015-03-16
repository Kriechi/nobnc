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

#ifndef NOSETTINGS_H
#define NOSETTINGS_H

#include <znc/noconfig.h>
#include <znc/nostring.h>

class NoFile;
class NoSettings;

struct NoSettingsEntry
{
    NoSettingsEntry();
    NoSettingsEntry(const NoSettings& Config);
    NoSettingsEntry(const NoSettingsEntry& other);
    ~NoSettingsEntry();
    NoSettingsEntry& operator=(const NoSettingsEntry& other);

    NoSettings* m_pSubConfig;
};

class NoSettings
{
public:
    NoSettings() : m_ConfigEntries(), m_SubConfigs() {}

    typedef std::map<NoString, NoStringVector> EntryMap;
    typedef std::map<NoString, NoSettingsEntry> SubConfig;
    typedef std::map<NoString, SubConfig> SubConfigMap;

    typedef EntryMap::const_iterator EntryMapIterator;
    typedef SubConfigMap::const_iterator SubConfigMapIterator;

    EntryMapIterator BeginEntries() const { return m_ConfigEntries.begin(); }
    EntryMapIterator EndEntries() const { return m_ConfigEntries.end(); }

    SubConfigMapIterator BeginSubConfigs() const { return m_SubConfigs.begin(); }
    SubConfigMapIterator EndSubConfigs() const { return m_SubConfigs.end(); }

    void AddKeyValuePair(const NoString& sName, const NoString& sValue)
    {
        if (sName.empty() || sValue.empty()) {
            return;
        }

        m_ConfigEntries[sName].push_back(sValue);
    }

    bool AddSubConfig(const NoString& sTag, const NoString& sName, NoSettings Config)
    {
        SubConfig& conf = m_SubConfigs[sTag];
        SubConfig::const_iterator it = conf.find(sName);

        if (it != conf.end()) {
            return false;
        }

        conf[sName] = Config;
        return true;
    }

    bool FindStringVector(const NoString& sName, NoStringVector& vsList, bool bErase = true)
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

    bool FindStringEntry(const NoString& sName, NoString& sRes, const NoString& sDefault = "")
    {
        EntryMap::iterator it = m_ConfigEntries.find(sName);
        sRes = sDefault;
        if (it == m_ConfigEntries.end() || it->second.empty()) return false;
        sRes = it->second.front();
        it->second.erase(it->second.begin());
        if (it->second.empty()) m_ConfigEntries.erase(it);
        return true;
    }

    bool FindBoolEntry(const NoString& sName, bool& bRes, bool bDefault = false)
    {
        NoString s;
        if (FindStringEntry(sName, s)) {
            bRes = s.ToBool();
            return true;
        }
        bRes = bDefault;
        return false;
    }

    bool FindUIntEntry(const NoString& sName, unsigned int& uRes, unsigned int uDefault = 0)
    {
        NoString s;
        if (FindStringEntry(sName, s)) {
            uRes = s.ToUInt();
            return true;
        }
        uRes = uDefault;
        return false;
    }

    bool FindUShortEntry(const NoString& sName, unsigned short& uRes, unsigned short uDefault = 0)
    {
        NoString s;
        if (FindStringEntry(sName, s)) {
            uRes = s.ToUShort();
            return true;
        }
        uRes = uDefault;
        return false;
    }

    bool FindDoubleEntry(const NoString& sName, double& fRes, double fDefault = 0)
    {
        NoString s;
        if (FindStringEntry(sName, s)) {
            fRes = s.ToDouble();
            return true;
        }
        fRes = fDefault;
        return false;
    }

    bool FindSubConfig(const NoString& sName, SubConfig& Config, bool bErase = true)
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

    bool empty() const { return m_ConfigEntries.empty() && m_SubConfigs.empty(); }

    bool Parse(NoFile& file, NoString& sErrorMsg);
    void Write(NoFile& file, unsigned int iIndentation = 0);

private:
    EntryMap m_ConfigEntries;
    SubConfigMap m_SubConfigs;
};

#endif // NOSETTINGS_H
