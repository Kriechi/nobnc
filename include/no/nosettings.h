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

#ifndef NOSETTINGS_H
#define NOSETTINGS_H

#include <no/noglobal.h>
#include <no/nostring.h>

class NoFile;
class NoSettings;

struct NO_EXPORT NoSettingsEntry
{
    NoSettingsEntry();
    NoSettingsEntry(const NoSettings& Config);
    NoSettingsEntry(const NoSettingsEntry& other);
    ~NoSettingsEntry();
    NoSettingsEntry& operator=(const NoSettingsEntry& other);

    NoSettings* m_subConfig;
};

class NO_EXPORT NoSettings
{
public:
    NoSettings();

    typedef std::map<NoString, NoStringVector> EntryMap;
    typedef std::map<NoString, NoSettingsEntry> SubConfig;
    typedef std::map<NoString, SubConfig> SubConfigMap;

    typedef EntryMap::const_iterator EntryMapIterator;
    typedef SubConfigMap::const_iterator SubConfigMapIterator;

    EntryMapIterator BeginEntries() const;
    EntryMapIterator EndEntries() const;

    SubConfigMapIterator BeginSubConfigs() const;
    SubConfigMapIterator EndSubConfigs() const;

    void AddKeyValuePair(const NoString& name, const NoString& value);

    bool AddSubConfig(const NoString& sTag, const NoString& name, NoSettings Config);

    bool FindStringVector(const NoString& name, NoStringVector& vsList, bool bErase = true);

    bool FindStringEntry(const NoString& name, NoString& sRes, const NoString& sDefault = "");

    bool FindBoolEntry(const NoString& name, bool& bRes, bool bDefault = false);

    bool FindUIntEntry(const NoString& name, uint& uRes, uint uDefault = 0);

    bool FindUShortEntry(const NoString& name, ushort& uRes, ushort uDefault = 0);

    bool FindDoubleEntry(const NoString& name, double& fRes, double fDefault = 0);

    bool FindSubConfig(const NoString& name, SubConfig& Config, bool bErase = true);

    bool empty() const;

    bool Parse(NoFile& file, NoString& sErrorMsg);
    void Write(NoFile& file, uint iIndentation = 0);

private:
    EntryMap m_entries;
    SubConfigMap m_subConfigs;
};

#endif // NOSETTINGS_H
