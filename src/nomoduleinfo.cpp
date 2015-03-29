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

#include "nomoduleinfo.h"

NoModuleInfo::NoModuleInfo() : NoModuleInfo("", "", No::NetworkModule)
{
}

NoModuleInfo::NoModuleInfo(const NoString& sName, const NoString& sPath, No::ModuleType eType)
    : m_types(),
      m_defaultType(eType),
      m_name(sName),
      m_path(sPath),
      m_description(""),
      m_wikiPage(""),
      m_argsHelpText(""),
      m_hasArgs(false),
      m_loader(nullptr)
{
}

bool NoModuleInfo::operator<(const NoModuleInfo& Info) const
{
    return (name() < Info.name());
}

bool NoModuleInfo::supportsType(No::ModuleType eType) const
{
    return m_types.find(eType) != m_types.end();
}

void NoModuleInfo::addType(No::ModuleType eType)
{
    m_types.insert(eType);
}

NoString NoModuleInfo::moduleTypeToString(No::ModuleType eType)
{
    switch (eType) {
    case No::GlobalModule:
        return "Global";
    case No::UserModule:
        return "User";
    case No::NetworkModule:
        return "Network";
    default:
        return "UNKNOWN";
    }
}

NoString NoModuleInfo::name() const
{
    return m_name;
}

NoString NoModuleInfo::path() const
{
    return m_path;
}

NoString NoModuleInfo::description() const
{
    return m_description;
}

NoString NoModuleInfo::wikiPage() const
{
    return m_wikiPage;
}

NoString NoModuleInfo::argsHelpText() const
{
    return m_argsHelpText;
}

bool NoModuleInfo::hasArgs() const
{
    return m_hasArgs;
}

NoModuleInfo::NoModuleLoader NoModuleInfo::loader() const
{
    return m_loader;
}

No::ModuleType NoModuleInfo::defaultType() const
{
    return m_defaultType;
}

void NoModuleInfo::setName(const NoString& s)
{
    m_name = s;
}

void NoModuleInfo::setPath(const NoString& s)
{
    m_path = s;
}

void NoModuleInfo::setDescription(const NoString& s)
{
    m_description = s;
}

void NoModuleInfo::setWikiPage(const NoString& s)
{
    m_wikiPage = s;
}

void NoModuleInfo::setArgsHelpText(const NoString& s)
{
    m_argsHelpText = s;
}

void NoModuleInfo::setHasArgs(bool b)
{
    m_hasArgs = b;
}

void NoModuleInfo::setLoader(NoModuleInfo::NoModuleLoader fLoader)
{
    m_loader = fLoader;
}

void NoModuleInfo::setDefaultType(No::ModuleType eType)
{
    m_defaultType = eType;
}
