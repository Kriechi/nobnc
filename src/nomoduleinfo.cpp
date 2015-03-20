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

#include "nomoduleinfo.h"

NoModuleInfo::NoModuleInfo() : NoModuleInfo("", "", No::NetworkModule) {}

NoModuleInfo::NoModuleInfo(const NoString& sName, const NoString& sPath, No::ModuleType eType)
    : m_seType(), m_eDefaultType(eType), m_sName(sName), m_sPath(sPath), m_sDescription(""), m_sWikiPage(""),
      m_sArgsHelpText(""), m_bHasArgs(false), m_fLoader(nullptr)
{
}

bool NoModuleInfo::operator<(const NoModuleInfo& Info) const { return (GetName() < Info.GetName()); }

bool NoModuleInfo::SupportsType(No::ModuleType eType) const { return m_seType.find(eType) != m_seType.end(); }

void NoModuleInfo::AddType(No::ModuleType eType) { m_seType.insert(eType); }

NoString NoModuleInfo::ModuleTypeToString(No::ModuleType eType)
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

const NoString& NoModuleInfo::GetName() const { return m_sName; }

const NoString& NoModuleInfo::GetPath() const { return m_sPath; }

const NoString& NoModuleInfo::GetDescription() const { return m_sDescription; }

const NoString& NoModuleInfo::GetWikiPage() const { return m_sWikiPage; }

const NoString& NoModuleInfo::GetArgsHelpText() const { return m_sArgsHelpText; }

bool NoModuleInfo::GetHasArgs() const { return m_bHasArgs; }

NoModuleInfo::NoModuleLoader NoModuleInfo::GetLoader() const { return m_fLoader; }

No::ModuleType NoModuleInfo::GetDefaultType() const { return m_eDefaultType; }

void NoModuleInfo::SetName(const NoString& s) { m_sName = s; }

void NoModuleInfo::SetPath(const NoString& s) { m_sPath = s; }

void NoModuleInfo::SetDescription(const NoString& s) { m_sDescription = s; }

void NoModuleInfo::SetWikiPage(const NoString& s) { m_sWikiPage = s; }

void NoModuleInfo::SetArgsHelpText(const NoString& s) { m_sArgsHelpText = s; }

void NoModuleInfo::SetHasArgs(bool b) { m_bHasArgs = b; }

void NoModuleInfo::SetLoader(NoModuleInfo::NoModuleLoader fLoader) { m_fLoader = fLoader; }

void NoModuleInfo::SetDefaultType(No::ModuleType eType) { m_eDefaultType = eType; }
