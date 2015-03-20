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

NoModInfo::NoModInfo() : NoModInfo("", "", No::NetworkModule) {}

NoModInfo::NoModInfo(const NoString& sName, const NoString& sPath, No::ModuleType eType)
    : m_seType(), m_eDefaultType(eType), m_sName(sName), m_sPath(sPath), m_sDescription(""), m_sWikiPage(""),
      m_sArgsHelpText(""), m_bHasArgs(false), m_fLoader(nullptr)
{
}

bool NoModInfo::operator<(const NoModInfo& Info) const { return (GetName() < Info.GetName()); }

bool NoModInfo::SupportsType(No::ModuleType eType) const { return m_seType.find(eType) != m_seType.end(); }

void NoModInfo::AddType(No::ModuleType eType) { m_seType.insert(eType); }

NoString NoModInfo::ModuleTypeToString(No::ModuleType eType)
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

const NoString& NoModInfo::GetName() const { return m_sName; }

const NoString& NoModInfo::GetPath() const { return m_sPath; }

const NoString& NoModInfo::GetDescription() const { return m_sDescription; }

const NoString& NoModInfo::GetWikiPage() const { return m_sWikiPage; }

const NoString& NoModInfo::GetArgsHelpText() const { return m_sArgsHelpText; }

bool NoModInfo::GetHasArgs() const { return m_bHasArgs; }

NoModInfo::ModLoader NoModInfo::GetLoader() const { return m_fLoader; }

No::ModuleType NoModInfo::GetDefaultType() const { return m_eDefaultType; }

void NoModInfo::SetName(const NoString& s) { m_sName = s; }

void NoModInfo::SetPath(const NoString& s) { m_sPath = s; }

void NoModInfo::SetDescription(const NoString& s) { m_sDescription = s; }

void NoModInfo::SetWikiPage(const NoString& s) { m_sWikiPage = s; }

void NoModInfo::SetArgsHelpText(const NoString& s) { m_sArgsHelpText = s; }

void NoModInfo::SetHasArgs(bool b) { m_bHasArgs = b; }

void NoModInfo::SetLoader(NoModInfo::ModLoader fLoader) { m_fLoader = fLoader; }

void NoModInfo::SetDefaultType(No::ModuleType eType) { m_eDefaultType = eType; }
