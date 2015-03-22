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

#ifndef NOMODULEINFO_H
#define NOMODULEINFO_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <no/nonamespace.h>

class NoUser;
class NoModule;
class NoNetwork;

typedef void* NoModuleHandle;

class NO_EXPORT NoModuleInfo
{
public:
    typedef NoModule* (*NoModuleLoader)(NoModuleHandle p, NoUser* pUser, NoNetwork* pNetwork, const NoString& sModName, const NoString& sModPath, No::ModuleType eType);

    NoModuleInfo();
    NoModuleInfo(const NoString& sName, const NoString& sPath, No::ModuleType eType);

    bool operator<(const NoModuleInfo& Info) const;

    bool SupportsType(No::ModuleType eType) const;

    void AddType(No::ModuleType eType);

    static NoString ModuleTypeToString(No::ModuleType eType);

    const NoString& GetName() const;
    const NoString& GetPath() const;
    const NoString& GetDescription() const;
    const NoString& GetWikiPage() const;
    const NoString& GetArgsHelpText() const;
    bool GetHasArgs() const;
    NoModuleLoader GetLoader() const;
    No::ModuleType GetDefaultType() const;

    void SetName(const NoString& s);
    void SetPath(const NoString& s);
    void SetDescription(const NoString& s);
    void SetWikiPage(const NoString& s);
    void SetArgsHelpText(const NoString& s);
    void SetHasArgs(bool b = false);
    void SetLoader(NoModuleLoader fLoader);
    void SetDefaultType(No::ModuleType eType);

private:
    std::set<No::ModuleType> m_types;
    No::ModuleType m_defaultType;
    NoString m_name;
    NoString m_path;
    NoString m_description;
    NoString m_wikiPage;
    NoString m_argsHelpText;
    bool m_hasArgs;
    NoModuleLoader m_loader;
};

template <class T>
void no_moduleInfo(NoModuleInfo& info)
{
}

template <class T>
NoModule* no_loadModule(NoModuleHandle handle, NoUser* user, NoNetwork* network, const NoString& name, const NoString& path, No::ModuleType type)
{
    return new T(handle, user, network, name, path, type);
}

#endif // NOMODULEINFO_H
