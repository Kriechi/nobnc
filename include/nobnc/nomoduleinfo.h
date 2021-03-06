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

#ifndef NOMODULEINFO_H
#define NOMODULEINFO_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
#include <nobnc/nonamespace.h>

class NoUser;
class NoModule;
class NoNetwork;

typedef void* NoModuleHandle;

class NO_EXPORT NoModuleInfo
{
public:
    typedef NoModule* (*NoModuleLoader)(NoModuleHandle p,
                                        NoUser* user,
                                        NoNetwork* network,
                                        const NoString& name,
                                        const NoString& path,
                                        No::ModuleType type);

    NoModuleInfo();
    NoModuleInfo(const NoString& name, const NoString& path, No::ModuleType type);

    bool operator<(const NoModuleInfo& info) const;

    bool supportsType(No::ModuleType type) const;

    void addType(No::ModuleType type);

    static NoString moduleTypeToString(No::ModuleType type);

    NoString name() const;
    NoString path() const;
    NoString description() const;
    NoString wikiPage() const;
    NoString argsHelpText() const;
    bool hasArgs() const;
    NoModuleLoader loader() const;
    No::ModuleType defaultType() const;

    void setName(const NoString& s);
    void setPath(const NoString& s);
    void setDescription(const NoString& s);
    void setWikiPage(const NoString& s);
    void setArgsHelpText(const NoString& s);
    void setHasArgs(bool b = false);
    void setLoader(NoModuleLoader fLoader);
    void setDefaultType(No::ModuleType type);

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
NoModule*
no_loadModule(NoModuleHandle handle, NoUser* user, NoNetwork* network, const NoString& name, const NoString& path, No::ModuleType type)
{
    return new T(handle, user, network, name, path, type);
}

#endif // NOMODULEINFO_H
