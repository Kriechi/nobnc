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

#ifndef NOMODULEJOB_H
#define NOMODULEJOB_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <no/nojob.h>

#ifdef HAVE_PTHREAD

class NoModule;

/// A NoJob version which can be safely used in modules. The job will be
/// cancelled when the module is unloaded.
class NO_EXPORT NoModuleJob : public NoJob
{
public:
    NoModuleJob(NoModule* pModule, const NoString& sName, const NoString& sDesc);
    virtual ~NoModuleJob();

    NoModuleJob(const NoModuleJob&) = delete;
    NoModuleJob& operator=(const NoModuleJob&) = delete;

    NoModule* module() const;
    NoString name() const;
    NoString description() const;

private:
    NoModule* m_module;
    const NoString m_name;
    const NoString m_description;
};
#endif // HAVE_PTHREAD

#endif // NOMODULEJOB_H
