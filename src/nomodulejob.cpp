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

#include "nomodulejob.h"
#include "nomodule.h"

#ifdef HAVE_PTHREAD

NoModuleJob::NoModuleJob(NoModule* pModule, const NoString& sName, const NoString& sDesc)
    : NoJob(), m_module(pModule), m_name(sName), m_description(sDesc)
{
}

NoModuleJob::~NoModuleJob() { m_module->UnlinkJob(this); }

const NoString& NoModuleJob::GetDescription() const { return m_description; }

const NoString& NoModuleJob::GetName() const { return m_name; }

NoModule* NoModuleJob::GetModule() const { return m_module; }

#endif // HAVE_PTHREAD
