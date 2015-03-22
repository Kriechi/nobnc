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

#include "nowebpage.h"


NoWebPage::NoWebPage(const NoString& sName, const NoString& sTitle, uint uFlags)
    : m_flags(uFlags), m_name(sName), m_title(sTitle), m_params()
{
}

NoWebPage::NoWebPage(const NoString& sName, const NoString& sTitle, const NoStringPairVector& vParams, uint uFlags)
    : m_flags(uFlags), m_name(sName), m_title(sTitle), m_params(vParams)
{
}

void NoWebPage::SetName(const NoString& s) { m_name = s; }

void NoWebPage::SetTitle(const NoString& s) { m_title = s; }

void NoWebPage::AddParam(const NoString& sName, const NoString& sValue) { m_params.push_back(make_pair(sName, sValue)); }

bool NoWebPage::RequiresAdmin() const { return m_flags & Admin; }

const NoString& NoWebPage::GetName() const { return m_name; }

const NoString& NoWebPage::GetTitle() const { return m_title; }

const NoStringPairVector& NoWebPage::GetParams() const { return m_params; }
