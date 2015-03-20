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

#ifndef NOWEBPAGE_H
#define NOWEBPAGE_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <memory>

class NoWebPage;
typedef std::shared_ptr<NoWebPage> TWebPage;
typedef std::vector<TWebPage> VWebPages;

class NO_EXPORT NoWebPage
{
public:
    NoWebPage(const NoString& sName, const NoString& sTitle = "", uint uFlags = 0)
        : m_uFlags(uFlags), m_sName(sName), m_sTitle(sTitle), m_vParams()
    {
    }

    NoWebPage(const NoString& sName, const NoString& sTitle, const NoStringPairVector& vParams, uint uFlags = 0)
        : m_uFlags(uFlags), m_sName(sName), m_sTitle(sTitle), m_vParams(vParams)
    {
    }

    enum { Admin = 1 };

    void SetName(const NoString& s) { m_sName = s; }
    void SetTitle(const NoString& s) { m_sTitle = s; }
    void AddParam(const NoString& sName, const NoString& sValue) { m_vParams.push_back(make_pair(sName, sValue)); }

    bool RequiresAdmin() const { return m_uFlags & Admin; }

    const NoString& GetName() const { return m_sName; }
    const NoString& GetTitle() const { return m_sTitle; }
    const NoStringPairVector& GetParams() const { return m_vParams; }

private:
    uint m_uFlags;
    NoString m_sName;
    NoString m_sTitle;
    NoStringPairVector m_vParams;
};

#endif // NOWEBPAGE_H
