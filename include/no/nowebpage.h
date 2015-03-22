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
    NoWebPage(const NoString& sName, const NoString& sTitle = "", uint uFlags = 0);
    NoWebPage(const NoString& sName, const NoString& sTitle, const NoStringPairVector& vParams, uint uFlags = 0);

    enum { Admin = 1 };

    void SetName(const NoString& s);
    void SetTitle(const NoString& s);
    void AddParam(const NoString& sName, const NoString& sValue);

    bool RequiresAdmin() const;

    const NoString& GetName() const;
    const NoString& GetTitle() const;
    const NoStringPairVector& GetParams() const;

private:
    uint m_flags;
    NoString m_name;
    NoString m_title;
    NoStringPairVector m_params;
};

#endif // NOWEBPAGE_H
