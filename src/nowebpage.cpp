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

#include "nowebpage.h"

class NoWebPagePrivate
{
public:
    uint flags;
    NoString name;
    NoString title;
    NoStringPairVector params;
};

NoWebPage::NoWebPage(const NoString& sName, const NoString& sTitle, uint uFlags)
    : d(new NoWebPagePrivate)
{
    d->flags = uFlags;
    d->name = sName;
    d->title = sTitle;
}

NoWebPage::NoWebPage(const NoString& sName, const NoString& sTitle, const NoStringPairVector& vParams, uint uFlags)
    : d(new NoWebPagePrivate)
{
    d->flags = uFlags;
    d->name = sName;
    d->title = sTitle;
    d->params = vParams;
}

NoWebPage::~NoWebPage()
{
}

void NoWebPage::SetName(const NoString& s) { d->name = s; }

void NoWebPage::SetTitle(const NoString& s) { d->title = s; }

void NoWebPage::AddParam(const NoString& sName, const NoString& sValue) { d->params.push_back(make_pair(sName, sValue)); }

bool NoWebPage::RequiresAdmin() const { return d->flags & Admin; }

const NoString& NoWebPage::GetName() const { return d->name; }

const NoString& NoWebPage::GetTitle() const { return d->title; }

const NoStringPairVector& NoWebPage::GetParams() const { return d->params; }
