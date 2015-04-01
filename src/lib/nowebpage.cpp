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
    uint flags = 0;
    NoString name = "";
    NoString title = "";
    NoStringPairVector params;
};

NoWebPage::NoWebPage(const NoString& name) : d(new NoWebPagePrivate)
{
    d->name = name;
}

NoWebPage::~NoWebPage()
{
}

uint NoWebPage::flags() const
{
    return d->flags;
}
void NoWebPage::setFlags(uint flags)
{
    d->flags = flags;
}

NoString NoWebPage::name() const
{
    return d->name;
}
void NoWebPage::setName(const NoString& name)
{
    d->name = name;
}

NoString NoWebPage::title() const
{
    return d->title;
}
void NoWebPage::setTitle(const NoString& title)
{
    d->title = title;
}

NoStringPairVector NoWebPage::params() const
{
    return d->params;
}
void NoWebPage::addParam(const NoString& name, const NoString& value)
{
    d->params.push_back(make_pair(name, value));
}
void NoWebPage::removeParam(const NoString& name, const NoString& value)
{
    d->params.push_back(make_pair(name, value));
}
