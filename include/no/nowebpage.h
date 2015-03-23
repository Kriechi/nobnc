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

#ifndef NOWEBPAGE_H
#define NOWEBPAGE_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <memory>

class NoWebPagePrivate;

class NO_EXPORT NoWebPage
{
public:
    NoWebPage(const NoString& name);
    ~NoWebPage();

    enum Flags { Admin = 1 };

    uint flags() const;
    void setFlags(uint flags);

    NoString name() const;
    void setName(const NoString& name);

    NoString title() const;
    void setTitle(const NoString& title);

    NoStringPairVector params() const;
    void addParam(const NoString& name, const NoString& value);
    void removeParam(const NoString& name, const NoString& value);

private:
    NoWebPage(const NoWebPage& other) = delete;
    NoWebPage& operator=(const NoWebPage& other) = delete;
    std::unique_ptr<NoWebPagePrivate> d;
};

#endif // NOWEBPAGE_H
