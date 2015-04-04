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

#ifndef NOHOSTMASK_H
#define NOHOSTMASK_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
#include <memory>

class NoHostMaskPrivate;

class NO_EXPORT NoHostMask
{
public:
    NoHostMask(const NoString& mask = "");
    NoHostMask(const NoHostMask& other);
    NoHostMask& operator=(const NoHostMask& other);
    ~NoHostMask();

    bool isNull() const;
    bool isValid() const;
    NoString toString() const;

    NoString nick() const;
    void setNick(const NoString& nick);

    NoString ident() const;
    void setIdent(const NoString& ident);

    NoString host() const;
    void setHost(const NoString& host);

private:
    std::shared_ptr<NoHostMaskPrivate> d;
};

#endif // NOHOSTMASK_H
