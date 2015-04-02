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

#ifndef NONICK_H
#define NONICK_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
#include <memory>

class NoNetwork;
class NoNickPrivate;

class NO_EXPORT NoNick
{
public:
    NoNick(const NoString& mask = "");
    NoNick(const NoNick& other);
    NoNick& operator=(const NoNick& other);
    ~NoNick();

    bool isValid() const;
    bool equals(const NoString& nick) const;

    NoString nick() const;
    void setNick(const NoString& nick);

    NoString ident() const;
    void setIdent(const NoString& ident);

    NoString host() const;
    void setHost(const NoString& host);

    NoString nickMask() const;
    NoString hostMask() const;

    NoNetwork* network() const;
    void setNetwork(NoNetwork* network);

    uchar perm() const;
    NoString perms() const;
    bool hasPerm(uchar perm) const;
    void addPerm(uchar perm);
    void removePerm(uchar perm);

    void reset(); // TODO: still used from NoChannel...

private:
    std::shared_ptr<NoNickPrivate> d;
};

#endif // NONICK_H
