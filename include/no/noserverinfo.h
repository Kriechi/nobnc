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

#ifndef NOSERVERINFO_H
#define NOSERVERINFO_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <memory>

class NoServerInfoPrivate;

class NO_EXPORT NoServerInfo
{
public:
    NoServerInfo(const NoString& host = "", ushort port = 6667);
    NoServerInfo(const NoServerInfo& other);
    NoServerInfo& operator=(const NoServerInfo& other);
    ~NoServerInfo();

    bool isValid() const;

    NoString host() const;
    void setHost(const NoString& host);

    ushort port() const;
    void setPort(ushort port);

    NoString password() const;
    void setPassword(const NoString& password);

    bool isSsl() const;
    void setSsl(bool ssl);

    NoString toString() const;

private:
    std::shared_ptr<NoServerInfoPrivate> d;
};

#endif // NOSERVERINFO_H
