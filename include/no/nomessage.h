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

#ifndef NOMESSAGE_H
#define NOMESSAGE_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <sys/time.h>
#include <memory>

class NoClient;
class NoMessagePrivate;

class NO_EXPORT NoMessage
{
public:
    NoMessage(const NoString& format = "", const NoString& text = "", const timeval* ts = nullptr);
    NoMessage(const NoMessage& other);
    NoMessage& operator=(const NoMessage& other);
    ~NoMessage();

    NoString GetLine(const NoClient& client, const NoStringMap& params) const;

    NoString GetFormat() const;
    void SetFormat(const NoString& format);

    NoString GetText() const;
    void SetText(const NoString& text);

    timeval GetTime() const;
    void SetTime(const timeval& ts);

    void UpdateTime();

private:
    std::shared_ptr<NoMessagePrivate> d;
};

#endif // NOMESSAGE_H
