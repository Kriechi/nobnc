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

#ifndef NOTABLE_H
#define NOTABLE_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
#include <memory>

class NoTablePrivate;

class NO_EXPORT NoTable
{
public:
    explicit NoTable(ulong preferredWidth = 110);
    NoTable(const NoTable& other);
    NoTable& operator=(const NoTable& other);
    ~NoTable();

    bool addColumn(const NoString& name, bool wrap = true);
    void addRow();
    bool setValue(const NoString& column, const NoString& value);
    NoStringVector toString() const;
    void clear();
    uint size() const;
    bool isEmpty() const;

private:
    std::shared_ptr<NoTablePrivate> d;
};

#endif // NOTABLE_H
