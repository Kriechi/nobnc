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

#ifndef NOREGISTRY_H
#define NOREGISTRY_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
#include <memory>

class NoModule;
class NoRegistryPrivate;

class NO_EXPORT NoRegistry
{
public:
    NoRegistry(const NoModule* module);
    ~NoRegistry();

    NoString filePath() const;
    const NoModule* module() const;

    bool load();
    bool save();
    bool copy(const NoString& path);

    bool isEmpty() const;
    NoStringVector keys() const;
    bool contains(const NoString& key) const;

    NoString value(const NoString& key) const;
    void setValue(const NoString& key, const NoString& value);
    void remove(const NoString& key);
    void clear();

private:
    NoRegistry(const NoRegistry&) = delete;
    NoRegistry& operator=(const NoRegistry&) = delete;
    std::unique_ptr<NoRegistryPrivate> d;
    friend class NoRegistryPrivate;
};

#endif // NOREGISTRY_H
