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

#include "noregistry.h"
#include "nomodule.h"
#include "noutils.h"
#include "nofile.h"
#include "nodir.h"

class NoRegistryPrivate
{
public:
    NoRegistryPrivate(const NoModule* module) : module(module) { }
    NoStringMap registry;
    const NoModule* module;
    bool dirty = false;
};

NoRegistry::NoRegistry(const NoModule* module) : d(new NoRegistryPrivate(module))
{
    d->module = module;
    load();
}

NoRegistry::~NoRegistry()
{
    if (d->dirty)
        save();
}

NoString NoRegistry::filePath() const
{
    return d->module->savePath() + "/.registry";
}

const NoModule* NoRegistry::module() const
{
    return d->module;
}

bool NoRegistry::load()
{
    d->dirty = No::readFromDisk(d->registry, filePath()) != No::MCS_SUCCESS;
    return !d->dirty;
}

bool NoRegistry::save()
{
    d->dirty = No::writeToDisk(d->registry, filePath(), 0600) != No::MCS_SUCCESS;
    return !d->dirty;
}

bool NoRegistry::copy(const NoString& path)
{
    NoString oldPath = d->module->savePath();
    if (oldPath != path) {
        NoFile file(oldPath + "/.registry");
        if (!file.Exists() || (!NoFile::Exists(path) && !NoDir::mkpath(path)))
            return false;
        return file.Copy(path + "/.registry");
    }
    return false;
}

bool NoRegistry::isEmpty() const
{
    return d->registry.empty();
}

NoStringVector NoRegistry::keys() const
{
    NoStringVector keys;
    keys.reserve(d->registry.size());
    for (const auto& it : d->registry)
        keys.push_back(it.first);
    return keys;
}

bool NoRegistry::contains(const NoString& key) const
{
    return d->registry.find(key) != d->registry.end();
}

NoString NoRegistry::value(const NoString& key) const
{
    auto it = d->registry.find(key);
    if (it != d->registry.end())
        return it->second;
    return "";
}

void NoRegistry::setValue(const NoString& key, const NoString& value)
{
    if (!d->dirty)
        d->dirty = d->registry[key] != value;
    d->registry[key] = value;
}

void NoRegistry::remove(const NoString& key)
{
    if (!d->dirty)
        d->dirty = d->registry.count(key);
    d->registry.erase(key);
}

void NoRegistry::clear()
{
    if (!d->dirty)
        d->dirty = !d->registry.empty();
    d->registry.clear();
}
