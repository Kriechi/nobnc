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

#ifndef NODIR_H
#define NODIR_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <memory>

class NoFile;
class NoDirPrivate;

class NO_EXPORT NoDir
{
public:
    NoDir(const NoString& path = ".");
    ~NoDir();

    static NoDir home();
    static NoDir current();

    std::vector<NoFile*> files(const NoString& wildcard = "*") const;

    static bool mkpath(const NoString& path, mode_t mode = 0700);

    uint remove();
    uint chmod(mode_t mode);

    NoString path() const;
    NoString filePath(const NoString& fileName) const;

    bool isParent(const NoString& filePath) const;

private:
    std::shared_ptr<NoDirPrivate> d;
};

#endif // NODIR_H
