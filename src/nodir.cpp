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

#include "nodir.h"
#include "nofile.h"
#include "noutils.h"
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

class NoDirPrivate
{
public:
    ~NoDirPrivate();

    void init();

    NoString path;
    mutable std::vector<NoFile*> files;
};

NoDirPrivate::~NoDirPrivate()
{
    for (NoFile* file : files)
        delete file;
    files.clear();
}

void NoDirPrivate::init()
{
    if (!files.empty())
        return;

    DIR* dir = opendir(path.empty() ? "." : path.c_str());
    if (!dir)
        return;

    dirent* de;
    while ((de = readdir(dir)) != nullptr) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        NoFile* file = new NoFile(path.trimSuffix_n("/") + "/" +
                                  de->d_name /*, this*/); // @todo need to pass pointer to 'this' if we want to do Sort()
        files.push_back(file);
    }

    closedir(dir);
}

NoDir::NoDir(const NoString& path) : d(new NoDirPrivate)
{
    d->path = path;
}

NoDir::~NoDir()
{
}

static NoString no_home()
{
    static NoString path;
    if (path.empty()) {
        const char* env = getenv("HOME");
        if (env)
            path = env;

        if (path.empty()) {
            const passwd* info = getpwuid(getuid());
            if (info)
                path = info->pw_dir;
        }

        if (path.empty())
            return "./";
    }
    return path;
}

NoDir NoDir::home()
{
    static NoDir dir(no_home());
    return dir;
}

static NoString no_cwd()
{
    static NoString path;
    if (path.empty()) {
        char* cwd = getcwd(nullptr, 0);
        if (cwd) {
            path = cwd;
            free(cwd);
        }
    }
    return path;
}

NoDir NoDir::current()
{
    static NoDir dir(no_cwd());
    return dir;
}

std::vector<NoFile*> NoDir::files(const NoString& wildcard) const
{
    const_cast<NoDir*>(this)->d->init();

    if (wildcard.empty() || wildcard.equals("*"))
        return d->files;

    std::vector<NoFile*> files;
    for (NoFile* file : d->files) {
        if (No::wildCmp(file->GetShortName(), wildcard))
            files.push_back(file);
    }
    return files;
}

bool NoDir::mkpath(const NoString& path, mode_t mode)
{
    if (path.empty()) {
        errno = ENOENT;
        return false;
    }

    NoString fullPath;
    if (path.startsWith("/"))
        fullPath = "/";

    for (const NoString& part : path.split("/", No::SkipEmptyParts)) {
        fullPath += part;

        int i = mkdir(fullPath.c_str(), mode);
        if (i != 0 && (errno != EEXIST || !NoFile(fullPath).IsDir()))
            return false;

        fullPath += "/";
    }
    return true;
}

uint NoDir::remove()
{
    d->init();

    uint count = 0;
    for (NoFile* file : d->files) {
        if (file->Delete())
            ++count;
    }
    return count;
}

uint NoDir::chmod(mode_t mode)
{
    d->init();

    uint count = 0;
    for (NoFile* file : d->files) {
        if (file->Chmod(mode))
            ++count;
    }
    return count;
}

bool NoDir::isParent(const NoString& filePath) const
{
    NoString prefix = d->path.replace_n("//", "/").trimRight_n("/") + "/";
    NoString absolutePath = NoDir(prefix).filePath(filePath);
    return absolutePath.startsWith(prefix);
}

NoString NoDir::filePath(const NoString& fileName) const
{
    if (fileName == "~")
        return no_home();

    NoString filePath = fileName;
    if (filePath.startsWith("~/")) {
        filePath.leftChomp(1);
        filePath = no_home() + fileName;
    }

    NoString ret = "";
    if (filePath.empty() || !filePath.startsWith("/"))
        ret = d->path;

    filePath += "/";

    if (ret.endsWith("/"))
        ret.rightChomp(1);

    NoString tmp;
    for (char c : filePath) {
        switch (c) {
        case '/':
            if (tmp == "..")
                ret = ret.substr(0, ret.rfind('/'));
            else if (tmp != "" && tmp != ".")
                ret += "/" + tmp;
            tmp = "";
            break;

        default:
            tmp += c;
            break;
        }
    }

    return ret.empty() ? "/" : ret;
}
