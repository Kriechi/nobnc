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

#ifndef NODIR_H
#define NODIR_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <no/nofile.h>

class NO_EXPORT NoDir : public std::vector<NoFile*>
{
public:
    NoDir(const NoString& sDir = "");
    ~NoDir();

    void CleanUp();

    size_t Fill(const NoString& sDir);

    size_t FillByWildcard(const NoString& sDir, const NoString& sWildcard);

    static uint Chmod(mode_t mode, const NoString& sWildcard, const NoString& sDir = ".");

    uint Chmod(mode_t mode);

    static uint Delete(const NoString& sWildcard, const NoString& sDir = ".");

    uint Delete();

    NoFile::Attribute GetSortAttr() const;
    bool IsDescending() const;

    // Check if sPath + "/" + sAdd (~/ is handled) is an absolute path which
    // resides under sPath. Returns absolute path on success, else "".
    static NoString CheckPathPrefix(const NoString& sPath, const NoString& sAdd, const NoString& sHomeDir = "");
    static NoString ChangeDir(const NoString& sPath, const NoString& sAdd, const NoString& sHomeDir = "");
    static bool MakeDir(const NoString& sPath, mode_t iMode = 0700);

    static NoString GetCWD();

private:
    NoFile::Attribute m_sort;
    bool m_desc;
};

#endif // NODIR_H
