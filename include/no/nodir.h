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

#include <no/noconfig.h>
#include <no/nostring.h>
#include <no/nofile.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

class NoDir : public std::vector<NoFile*>
{
public:
    NoDir(const NoString& sDir) : m_eSortAttr(NoFile::FA_Name), m_bDesc(false) { Fill(sDir); }

    NoDir() : m_eSortAttr(NoFile::FA_Name), m_bDesc(false) {}

    ~NoDir() { CleanUp(); }

    void CleanUp()
    {
        for (unsigned int a = 0; a < size(); a++) {
            delete (*this)[a];
        }

        clear();
    }

    size_t Fill(const NoString& sDir) { return FillByWildcard(sDir, "*"); }

    size_t FillByWildcard(const NoString& sDir, const NoString& sWildcard)
    {
        CleanUp();
        DIR* dir = opendir((sDir.empty()) ? "." : sDir.c_str());

        if (!dir) {
            return 0;
        }

        struct dirent* de;

        while ((de = readdir(dir)) != nullptr) {
            if ((strcmp(de->d_name, ".") == 0) || (strcmp(de->d_name, "..") == 0)) {
                continue;
            }
            if ((!sWildcard.empty()) && (!NoString(de->d_name).WildCmp(sWildcard))) {
                continue;
            }

            NoFile* file =
            new NoFile(sDir.TrimSuffix_n("/") + "/" +
                      de->d_name /*, this*/); // @todo need to pass pointer to 'this' if we want to do Sort()
            push_back(file);
        }

        closedir(dir);
        return size();
    }

    static unsigned int Chmod(mode_t mode, const NoString& sWildcard, const NoString& sDir = ".")
    {
        NoDir cDir;
        cDir.FillByWildcard(sDir, sWildcard);
        return cDir.Chmod(mode);
    }

    unsigned int Chmod(mode_t mode)
    {
        unsigned int uRet = 0;
        for (unsigned int a = 0; a < size(); a++) {
            if ((*this)[a]->Chmod(mode)) {
                uRet++;
            }
        }

        return uRet;
    }

    static unsigned int Delete(const NoString& sWildcard, const NoString& sDir = ".")
    {
        NoDir cDir;
        cDir.FillByWildcard(sDir, sWildcard);
        return cDir.Delete();
    }

    unsigned int Delete()
    {
        unsigned int uRet = 0;
        for (unsigned int a = 0; a < size(); a++) {
            if ((*this)[a]->Delete()) {
                uRet++;
            }
        }

        return uRet;
    }

    NoFile::EFileAttr GetSortAttr() const { return m_eSortAttr; }
    bool IsDescending() const { return m_bDesc; }

    // Check if sPath + "/" + sAdd (~/ is handled) is an absolute path which
    // resides under sPath. Returns absolute path on success, else "".
    static NoString CheckPathPrefix(const NoString& sPath, const NoString& sAdd, const NoString& sHomeDir = "");
    static NoString ChangeDir(const NoString& sPath, const NoString& sAdd, const NoString& sHomeDir = "");
    static bool MakeDir(const NoString& sPath, mode_t iMode = 0700);

    static NoString GetCWD()
    {
        NoString sRet;
        char* pszCurDir = getcwd(nullptr, 0);
        if (pszCurDir) {
            sRet = pszCurDir;
            free(pszCurDir);
        }

        return sRet;
    }

private:
    NoFile::EFileAttr m_eSortAttr;
    bool m_bDesc;
};

#endif // NODIR_H
