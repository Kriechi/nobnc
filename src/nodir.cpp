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

#include "nodir.h"
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

NoString NoDir::ChangeDir(const NoString& sPath, const NoString& sAdd, const NoString& sHome)
{
    NoString sHomeDir(sHome);

    if (sHomeDir.empty()) {
        sHomeDir = NoFile::GetHomePath();
    }

    if (sAdd == "~") {
        return sHomeDir;
    }

    NoString sAddDir(sAdd);

    if (sAddDir.Left(2) == "~/") {
        sAddDir.LeftChomp(1);
        sAddDir = sHomeDir + sAddDir;
    }

    NoString sRet = ((sAddDir.size()) && (sAddDir[0] == '/')) ? "" : sPath;
    sAddDir += "/";
    NoString sCurDir;

    if (sRet.Right(1) == "/") {
        sRet.RightChomp(1);
    }

    for (uint a = 0; a < sAddDir.size(); a++) {
        switch (sAddDir[a]) {
        case '/':
            if (sCurDir == "..") {
                sRet = sRet.substr(0, sRet.rfind('/'));
            } else if ((sCurDir != "") && (sCurDir != ".")) {
                sRet += "/" + sCurDir;
            }

            sCurDir = "";
            break;
        default:
            sCurDir += sAddDir[a];
            break;
        }
    }

    return (sRet.empty()) ? "/" : sRet;
}

NoDir::NoDir(const NoString& sDir) : m_eSortAttr(NoFile::FA_Name), m_bDesc(false)
{
    if (!sDir.empty())
        Fill(sDir);
}

NoDir::~NoDir() { CleanUp(); }

void NoDir::CleanUp()
{
    for (uint a = 0; a < size(); a++) {
        delete (*this)[a];
    }

    clear();
}

size_t NoDir::Fill(const NoString& sDir) { return FillByWildcard(sDir, "*"); }

size_t NoDir::FillByWildcard(const NoString& sDir, const NoString& sWildcard)
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

uint NoDir::Chmod(mode_t mode, const NoString& sWildcard, const NoString& sDir)
{
    NoDir cDir;
    cDir.FillByWildcard(sDir, sWildcard);
    return cDir.Chmod(mode);
}

uint NoDir::Chmod(mode_t mode)
{
    uint uRet = 0;
    for (uint a = 0; a < size(); a++) {
        if ((*this)[a]->Chmod(mode)) {
            uRet++;
        }
    }

    return uRet;
}

uint NoDir::Delete(const NoString& sWildcard, const NoString& sDir)
{
    NoDir cDir;
    cDir.FillByWildcard(sDir, sWildcard);
    return cDir.Delete();
}

uint NoDir::Delete()
{
    uint uRet = 0;
    for (uint a = 0; a < size(); a++) {
        if ((*this)[a]->Delete()) {
            uRet++;
        }
    }

    return uRet;
}

NoFile::EFileAttr NoDir::GetSortAttr() const { return m_eSortAttr; }

bool NoDir::IsDescending() const { return m_bDesc; }

NoString NoDir::CheckPathPrefix(const NoString& sPath, const NoString& sAdd, const NoString& sHomeDir)
{
    NoString sPrefix = sPath.Replace_n("//", "/").TrimRight_n("/") + "/";
    NoString sAbsolutePath = ChangeDir(sPrefix, sAdd, sHomeDir);

    if (sAbsolutePath.Left(sPrefix.length()) != sPrefix) return "";
    return sAbsolutePath;
}

bool NoDir::MakeDir(const NoString& sPath, mode_t iMode)
{
    NoString sDir;
    NoStringVector::iterator it;

    // Just in case someone tries this...
    if (sPath.empty()) {
        errno = ENOENT;
        return false;
    }

    // If this is an absolute path, we need to handle this now!
    if (sPath.Left(1) == "/") sDir = "/";

    // For every single subpath, do...
    NoStringVector dirs = sPath.Split("/", No::SkipEmptyParts);
    for (it = dirs.begin(); it != dirs.end(); ++it) {
        // Add this to the path we already created
        sDir += *it;

        int i = mkdir(sDir.c_str(), iMode);

        if (i != 0) {
            // All errors except EEXIST are fatal
            if (errno != EEXIST) return false;

            // If it's EEXIST we have to make sure it's a dir
            if (!NoFile::IsDir(sDir)) return false;
        }

        sDir += "/";
    }

    // All went well
    return true;
}

NoString NoDir::GetCWD()
{
    NoString sRet;
    char* pszCurDir = getcwd(nullptr, 0);
    if (pszCurDir) {
        sRet = pszCurDir;
        free(pszCurDir);
    }

    return sRet;
}
