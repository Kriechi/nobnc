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

CString CDir::ChangeDir(const CString& sPath, const CString& sAdd, const CString& sHome)
{
    CString sHomeDir(sHome);

    if (sHomeDir.empty()) {
        sHomeDir = CFile::GetHomePath();
    }

    if (sAdd == "~") {
        return sHomeDir;
    }

    CString sAddDir(sAdd);

    if (sAddDir.Left(2) == "~/") {
        sAddDir.LeftChomp();
        sAddDir = sHomeDir + sAddDir;
    }

    CString sRet = ((sAddDir.size()) && (sAddDir[0] == '/')) ? "" : sPath;
    sAddDir += "/";
    CString sCurDir;

    if (sRet.Right(1) == "/") {
        sRet.RightChomp();
    }

    for (unsigned int a = 0; a < sAddDir.size(); a++) {
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

CString CDir::CheckPathPrefix(const CString& sPath, const CString& sAdd, const CString& sHomeDir)
{
    CString sPrefix = sPath.Replace_n("//", "/").TrimRight_n("/") + "/";
    CString sAbsolutePath = ChangeDir(sPrefix, sAdd, sHomeDir);

    if (sAbsolutePath.Left(sPrefix.length()) != sPrefix) return "";
    return sAbsolutePath;
}

bool CDir::MakeDir(const CString& sPath, mode_t iMode)
{
    CString sDir;
    VCString dirs;
    VCString::iterator it;

    // Just in case someone tries this...
    if (sPath.empty()) {
        errno = ENOENT;
        return false;
    }

    // If this is an absolute path, we need to handle this now!
    if (sPath.Left(1) == "/") sDir = "/";

    // For every single subpath, do...
    sPath.Split("/", dirs, false);
    for (it = dirs.begin(); it != dirs.end(); ++it) {
        // Add this to the path we already created
        sDir += *it;

        int i = mkdir(sDir.c_str(), iMode);

        if (i != 0) {
            // All errors except EEXIST are fatal
            if (errno != EEXIST) return false;

            // If it's EEXIST we have to make sure it's a dir
            if (!CFile::IsDir(sDir)) return false;
        }

        sDir += "/";
    }

    // All went well
    return true;
}
