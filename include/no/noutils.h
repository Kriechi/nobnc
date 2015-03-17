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

#ifndef NOUTILS_H
#define NOUTILS_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <assert.h>
#include <cstdio>
#include <map>
#include <sys/file.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

class NO_EXPORT NoUtils
{
public:
    NoUtils();
    ~NoUtils();

    static NoString GetIP(ulong addr);
    static ulong GetLongIP(const NoString& sIP);

    static void PrintError(const NoString& sMessage);
    static void PrintMessage(const NoString& sMessage, bool bStrong = false);
    static void PrintPrompt(const NoString& sMessage);
    static void PrintAction(const NoString& sMessage);
    static void PrintStatus(bool bSuccess, const NoString& sMessage = "");

    // TODO refactor this
    static const NoString sDefaultHash;

    static NoString GetSaltedHashPass(NoString& sSalt);
    static NoString GetSalt();
    static NoString SaltedMD5Hash(const NoString& sPass, const NoString& sSalt);
    static NoString SaltedSHA256Hash(const NoString& sPass, const NoString& sSalt);
    static NoString GetPass(const NoString& sPrompt);
    static bool GetInput(const NoString& sPrompt, NoString& sRet, const NoString& sDefault = "", const NoString& sHint = "");
    static bool GetBoolInput(const NoString& sPrompt, bool bDefault);
    static bool GetBoolInput(const NoString& sPrompt, bool* pbDefault = nullptr);
    static bool
    GetNumInput(const NoString& sPrompt, uint& uRet, uint uMin = 0, uint uMax = ~0, uint uDefault = ~0);

    static ulonglong GetMillTime()
    {
        struct timeval tv;
        ulonglong iTime = 0;
        gettimeofday(&tv, nullptr);
        iTime = (ulonglong)tv.tv_sec * 1000;
        iTime += ((ulonglong)tv.tv_usec / 1000);
        return iTime;
    }
#ifdef HAVE_LIBSSL
    static void GenerateCert(FILE* pOut, const NoString& sHost = "");
#endif /* HAVE_LIBSSL */

    static NoString CTime(time_t t, const NoString& sTZ);
    static NoString FormatTime(time_t t, const NoString& sFormat, const NoString& sTZ);
    static NoString FormatServerTime(const timeval& tv);
    static NoStringSet GetTimezones();
    static NoStringSet GetEncodings();

    static NoStringMap GetMessageTags(const NoString& sLine);
    static void SetMessageTags(NoString& sLine, const NoStringMap& mssTags);
};

#endif // NOUTILS_H
