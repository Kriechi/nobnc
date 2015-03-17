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

#include "noutils.h"
#include "nodebug.h"
#include "nofile.h"
#include "nodir.h"
#include "nomd5.h"
#include <sys/time.h>
#include <unistd.h>

#ifdef HAVE_ICU
#include <unicode/ucnv.h>
#include <unicode/errorcode.h>
#endif

// Required with GCC 4.3+ if openssl is disabled
#include <cstring>
#include <cstdlib>

NoString NoUtils::GetIP(ulong addr)
{
    char szBuf[16];
    memset((char*)szBuf, 0, 16);

    if (addr >= (1 << 24)) {
        ulong ip[4];
        ip[0] = addr >> 24 & 255;
        ip[1] = addr >> 16 & 255;
        ip[2] = addr >> 8 & 255;
        ip[3] = addr & 255;
        sprintf(szBuf, "%lu.%lu.%lu.%lu", ip[0], ip[1], ip[2], ip[3]);
    }

    return szBuf;
}

ulong NoUtils::GetLongIP(const NoString& sIP)
{
    ulong ret;
    char ip[4][4];
    uint i;

    i = sscanf(sIP.c_str(), "%3[0-9].%3[0-9].%3[0-9].%3[0-9]", ip[0], ip[1], ip[2], ip[3]);
    if (i != 4) return 0;

    // Beware that atoi("200") << 24 would overflow and turn negative!
    ret = atol(ip[0]) << 24;
    ret += atol(ip[1]) << 16;
    ret += atol(ip[2]) << 8;
    ret += atol(ip[3]) << 0;

    return ret;
}

// If you change this here and in GetSaltedHashPass(),
// don't forget NoUser::HASH_DEFAULT!
// TODO refactor this
const NoString NoUtils::sDefaultHash = "sha256";
NoString NoUtils::GetSaltedHashPass(NoString& sSalt)
{
    sSalt = GetSalt();

    while (true) {
        NoString pass1;
        do {
            pass1 = NoUtils::GetPass("Enter password");
        } while (pass1.empty());

        NoString pass2 = NoUtils::GetPass("Confirm password");

        if (!pass1.Equals(pass2, NoString::CaseSensitive)) {
            NoUtils::PrintError("The supplied passwords did not match");
        } else {
            // Construct the salted pass
            return SaltedSHA256Hash(pass1, sSalt);
        }
    }
}

NoString NoUtils::GetSalt() { return NoString::RandomString(20); }

NoString NoUtils::MD5(const NoString& sStr) { return (const char*) NoMD5(sStr); }

NoString NoUtils::SaltedMD5Hash(const NoString& sPass, const NoString& sSalt) { return MD5(sPass + sSalt); }

NoString NoUtils::SaltedSHA256Hash(const NoString& sPass, const NoString& sSalt) { return NoString(sPass + sSalt).SHA256(); }

NoString NoUtils::GetPass(const NoString& sPrompt)
{
    PrintPrompt(sPrompt);
#ifdef HAVE_GETPASSPHRASE
    return getpassphrase("");
#else
    return getpass("");
#endif
}

bool NoUtils::GetBoolInput(const NoString& sPrompt, bool bDefault) { return NoUtils::GetBoolInput(sPrompt, &bDefault); }

bool NoUtils::GetBoolInput(const NoString& sPrompt, bool* pbDefault)
{
    NoString sRet, sDefault;

    if (pbDefault) {
        sDefault = (*pbDefault) ? "yes" : "no";
    }

    while (true) {
        GetInput(sPrompt, sRet, sDefault, "yes/no");

        if (sRet.Equals("y") || sRet.Equals("yes")) {
            return true;
        } else if (sRet.Equals("n") || sRet.Equals("no")) {
            return false;
        }
    }
}

bool NoUtils::GetNumInput(const NoString& sPrompt, uint& uRet, uint uMin, uint uMax, uint uDefault)
{
    if (uMin > uMax) {
        return false;
    }

    NoString sDefault = (uDefault != (uint)~0) ? NoString(uDefault) : "";
    NoString sNum, sHint;

    if (uMax != (uint)~0) {
        sHint = NoString(uMin) + " to " + NoString(uMax);
    } else if (uMin > 0) {
        sHint = NoString(uMin) + " and up";
    }

    while (true) {
        GetInput(sPrompt, sNum, sDefault, sHint);
        if (sNum.empty()) {
            return false;
        }

        uRet = sNum.ToUInt();

        if ((uRet >= uMin && uRet <= uMax)) {
            break;
        }

        NoUtils::PrintError("Number must be " + sHint);
    }

    return true;
}

ulonglong NoUtils::GetMillTime()
{
    struct timeval tv;
    ulonglong iTime = 0;
    gettimeofday(&tv, nullptr);
    iTime = (ulonglong)tv.tv_sec * 1000;
    iTime += ((ulonglong)tv.tv_usec / 1000);
    return iTime;
}

bool NoUtils::GetInput(const NoString& sPrompt, NoString& sRet, const NoString& sDefault, const NoString& sHint)
{
    NoString sExtra;
    NoString sInput;
    sExtra += (!sHint.empty()) ? (" (" + sHint + ")") : "";
    sExtra += (!sDefault.empty()) ? (" [" + sDefault + "]") : "";

    PrintPrompt(sPrompt + sExtra);
    char szBuf[1024];
    memset(szBuf, 0, 1024);
    if (fgets(szBuf, 1024, stdin) == nullptr) {
        // Reading failed (Error? EOF?)
        PrintError("Error while reading from stdin. Exiting...");
        exit(-1);
    }
    sInput = szBuf;

    if (sInput.Right(1) == "\n") {
        sInput.RightChomp();
    }

    if (sInput.empty()) {
        sRet = sDefault;
    } else {
        sRet = sInput;
    }

    return !sRet.empty();
}

#define BOLD "\033[1m"
#define NORM "\033[22m"

#define RED "\033[31m"
#define GRN "\033[32m"
#define YEL "\033[33m"
#define BLU "\033[34m"
#define DFL "\033[39m"

void NoUtils::PrintError(const NoString& sMessage)
{
    if (NoDebug::StdoutIsTTY())
        fprintf(stdout, BOLD BLU "[" RED " ** " BLU "]" DFL NORM " %s\n", sMessage.c_str());
    else
        fprintf(stdout, "%s\n", sMessage.c_str());
    fflush(stdout);
}

void NoUtils::PrintPrompt(const NoString& sMessage)
{
    if (NoDebug::StdoutIsTTY())
        fprintf(stdout, BOLD BLU "[" YEL " ?? " BLU "]" DFL NORM " %s: ", sMessage.c_str());
    else
        fprintf(stdout, "[ ?? ] %s: ", sMessage.c_str());
    fflush(stdout);
}

void NoUtils::PrintMessage(const NoString& sMessage, bool bStrong)
{
    if (NoDebug::StdoutIsTTY()) {
        if (bStrong)
            fprintf(stdout, BOLD BLU "[" YEL " ** " BLU "]" DFL BOLD " %s" NORM "\n", sMessage.c_str());
        else
            fprintf(stdout, BOLD BLU "[" YEL " ** " BLU "]" DFL NORM " %s\n", sMessage.c_str());
    } else
        fprintf(stdout, "%s\n", sMessage.c_str());

    fflush(stdout);
}

void NoUtils::PrintAction(const NoString& sMessage)
{
    if (NoDebug::StdoutIsTTY())
        fprintf(stdout, BOLD BLU "[ .. " BLU "]" DFL NORM " %s...\n", sMessage.c_str());
    else
        fprintf(stdout, "%s... ", sMessage.c_str());
    fflush(stdout);
}

void NoUtils::PrintStatus(bool bSuccess, const NoString& sMessage)
{
    if (NoDebug::StdoutIsTTY()) {
        if (bSuccess) {
            fprintf(stdout, BOLD BLU "[" GRN " >> " BLU "]" DFL NORM);
            fprintf(stdout, " %s\n", sMessage.empty() ? "ok" : sMessage.c_str());
        } else {
            fprintf(stdout, BOLD BLU "[" RED " !! " BLU "]" DFL NORM);
            fprintf(stdout, BOLD RED " %s" DFL NORM "\n", sMessage.empty() ? "failed" : sMessage.c_str());
        }
    } else {
        if (bSuccess) {
            fprintf(stdout, "%s\n", sMessage.c_str());
        } else {
            if (!sMessage.empty()) {
                fprintf(stdout, "[ %s ]", sMessage.c_str());
            }

            fprintf(stdout, "\n");
        }
    }

    fflush(stdout);
}

namespace
{
/* Switch GMT-X and GMT+X
 *
 * See https://en.wikipedia.org/wiki/Tz_database#Area
 *
 * "In order to conform with the POSIX style, those zone names beginning
 * with "Etc/GMT" have their sign reversed from what most people expect.
 * In this style, zones west of GMT have a positive sign and those east
 * have a negative sign in their name (e.g "Etc/GMT-14" is 14 hours
 * ahead/east of GMT.)"
 */
inline NoString FixGMT(NoString sTZ)
{
    if (sTZ.length() >= 4 && sTZ.Left(3) == "GMT") {
        if (sTZ[3] == '+') {
            sTZ[3] = '-';
        } else if (sTZ[3] == '-') {
            sTZ[3] = '+';
        }
    }
    return sTZ;
}
}

NoString NoUtils::CTime(time_t t, const NoString& sTimezone)
{
    char s[30] = {}; // should have at least 26 bytes
    if (sTimezone.empty()) {
        ctime_r(&t, s);
        // ctime() adds a trailing newline
        return NoString(s).Trim_n();
    }
    NoString sTZ = FixGMT(sTimezone);

    // backup old value
    char* oldTZ = getenv("TZ");
    if (oldTZ) oldTZ = strdup(oldTZ);
    setenv("TZ", sTZ.c_str(), 1);
    tzset();

    ctime_r(&t, s);

    // restore old value
    if (oldTZ) {
        setenv("TZ", oldTZ, 1);
        free(oldTZ);
    } else {
        unsetenv("TZ");
    }
    tzset();

    return NoString(s).Trim_n();
}

NoString NoUtils::FormatTime(time_t t, const NoString& sFormat, const NoString& sTimezone)
{
    char s[1024] = {};
    tm m;
    if (sTimezone.empty()) {
        localtime_r(&t, &m);
        strftime(s, sizeof(s), sFormat.c_str(), &m);
        return s;
    }
    NoString sTZ = FixGMT(sTimezone);

    // backup old value
    char* oldTZ = getenv("TZ");
    if (oldTZ) oldTZ = strdup(oldTZ);
    setenv("TZ", sTZ.c_str(), 1);
    tzset();

    localtime_r(&t, &m);
    strftime(s, sizeof(s), sFormat.c_str(), &m);

    // restore old value
    if (oldTZ) {
        setenv("TZ", oldTZ, 1);
        free(oldTZ);
    } else {
        unsetenv("TZ");
    }
    tzset();

    return s;
}

NoString NoUtils::FormatServerTime(const timeval& tv)
{
    NoString s_msec(tv.tv_usec / 1000);
    while (s_msec.length() < 3) {
        s_msec = "0" + s_msec;
    }
    // TODO support leap seconds properly
    // TODO support message-tags properly
    struct tm stm;
    memset(&stm, 0, sizeof(stm));
    const time_t secs =
    tv.tv_sec; // OpenBSD has tv_sec as int, so explicitly convert it to time_t to make gmtime_r() happy
    gmtime_r(&secs, &stm);
    char sTime[20] = {};
    strftime(sTime, sizeof(sTime), "%Y-%m-%dT%H:%M:%S", &stm);
    return NoString(sTime) + "." + s_msec + "Z";
}

namespace
{
void FillTimezones(const NoString& sPath, NoStringSet& result, const NoString& sPrefix)
{
    NoDir Dir;
    Dir.Fill(sPath);
    for (NoFile* pFile : Dir) {
        NoString sName = pFile->GetShortName();
        NoString sFile = pFile->GetLongName();
        if (sName == "posix" || sName == "right") continue; // these 2 dirs contain the same filenames
        if (sName.Right(4) == ".tab" || sName == "posixrules" || sName == "localtime") continue;
        if (pFile->IsDir()) {
            if (sName == "Etc") {
                FillTimezones(sFile, result, sPrefix);
            } else {
                FillTimezones(sFile, result, sPrefix + sName + "/");
            }
        } else {
            result.insert(sPrefix + sName);
        }
    }
}
}

NoStringSet NoUtils::GetTimezones()
{
    static NoStringSet result;
    if (result.empty()) {
        FillTimezones("/usr/share/zoneinfo", result, "");
    }
    return result;
}

NoStringSet NoUtils::GetEncodings()
{
    static NoStringSet ssResult;
#ifdef HAVE_ICU
    if (ssResult.empty()) {
        for (int i = 0; i < ucnv_countAvailable(); ++i) {
            const char* pConvName = ucnv_getAvailableName(i);
            ssResult.insert(pConvName);
            icu::ErrorCode e;
            for (int st = 0; st < ucnv_countStandards(); ++st) {
                const char* pStdName = ucnv_getStandard(st, e);
                icu::LocalUEnumerationPointer ue(ucnv_openStandardNames(pConvName, pStdName, e));
                while (const char* pStdConvNameEnum = uenum_next(ue.getAlias(), nullptr, e)) {
                    ssResult.insert(pStdConvNameEnum);
                }
            }
        }
    }
#endif
    return ssResult;
}

NoStringMap NoUtils::GetMessageTags(const NoString& sLine)
{
    if (sLine.StartsWith("@")) {
        NoStringVector vsTags;
        sLine.Token(0).TrimPrefix_n("@").Split(";", vsTags, false);

        NoStringMap mssTags;
        for (const NoString& sTag : vsTags) {
            NoString sKey = sTag.Token(0, false, "=", true);
            NoString sValue = sTag.Token(1, true, "=", true);
            mssTags[sKey] = sValue.Escape(NoString::EMSGTAG, NoString::NoString::EASCII);
        }
        return mssTags;
    }
    return NoStringMap::EmptyMap;
}

void NoUtils::SetMessageTags(NoString& sLine, const NoStringMap& mssTags)
{
    if (sLine.StartsWith("@")) {
        sLine.LeftChomp(sLine.Token(0).length() + 1);
    }

    if (!mssTags.empty()) {
        NoString sTags;
        for (const auto& it : mssTags) {
            if (!sTags.empty()) {
                sTags += ";";
            }
            sTags += it.first;
            if (!it.second.empty()) sTags += "=" + it.second.Escape_n(NoString::EMSGTAG);
        }
        sLine = "@" + sTags + " " + sLine;
    }
}
