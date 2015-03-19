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
#include "noescape.h"
#include "noblowfish.h"
#include "md5/md5.h"
#include "sha2/sha2.h"
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

#ifdef HAVE_LIBSSL
static NoString Crypt(const NoString& sStr, const NoString& sPass, bool bEncrypt, const NoString& sIvec)
{
    NoString ret = sStr;

    uchar szIvec[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    BF_KEY bKey;

    if (sIvec.length() >= 8)
        memcpy(szIvec, sIvec.data(), 8);

    BF_set_key(&bKey, (uint)sPass.length(), (uchar*)sPass.data());
    uint uPad = ret.length() % 8;

    if (uPad) {
        uPad = 8 - uPad;
        ret.append(uPad, '\0');
    }

    size_t uLen = ret.length();
    uchar* szBuff = (uchar*)malloc(uLen);
    BF_cbc_encrypt((const uchar*)ret.data(), szBuff, uLen, &bKey, szIvec, ((bEncrypt) ? BF_ENCRYPT : BF_DECRYPT));

    ret.clear();
    ret.append((const char*)szBuff, uLen);
    free(szBuff);
    return ret;
}

NoString NoUtils::Encrypt(const NoString& sStr, const NoString& sPass, const NoString& sIvec)
{
    return Crypt(sStr, sPass, true, sIvec);
}

NoString NoUtils::Decrypt(const NoString& sStr, const NoString& sPass, const NoString& sIvec)
{
    return Crypt(sStr, sPass, false, sIvec);
}
#endif // HAVE_LIBSSL

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

        if (!pass1.Equals(pass2, No::CaseSensitive)) {
            NoUtils::PrintError("The supplied passwords did not match");
        } else {
            // Construct the salted pass
            return SaltedSHA256Hash(pass1, sSalt);
        }
    }
}

NoString NoUtils::GetSalt() { return RandomString(20); }

NoString NoUtils::MD5(const NoString& sStr) { return MD5::md5(sStr); }

NoString NoUtils::SHA256(const NoString& sStr)
{
    uchar digest[SHA256_DIGEST_SIZE];
    char digest_hex[SHA256_DIGEST_SIZE * 2 + 1];
    const uchar* message = (const uchar*)sStr.c_str();

    sha256(message, sStr.length(), digest);

    snprintf(digest_hex,
             sizeof(digest_hex),
             "%02x%02x%02x%02x%02x%02x%02x%02x"
             "%02x%02x%02x%02x%02x%02x%02x%02x"
             "%02x%02x%02x%02x%02x%02x%02x%02x"
             "%02x%02x%02x%02x%02x%02x%02x%02x",
             digest[0],
             digest[1],
             digest[2],
             digest[3],
             digest[4],
             digest[5],
             digest[6],
             digest[7],
             digest[8],
             digest[9],
             digest[10],
             digest[11],
             digest[12],
             digest[13],
             digest[14],
             digest[15],
             digest[16],
             digest[17],
             digest[18],
             digest[19],
             digest[20],
             digest[21],
             digest[22],
             digest[23],
             digest[24],
             digest[25],
             digest[26],
             digest[27],
             digest[28],
             digest[29],
             digest[30],
             digest[31]);

    return digest_hex;
}

NoString NoUtils::SaltedMD5Hash(const NoString& sPass, const NoString& sSalt) { return MD5(sPass + sSalt); }

NoString NoUtils::SaltedSHA256Hash(const NoString& sPass, const NoString& sSalt) { return SHA256(sPass + sSalt); }

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
        sInput.RightChomp(1);
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
        NoStringVector vsTags = sLine.Token(0).TrimPrefix_n("@").Split(";", No::SkipEmptyParts);

        NoStringMap mssTags;
        for (const NoString& sTag : vsTags) {
            NoString sKey = sTag.Token(0, false, "=", No::KeepEmptyParts);
            NoString sValue = sTag.Token(1, true, "=", No::KeepEmptyParts);
            mssTags[sKey] = No::Escape_n(sValue, No::MsgTagFormat, No::AsciiFormat);
        }
        return mssTags;
    }
    return NoStringMap();
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
            if (!it.second.empty()) sTags += "=" + No::Escape_n(it.second, No::MsgTagFormat);
        }
        sLine = "@" + sTags + " " + sLine;
    }
}

static const char hexdigits[] = "0123456789abcdef";

static NoString& Encode(NoString& sValue)
{
    NoString sTmp;
    for (uchar c : sValue) {
        // isalnum() needs uchar as argument and this code
        // assumes unsigned, too.
        if (isalnum(c)) {
            sTmp += c;
        } else {
            sTmp += "%";
            sTmp += hexdigits[c >> 4];
            sTmp += hexdigits[c & 0xf];
            sTmp += ";";
        }
    }
    sValue = sTmp;
    return sValue;
}

NoUtils::status_t NoUtils::WriteToDisk(const NoStringMap& values, const NoString& sPath, mode_t iMode)
{
    NoFile cFile(sPath);

    if (values.empty()) {
        if (!cFile.Exists()) return MCS_SUCCESS;
        if (cFile.Delete()) return MCS_SUCCESS;
    }

    if (!cFile.Open(O_WRONLY | O_CREAT | O_TRUNC, iMode))
        return MCS_EOPEN;

    for (const auto& it : values) {
        NoString sKey = it.first;
        NoString sValue = it.second;

        if (sKey.empty()) {
            continue;
        }

        if (cFile.Write(Encode(sKey) + " " + Encode(sValue) + "\n") <= 0) {
            return MCS_EWRITE;
        }
    }

    cFile.Close();

    return MCS_SUCCESS;
}

static NoString& Decode(NoString& sValue)
{
    const char* pTmp = sValue.c_str();
    char* endptr;
    NoString sTmp;

    while (*pTmp) {
        if (*pTmp != '%') {
            sTmp += *pTmp++;
        } else {
            char ch = (char)strtol(pTmp + 1, &endptr, 16);
            if (*endptr == ';') {
                sTmp += ch;
                pTmp = ++endptr;
            } else {
                sTmp += *pTmp++;
            }
        }
    }

    sValue = sTmp;
    return sValue;
}

NoUtils::status_t NoUtils::ReadFromDisk(NoStringMap& values, const NoString& sPath)
{
    NoFile cFile(sPath);
    if (!cFile.Open(O_RDONLY))
        return MCS_EOPEN;

    NoString sBuffer;

    while (cFile.ReadLine(sBuffer)) {
        sBuffer.Trim();
        NoString sKey = sBuffer.Token(0);
        NoString sValue = sBuffer.Token(1);
        Decode(sKey);
        Decode(sValue);

        values[sKey] = sValue;
    }
    cFile.Close();

    return MCS_SUCCESS;
}

NoString NoUtils::ToByteStr(ulonglong d)
{
    const ulonglong KiB = 1024;
    const ulonglong MiB = KiB * 1024;
    const ulonglong GiB = MiB * 1024;
    const ulonglong TiB = GiB * 1024;

    if (d > TiB) {
        return NoString(d / TiB) + " TiB";
    } else if (d > GiB) {
        return NoString(d / GiB) + " GiB";
    } else if (d > MiB) {
        return NoString(d / MiB) + " MiB";
    } else if (d > KiB) {
        return NoString(d / KiB) + " KiB";
    }

    return NoString(d) + " B";
}

NoString NoUtils::ToTimeStr(ulong s)
{
    const ulong m = 60;
    const ulong h = m * 60;
    const ulong d = h * 24;
    const ulong w = d * 7;
    const ulong y = d * 365;
    NoString sRet;

#define TIMESPAN(time, str)                  \
    if (s >= time) {                         \
        sRet += NoString(s / time) + str " "; \
        s = s % time;                        \
    }
    TIMESPAN(y, "y");
    TIMESPAN(w, "w");
    TIMESPAN(d, "d");
    TIMESPAN(h, "h");
    TIMESPAN(m, "m");
    TIMESPAN(1, "s");

    if (sRet.empty()) return "0s";

    return sRet.RightChomp_n(1);
}

NoString NoUtils::ToPercent(double d)
{
    char szRet[32];
    snprintf(szRet, 32, "%.02f%%", d);
    return szRet;
}

NoString NoUtils::StripControls(const NoString& str)
{
    NoString sRet;
    const uchar* pStart = (const uchar*)str.data();
    uchar ch = *pStart;
    ulong iLength = str.length();
    sRet.reserve(iLength);
    bool colorCode = false;
    uint digits = 0;
    bool comma = false;

    for (uint a = 0; a < iLength; a++, ch = pStart[a]) {
        // Color code. Format: \x03([0-9]{1,2}(,[0-9]{1,2})?)?
        if (ch == 0x03) {
            colorCode = true;
            digits = 0;
            comma = false;
            continue;
        }
        if (colorCode) {
            if (isdigit(ch) && digits < 2) {
                digits++;
                continue;
            }
            if (ch == ',' && !comma && digits > 0) {
                comma = true;
                digits = 0;
                continue;
            }

            colorCode = false;

            if (digits == 0 && comma) { // There was a ',' which wasn't followed by digits, we should print it.
                sRet += ',';
            }
        }
        // CO controls codes
        if (ch < 0x20 || ch == 0x7F) continue;
        sRet += ch;
    }
    if (colorCode && digits == 0 && comma) {
        sRet += ',';
    }

    sRet.reserve(0);
    return sRet;
}

NoString NoUtils::RandomString(uint uLength)
{
    const char chars[] = "abcdefghijklmnopqrstuvwxyz"
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                         "0123456789!?.,:;/*-+_()";
    // -1 because sizeof() includes the trailing '\0' byte
    const size_t len = sizeof(chars) / sizeof(chars[0]) - 1;
    size_t p;
    NoString sRet;

    for (uint a = 0; a < uLength; a++) {
        p = (size_t)(len * (rand() / (RAND_MAX + 1.0)));
        sRet += chars[p];
    }

    return sRet;
}

NoString NoUtils::NamedFormat(const NoString& sFormat, const NoStringMap& msValues)
{
    NoString sRet;

    NoString sKey;
    bool bEscape = false;
    bool bParam = false;
    const char* p = sFormat.c_str();

    while (*p) {
        if (!bParam) {
            if (bEscape) {
                sRet += *p;
                bEscape = false;
            } else if (*p == '\\') {
                bEscape = true;
            } else if (*p == '{') {
                bParam = true;
                sKey.clear();
            } else {
                sRet += *p;
            }

        } else {
            if (bEscape) {
                sKey += *p;
                bEscape = false;
            } else if (*p == '\\') {
                bEscape = true;
            } else if (*p == '}') {
                bParam = false;
                NoStringMap::const_iterator it = msValues.find(sKey);
                if (it != msValues.end()) {
                    sRet += (*it).second;
                }
            } else {
                sKey += *p;
            }
        }

        p++;
    }

    return sRet;
}

NoString NoUtils::Ellipsize(const NoString& str, uint uLen)
{
    if (uLen >= str.size()) {
        return str;
    }

    NoString sRet;

    // @todo this looks suspect
    if (uLen < 4) {
        for (uint a = 0; a < uLen; a++) {
            sRet += ".";
        }

        return sRet;
    }

    sRet = str.substr(0, uLen - 3) + "...";

    return sRet;
}

extern NoStringVector Split_helper(const NoString& str, const NoString& sDelim, No::SplitBehavior behavior, const NoString& sLeft, const NoString& sRight, bool bTrimQuotes);

NoStringMap NoUtils::OptionSplit(const NoString& str)
{
    NoString sName;
    NoString sCopy(str);
    NoStringMap msRet;

    while (!sCopy.empty()) {
        sName = sCopy.Token(0, false, "=", No::SkipEmptyParts, "\"", "\"", false).Trim_n();
        sCopy = sCopy.Token(1, true, "=", No::SkipEmptyParts, "\"", "\"", false).TrimLeft_n();

        if (sName.empty()) {
            continue;
        }

        NoStringVector vsNames = Split_helper(sName, " ", No::SkipEmptyParts, "\"", "\"", true);

        for (uint a = 0; a < vsNames.size(); a++) {
            NoString sKeyName = vsNames[a];

            if ((a + 1) == vsNames.size()) {
                msRet[sKeyName] = sCopy.Token(0, false, " ", No::SkipEmptyParts, "\"", "\"");
                sCopy = sCopy.Token(1, true, " ", No::SkipEmptyParts, "\"", "\"", false);
            } else {
                msRet[sKeyName] = "";
            }
        }
    }

    return msRet;
}

NoStringVector NoUtils::QuoteSplit(const NoString& str)
{
    return Split_helper(str, " ", No::SkipEmptyParts, "\"", "\"", true);
}
