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

#include "noutils.h"
#include "nodebug.h"
#include "nofile.h"
#include "nodir.h"
#include "noescape.h"
#include "md5/md5.h"
#include "sha2/sha2.h"
#include <sys/time.h>
#include <unistd.h>

#ifdef HAVE_ICU
#include <unicode/ucnv.h>
#include <unicode/errorcode.h>
#endif

#ifdef HAVE_LIBSSL
#include <openssl/blowfish.h>
#endif // HAVE_LIBSSL

// Required with GCC 4.3+ if openssl is disabled
#include <cstring>
#include <cstdlib>

NoString No::formatIp(ulong addr)
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

ulong No::formatLongIp(const NoString& sIP)
{
    ulong ret;
    char ip[4][4];
    uint i;

    i = sscanf(sIP.c_str(), "%3[0-9].%3[0-9].%3[0-9].%3[0-9]", ip[0], ip[1], ip[2], ip[3]);
    if (i != 4)
        return 0;

    // Beware that atoi("200") << 24 would overflow and turn negative!
    ret = atol(ip[0]) << 24;
    ret += atol(ip[1]) << 16;
    ret += atol(ip[2]) << 8;
    ret += atol(ip[3]) << 0;

    return ret;
}

#ifdef HAVE_LIBSSL
static NoString blowfish(const NoString& data, const NoString& password, int mode)
{
    NoString ret = data;

    uchar ivec[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    BF_KEY key;

    BF_set_key(&key, (uint)password.length(), (uchar*)password.data());
    uint pad = ret.length() % 8;

    if (pad) {
        pad = 8 - pad;
        ret.append(pad, '\0');
    }

    size_t len = ret.length();
    uchar* buff = (uchar*)malloc(len);
    BF_cbc_encrypt((const uchar*)ret.data(), buff, len, &key, ivec, mode);

    ret.clear();
    ret.append((const char*)buff, len);
    free(buff);
    return ret;
}

NoString No::encrypt(const NoString& data, const NoString& password)
{
    return blowfish(data, password, BF_ENCRYPT);
}

NoString No::decrypt(const NoString& data, const NoString& password)
{
    return blowfish(data, password, BF_DECRYPT);
}
#endif // HAVE_LIBSSL

NoString No::getSaltedHashPass(NoString& salt)
{
    salt = No::salt();

    while (true) {
        NoString pass1;
        do {
            pass1 = No::getPass("Enter password");
        } while (pass1.empty());

        NoString pass2 = No::getPass("Confirm password");

        if (!pass1.equals(pass2, No::CaseSensitive)) {
            No::printError("The supplied passwords did not match");
        } else {
            // Construct the salted pass
            return saltedSha256(pass1, salt);
        }
    }
}

NoString No::salt()
{
    return randomString(20);
}

// If you change this here and in GetSaltedHashPass(),
// don't forget NoUser::HASH_DEFAULT!
// TODO refactor this
NoString No::defaultHash()
{
    return "sha256";
}

NoString No::md5(const NoString& str)
{
    return MD5::md5(str);
}

NoString No::sha256(const NoString& str)
{
    uchar digest[SHA256_DIGEST_SIZE];
    char digest_hex[SHA256_DIGEST_SIZE * 2 + 1];
    const uchar* message = (const uchar*)str.c_str();

    ::sha256(message, str.length(), digest);

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

NoString No::saltedMd5(const NoString& pass, const NoString& salt)
{
    return md5(pass + salt);
}

NoString No::saltedSha256(const NoString& pass, const NoString& salt)
{
    return sha256(pass + salt);
}

NoString No::getPass(const NoString& sPrompt)
{
    printPrompt(sPrompt);
#ifdef HAVE_GETPASSPHRASE
    return getpassphrase("");
#else
    return getpass("");
#endif
}

bool No::getBoolInput(const NoString& sPrompt, bool bDefault)
{
    return No::getBoolInput(sPrompt, &bDefault);
}

bool No::getBoolInput(const NoString& sPrompt, bool* pbDefault)
{
    NoString ret, sDefault;

    if (pbDefault) {
        sDefault = (*pbDefault) ? "yes" : "no";
    }

    while (true) {
        getInput(sPrompt, ret, sDefault, "yes/no");

        if (ret.equals("y") || ret.equals("yes")) {
            return true;
        } else if (ret.equals("n") || ret.equals("no")) {
            return false;
        }
    }
}

bool No::getNumInput(const NoString& sPrompt, uint& uRet, uint uMin, uint uMax, uint uDefault)
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
        getInput(sPrompt, sNum, sDefault, sHint);
        if (sNum.empty()) {
            return false;
        }

        uRet = sNum.toUInt();

        if ((uRet >= uMin && uRet <= uMax)) {
            break;
        }

        No::printError("Number must be " + sHint);
    }

    return true;
}

ulonglong No::millTime()
{
    struct timeval tv;
    ulonglong iTime = 0;
    gettimeofday(&tv, nullptr);
    iTime = (ulonglong)tv.tv_sec * 1000;
    iTime += ((ulonglong)tv.tv_usec / 1000);
    return iTime;
}

bool No::getInput(const NoString& sPrompt, NoString& ret, const NoString& sDefault, const NoString& sHint)
{
    NoString sExtra;
    NoString sInput;
    sExtra += (!sHint.empty()) ? (" (" + sHint + ")") : "";
    sExtra += (!sDefault.empty()) ? (" [" + sDefault + "]") : "";

    printPrompt(sPrompt + sExtra);
    char szBuf[1024];
    memset(szBuf, 0, 1024);
    if (fgets(szBuf, 1024, stdin) == nullptr) {
        // Reading failed (Error? EOF?)
        printError("Error while reading from stdin. Exiting...");
        exit(-1);
    }
    sInput = szBuf;

    if (sInput.right(1) == "\n") {
        sInput.rightChomp(1);
    }

    if (sInput.empty()) {
        ret = sDefault;
    } else {
        ret = sInput;
    }

    return !ret.empty();
}

#define BOLD "\033[1m"
#define NORM "\033[22m"

#define RED "\033[31m"
#define GRN "\033[32m"
#define YEL "\033[33m"
#define BLU "\033[34m"
#define DFL "\033[39m"

void No::printError(const NoString& sMessage)
{
    if (NoDebug::isFormatted())
        fprintf(stdout, BOLD BLU "[" RED " ** " BLU "]" DFL NORM " %s\n", sMessage.c_str());
    else
        fprintf(stdout, "%s\n", sMessage.c_str());
    fflush(stdout);
}

void No::printPrompt(const NoString& sMessage)
{
    if (NoDebug::isFormatted())
        fprintf(stdout, BOLD BLU "[" YEL " ?? " BLU "]" DFL NORM " %s: ", sMessage.c_str());
    else
        fprintf(stdout, "[ ?? ] %s: ", sMessage.c_str());
    fflush(stdout);
}

void No::printMessage(const NoString& sMessage, bool bStrong)
{
    if (NoDebug::isFormatted()) {
        if (bStrong)
            fprintf(stdout, BOLD BLU "[" YEL " ** " BLU "]" DFL BOLD " %s" NORM "\n", sMessage.c_str());
        else
            fprintf(stdout, BOLD BLU "[" YEL " ** " BLU "]" DFL NORM " %s\n", sMessage.c_str());
    } else
        fprintf(stdout, "%s\n", sMessage.c_str());

    fflush(stdout);
}

void No::printAction(const NoString& sMessage)
{
    if (NoDebug::isFormatted())
        fprintf(stdout, BOLD BLU "[ .. " BLU "]" DFL NORM " %s...\n", sMessage.c_str());
    else
        fprintf(stdout, "%s... ", sMessage.c_str());
    fflush(stdout);
}

void No::printStatus(bool bSuccess, const NoString& sMessage)
{
    if (NoDebug::isFormatted()) {
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
    if (sTZ.length() >= 4 && sTZ.left(3) == "GMT") {
        if (sTZ[3] == '+') {
            sTZ[3] = '-';
        } else if (sTZ[3] == '-') {
            sTZ[3] = '+';
        }
    }
    return sTZ;
}
}

NoString No::cTime(time_t t, const NoString& sTimezone)
{
    char s[30] = {}; // should have at least 26 bytes
    if (sTimezone.empty()) {
        ctime_r(&t, s);
        // ctime() adds a trailing newline
        return NoString(s).trim_n();
    }
    NoString sTZ = FixGMT(sTimezone);

    // backup old value
    char* oldTZ = getenv("TZ");
    if (oldTZ)
        oldTZ = strdup(oldTZ);
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

    return NoString(s).trim_n();
}

NoString No::formatTime(time_t t, const NoString& format, const NoString& sTimezone)
{
    char s[1024] = {};
    tm m;
    if (sTimezone.empty()) {
        localtime_r(&t, &m);
        strftime(s, sizeof(s), format.c_str(), &m);
        return s;
    }
    NoString sTZ = FixGMT(sTimezone);

    // backup old value
    char* oldTZ = getenv("TZ");
    if (oldTZ)
        oldTZ = strdup(oldTZ);
    setenv("TZ", sTZ.c_str(), 1);
    tzset();

    localtime_r(&t, &m);
    strftime(s, sizeof(s), format.c_str(), &m);

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

NoString No::formatServerTime(const timeval& tv)
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
    NoDir Dir(sPath);
    for (NoFile* pFile : Dir.files()) {
        NoString name = pFile->GetShortName();
        NoString sFile = pFile->GetLongName();
        if (name == "posix" || name == "right")
            continue; // these 2 dirs contain the same filenames
        if (name.right(4) == ".tab" || name == "posixrules" || name == "localtime")
            continue;
        if (pFile->IsDir()) {
            if (name == "Etc") {
                FillTimezones(sFile, result, sPrefix);
            } else {
                FillTimezones(sFile, result, sPrefix + name + "/");
            }
        } else {
            result.insert(sPrefix + name);
        }
    }
}
}

NoStringSet No::timezones()
{
    static NoStringSet result;
    if (result.empty()) {
        FillTimezones("/usr/share/zoneinfo", result, "");
    }
    return result;
}

NoStringSet No::encodings()
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

NoStringMap No::messageTags(const NoString& line)
{
    if (line.startsWith("@")) {
        NoStringVector vsTags = No::token(line, 0).trimPrefix_n("@").split(";", No::SkipEmptyParts);

        NoStringMap mssTags;
        for (const NoString& sTag : vsTags) {
            size_t eq = sTag.find("=");
            if (eq != NoString::npos) {
                NoString sKey = sTag.substr(0, eq);
                NoString sValue = sTag.substr(eq + 1);
                mssTags[sKey] = No::escape(sValue, No::MsgTagFormat, No::AsciiFormat);
            } else {
                mssTags[sTag] = "";
            }
        }
        return mssTags;
    }
    return NoStringMap();
}

void No::setMessageTags(NoString& line, const NoStringMap& mssTags)
{
    if (line.startsWith("@")) {
        line.leftChomp(No::token(line, 0).length() + 1);
    }

    if (!mssTags.empty()) {
        NoString sTags;
        for (const auto& it : mssTags) {
            if (!sTags.empty()) {
                sTags += ";";
            }
            sTags += it.first;
            if (!it.second.empty())
                sTags += "=" + No::escape(it.second, No::MsgTagFormat);
        }
        line = "@" + sTags + " " + line;
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

No::status_t No::writeToDisk(const NoStringMap& values, const NoString& sPath, mode_t iMode)
{
    NoFile cFile(sPath);

    if (values.empty()) {
        if (!cFile.Exists())
            return MCS_SUCCESS;
        if (cFile.Delete())
            return MCS_SUCCESS;
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

No::status_t No::readFromDisk(NoStringMap& values, const NoString& sPath)
{
    NoFile cFile(sPath);
    if (!cFile.Open(O_RDONLY))
        return MCS_EOPEN;

    NoString sBuffer;

    while (cFile.ReadLine(sBuffer)) {
        sBuffer.trim();
        NoString sKey = No::token(sBuffer, 0);
        NoString sValue = No::token(sBuffer, 1);
        Decode(sKey);
        Decode(sValue);

        values[sKey] = sValue;
    }
    cFile.Close();

    return MCS_SUCCESS;
}

NoString No::toByteStr(ulonglong d)
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

NoString No::toTimeStr(ulong s)
{
    const ulong m = 60;
    const ulong h = m * 60;
    const ulong d = h * 24;
    const ulong w = d * 7;
    const ulong y = d * 365;
    NoString ret;

#define TIMESPAN(time, str)                   \
    if (s >= time) {                          \
        ret += NoString(s / time) + str " "; \
        s = s % time;                         \
    }
    TIMESPAN(y, "y");
    TIMESPAN(w, "w");
    TIMESPAN(d, "d");
    TIMESPAN(h, "h");
    TIMESPAN(m, "m");
    TIMESPAN(1, "s");

    if (ret.empty())
        return "0s";

    return ret.rightChomp_n(1);
}

NoString No::toPercent(double d)
{
    char szRet[32];
    snprintf(szRet, 32, "%.02f%%", d);
    return szRet;
}

NoString No::stripControls(const NoString& str)
{
    NoString ret;
    const uchar* pStart = (const uchar*)str.data();
    uchar ch = *pStart;
    ulong iLength = str.length();
    ret.reserve(iLength);
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
                ret += ',';
            }
        }
        // CO controls codes
        if (ch < 0x20 || ch == 0x7F)
            continue;
        ret += ch;
    }
    if (colorCode && digits == 0 && comma) {
        ret += ',';
    }

    ret.reserve(0);
    return ret;
}

NoString No::randomString(uint uLength)
{
    const char chars[] = "abcdefghijklmnopqrstuvwxyz"
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                         "0123456789!?.,:;/*-+_()";
    // -1 because sizeof() includes the trailing '\0' byte
    const size_t len = sizeof(chars) / sizeof(chars[0]) - 1;
    size_t p;
    NoString ret;

    for (uint a = 0; a < uLength; a++) {
        p = (size_t)(len * (rand() / (RAND_MAX + 1.0)));
        ret += chars[p];
    }

    return ret;
}

NoString No::namedFormat(const NoString& format, const NoStringMap& msValues)
{
    NoString ret;

    NoString sKey;
    bool bEscape = false;
    bool bParam = false;
    const char* p = format.c_str();

    while (*p) {
        if (!bParam) {
            if (bEscape) {
                ret += *p;
                bEscape = false;
            } else if (*p == '\\') {
                bEscape = true;
            } else if (*p == '{') {
                bParam = true;
                sKey.clear();
            } else {
                ret += *p;
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
                    ret += (*it).second;
                }
            } else {
                sKey += *p;
            }
        }

        p++;
    }

    return ret;
}

NoString No::ellipsize(const NoString& str, uint uLen)
{
    if (uLen >= str.size()) {
        return str;
    }

    NoString ret;

    // @todo this looks suspect
    if (uLen < 4) {
        for (uint a = 0; a < uLen; a++) {
            ret += ".";
        }

        return ret;
    }

    ret = str.substr(0, uLen - 3) + "...";

    return ret;
}

NoStringVector
Split_helper(const NoString& str, const NoString& sDelim, No::SplitBehavior behavior, const NoString& sLeft, const NoString& sRight, bool bTrimQuotes)
{
    NoStringVector vsRet;

    if (str.empty()) {
        return vsRet;
    }

    NoString sTmp;
    bool bInside = false;
    NoString::size_type uDelimLen = sDelim.length();
    NoString::size_type uLeftLen = sLeft.length();
    NoString::size_type uRightLen = sRight.length();
    const char* p = str.c_str();

    if (behavior == No::SkipEmptyParts) {
        while (strncasecmp(p, sDelim.c_str(), uDelimLen) == 0) {
            p += uDelimLen;
        }
    }

    while (*p) {
        if (uLeftLen && uRightLen && !bInside && strncasecmp(p, sLeft.c_str(), uLeftLen) == 0) {
            if (!bTrimQuotes) {
                sTmp += sLeft;
            }

            p += uLeftLen;
            bInside = true;
            continue;
        }

        if (uLeftLen && uRightLen && bInside && strncasecmp(p, sRight.c_str(), uRightLen) == 0) {
            if (!bTrimQuotes) {
                sTmp += sRight;
            }

            p += uRightLen;
            bInside = false;
            continue;
        }

        if (uDelimLen && !bInside && strncasecmp(p, sDelim.c_str(), uDelimLen) == 0) {
            vsRet.push_back(sTmp);
            sTmp.clear();
            p += uDelimLen;

            if (behavior == No::SkipEmptyParts) {
                while (strncasecmp(p, sDelim.c_str(), uDelimLen) == 0) {
                    p += uDelimLen;
                }
            }

            bInside = false;
            continue;
        } else {
            sTmp += *p;
        }

        p++;
    }

    if (!sTmp.empty()) {
        vsRet.push_back(sTmp);
    }

    return vsRet;
}

static NoString Token_impl(const NoString& s, size_t uPos, bool bRest, const NoString& sSep)
{
    const char* sep_str = sSep.c_str();
    size_t sep_len = sSep.length();
    const char* str = s.c_str();
    size_t str_len = s.length();
    size_t start_pos = 0;
    size_t end_pos;

    while (strncmp(&str[start_pos], sep_str, sep_len) == 0) {
        start_pos += sep_len;
    }

    // First, find the start of our token
    while (uPos != 0 && start_pos < str_len) {
        bool bFoundSep = false;

        while (strncmp(&str[start_pos], sep_str, sep_len) == 0) {
            start_pos += sep_len;
            bFoundSep = true;
        }

        if (bFoundSep) {
            uPos--;
        } else {
            start_pos++;
        }
    }

    // String is over?
    if (start_pos >= str_len)
        return "";

    // If they want everything from here on, give it to them
    if (bRest) {
        return s.substr(start_pos);
    }

    // Now look for the end of the token they want
    end_pos = start_pos;
    while (end_pos < str_len) {
        if (strncmp(&str[end_pos], sep_str, sep_len) == 0)
            return s.substr(start_pos, end_pos - start_pos);

        end_pos++;
    }

    // They want the last token in the string, not something in between
    return s.substr(start_pos);
}

NoString Token_helper(const NoString& str, size_t uPos, bool bRest, const NoString& sSep, const NoString& sLeft, const NoString& sRight)
{
    NoStringVector vsTokens = Split_helper(str, sSep, No::SkipEmptyParts, sLeft, sRight, false);
    if (vsTokens.size() > uPos) {
        NoString ret;

        for (size_t a = uPos; a < vsTokens.size(); a++) {
            if (a > uPos) {
                ret += sSep;
            }

            ret += vsTokens[a];

            if (!bRest) {
                break;
            }
        }

        return ret;
    }

    return Token_impl(str, uPos, bRest, sSep);
}

NoStringMap No::optionSplit(const NoString& str)
{
    NoString name;
    NoString sCopy(str);
    NoStringMap msRet;

    while (!sCopy.empty()) {
        name = Token_helper(sCopy, 0, false, "=", "\"", "\"").trim_n();
        sCopy = Token_helper(sCopy, 1, true, "=", "\"", "\"").trimLeft_n();

        if (name.empty()) {
            continue;
        }

        NoStringVector vsNames = Split_helper(name, " ", No::SkipEmptyParts, "\"", "\"", true);

        for (uint a = 0; a < vsNames.size(); a++) {
            NoString sKeyName = vsNames[a];

            if ((a + 1) == vsNames.size()) {
                msRet[sKeyName] = Token_helper(sCopy, 0, false, " ", "\"", "\"");
                sCopy = Token_helper(sCopy, 1, true, " ", "\"", "\"");
            } else {
                msRet[sKeyName] = "";
            }
        }
    }

    return msRet;
}

NoStringVector No::quoteSplit(const NoString& str)
{
    return Split_helper(str, " ", No::SkipEmptyParts, "\"", "\"", false);
}

bool No::wildCmp(const NoString& sString, const NoString& wild, No::CaseSensitivity cs)
{
    // avoid a copy when cs == No::CaseSensitive (C++ deliberately specifies that binding
    // a temporary object to a reference to const on the stack lengthens the lifetime
    // of the temporary to the lifetime of the reference itself)
    const NoString& wld = (cs == No::CaseSensitive ? wild : wild.toLower());
    const NoString& str = (cs == No::CaseSensitive ? sString : sString.toLower());

    // Written by Jack Handy - jakkhandy@hotmail.com
    const char* wd = wld.c_str(), *ns = str.c_str();
    const char* cp = nullptr, *mp = nullptr;

    while ((*ns) && (*wd != '*')) {
        if ((*wd != *ns) && (*wd != '?')) {
            return false;
        }

        wd++;
        ns++;
    }

    while (*ns) {
        if (*wd == '*') {
            if (!*++wd) {
                return true;
            }

            mp = wd;
            cp = ns + 1;
        } else if ((*wd == *ns) || (*wd == '?')) {
            wd++;
            ns++;
        } else {
            wd = mp;
            ns = cp++;
        }
    }

    while (*wd == '*') {
        wd++;
    }

    return (*wd == 0);
}

NoString No::token(const NoString& str, size_t uPos, const NoString& sSep)
{
    return Token_impl(str, uPos, false, sSep);
}

NoString No::tokens(const NoString& str, size_t uPos, const NoString& sSep)
{
    return Token_impl(str, uPos, true, sSep);
}

NoString No::firstLine(const NoString& str)
{
    return token(str, 0, "\n");
}
