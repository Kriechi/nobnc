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

#include "nostring.h"
#include <sstream>

NoStringVector Split_helper(const NoString& str, const NoString& sDelim, No::SplitBehavior, const NoString& sLeft, const NoString& sRight, bool bTrimQuotes);

static const uchar XX = 0xff;
static const uchar base64_table[256] = {
    XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
    XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, 62, XX, XX, XX, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
    XX, XX, XX, XX, XX, XX, XX, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, XX, XX, XX, XX, XX, XX, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
    45, 46, 47, 48, 49, 50, 51, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
    XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
    XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
    XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
    XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,
};

NoString::NoString() : std::string()
{
}

NoString::NoString(const char* c) : std::string(c)
{
}

NoString::NoString(const char* c, size_t l) : std::string(c, l)
{
}

NoString::NoString(const std::string& s) : std::string(s)
{
}

NoString::NoString(size_t n, char c) : std::string(n, c)
{
}

NoString::NoString(bool b) : std::string(b ? "true" : "false")
{
}

NoString::NoString(char c) : std::string()
{
    std::stringstream s;
    s << c;
    *this = s.str();
}

NoString::NoString(uchar c) : std::string()
{
    std::stringstream s;
    s << c;
    *this = s.str();
}

NoString::NoString(short i) : std::string()
{
    std::stringstream s;
    s << i;
    *this = s.str();
}

NoString::NoString(ushort i) : std::string()
{
    std::stringstream s;
    s << i;
    *this = s.str();
}

NoString::NoString(int i) : std::string()
{
    std::stringstream s;
    s << i;
    *this = s.str();
}

NoString::NoString(uint i) : std::string()
{
    std::stringstream s;
    s << i;
    *this = s.str();
}

NoString::NoString(long i) : std::string()
{
    std::stringstream s;
    s << i;
    *this = s.str();
}

NoString::NoString(ulong i) : std::string()
{
    std::stringstream s;
    s << i;
    *this = s.str();
}

NoString::NoString(long long i) : std::string()
{
    std::stringstream s;
    s << i;
    *this = s.str();
}

NoString::NoString(ulonglong i) : std::string()
{
    std::stringstream s;
    s << i;
    *this = s.str();
}

NoString::NoString(double i, int precision) : std::string()
{
    std::stringstream s;
    s.precision(precision);
    s << std::fixed << i;
    *this = s.str();
}

NoString::NoString(float i, int precision) : std::string()
{
    std::stringstream s;
    s.precision(precision);
    s << std::fixed << i;
    *this = s.str();
}

int NoString::compare(const NoString& s, No::CaseSensitivity cs) const
{
    if (cs == No::CaseSensitive)
        return strcmp(c_str(), s.c_str());
    else
        return strcasecmp(c_str(), s.c_str());
}

bool NoString::equals(const NoString& s, No::CaseSensitivity cs) const
{
    return compare(s, cs) == 0;
}

NoString NoString::toUpper() const
{
    NoString sRet = *this;
    for (char& c : sRet) {
        // TODO use unicode
        c = (char)toupper(c);
    }
    return sRet;
}

NoString NoString::toLower() const
{
    NoString sRet = *this;
    for (char& c : sRet) {
        // TODO use unicode
        c = (char)tolower(c);
    }
    return sRet;
}

NoString NoString::replace_n(const NoString& sReplace, const NoString& sWith) const
{
    NoString sRet = *this;
    sRet.replace(sReplace, sWith);
    return sRet;
}

uint NoString::replace(const NoString& sReplace, const NoString& sWith)
{
    uint uRet = 0;
    NoString sCopy = *this;
    clear();

    NoString::size_type uReplaceWidth = sReplace.length();
    const char* p = sCopy.c_str();

    while (*p) {
        if (strncmp(p, sReplace.c_str(), uReplaceWidth) == 0) {
            append(sWith);
            p += uReplaceWidth - 1;
            uRet++;
        } else {
            append(p, 1);
        }

        p++;
    }

    return uRet;
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
    if (start_pos >= str_len) return "";

    // If they want everything from here on, give it to them
    if (bRest) {
        return s.substr(start_pos);
    }

    // Now look for the end of the token they want
    end_pos = start_pos;
    while (end_pos < str_len) {
        if (strncmp(&str[end_pos], sep_str, sep_len) == 0) return s.substr(start_pos, end_pos - start_pos);

        end_pos++;
    }

    // They want the last token in the string, not something in between
    return s.substr(start_pos);
}

NoString Token_helper(const NoString& str, size_t uPos, bool bRest, const NoString& sSep, const NoString& sLeft, const NoString& sRight)
{
    NoStringVector vsTokens = Split_helper(str, sSep, No::SkipEmptyParts, sLeft, sRight, false);
    if (vsTokens.size() > uPos) {
        NoString sRet;

        for (size_t a = uPos; a < vsTokens.size(); a++) {
            if (a > uPos) {
                sRet += sSep;
            }

            sRet += vsTokens[a];

            if (!bRest) {
                break;
            }
        }

        return sRet;
    }

    return Token_impl(str, uPos, bRest, sSep);
}

NoString NoString::token(size_t uPos, const NoString& sSep) const
{
    return Token_impl(*this, uPos, false, sSep);
}

NoString NoString::tokens(size_t uPos, const NoString& sSep) const
{
    return Token_impl(*this, uPos, true, sSep);
}

NoString NoString::left(size_type uCount) const
{
    uCount = (uCount > length()) ? length() : uCount;
    return substr(0, uCount);
}

NoString NoString::right(size_type uCount) const
{
    uCount = (uCount > length()) ? length() : uCount;
    return substr(length() - uCount, uCount);
}

NoStringVector Split_helper(const NoString& str, const NoString& sDelim, No::SplitBehavior behavior, const NoString& sLeft, const NoString& sRight, bool bTrimQuotes)
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

NoStringVector NoString::split(const NoString& separator, No::SplitBehavior behavior) const
{
    return Split_helper(*this, separator, behavior, "", "", true);
}

NoString NoString::toBase64(uint uWrap) const
{
    const char b64table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    NoString sRet;
    size_t len = size();
    const uchar* input = (const uchar*)c_str();
    uchar* output, *p;
    size_t i = 0, mod = len % 3, toalloc;
    toalloc = (len / 3) * 4 + (3 - mod) % 3 + 1 + 8;

    if (uWrap) {
        toalloc += len / 57;
        if (len % 57) {
            toalloc++;
        }
    }

    if (toalloc < len) {
        return sRet;
    }

    p = output = new uchar[toalloc];

    while (i < len - mod) {
        *p++ = b64table[input[i++] >> 2];
        *p++ = b64table[((input[i - 1] << 4) | (input[i] >> 4)) & 0x3f];
        *p++ = b64table[((input[i] << 2) | (input[i + 1] >> 6)) & 0x3f];
        *p++ = b64table[input[i + 1] & 0x3f];
        i += 2;

        if (uWrap && !(i % 57)) {
            *p++ = '\n';
        }
    }

    if (!mod) {
        if (uWrap && i % 57) {
            *p++ = '\n';
        }
    } else {
        *p++ = b64table[input[i++] >> 2];
        *p++ = b64table[((input[i - 1] << 4) | (input[i] >> 4)) & 0x3f];
        if (mod == 1) {
            *p++ = '=';
        } else {
            *p++ = b64table[(input[i] << 2) & 0x3f];
        }

        *p++ = '=';

        if (uWrap) {
            *p++ = '\n';
        }
    }

    *p = 0;
    sRet = (char*)output;
    delete[] output;
    return sRet;
}

NoString NoString::fromBase64(const NoString& base64)
{
    NoString sTmp(base64);
    // remove new lines
    sTmp.replace("\r", "");
    sTmp.replace("\n", "");

    const char* in = sTmp.c_str();
    char c, c1, *p;
    ulong i;
    ulong uLen = sTmp.size();
    char* out = new char[uLen + 1];

    for (i = 0, p = out; i < uLen; i++) {
        c = (char)base64_table[(uchar)in[i++]];
        c1 = (char)base64_table[(uchar)in[i++]];
        *p++ = char((c << 2) | ((c1 >> 4) & 0x3));

        if (i < uLen) {
            if (in[i] == '=') {
                break;
            }
            c = (char)base64_table[(uchar)in[i]];
            *p++ = char(((c1 << 4) & 0xf0) | ((c >> 2) & 0xf));
        }

        if (++i < uLen) {
            if (in[i] == '=') {
                break;
            }
            *p++ = char(((c << 6) & 0xc0) | (char)base64_table[(uchar)in[i]]);
        }
    }

    *p = '\0';
    ulong uRet = p - out;
    NoString sRet;
    sRet.append(out, uRet);
    delete[] out;

    return sRet;
}

bool NoString::toBool() const
{
    NoString sTrimmed = trim_n();
    return (!sTrimmed.trim_n("0").empty() && !sTrimmed.equals("false") && !sTrimmed.equals("off") &&
            !sTrimmed.equals("no") && !sTrimmed.equals("n"));
}

short NoString::toShort() const
{
    return (short int)strtol(this->c_str(), (char**)nullptr, 10);
}

ushort NoString::toUShort() const
{
    return (ushort)strtoul(this->c_str(), (char**)nullptr, 10);
}

uint NoString::toUInt() const
{
    return (uint)strtoul(this->c_str(), (char**)nullptr, 10);
}

int NoString::toInt() const
{
    return (int)strtol(this->c_str(), (char**)nullptr, 10);
}

long NoString::toLong() const
{
    return strtol(this->c_str(), (char**)nullptr, 10);
}

ulong NoString::toULong() const
{
    return strtoul(c_str(), nullptr, 10);
}

ulonglong NoString::toULongLong() const
{
    return strtoull(c_str(), nullptr, 10);
}

long long NoString::toLongLong() const
{
    return strtoll(c_str(), nullptr, 10);
}

double NoString::toDouble() const
{
    return strtod(c_str(), nullptr);
}

bool NoString::trim(const NoString& s)
{
    bool bLeft = trimLeft(s);
    return (trimRight(s) || bLeft);
}

bool NoString::trimLeft(const NoString& s)
{
    size_type i = find_first_not_of(s);

    if (i == 0) return false;

    if (i != npos)
        this->erase(0, i);
    else
        this->clear();

    return true;
}

bool NoString::trimRight(const NoString& s)
{
    size_type i = find_last_not_of(s);

    if (i + 1 == length()) return false;

    if (i != npos)
        this->erase(i + 1, npos);
    else
        this->clear();

    return true;
}

NoString NoString::trim_n(const NoString& s) const
{
    NoString sRet = *this;
    sRet.trim(s);
    return sRet;
}

NoString NoString::trimLeft_n(const NoString& s) const
{
    NoString sRet = *this;
    sRet.trimLeft(s);
    return sRet;
}

NoString NoString::trimRight_n(const NoString& s) const
{
    NoString sRet = *this;
    sRet.trimRight(s);
    return sRet;
}

bool NoString::trimPrefix(const NoString& sPrefix)
{
    if (startsWith(sPrefix)) {
        leftChomp(sPrefix.length());
        return true;
    } else {
        return false;
    }
}

bool NoString::trimSuffix(const NoString& sSuffix)
{
    if (right(sSuffix.length()).equals(sSuffix)) {
        rightChomp(sSuffix.length());
        return true;
    } else {
        return false;
    }
}

size_t NoString::find(char c, No::CaseSensitivity cs) const
{
    return find(NoString(c), cs);
}

size_t NoString::find(const NoString& s, No::CaseSensitivity cs) const
{
    return find(s, 0, cs);
}

size_t NoString::find(const NoString& s, size_t pos, No::CaseSensitivity cs) const
{
    if (cs == No::CaseSensitive) {
        return std::string::find(s, pos);
    } else {
        return toLower().std::string::find(s.toLower(), pos);
    }
}

bool NoString::startsWith(const NoString& sPrefix, No::CaseSensitivity cs) const
{
    return left(sPrefix.length()).equals(sPrefix, cs);
}

bool NoString::endsWith(const NoString& sSuffix, No::CaseSensitivity cs) const
{
    return right(sSuffix.length()).equals(sSuffix, cs);
}

bool NoString::contains(const NoString& s, No::CaseSensitivity cs) const
{
    return find(s, cs) != npos;
}

NoString NoString::trimPrefix_n(const NoString& sPrefix) const
{
    NoString sRet = *this;
    sRet.trimPrefix(sPrefix);
    return sRet;
}

NoString NoString::trimSuffix_n(const NoString& sSuffix) const
{
    NoString sRet = *this;
    sRet.trimSuffix(sSuffix);
    return sRet;
}

NoString NoString::leftChomp_n(size_type uLen) const
{
    NoString sRet = *this;
    sRet.leftChomp(uLen);
    return sRet;
}

NoString NoString::rightChomp_n(size_type uLen) const
{
    NoString sRet = *this;
    sRet.rightChomp(uLen);
    return sRet;
}

bool NoString::leftChomp(size_type uLen)
{
    bool bRet = false;

    while ((uLen--) && (length())) {
        erase(0, 1);
        bRet = true;
    }

    return bRet;
}

bool NoString::rightChomp(size_type uLen)
{
    bool bRet = false;

    while ((uLen--) && (length())) {
        erase(length() - 1);
        bRet = true;
    }

    return bRet;
}
