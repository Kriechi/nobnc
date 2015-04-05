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

#include "nostring.h"
#include <sstream>

NoStringVector
Split_helper(const NoString& str, const NoString& sDelim, No::SplitBehavior, const NoString& sLeft, const NoString& sRight, bool bTrimQuotes);

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

NoString::NoString(const char* str) : std::string(str)
{
}

NoString::NoString(const char* str, uint size) : std::string(str, size)
{
}

NoString::NoString(const std::string& str) : std::string(str)
{
}

NoString::NoString(uint size, char ch) : std::string(size, ch)
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
    NoString ret = *this;
    for (char& c : ret) {
        // TODO use unicode
        c = (char)toupper(c);
    }
    return ret;
}

NoString NoString::toLower() const
{
    NoString ret = *this;
    for (char& c : ret) {
        // TODO use unicode
        c = (char)tolower(c);
    }
    return ret;
}

NoString NoString::replace_n(const NoString& sReplace, const NoString& sWith) const
{
    NoString ret = *this;
    ret.replace(sReplace, sWith);
    return ret;
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

NoString NoString::left(uint uCount) const
{
    uCount = (uCount > length()) ? length() : uCount;
    return substr(0, uCount);
}

NoString NoString::right(uint uCount) const
{
    uCount = (uCount > length()) ? length() : uCount;
    return substr(length() - uCount, uCount);
}

extern NoStringVector
Split_helper(const NoString& str, const NoString& sDelim, No::SplitBehavior behavior, const NoString& sLeft, const NoString& sRight, bool bTrimQuotes);

NoStringVector NoString::split(const NoString& separator, No::SplitBehavior behavior) const
{
    return Split_helper(*this, separator, behavior, "", "", true);
}

NoString NoString::toBase64(uint uWrap) const
{
    const char b64table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    NoString ret;
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
        return ret;
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
    ret = (char*)output;
    delete[] output;
    return ret;
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
    ulong len = sTmp.size();
    char* out = new char[len + 1];

    for (i = 0, p = out; i < len; i++) {
        c = (char)base64_table[(uchar)in[i++]];
        c1 = (char)base64_table[(uchar)in[i++]];
        *p++ = char((c << 2) | ((c1 >> 4) & 0x3));

        if (i < len) {
            if (in[i] == '=') {
                break;
            }
            c = (char)base64_table[(uchar)in[i]];
            *p++ = char(((c1 << 4) & 0xf0) | ((c >> 2) & 0xf));
        }

        if (++i < len) {
            if (in[i] == '=') {
                break;
            }
            *p++ = char(((c << 6) & 0xc0) | (char)base64_table[(uchar)in[i]]);
        }
    }

    *p = '\0';
    ulong uRet = p - out;
    NoString ret;
    ret.append(out, uRet);
    delete[] out;

    return ret;
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

    if (i == 0)
        return false;

    if (i != npos)
        this->erase(0, i);
    else
        this->clear();

    return true;
}

bool NoString::trimRight(const NoString& s)
{
    size_type i = find_last_not_of(s);

    if (i + 1 == length())
        return false;

    if (i != npos)
        this->erase(i + 1, npos);
    else
        this->clear();

    return true;
}

NoString NoString::trim_n(const NoString& s) const
{
    NoString ret = *this;
    ret.trim(s);
    return ret;
}

NoString NoString::trimLeft_n(const NoString& s) const
{
    NoString ret = *this;
    ret.trimLeft(s);
    return ret;
}

NoString NoString::trimRight_n(const NoString& s) const
{
    NoString ret = *this;
    ret.trimRight(s);
    return ret;
}

bool NoString::trimPrefix(const NoString& prefix)
{
    if (startsWith(prefix)) {
        leftChomp(prefix.length());
        return true;
    } else {
        return false;
    }
}

bool NoString::trimSuffix(const NoString& suffix)
{
    if (right(suffix.length()).equals(suffix)) {
        rightChomp(suffix.length());
        return true;
    } else {
        return false;
    }
}

ulong NoString::find(char c, No::CaseSensitivity cs) const
{
    return find(NoString(c), 0, cs);
}

ulong NoString::find(const NoString& s, No::CaseSensitivity cs) const
{
    return find(s, 0, cs);
}

ulong NoString::find(const NoString& s, uint pos, No::CaseSensitivity cs) const
{
    if (cs == No::CaseSensitive) {
        return std::string::find(s, pos);
    } else {
        return toLower().std::string::find(s.toLower(), pos);
    }
}

bool NoString::startsWith(const NoString& prefix, No::CaseSensitivity cs) const
{
    return left(prefix.length()).equals(prefix, cs);
}

bool NoString::endsWith(const NoString& suffix, No::CaseSensitivity cs) const
{
    return right(suffix.length()).equals(suffix, cs);
}

bool NoString::contains(char ch, No::CaseSensitivity cs) const
{
    return find(NoString(ch), cs) != npos;
}

bool NoString::contains(const NoString& s, No::CaseSensitivity cs) const
{
    return find(s, cs) != npos;
}

NoString NoString::trimPrefix_n(const NoString& prefix) const
{
    NoString ret = *this;
    ret.trimPrefix(prefix);
    return ret;
}

NoString NoString::trimSuffix_n(const NoString& suffix) const
{
    NoString ret = *this;
    ret.trimSuffix(suffix);
    return ret;
}

NoString NoString::leftChomp_n(uint len) const
{
    NoString ret = *this;
    ret.leftChomp(len);
    return ret;
}

NoString NoString::rightChomp_n(uint len) const
{
    NoString ret = *this;
    ret.rightChomp(len);
    return ret;
}

bool NoString::leftChomp(uint len)
{
    bool bRet = false;

    while ((len--) && (length())) {
        erase(0, 1);
        bRet = true;
    }

    return bRet;
}

bool NoString::rightChomp(uint len)
{
    bool bRet = false;

    while ((len--) && (length())) {
        erase(length() - 1);
        bRet = true;
    }

    return bRet;
}
