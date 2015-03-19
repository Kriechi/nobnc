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

uchar* NoString::strnchr(const uchar* src, uchar c, uint iMaxBytes, uchar* pFill, uint* piCount) const
{
    for (uint a = 0; a < iMaxBytes && *src; a++, src++) {
        if (pFill) {
            pFill[a] = *src;
        }

        if (*src == c) {
            if (pFill) {
                pFill[a + 1] = 0;
            }

            if (piCount) {
                *piCount = a;
            }

            return (uchar*)src;
        }
    }

    if (pFill) {
        *pFill = 0;
    }

    if (piCount) {
        *piCount = 0;
    }

    return nullptr;
}

int NoString::Compare(const NoString& s, CaseSensitivity cs) const
{
    if (cs == CaseSensitive)
        return strcmp(c_str(), s.c_str());
    else
        return strcasecmp(c_str(), s.c_str());
}

bool NoString::Equals(const NoString& s, CaseSensitivity cs) const
{
    return Compare(s, cs) == 0;
}

bool NoString::WildCmp(const NoString& sWild, CaseSensitivity cs) const
{
    // avoid a copy when cs == CaseSensitive (C++ deliberately specifies that binding
    // a temporary object to a reference to const on the stack lengthens the lifetime
    // of the temporary to the lifetime of the reference itself)
    const NoString& sWld = (cs == CaseSensitive ? sWild : sWild.AsLower());
    const NoString& sStr = (cs == CaseSensitive ? *this : AsLower());

    // Written by Jack Handy - jakkhandy@hotmail.com
    const char* wild = sWld.c_str(), *NoString = sStr.c_str();
    const char* cp = nullptr, *mp = nullptr;

    while ((*NoString) && (*wild != '*')) {
        if ((*wild != *NoString) && (*wild != '?')) {
            return false;
        }

        wild++;
        NoString++;
    }

    while (*NoString) {
        if (*wild == '*') {
            if (!*++wild) {
                return true;
            }

            mp = wild;
            cp = NoString + 1;
        } else if ((*wild == *NoString) || (*wild == '?')) {
            wild++;
            NoString++;
        } else {
            wild = mp;
            NoString = cp++;
        }
    }

    while (*wild == '*') {
        wild++;
    }

    return (*wild == 0);
}

NoString& NoString::MakeUpper()
{
    for (char& c : *this) {
        // TODO use unicode
        c = (char)toupper(c);
    }

    return *this;
}

NoString& NoString::MakeLower()
{
    for (char& c : *this) {
        // TODO use unicode
        c = (char)tolower(c);
    }

    return *this;
}

NoString NoString::AsUpper() const
{
    NoString sRet = *this;
    sRet.MakeUpper();
    return sRet;
}

NoString NoString::AsLower() const
{
    NoString sRet = *this;
    sRet.MakeLower();
    return sRet;
}

NoString::EEscape NoString::ToEscape(const NoString& sEsc)
{
    if (sEsc.Equals("ASCII")) {
        return EASCII;
    } else if (sEsc.Equals("HTML")) {
        return EHTML;
    } else if (sEsc.Equals("URL")) {
        return EURL;
    } else if (sEsc.Equals("SQL")) {
        return ESQL;
    } else if (sEsc.Equals("NAMEDFMT")) {
        return ENAMEDFMT;
    } else if (sEsc.Equals("DEBUG")) {
        return EDEBUG;
    } else if (sEsc.Equals("MSGTAG")) {
        return EMSGTAG;
    } else if (sEsc.Equals("HEXCOLON")) {
        return EHEXCOLON;
    }

    return EASCII;
}

NoString NoString::Escape_n(EEscape eFrom, EEscape eTo) const
{
    NoString sRet;
    const char szHex[] = "0123456789ABCDEF";
    const uchar* pStart = (const uchar*)data();
    const uchar* p = (const uchar*)data();
    size_type iLength = length();
    sRet.reserve(iLength * 3);
    uchar pTmp[21];
    uint iCounted = 0;

    for (uint a = 0; a < iLength; a++, p = pStart + a) {
        uchar ch = 0;

        switch (eFrom) {
        case EHTML:
            if ((*p == '&') && (strnchr((uchar*)p, ';', sizeof(pTmp) - 1, pTmp, &iCounted))) {
                // please note that we do not have any Unicode or UTF-8 support here at all.

                if ((iCounted >= 3) && (pTmp[1] == '#')) { // do XML and HTML &#97; &#x3c
                    int base = 10;

                    if ((pTmp[2] & 0xDF) == 'X') {
                        base = 16;
                    }

                    char* endptr = nullptr;
                    ulong b = strtol((const char*)(pTmp + 2 + (base == 16)), &endptr, base);

                    if ((*endptr == ';') && (b <= 255)) { // incase they do something like &#7777777777;
                        ch = (uchar)b;
                        a += iCounted;
                        break;
                    }
                }

                if (ch == 0) {
                    if (!strncasecmp((const char*)&pTmp, "&lt;", 2))
                        ch = '<';
                    else if (!strncasecmp((const char*)&pTmp, "&gt;", 2))
                        ch = '>';
                    else if (!strncasecmp((const char*)&pTmp, "&quot;", 4))
                        ch = '"';
                    else if (!strncasecmp((const char*)&pTmp, "&amp;", 3))
                        ch = '&';
                }

                if (ch > 0) {
                    a += iCounted;
                } else {
                    ch = *p; // Not a valid escape, just record the &
                }
            } else {
                ch = *p;
            }
            break;
        case EASCII:
            ch = *p;
            break;
        case EURL:
            if (*p == '%' && (a + 2) < iLength && isxdigit(*(p + 1)) && isxdigit(*(p + 2))) {
                p++;
                if (isdigit(*p)) {
                    ch = (uchar)((*p - '0') << 4);
                } else {
                    ch = (uchar)((tolower(*p) - 'a' + 10) << 4);
                }

                p++;
                if (isdigit(*p)) {
                    ch |= (uchar)(*p - '0');
                } else {
                    ch |= (uchar)(tolower(*p) - 'a' + 10);
                }

                a += 2;
            } else if (pStart[a] == '+') {
                ch = ' ';
            } else {
                ch = *p;
            }

            break;
        case ESQL:
            if (*p != '\\' || iLength < (a + 1)) {
                ch = *p;
            } else {
                a++;
                p++;

                if (*p == 'n') {
                    ch = '\n';
                } else if (*p == 'r') {
                    ch = '\r';
                } else if (*p == '0') {
                    ch = '\0';
                } else if (*p == 't') {
                    ch = '\t';
                } else if (*p == 'b') {
                    ch = '\b';
                } else {
                    ch = *p;
                }
            }

            break;
        case ENAMEDFMT:
            if (*p != '\\' || iLength < (a + 1)) {
                ch = *p;
            } else {
                a++;
                p++;
                ch = *p;
            }

            break;
        case EDEBUG:
            if (*p == '\\' && (a + 3) < iLength && *(p + 1) == 'x' && isxdigit(*(p + 2)) && isxdigit(*(p + 3))) {
                p += 2;
                if (isdigit(*p)) {
                    ch = (uchar)((*p - '0') << 4);
                } else {
                    ch = (uchar)((tolower(*p) - 'a' + 10) << 4);
                }

                p++;
                if (isdigit(*p)) {
                    ch |= (uchar)(*p - '0');
                } else {
                    ch |= (uchar)(tolower(*p) - 'a' + 10);
                }

                a += 3;
            } else if (*p == '\\' && a + 1 < iLength && *(p + 1) == '.') {
                a++;
                p++;
                ch = '\\';
            } else {
                ch = *p;
            }

            break;
        case EMSGTAG:
            if (*p != '\\' || iLength < (a + 1)) {
                ch = *p;
            } else {
                a++;
                p++;

                if (*p == ':') {
                    ch = ';';
                } else if (*p == 's') {
                    ch = ' ';
                } else if (*p == '0') {
                    ch = '\0';
                } else if (*p == '\\') {
                    ch = '\\';
                } else if (*p == 'r') {
                    ch = '\r';
                } else if (*p == 'n') {
                    ch = '\n';
                } else {
                    ch = *p;
                }
            }

            break;
        case EHEXCOLON: {
            while (!isxdigit(*p) && a < iLength) {
                a++;
                p++;
            }
            if (a == iLength) {
                continue;
            }
            if (isdigit(*p)) {
                ch = (uchar)((*p - '0') << 4);
            } else {
                ch = (uchar)((tolower(*p) - 'a' + 10) << 4);
            }
            a++;
            p++;
            while (!isxdigit(*p) && a < iLength) {
                a++;
                p++;
            }
            if (a == iLength) {
                continue;
            }
            if (isdigit(*p)) {
                ch |= (uchar)(*p - '0');
            } else {
                ch |= (uchar)(tolower(*p) - 'a' + 10);
            }
        } break;
        }

        switch (eTo) {
        case EHTML:
            if (ch == '<')
                sRet += "&lt;";
            else if (ch == '>')
                sRet += "&gt;";
            else if (ch == '"')
                sRet += "&quot;";
            else if (ch == '&')
                sRet += "&amp;";
            else {
                sRet += ch;
            }

            break;
        case EASCII:
            sRet += ch;
            break;
        case EURL:
            if (isalnum(ch) || ch == '_' || ch == '.' || ch == '-') {
                sRet += ch;
            } else if (ch == ' ') {
                sRet += '+';
            } else {
                sRet += '%';
                sRet += szHex[ch >> 4];
                sRet += szHex[ch & 0xf];
            }

            break;
        case ESQL:
            if (ch == '\0') {
                sRet += '\\';
                sRet += '0';
            } else if (ch == '\n') {
                sRet += '\\';
                sRet += 'n';
            } else if (ch == '\t') {
                sRet += '\\';
                sRet += 't';
            } else if (ch == '\r') {
                sRet += '\\';
                sRet += 'r';
            } else if (ch == '\b') {
                sRet += '\\';
                sRet += 'b';
            } else if (ch == '\"') {
                sRet += '\\';
                sRet += '\"';
            } else if (ch == '\'') {
                sRet += '\\';
                sRet += '\'';
            } else if (ch == '\\') {
                sRet += '\\';
                sRet += '\\';
            } else {
                sRet += ch;
            }

            break;
        case ENAMEDFMT:
            if (ch == '\\') {
                sRet += '\\';
                sRet += '\\';
            } else if (ch == '{') {
                sRet += '\\';
                sRet += '{';
            } else if (ch == '}') {
                sRet += '\\';
                sRet += '}';
            } else {
                sRet += ch;
            }

            break;
        case EDEBUG:
            if (ch < 0x20 || ch == 0x7F) {
                sRet += "\\x";
                sRet += szHex[ch >> 4];
                sRet += szHex[ch & 0xf];
            } else if (ch == '\\') {
                sRet += "\\.";
            } else {
                sRet += ch;
            }

            break;
        case EMSGTAG:
            if (ch == ';') {
                sRet += '\\';
                sRet += ':';
            } else if (ch == ' ') {
                sRet += '\\';
                sRet += 's';
            } else if (ch == '\0') {
                sRet += '\\';
                sRet += '0';
            } else if (ch == '\\') {
                sRet += '\\';
                sRet += '\\';
            } else if (ch == '\r') {
                sRet += '\\';
                sRet += 'r';
            } else if (ch == '\n') {
                sRet += '\\';
                sRet += 'n';
            } else {
                sRet += ch;
            }

            break;
        case EHEXCOLON: {
            sRet += tolower(szHex[ch >> 4]);
            sRet += tolower(szHex[ch & 0xf]);
            sRet += ":";
        } break;
        }
    }

    if (eTo == EHEXCOLON) {
        sRet.TrimRight(":");
    }

    return sRet;
}

NoString NoString::Escape_n(EEscape eTo) const
{
    return Escape_n(EASCII, eTo);
}

NoString& NoString::Escape(EEscape eFrom, EEscape eTo)
{
    return (*this = Escape_n(eFrom, eTo));
}

NoString& NoString::Escape(EEscape eTo)
{
    return (*this = Escape_n(eTo));
}

NoString NoString::Replace_n(const NoString& sReplace, const NoString& sWith, const NoString& sLeft, const NoString& sRight, bool bRemoveDelims) const
{
    NoString sRet = *this;
    sRet.Replace(sReplace, sWith, sLeft, sRight, bRemoveDelims);
    return sRet;
}

uint NoString::Replace(const NoString& sReplace, const NoString& sWith, const NoString& sLeft, const NoString& sRight, bool bRemoveDelims)
{
    uint uRet = 0;
    NoString sCopy = *this;
    clear();

    NoString::size_type uReplaceWidth = sReplace.length();
    NoString::size_type uLeftWidth = sLeft.length();
    NoString::size_type uRightWidth = sRight.length();
    const char* p = sCopy.c_str();
    bool bInside = false;

    while (*p) {
        if (!bInside && uLeftWidth && strncmp(p, sLeft.c_str(), uLeftWidth) == 0) {
            if (!bRemoveDelims) {
                append(sLeft);
            }

            p += uLeftWidth - 1;
            bInside = true;
        } else if (bInside && uRightWidth && strncmp(p, sRight.c_str(), uRightWidth) == 0) {
            if (!bRemoveDelims) {
                append(sRight);
            }

            p += uRightWidth - 1;
            bInside = false;
        } else if (!bInside && strncmp(p, sReplace.c_str(), uReplaceWidth) == 0) {
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

NoString NoString::Token(size_t uPos, bool bRest, const NoString& sSep, bool bAllowEmpty, const NoString& sLeft, const NoString& sRight, bool bTrimQuotes) const
{
    NoStringVector vsTokens;
    if (Split(sSep, vsTokens, bAllowEmpty, sLeft, sRight, bTrimQuotes) > uPos) {
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

    return Token(uPos, bRest, sSep, bAllowEmpty);
}

NoString NoString::Token(size_t uPos, bool bRest, const NoString& sSep, bool bAllowEmpty) const
{
    const char* sep_str = sSep.c_str();
    size_t sep_len = sSep.length();
    const char* str = c_str();
    size_t str_len = length();
    size_t start_pos = 0;
    size_t end_pos;

    if (!bAllowEmpty) {
        while (strncmp(&str[start_pos], sep_str, sep_len) == 0) {
            start_pos += sep_len;
        }
    }

    // First, find the start of our token
    while (uPos != 0 && start_pos < str_len) {
        bool bFoundSep = false;

        while (strncmp(&str[start_pos], sep_str, sep_len) == 0 && (!bFoundSep || !bAllowEmpty)) {
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
        return substr(start_pos);
    }

    // Now look for the end of the token they want
    end_pos = start_pos;
    while (end_pos < str_len) {
        if (strncmp(&str[end_pos], sep_str, sep_len) == 0) return substr(start_pos, end_pos - start_pos);

        end_pos++;
    }

    // They want the last token in the string, not something in between
    return substr(start_pos);
}

NoString NoString::Left(size_type uCount) const
{
    uCount = (uCount > length()) ? length() : uCount;
    return substr(0, uCount);
}

NoString NoString::Right(size_type uCount) const
{
    uCount = (uCount > length()) ? length() : uCount;
    return substr(length() - uCount, uCount);
}

NoString::size_type NoString::Split(const NoString& sDelim, NoStringVector& vsRet, bool bAllowEmpty, const NoString& sLeft, const NoString& sRight, bool bTrimQuotes, bool bTrimWhiteSpace) const
{
    vsRet.clear();

    if (empty()) {
        return 0;
    }

    NoString sTmp;
    bool bInside = false;
    size_type uDelimLen = sDelim.length();
    size_type uLeftLen = sLeft.length();
    size_type uRightLen = sRight.length();
    const char* p = c_str();

    if (!bAllowEmpty) {
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
            if (bTrimWhiteSpace) {
                sTmp.Trim();
            }

            vsRet.push_back(sTmp);
            sTmp.clear();
            p += uDelimLen;

            if (!bAllowEmpty) {
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
        if (bTrimWhiteSpace) {
            sTmp.Trim();
        }

        vsRet.push_back(sTmp);
    }

    return vsRet.size();
}

NoString::size_type NoString::Split(const NoString& sDelim, NoStringSet& ssRet, bool bAllowEmpty, const NoString& sLeft, const NoString& sRight, bool bTrimQuotes, bool bTrimWhiteSpace) const
{
    NoStringVector vsTokens;

    Split(sDelim, vsTokens, bAllowEmpty, sLeft, sRight, bTrimQuotes, bTrimWhiteSpace);

    ssRet.clear();

    for (const NoString& sToken : vsTokens) {
        ssRet.insert(sToken);
    }

    return ssRet.size();
}

NoString NoString::ToBase64(uint uWrap) const
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

NoString NoString::FromBase64(const NoString& base64)
{
    NoString sTmp(base64);
    // remove new lines
    sTmp.Replace("\r", "");
    sTmp.Replace("\n", "");

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

bool NoString::ToBool() const
{
    NoString sTrimmed = Trim_n();
    return (!sTrimmed.Trim_n("0").empty() && !sTrimmed.Equals("false") && !sTrimmed.Equals("off") &&
            !sTrimmed.Equals("no") && !sTrimmed.Equals("n"));
}

short NoString::ToShort() const
{
    return (short int)strtol(this->c_str(), (char**)nullptr, 10);
}

ushort NoString::ToUShort() const
{
    return (ushort)strtoul(this->c_str(), (char**)nullptr, 10);
}

uint NoString::ToUInt() const
{
    return (uint)strtoul(this->c_str(), (char**)nullptr, 10);
}

int NoString::ToInt() const
{
    return (int)strtol(this->c_str(), (char**)nullptr, 10);
}

long NoString::ToLong() const
{
    return strtol(this->c_str(), (char**)nullptr, 10);
}

ulong NoString::ToULong() const
{
    return strtoul(c_str(), nullptr, 10);
}

ulonglong NoString::ToULongLong() const
{
    return strtoull(c_str(), nullptr, 10);
}

long long NoString::ToLongLong() const
{
    return strtoll(c_str(), nullptr, 10);
}

double NoString::ToDouble() const
{
    return strtod(c_str(), nullptr);
}

bool NoString::Trim(const NoString& s)
{
    bool bLeft = TrimLeft(s);
    return (TrimRight(s) || bLeft);
}

bool NoString::TrimLeft(const NoString& s)
{
    size_type i = find_first_not_of(s);

    if (i == 0) return false;

    if (i != npos)
        this->erase(0, i);
    else
        this->clear();

    return true;
}

bool NoString::TrimRight(const NoString& s)
{
    size_type i = find_last_not_of(s);

    if (i + 1 == length()) return false;

    if (i != npos)
        this->erase(i + 1, npos);
    else
        this->clear();

    return true;
}

NoString NoString::Trim_n(const NoString& s) const
{
    NoString sRet = *this;
    sRet.Trim(s);
    return sRet;
}

NoString NoString::TrimLeft_n(const NoString& s) const
{
    NoString sRet = *this;
    sRet.TrimLeft(s);
    return sRet;
}

NoString NoString::TrimRight_n(const NoString& s) const
{
    NoString sRet = *this;
    sRet.TrimRight(s);
    return sRet;
}

bool NoString::TrimPrefix(const NoString& sPrefix)
{
    if (StartsWith(sPrefix)) {
        LeftChomp(sPrefix.length());
        return true;
    } else {
        return false;
    }
}

bool NoString::TrimSuffix(const NoString& sSuffix)
{
    if (Right(sSuffix.length()).Equals(sSuffix)) {
        RightChomp(sSuffix.length());
        return true;
    } else {
        return false;
    }
}

size_t NoString::Find(const NoString& s, CaseSensitivity cs) const
{
    if (cs == CaseSensitive) {
        return find(s);
    } else {
        return AsLower().find(s.AsLower());
    }
}

bool NoString::StartsWith(const NoString& sPrefix, CaseSensitivity cs) const
{
    return Left(sPrefix.length()).Equals(sPrefix, cs);
}

bool NoString::EndsWith(const NoString& sSuffix, CaseSensitivity cs) const
{
    return Right(sSuffix.length()).Equals(sSuffix, cs);
}

bool NoString::Contains(const NoString& s, CaseSensitivity cs) const
{
    return Find(s, cs) != npos;
}

NoString NoString::TrimPrefix_n(const NoString& sPrefix) const
{
    NoString sRet = *this;
    sRet.TrimPrefix(sPrefix);
    return sRet;
}

NoString NoString::TrimSuffix_n(const NoString& sSuffix) const
{
    NoString sRet = *this;
    sRet.TrimSuffix(sSuffix);
    return sRet;
}

NoString NoString::LeftChomp_n(size_type uLen) const
{
    NoString sRet = *this;
    sRet.LeftChomp(uLen);
    return sRet;
}

NoString NoString::RightChomp_n(size_type uLen) const
{
    NoString sRet = *this;
    sRet.RightChomp(uLen);
    return sRet;
}

bool NoString::LeftChomp(size_type uLen)
{
    bool bRet = false;

    while ((uLen--) && (length())) {
        erase(0, 1);
        bRet = true;
    }

    return bRet;
}

bool NoString::RightChomp(size_type uLen)
{
    bool bRet = false;

    while ((uLen--) && (length())) {
        erase(length() - 1);
        bRet = true;
    }

    return bRet;
}
