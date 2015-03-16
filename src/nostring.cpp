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
#include "nofile.h"
#include "noutils.h"
#include "nomd5.h"
#include "nosha256.h"
#include <sstream>

using std::stringstream;

NoString::NoString(char c) : string()
{
    stringstream s;
    s << c;
    *this = s.str();
}
NoString::NoString(unsigned char c) : string()
{
    stringstream s;
    s << c;
    *this = s.str();
}
NoString::NoString(short i) : string()
{
    stringstream s;
    s << i;
    *this = s.str();
}
NoString::NoString(unsigned short i) : string()
{
    stringstream s;
    s << i;
    *this = s.str();
}
NoString::NoString(int i) : string()
{
    stringstream s;
    s << i;
    *this = s.str();
}
NoString::NoString(unsigned int i) : string()
{
    stringstream s;
    s << i;
    *this = s.str();
}
NoString::NoString(long i) : string()
{
    stringstream s;
    s << i;
    *this = s.str();
}
NoString::NoString(unsigned long i) : string()
{
    stringstream s;
    s << i;
    *this = s.str();
}
NoString::NoString(long long i) : string()
{
    stringstream s;
    s << i;
    *this = s.str();
}
NoString::NoString(unsigned long long i) : string()
{
    stringstream s;
    s << i;
    *this = s.str();
}
NoString::NoString(double i, int precision) : string()
{
    stringstream s;
    s.precision(precision);
    s << std::fixed << i;
    *this = s.str();
}
NoString::NoString(float i, int precision) : string()
{
    stringstream s;
    s.precision(precision);
    s << std::fixed << i;
    *this = s.str();
}

unsigned char*
NoString::strnchr(const unsigned char* src, unsigned char c, unsigned int iMaxBytes, unsigned char* pFill, unsigned int* piCount) const
{
    for (unsigned int a = 0; a < iMaxBytes && *src; a++, src++) {
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

            return (unsigned char*)src;
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

int NoString::CaseCmp(const NoString& s, NoString::size_type uLen) const
{
    if (uLen != NoString::npos) {
        return strncasecmp(c_str(), s.c_str(), uLen);
    }
    return strcasecmp(c_str(), s.c_str());
}

int NoString::StrCmp(const NoString& s, NoString::size_type uLen) const
{
    if (uLen != NoString::npos) {
        return strncmp(c_str(), s.c_str(), uLen);
    }
    return strcmp(c_str(), s.c_str());
}

bool NoString::Equals(const NoString& s, CaseSensitivity cs) const
{
    if (cs == CaseSensitive) {
        return (StrCmp(s) == 0);
    } else {
        return (CaseCmp(s) == 0);
    }
}

bool NoString::Equals(const NoString& s, bool bCaseSensitive, NoString::size_type uLen) const
{
    if (bCaseSensitive) {
        return (StrCmp(s, uLen) == 0);
    } else {
        return (CaseCmp(s, uLen) == 0);
    }
}

bool NoString::WildCmp(const NoString& sWild, const NoString& sString, CaseSensitivity cs)
{
    // avoid a copy when cs == CaseSensitive (C++ deliberately specifies that binding
    // a temporary object to a reference to const on the stack lengthens the lifetime
    // of the temporary to the lifetime of the reference itself)
    const NoString& sWld = (cs == CaseSensitive ? sWild : sWild.AsLower());
    const NoString& sStr = (cs == CaseSensitive ? sString : sString.AsLower());

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

bool NoString::WildCmp(const NoString& sWild, CaseSensitivity cs) const { return NoString::WildCmp(sWild, *this, cs); }

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
    const unsigned char* pStart = (const unsigned char*)data();
    const unsigned char* p = (const unsigned char*)data();
    size_type iLength = length();
    sRet.reserve(iLength * 3);
    unsigned char pTmp[21];
    unsigned int iCounted = 0;

    for (unsigned int a = 0; a < iLength; a++, p = pStart + a) {
        unsigned char ch = 0;

        switch (eFrom) {
        case EHTML:
            if ((*p == '&') && (strnchr((unsigned char*)p, ';', sizeof(pTmp) - 1, pTmp, &iCounted))) {
                // please note that we do not have any Unicode or UTF-8 support here at all.

                if ((iCounted >= 3) && (pTmp[1] == '#')) { // do XML and HTML &#97; &#x3c
                    int base = 10;

                    if ((pTmp[2] & 0xDF) == 'X') {
                        base = 16;
                    }

                    char* endptr = nullptr;
                    unsigned long int b = strtol((const char*)(pTmp + 2 + (base == 16)), &endptr, base);

                    if ((*endptr == ';') && (b <= 255)) { // incase they do something like &#7777777777;
                        ch = (unsigned char)b;
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
                    ch = (unsigned char)((*p - '0') << 4);
                } else {
                    ch = (unsigned char)((tolower(*p) - 'a' + 10) << 4);
                }

                p++;
                if (isdigit(*p)) {
                    ch |= (unsigned char)(*p - '0');
                } else {
                    ch |= (unsigned char)(tolower(*p) - 'a' + 10);
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
                    ch = (unsigned char)((*p - '0') << 4);
                } else {
                    ch = (unsigned char)((tolower(*p) - 'a' + 10) << 4);
                }

                p++;
                if (isdigit(*p)) {
                    ch |= (unsigned char)(*p - '0');
                } else {
                    ch |= (unsigned char)(tolower(*p) - 'a' + 10);
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
                ch = (unsigned char)((*p - '0') << 4);
            } else {
                ch = (unsigned char)((tolower(*p) - 'a' + 10) << 4);
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
                ch |= (unsigned char)(*p - '0');
            } else {
                ch |= (unsigned char)(tolower(*p) - 'a' + 10);
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

NoString NoString::Escape_n(EEscape eTo) const { return Escape_n(EASCII, eTo); }

NoString& NoString::Escape(EEscape eFrom, EEscape eTo) { return (*this = Escape_n(eFrom, eTo)); }

NoString& NoString::Escape(EEscape eTo) { return (*this = Escape_n(eTo)); }

NoString NoString::Replace_n(const NoString& sReplace, const NoString& sWith, const NoString& sLeft, const NoString& sRight, bool bRemoveDelims) const
{
    NoString sRet = *this;
    NoString::Replace(sRet, sReplace, sWith, sLeft, sRight, bRemoveDelims);
    return sRet;
}

unsigned int NoString::Replace(const NoString& sReplace, const NoString& sWith, const NoString& sLeft, const NoString& sRight, bool bRemoveDelims)
{
    return NoString::Replace(*this, sReplace, sWith, sLeft, sRight, bRemoveDelims);
}

unsigned int
NoString::Replace(NoString& sStr, const NoString& sReplace, const NoString& sWith, const NoString& sLeft, const NoString& sRight, bool bRemoveDelims)
{
    unsigned int uRet = 0;
    NoString sCopy = sStr;
    sStr.clear();

    size_type uReplaceWidth = sReplace.length();
    size_type uLeftWidth = sLeft.length();
    size_type uRightWidth = sRight.length();
    const char* p = sCopy.c_str();
    bool bInside = false;

    while (*p) {
        if (!bInside && uLeftWidth && strncmp(p, sLeft.c_str(), uLeftWidth) == 0) {
            if (!bRemoveDelims) {
                sStr += sLeft;
            }

            p += uLeftWidth - 1;
            bInside = true;
        } else if (bInside && uRightWidth && strncmp(p, sRight.c_str(), uRightWidth) == 0) {
            if (!bRemoveDelims) {
                sStr += sRight;
            }

            p += uRightWidth - 1;
            bInside = false;
        } else if (!bInside && strncmp(p, sReplace.c_str(), uReplaceWidth) == 0) {
            sStr += sWith;
            p += uReplaceWidth - 1;
            uRet++;
        } else {
            sStr.append(p, 1);
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

NoString NoString::Ellipsize(unsigned int uLen) const
{
    if (uLen >= size()) {
        return *this;
    }

    string sRet;

    // @todo this looks suspect
    if (uLen < 4) {
        for (unsigned int a = 0; a < uLen; a++) {
            sRet += ".";
        }

        return sRet;
    }

    sRet = substr(0, uLen - 3) + "...";

    return sRet;
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

NoString::size_type NoString::URLSplit(NoStringMap& msRet) const
{
    msRet.clear();

    NoStringVector vsPairs;
    Split("&", vsPairs);

    for (const NoString& sPair : vsPairs) {
        msRet[sPair.Token(0, false, "=").Escape(NoString::EURL, NoString::EASCII)] =
        sPair.Token(1, true, "=").Escape(NoString::EURL, NoString::EASCII);
    }

    return msRet.size();
}

NoString::size_type NoString::OptionSplit(NoStringMap& msRet, bool bUpperKeys) const
{
    NoString sName;
    NoString sCopy(*this);
    msRet.clear();

    while (!sCopy.empty()) {
        sName = sCopy.Token(0, false, "=", false, "\"", "\"", false).Trim_n();
        sCopy = sCopy.Token(1, true, "=", false, "\"", "\"", false).TrimLeft_n();

        if (sName.empty()) {
            continue;
        }

        NoStringVector vsNames;
        sName.Split(" ", vsNames, false, "\"", "\"");

        for (unsigned int a = 0; a < vsNames.size(); a++) {
            NoString sKeyName = vsNames[a];

            if (bUpperKeys) {
                sKeyName.MakeUpper();
            }

            if ((a + 1) == vsNames.size()) {
                msRet[sKeyName] = sCopy.Token(0, false, " ", false, "\"", "\"");
                sCopy = sCopy.Token(1, true, " ", false, "\"", "\"", false);
            } else {
                msRet[sKeyName] = "";
            }
        }
    }

    return msRet.size();
}

NoString::size_type NoString::QuoteSplit(NoStringVector& vsRet) const
{
    vsRet.clear();
    return Split(" ", vsRet, false, "\"", "\"", true);
}

NoString::size_type
NoString::Split(const NoString& sDelim, NoStringVector& vsRet, bool bAllowEmpty, const NoString& sLeft, const NoString& sRight, bool bTrimQuotes, bool bTrimWhiteSpace) const
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

NoString::size_type
NoString::Split(const NoString& sDelim, NoStringSet& ssRet, bool bAllowEmpty, const NoString& sLeft, const NoString& sRight, bool bTrimQuotes, bool bTrimWhiteSpace) const
{
    NoStringVector vsTokens;

    Split(sDelim, vsTokens, bAllowEmpty, sLeft, sRight, bTrimQuotes, bTrimWhiteSpace);

    ssRet.clear();

    for (const NoString& sToken : vsTokens) {
        ssRet.insert(sToken);
    }

    return ssRet.size();
}

NoString NoString::NamedFormat(const NoString& sFormat, const NoStringMap& msValues)
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

NoString NoString::RandomString(unsigned int uLength)
{
    const char chars[] = "abcdefghijklmnopqrstuvwxyz"
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                         "0123456789!?.,:;/*-+_()";
    // -1 because sizeof() includes the trailing '\0' byte
    const size_t len = sizeof(chars) / sizeof(chars[0]) - 1;
    size_t p;
    NoString sRet;

    for (unsigned int a = 0; a < uLength; a++) {
        p = (size_t)(len * (rand() / (RAND_MAX + 1.0)));
        sRet += chars[p];
    }

    return sRet;
}

bool NoString::Base64Encode(unsigned int uWrap)
{
    NoString sCopy(*this);
    return sCopy.Base64Encode(*this, uWrap);
}

unsigned long NoString::Base64Decode()
{
    NoString sCopy(*this);
    return sCopy.Base64Decode(*this);
}

NoString NoString::Base64Encode_n(unsigned int uWrap) const
{
    NoString sRet;
    Base64Encode(sRet, uWrap);
    return sRet;
}

NoString NoString::Base64Decode_n() const
{
    NoString sRet;
    Base64Decode(sRet);
    return sRet;
}

bool NoString::Base64Encode(NoString& sRet, unsigned int uWrap) const
{
    const char b64table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    sRet.clear();
    size_t len = size();
    const unsigned char* input = (const unsigned char*)c_str();
    unsigned char* output, *p;
    size_t i = 0, mod = len % 3, toalloc;
    toalloc = (len / 3) * 4 + (3 - mod) % 3 + 1 + 8;

    if (uWrap) {
        toalloc += len / 57;
        if (len % 57) {
            toalloc++;
        }
    }

    if (toalloc < len) {
        return 0;
    }

    p = output = new unsigned char[toalloc];

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
    return true;
}

unsigned long NoString::Base64Decode(NoString& sRet) const
{
    NoString sTmp(*this);
    // remove new lines
    sTmp.Replace("\r", "");
    sTmp.Replace("\n", "");

    const char* in = sTmp.c_str();
    char c, c1, *p;
    unsigned long i;
    unsigned long uLen = sTmp.size();
    char* out = new char[uLen + 1];

    for (i = 0, p = out; i < uLen; i++) {
        c = (char)base64_table[(unsigned char)in[i++]];
        c1 = (char)base64_table[(unsigned char)in[i++]];
        *p++ = char((c << 2) | ((c1 >> 4) & 0x3));

        if (i < uLen) {
            if (in[i] == '=') {
                break;
            }
            c = (char)base64_table[(unsigned char)in[i]];
            *p++ = char(((c1 << 4) & 0xf0) | ((c >> 2) & 0xf));
        }

        if (++i < uLen) {
            if (in[i] == '=') {
                break;
            }
            *p++ = char(((c << 6) & 0xc0) | (char)base64_table[(unsigned char)in[i]]);
        }
    }

    *p = '\0';
    unsigned long uRet = p - out;
    sRet.clear();
    sRet.append(out, uRet);
    delete[] out;

    return uRet;
}

NoString NoString::MD5() const { return (const char*)NoMD5(*this); }

NoString NoString::SHA256() const
{
    unsigned char digest[SHA256_DIGEST_SIZE];
    char digest_hex[SHA256_DIGEST_SIZE * 2 + 1];
    const unsigned char* message = (const unsigned char*)c_str();

    sha256(message, length(), digest);

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

#ifdef HAVE_LIBSSL
NoString NoString::Encrypt_n(const NoString& sPass, const NoString& sIvec) const
{
    NoString sRet;
    sRet.Encrypt(sPass, sIvec);
    return sRet;
}

NoString NoString::Decrypt_n(const NoString& sPass, const NoString& sIvec) const
{
    NoString sRet;
    sRet.Decrypt(sPass, sIvec);
    return sRet;
}

void NoString::Encrypt(const NoString& sPass, const NoString& sIvec) { Crypt(sPass, true, sIvec); }

void NoString::Decrypt(const NoString& sPass, const NoString& sIvec) { Crypt(sPass, false, sIvec); }

void NoString::Crypt(const NoString& sPass, bool bEncrypt, const NoString& sIvec)
{
    unsigned char szIvec[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    BF_KEY bKey;

    if (sIvec.length() >= 8) {
        memcpy(szIvec, sIvec.data(), 8);
    }

    BF_set_key(&bKey, (unsigned int)sPass.length(), (unsigned char*)sPass.data());
    unsigned int uPad = (length() % 8);

    if (uPad) {
        uPad = 8 - uPad;
        append(uPad, '\0');
    }

    size_t uLen = length();
    unsigned char* szBuff = (unsigned char*)malloc(uLen);
    BF_cbc_encrypt((const unsigned char*)data(), szBuff, uLen, &bKey, szIvec, ((bEncrypt) ? BF_ENCRYPT : BF_DECRYPT));

    clear();
    append((const char*)szBuff, uLen);
    free(szBuff);
}
#endif // HAVE_LIBSSL

NoString NoString::ToPercent(double d)
{
    char szRet[32];
    snprintf(szRet, 32, "%.02f%%", d);
    return szRet;
}

NoString NoString::ToByteStr(unsigned long long d)
{
    const unsigned long long KiB = 1024;
    const unsigned long long MiB = KiB * 1024;
    const unsigned long long GiB = MiB * 1024;
    const unsigned long long TiB = GiB * 1024;

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

NoString NoString::ToTimeStr(unsigned long s)
{
    const unsigned long m = 60;
    const unsigned long h = m * 60;
    const unsigned long d = h * 24;
    const unsigned long w = d * 7;
    const unsigned long y = d * 365;
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

    return sRet.RightChomp_n();
}

bool NoString::ToBool() const
{
    NoString sTrimmed = Trim_n();
    return (!sTrimmed.Trim_n("0").empty() && !sTrimmed.Equals("false") && !sTrimmed.Equals("off") &&
            !sTrimmed.Equals("no") && !sTrimmed.Equals("n"));
}

short NoString::ToShort() const { return (short int)strtol(this->c_str(), (char**)nullptr, 10); }
unsigned short NoString::ToUShort() const { return (unsigned short int)strtoul(this->c_str(), (char**)nullptr, 10); }
unsigned int NoString::ToUInt() const { return (unsigned int)strtoul(this->c_str(), (char**)nullptr, 10); }
int NoString::ToInt() const { return (int)strtol(this->c_str(), (char**)nullptr, 10); }
long NoString::ToLong() const { return strtol(this->c_str(), (char**)nullptr, 10); }
unsigned long NoString::ToULong() const { return strtoul(c_str(), nullptr, 10); }
unsigned long long NoString::ToULongLong() const { return strtoull(c_str(), nullptr, 10); }
long long NoString::ToLongLong() const { return strtoll(c_str(), nullptr, 10); }
double NoString::ToDouble() const { return strtod(c_str(), nullptr); }


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

bool NoString::Contains(const NoString& s, CaseSensitivity cs) const { return Find(s, cs) != npos; }


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

NoString NoString::StripControls_n() const
{
    NoString sRet;
    const unsigned char* pStart = (const unsigned char*)data();
    unsigned char ch = *pStart;
    size_type iLength = length();
    sRet.reserve(iLength);
    bool colorCode = false;
    unsigned int digits = 0;
    bool comma = false;

    for (unsigned int a = 0; a < iLength; a++, ch = pStart[a]) {
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

NoString& NoString::StripControls() { return (*this = StripControls_n()); }

//////////////// NoStringMap ////////////////
const NoStringMap NoStringMap::EmptyMap;

NoStringMap::status_t NoStringMap::WriteToDisk(const NoString& sPath, mode_t iMode) const
{
    NoFile cFile(sPath);

    if (this->empty()) {
        if (!cFile.Exists()) return MCS_SUCCESS;
        if (cFile.Delete()) return MCS_SUCCESS;
    }

    if (!cFile.Open(O_WRONLY | O_CREAT | O_TRUNC, iMode)) {
        return MCS_EOPEN;
    }

    for (const auto& it : *this) {
        NoString sKey = it.first;
        NoString sValue = it.second;
        if (!WriteFilter(sKey, sValue)) {
            return MCS_EWRITEFIL;
        }

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

NoStringMap::status_t NoStringMap::ReadFromDisk(const NoString& sPath)
{
    clear();
    NoFile cFile(sPath);
    if (!cFile.Open(O_RDONLY)) {
        return MCS_EOPEN;
    }

    NoString sBuffer;

    while (cFile.ReadLine(sBuffer)) {
        sBuffer.Trim();
        NoString sKey = sBuffer.Token(0);
        NoString sValue = sBuffer.Token(1);
        Decode(sKey);
        Decode(sValue);

        if (!ReadFilter(sKey, sValue)) return MCS_EREADFIL;

        (*this)[sKey] = sValue;
    }
    cFile.Close();

    return MCS_SUCCESS;
}


static const char hexdigits[] = "0123456789abcdef";

NoString& NoStringMap::Encode(NoString& sValue) const
{
    NoString sTmp;
    for (unsigned char c : sValue) {
        // isalnum() needs unsigned char as argument and this code
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

NoString& NoStringMap::Decode(NoString& sValue) const
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
