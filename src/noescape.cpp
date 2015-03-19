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

#include "noescape.h"

namespace No {

static uchar* strnchr(const uchar* src, uchar c, uint iMaxBytes, uchar* pFill, uint* piCount)
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

NoString Escape_n(const NoString& str, No::EscapeFormat eTo)
{
    return Escape_n(str, No::AsciiFormat, eTo);
}

NoString Escape_n(const NoString& str, No::EscapeFormat eFrom, No::EscapeFormat eTo)
{
    NoString sRet;
    const char szHex[] = "0123456789ABCDEF";
    const uchar* pStart = (const uchar*)str.data();
    const uchar* p = (const uchar*)str.data();
    NoString::size_type iLength = str.length();
    sRet.reserve(iLength * 3);
    uchar pTmp[21];
    uint iCounted = 0;

    for (uint a = 0; a < iLength; a++, p = pStart + a) {
        uchar ch = 0;

        switch (eFrom) {
        case No::HtmlFormat:
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
        case No::AsciiFormat:
            ch = *p;
            break;
        case No::UrlFormat:
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
        case No::SqlFormat:
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
        case No::NamedFormat:
            if (*p != '\\' || iLength < (a + 1)) {
                ch = *p;
            } else {
                a++;
                p++;
                ch = *p;
            }

            break;
        case No::DebugFormat:
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
        case No::MsgTagFormat:
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
        case No::HexColonFormat: {
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
        case No::HtmlFormat:
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
        case No::AsciiFormat:
            sRet += ch;
            break;
        case No::UrlFormat:
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
        case No::SqlFormat:
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
        case No::NamedFormat:
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
        case No::DebugFormat:
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
        case No::MsgTagFormat:
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
        case No::HexColonFormat: {
            sRet += tolower(szHex[ch >> 4]);
            sRet += tolower(szHex[ch & 0xf]);
            sRet += ":";
        } break;
        }
    }

    if (eTo == No::HexColonFormat) {
        sRet.TrimRight(":");
    }

    return sRet;
}

}
