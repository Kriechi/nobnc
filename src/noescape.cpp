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

static uchar* strnchr(const uchar* src, uchar c, uint max, uchar* fill, uint* count)
{
    for (uint a = 0; a < max && *src; a++, src++) {
        if (fill)
            fill[a] = *src;

        if (*src == c) {
            if (fill)
                fill[a + 1] = 0;
            if (count)
                *count = a;
            return (uchar*)src;
        }
    }

    if (fill)
        *fill = 0;
    if (count)
        *count = 0;
    return nullptr;
}

NoString escape(const NoString& str, No::EscapeFormat to)
{
    return escape(str, No::AsciiFormat, to);
}

NoString escape(const NoString& str, No::EscapeFormat from, No::EscapeFormat to)
{
    NoString ret;
    const char hex[] = "0123456789ABCDEF";
    const uchar* start = (const uchar*)str.data();
    const uchar* p = (const uchar*)str.data();
    ulong len = str.length();
    ret.reserve(len * 3);
    uchar tmp[21];
    uint counted = 0;

    for (uint a = 0; a < len; a++, p = start + a) {
        uchar ch = 0;

        switch (from) {
        case No::HtmlFormat:
            if ((*p == '&') && (strnchr((uchar*)p, ';', sizeof(tmp) - 1, tmp, &counted))) {
                // please note that we do not have any Unicode or UTF-8 support here at all.

                if ((counted >= 3) && (tmp[1] == '#')) { // do XML and HTML &#97; &#x3c
                    int base = 10;

                    if ((tmp[2] & 0xDF) == 'X')
                        base = 16;

                    char* endptr = nullptr;
                    ulong b = strtol((const char*)(tmp + 2 + (base == 16)), &endptr, base);

                    if ((*endptr == ';') && (b <= 255)) { // incase they do something like &#7777777777;
                        ch = (uchar)b;
                        a += counted;
                        break;
                    }
                }

                if (ch == 0) {
                    if (!strncasecmp((const char*)&tmp, "&lt;", 2))
                        ch = '<';
                    else if (!strncasecmp((const char*)&tmp, "&gt;", 2))
                        ch = '>';
                    else if (!strncasecmp((const char*)&tmp, "&quot;", 4))
                        ch = '"';
                    else if (!strncasecmp((const char*)&tmp, "&amp;", 3))
                        ch = '&';
                }

                if (ch > 0)
                    a += counted;
                else
                    ch = *p; // Not a valid escape, just record the &
            } else {
                ch = *p;
            }
            break;

        case No::AsciiFormat:
            ch = *p;
            break;

        case No::UrlFormat:
            if (*p == '%' && (a + 2) < len && isxdigit(*(p + 1)) && isxdigit(*(p + 2))) {
                p++;
                if (isdigit(*p))
                    ch = (uchar)((*p - '0') << 4);
                else
                    ch = (uchar)((tolower(*p) - 'a' + 10) << 4);

                p++;
                if (isdigit(*p))
                    ch |= (uchar)(*p - '0');
                else
                    ch |= (uchar)(tolower(*p) - 'a' + 10);

                a += 2;
            } else if (start[a] == '+') {
                ch = ' ';
            } else {
                ch = *p;
            }
            break;

        case No::SqlFormat:
            if (*p != '\\' || len < (a + 1)) {
                ch = *p;
            } else {
                a++;
                p++;

                if (*p == 'n')
                    ch = '\n';
                else if (*p == 'r')
                    ch = '\r';
                else if (*p == '0')
                    ch = '\0';
                else if (*p == 't')
                    ch = '\t';
                else if (*p == 'b')
                    ch = '\b';
                else
                    ch = *p;
            }
            break;

        case No::NamedFormat:
            if (*p != '\\' || len < (a + 1)) {
                ch = *p;
            } else {
                a++;
                p++;
                ch = *p;
            }
            break;

        case No::DebugFormat:
            if (*p == '\\' && (a + 3) < len && *(p + 1) == 'x' && isxdigit(*(p + 2)) && isxdigit(*(p + 3))) {
                p += 2;
                if (isdigit(*p))
                    ch = (uchar)((*p - '0') << 4);
                else
                    ch = (uchar)((tolower(*p) - 'a' + 10) << 4);

                p++;
                if (isdigit(*p))
                    ch |= (uchar)(*p - '0');
                else
                    ch |= (uchar)(tolower(*p) - 'a' + 10);

                a += 3;
            } else if (*p == '\\' && a + 1 < len && *(p + 1) == '.') {
                a++;
                p++;
                ch = '\\';
            } else {
                ch = *p;
            }
            break;

        case No::MsgTagFormat:
            if (*p != '\\' || len < (a + 1)) {
                ch = *p;
            } else {
                a++;
                p++;

                if (*p == ':')
                    ch = ';';
                else if (*p == 's')
                    ch = ' ';
                else if (*p == '0')
                    ch = '\0';
                else if (*p == '\\')
                    ch = '\\';
                else if (*p == 'r')
                    ch = '\r';
                else if (*p == 'n')
                    ch = '\n';
                else
                    ch = *p;
            }
            break;

        case No::HexColonFormat:
            while (!isxdigit(*p) && a < len) {
                a++;
                p++;
            }
            if (a == len)
                continue;

            if (isdigit(*p))
                ch = (uchar)((*p - '0') << 4);
            else
                ch = (uchar)((tolower(*p) - 'a' + 10) << 4);

            a++;
            p++;
            while (!isxdigit(*p) && a < len) {
                a++;
                p++;
            }
            if (a == len)
                continue;

            if (isdigit(*p))
                ch |= (uchar)(*p - '0');
            else
                ch |= (uchar)(tolower(*p) - 'a' + 10);
            break;
        }

        switch (to) {
        case No::HtmlFormat:
            if (ch == '<')
                ret += "&lt;";
            else if (ch == '>')
                ret += "&gt;";
            else if (ch == '"')
                ret += "&quot;";
            else if (ch == '&')
                ret += "&amp;";
            else {
                ret += ch;
            }
            break;

        case No::AsciiFormat:
            ret += ch;
            break;

        case No::UrlFormat:
            if (isalnum(ch) || ch == '_' || ch == '.' || ch == '-') {
                ret += ch;
            } else if (ch == ' ') {
                ret += '+';
            } else {
                ret += '%';
                ret += hex[ch >> 4];
                ret += hex[ch & 0xf];
            }
            break;

        case No::SqlFormat:
            if (ch == '\0')
                ret += "\\0";
            else if (ch == '\n')
                ret += "\\n";
            else if (ch == '\t')
                ret += "\\t";
            else if (ch == '\r')
                ret += "\\r";
            else if (ch == '\b')
                ret += "\\b";
            else if (ch == '\"')
                ret += "\\\"";
            else if (ch == '\'')
                ret += "\\\'";
            else if (ch == '\\')
                ret += "\\\\";
            else
                ret += ch;
            break;

        case No::NamedFormat:
            if (ch == '\\')
                ret += "\\\\";
            else if (ch == '{')
                ret += "\\{";
            else if (ch == '}')
                ret += "\\}";
            else
                ret += ch;
            break;

        case No::DebugFormat:
            if (ch < 0x20 || ch == 0x7F) {
                ret += "\\x";
                ret += hex[ch >> 4];
                ret += hex[ch & 0xf];
            } else if (ch == '\\') {
                ret += "\\.";
            } else {
                ret += ch;
            }
            break;

        case No::MsgTagFormat:
            if (ch == ';')
                ret += "\\:";
            else if (ch == ' ')
                ret += "\\s";
            else if (ch == '\0')
                ret += "\\0";
            else if (ch == '\\')
                ret += "\\\\";
            else if (ch == '\r')
                ret += "\\r";
            else if (ch == '\n')
                ret += "\\n";
            else
                ret += ch;
            break;

        case No::HexColonFormat:
            ret += tolower(hex[ch >> 4]);
            ret += tolower(hex[ch & 0xf]);
            ret += ":";
            break;
        }
    }

    if (to == No::HexColonFormat)
        ret.TrimRight(":");

    return ret;
}

}
