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

#ifndef NONAMESPACE_H
#define NONAMESPACE_H

#include <nobnc/noglobal.h>

namespace No
{
enum CaseSensitivity { CaseInsensitive, CaseSensitive };
enum SplitBehavior { KeepEmptyParts, SkipEmptyParts };
enum AddressType { Ipv4Address = 1, Ipv6Address = 2, Ipv4AndIpv6Address = Ipv4Address | Ipv6Address };
enum ModuleType { GlobalModule, UserModule, NetworkModule };
enum AcceptType { AcceptIrc = 1, AcceptHttp = 2, AcceptAll = AcceptIrc | AcceptHttp };
enum EscapeFormat {
    AsciiFormat,
    UrlFormat,
    HtmlFormat,
    SqlFormat,
    NamedFormat,
    DebugFormat,
    MsgTagFormat,
    HexColonFormat
};
}

#endif // NONAMESPACE_H
