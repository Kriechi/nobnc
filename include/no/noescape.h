/*
 * Copyright (C) 2004-2013 ZNC, see the NOTICE file for details.
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

#ifndef NOESCAPE_H
#define NOESCAPE_H

#include <no/noglobal.h>
#include <no/nostring.h>

#define _NAMEDFMT(str) No::escape(str, No::NamedFormat)

namespace No
{
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

    NO_EXPORT NoString escape(const NoString& str, No::EscapeFormat to);
    NO_EXPORT NoString escape(const NoString& str, No::EscapeFormat from, No::EscapeFormat to);
}

#endif // NOESCAPE_H
