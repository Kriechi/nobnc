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

#ifndef NOIRCSOCKET_H
#define NOIRCSOCKET_H

#include <no/noglobal.h>
#include <no/nosocket.h>

/**
 * @class NoIrcSocket
 * @brief Base IRC socket for client<->ZNC, and ZNC<->server
 */
class NO_EXPORT NoIrcSocket : public NoSocket
{
public:
#ifdef HAVE_ICU
    /**
     * @brief Allow IRC control characters to appear even if protocol encoding explicitly disallows them.
     *
     * E.g. ISO-2022-JP disallows 0x0F, which in IRC means "reset format",
     * so by default it gets replaced with U+FFFD ("replacement character").
     * https://code.google.com/p/chromium/issues/detail?id=277062#c3
     *
     * In case if protocol encoding uses these code points for something else, the encoding takes preference,
     * and they are not IRC control characters anymore.
     */
    void IcuExtToUCallbackImpl(UConverterToUnicodeArgs* toArgs,
                           const char* codeUnits,
                           int32_t length,
                           UConverterCallbackReason reason,
                           UErrorCode* err) override;
    void IcuExtFromUCallbackImpl(UConverterFromUnicodeArgs* fromArgs,
                             const UChar* codeUnits,
                             int32_t length,
                             UChar32 codePoint,
                             UConverterCallbackReason reason,
                             UErrorCode* err) override;
#endif
};

#endif // NOSOCKET_H
