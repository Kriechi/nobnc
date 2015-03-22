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

#include "noblowfish.h"
#include <cassert>

#ifdef HAVE_LIBSSL
#include <openssl/blowfish.h>
#endif // HAVE_LIBSSL

bool NoBlowfish::isAvailable()
{
#ifdef HAVE_LIBSSL
    return true;
#else
    return false;
#endif
}

#ifdef HAVE_LIBSSL
static NoString blowfish(const NoString& data, const NoString& password, int encrypt)
{
    int num = 0;

    BF_KEY key;
    BF_set_key(&key, (uint)password.length(), (uchar*)password.data());

    const uint len = data.length();
    const uchar* input = (const uchar*)data.data();

    uchar* output = (uchar*)malloc(len);
    uchar* ivec = (uchar*)calloc(sizeof(uchar), 8);

    BF_cfb64_encrypt(input, output, len, &key, ivec, &num, encrypt);

    NoString str = NoString((const char*)output, len);

    free(output);
    free(ivec);

    return str;
}
#endif // HAVE_LIBSSL

NoString NoBlowfish::encrypt(const NoString& data, const NoString& password)
{
#ifdef HAVE_LIBSSL
    return blowfish(data, password, BF_ENCRYPT);
#else
    assert(false); // NoBlowFish::isAvailable()
    return "";
#endif
}

NoString NoBlowfish::decrypt(const NoString& data, const NoString& password)
{
#ifdef HAVE_LIBSSL
    return blowfish(data, password, BF_DECRYPT);
#else
    assert(false); // NoBlowFish::isAvailable()
    return "";
#endif
}
