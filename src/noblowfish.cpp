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

#ifdef HAVE_LIBSSL
//#include <openssl/ssl.h>

static const char g_HexDigits[] = "0123456789abcdef";

NoBlowfish::NoBlowfish(const NoString& sPassword, int iEncrypt, const NoString& sIvec)
    : m_ivec((uchar*)calloc(sizeof(uchar), 8)), m_bkey(), m_iEncrypt(iEncrypt), m_num(0)
{

    if (sIvec.length() >= 8) {
        memcpy(m_ivec, sIvec.data(), 8);
    }

    BF_set_key(&m_bkey, (uint)sPassword.length(), (uchar*)sPassword.data());
}

NoBlowfish::~NoBlowfish() { free(m_ivec); }

//! output must be freed
uchar* NoBlowfish::MD5(const uchar* input, u_int ilen)
{
    uchar* output = (uchar*)malloc(MD5_DIGEST_LENGTH);
    ::MD5(input, ilen, output);
    return output;
}

//! returns an md5 of the NoString (not hex encoded)
NoString NoBlowfish::MD5(const NoString& sInput, bool bHexEncode)
{
    NoString sRet;
    uchar* data = MD5((const uchar*)sInput.data(), (uint)sInput.length());

    if (!bHexEncode) {
        sRet.append((const char*)data, MD5_DIGEST_LENGTH);
    } else {
        for (int a = 0; a < MD5_DIGEST_LENGTH; a++) {
            sRet += g_HexDigits[data[a] >> 4];
            sRet += g_HexDigits[data[a] & 0xf];
        }
    }

    free(data);
    return sRet;
}

//! output must be the same size as input
void NoBlowfish::Crypt(uchar* input, uchar* output, u_int uBytes)
{
    BF_cfb64_encrypt(input, output, uBytes, &m_bkey, m_ivec, &m_num, m_iEncrypt);
}

//! must free result
uchar* NoBlowfish::Crypt(uchar* input, u_int uBytes)
{
    uchar* buff = (uchar*)malloc(uBytes);
    Crypt(input, buff, uBytes);
    return buff;
}

NoString NoBlowfish::Crypt(const NoString& sData)
{
    uchar* buff = Crypt((uchar*)sData.data(), (uint)sData.length());
    NoString sOutput;
    sOutput.append((const char*)buff, sData.length());
    free(buff);
    return sOutput;
}

#endif // HAVE_LIBSSL
