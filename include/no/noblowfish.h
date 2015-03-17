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

#ifndef NOBLOWFISH_H
#define NOBLOWFISH_H

#include <no/noglobal.h>
#include <no/nostring.h>

#ifdef HAVE_LIBSSL

#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/md5.h>

//! does Blowfish w/64 bit feedback, no padding
class NO_EXPORT NoBlowfish
{
public:
    /**
     * @param sPassword key to encrypt with
     * @param iEncrypt encrypt method (BF_DECRYPT or BF_ENCRYPT)
     * @param sIvec what to set the ivector to start with, default sets it all 0's
     */
    NoBlowfish(const NoString& sPassword, int iEncrypt, const NoString& sIvec = "");
    ~NoBlowfish();

    NoBlowfish(const NoBlowfish&) = default;
    NoBlowfish& operator=(const NoBlowfish&) = default;

    //! output must be freed
    static uchar* MD5(const uchar* input, u_int ilen);

    //! returns an md5 of the NoString (not hex encoded)
    static NoString MD5(const NoString& sInput, bool bHexEncode = false);

    //! output must be the same size as input
    void Crypt(uchar* input, uchar* output, u_int ibytes);

    //! must free result
    uchar* Crypt(uchar* input, u_int ibytes);
    NoString Crypt(const NoString& sData);

private:
    uchar* m_ivec;
    BF_KEY m_bkey;
    int m_iEncrypt, m_num;
};

#endif // HAVE_LIBSSL

#endif // NOBLOWFISH_H
