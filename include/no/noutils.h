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

#ifndef NOUTILS_H
#define NOUTILS_H

#include <no/noglobal.h>
#include <no/nostring.h>

class NO_EXPORT NoUtils
{
public:
    static NoString GetIP(ulong addr);
    static ulong GetLongIP(const NoString& sIP);

    static void PrintError(const NoString& sMessage);
    static void PrintMessage(const NoString& sMessage, bool bStrong = false);
    static void PrintPrompt(const NoString& sMessage);
    static void PrintAction(const NoString& sMessage);
    static void PrintStatus(bool bSuccess, const NoString& sMessage = "");

#ifdef HAVE_LIBSSL
    static NoString Encrypt(const NoString& sStr, const NoString& sPass, const NoString& sIvec = "");
    static NoString Decrypt(const NoString& sStr, const NoString& sPass, const NoString& sIvec = "");
#endif

    // TODO refactor this
    static const NoString sDefaultHash;

    static NoString GetSaltedHashPass(NoString& sSalt);
    static NoString GetSalt();
    static NoString MD5(const NoString& sStr);
    static NoString SHA256(const NoString& sStr);
    static NoString SaltedMD5Hash(const NoString& sPass, const NoString& sSalt);
    static NoString SaltedSHA256Hash(const NoString& sPass, const NoString& sSalt);
    static NoString GetPass(const NoString& sPrompt);
    static bool GetInput(const NoString& sPrompt, NoString& sRet, const NoString& sDefault = "", const NoString& sHint = "");
    static bool GetBoolInput(const NoString& sPrompt, bool bDefault);
    static bool GetBoolInput(const NoString& sPrompt, bool* pbDefault = nullptr);
    static bool
    GetNumInput(const NoString& sPrompt, uint& uRet, uint uMin = 0, uint uMax = ~0, uint uDefault = ~0);

    static ulonglong GetMillTime();

    static NoString CTime(time_t t, const NoString& sTZ);
    static NoString FormatTime(time_t t, const NoString& sFormat, const NoString& sTZ);
    static NoString FormatServerTime(const timeval& tv);
    static NoStringSet GetTimezones();
    static NoStringSet GetEncodings();

    static NoStringMap GetMessageTags(const NoString& sLine);
    static void SetMessageTags(NoString& sLine, const NoStringMap& mssTags);

    /** Status codes that can be returned by WriteToDisk() and
     * ReadFromDisk(). */
    enum status_t {
        /// No errors.
        MCS_SUCCESS = 0,
        /// Opening the file failed.
        MCS_EOPEN = 1,
        /// Writing to the file failed.
        MCS_EWRITE = 2,
    };

    /** Write a map to a file.
     * @param sPath The file name to write to.
     * @param iMode The mode for the file.
     * @return The result of the operation.
     * @see WriteFilter.
     */
    static status_t WriteToDisk(const NoStringMap& values, const NoString& sPath, mode_t iMode = 0644);
    /** Read a map from a file.
     * @param sPath The file name to read from.
     * @return The result of the operation.
     * @see ReadFilter.
     */
    static status_t ReadFromDisk(NoStringMap& values, const NoString& sPath);

    /** Pretty-print a number of bytes.
     * @param d The number of bytes.
     * @return A string describing the number of bytes.
     */
    static NoString ToByteStr(ulonglong d);
    /** Pretty-print a time span.
     * @param s Number of seconds to print.
     * @return A string like "4w 6d 4h 3m 58s".
     */
    static NoString ToTimeStr(ulong s);
    /** Pretty-print a percent value.
     * @param d The percent value. This should be in range 0-100.
     * @return The "pretty" string.
     */
    static NoString ToPercent(double d);

    /** Remove controls characters from the string.
     * Controls characters are color codes, and those in C0 set
     * See https://en.wikipedia.org/wiki/C0_and_C1_control_codes
     * @return A string without control codes.
     */
    static NoString StripControls(const NoString& str);

    /** Produces a random string.
     * @param uLength The length of the resulting string.
     * @return A random string.
     */
    static NoString RandomString(uint uLength);
};

#endif // NOUTILS_H
