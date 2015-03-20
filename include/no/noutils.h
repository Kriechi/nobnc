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

namespace No
{
    NO_EXPORT NoString formatIp(ulong addr);
    NO_EXPORT ulong formatLongIp(const NoString& sIP);

    NO_EXPORT void printError(const NoString& sMessage);
    NO_EXPORT void printMessage(const NoString& sMessage, bool bStrong = false);
    NO_EXPORT void printPrompt(const NoString& sMessage);
    NO_EXPORT void printAction(const NoString& sMessage);
    NO_EXPORT void printStatus(bool bSuccess, const NoString& sMessage = "");

#ifdef HAVE_LIBSSL
    NO_EXPORT NoString encrypt(const NoString& sStr, const NoString& sPass, const NoString& sIvec = "");
    NO_EXPORT NoString decrypt(const NoString& sStr, const NoString& sPass, const NoString& sIvec = "");
#endif

    NO_EXPORT NoString salt();
    NO_EXPORT NoString defaultHash();
    NO_EXPORT NoString md5(const NoString& sStr);
    NO_EXPORT NoString sha256(const NoString& sStr);
    NO_EXPORT NoString saltedMd5(const NoString& sPass, const NoString& sSalt);
    NO_EXPORT NoString saltedSha256(const NoString& sPass, const NoString& sSalt);

    NO_EXPORT NoString getPass(const NoString& sPrompt);
    NO_EXPORT NoString getSaltedHashPass(NoString& sSalt);
    NO_EXPORT bool getInput(const NoString& sPrompt, NoString& sRet, const NoString& sDefault = "", const NoString& sHint = "");
    NO_EXPORT bool getBoolInput(const NoString& sPrompt, bool bDefault);
    NO_EXPORT bool getBoolInput(const NoString& sPrompt, bool* pbDefault = nullptr);
    NO_EXPORT bool getNumInput(const NoString& sPrompt, uint& uRet, uint uMin = 0, uint uMax = ~0, uint uDefault = ~0);

    NO_EXPORT ulonglong millTime();

    NO_EXPORT NoString cTime(time_t t, const NoString& sTZ);
    NO_EXPORT NoString formatTime(time_t t, const NoString& sFormat, const NoString& sTZ);
    NO_EXPORT NoString formatServerTime(const timeval& tv);
    NO_EXPORT NoStringSet timezones();
    NO_EXPORT NoStringSet encodings();

    NO_EXPORT NoStringMap messageTags(const NoString& sLine);
    NO_EXPORT void setMessageTags(NoString& sLine, const NoStringMap& mssTags);

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
    NO_EXPORT status_t writeToDisk(const NoStringMap& values, const NoString& sPath, mode_t iMode = 0644);
    /** Read a map from a file.
     * @param sPath The file name to read from.
     * @return The result of the operation.
     * @see ReadFilter.
     */
    NO_EXPORT status_t readFromDisk(NoStringMap& values, const NoString& sPath);

    /** Pretty-print a number of bytes.
     * @param d The number of bytes.
     * @return A string describing the number of bytes.
     */
    NO_EXPORT NoString toByteStr(ulonglong d);
    /** Pretty-print a time span.
     * @param s Number of seconds to print.
     * @return A string like "4w 6d 4h 3m 58s".
     */
    NO_EXPORT NoString toTimeStr(ulong s);
    /** Pretty-print a percent value.
     * @param d The percent value. This should be in range 0-100.
     * @return The "pretty" string.
     */
    NO_EXPORT NoString toPercent(double d);

    /** Remove controls characters from the string.
     * Controls characters are color codes, and those in C0 set
     * See https://en.wikipedia.org/wiki/C0_and_C1_control_codes
     * @return A string without control codes.
     */
    NO_EXPORT NoString stripControls(const NoString& str);

    /** Produces a random string.
     * @param uLength The length of the resulting string.
     * @return A random string.
     */
    NO_EXPORT NoString randomString(uint uLength);

    /** Build a string from a format string, replacing values from a map.
     * The format specification can contain simple named parameters that match
     * keys in the given map. For example in the string "a {b} c", the key "b"
     * is looked up in the map, and inserted for "{b}".
     * @param sFormat The format specification.
     * @param msValues A map of named parameters to their values.
     * @return The string with named parameters replaced.
     */
    NO_EXPORT NoString namedFormat(const NoString& sFormat, const NoStringMap& msValues);

    /** Ellipsize the current string.
     * For example, ellipsizing "Hello, I'm Bob" to the length 9 would
     * result in "Hello,...".
     * @param uLen The length to ellipsize to.
     * @return The ellipsized string.
     */
    NO_EXPORT NoString ellipsize(const NoString& str, uint uLen);

    NO_EXPORT NoStringMap optionSplit(const NoString& str);
    NO_EXPORT NoStringVector quoteSplit(const NoString& str);

    /**
     * Do a wildcard comparison on this string.
     * For example, the following returns true:
     * <code>WildCmp("*!?bar@foo", "I_am!~bar@foo");</code>
     * @param sWild The wildcards used to for the comparison.
     * @param cs CaseSensitive (default) if you want the comparison
     *           to be case sensitive, CaseInsensitive otherwise.
     * @todo Make cs CaseInsensitive by default.
     * @return The result of <code>this->WildCmp(sWild, *this);</code>.
     */
    NO_EXPORT bool wildCmp(const NoString& sStr, const NoString& sWild, No::CaseSensitivity cs = No::CaseSensitive);

    /** Get a token out of this string. For example in the string "a bc d  e",
     *  each of "a", "bc", "d" and "e" are tokens.
     * @param uPos The number of the token you are interested. The first
     *             token has a position of 0.
     * @param sSep Seperator between tokens.
     * @param bAllowEmpty If this is true, empty tokens are allowed. In the
     *                    example from above this means that there is a
     *                    token "" before the "e" token.
     * @return The token you asked for and, if bRest is true, everything
     *         after it.
     * @see Split() if you need a string split into all of its tokens.
     */
    NO_EXPORT NoString token(const NoString& str, size_t uPos, const NoString& sSep = " ");

    /** Get a token out of this string. For example in the string "a bc d  e",
     *  each of "a", "bc", "d" and "e" are tokens.
     * @param uPos The number of the token you are interested. The first
     *             token has a position of 0.
     * @param sSep Seperator between tokens.
     * @param bAllowEmpty If this is true, empty tokens are allowed. In the
     *                    example from above this means that there is a
     *                    token "" before the "e" token.
     * @return The token you asked for and, if bRest is true, everything
     *         after it.
     * @see Split() if you need a string split into all of its tokens.
     */
    NO_EXPORT NoString tokens(const NoString& str, size_t uPos, const NoString& sSep = " ");

    /** Get the first line of this string.
     * @return The first line of text.
     */
    NO_EXPORT NoString firstLine(const NoString& str);
}

#endif // NOUTILS_H
