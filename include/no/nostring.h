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

#ifndef NOSTRING_H
#define NOSTRING_H

#include <no/noglobal.h>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <sstream>
#include <cstring>

#define _NAMEDFMT(s) NoString(s).Escape_n(NoString::ENAMEDFMT)

class NoString;

typedef std::set<NoString> NoStringSet;
typedef std::vector<NoString> NoStringVector;
typedef std::map<NoString, NoString> NoStringMap;
typedef std::pair<NoString, NoString> NoStringPair;
typedef std::vector<NoStringPair> NoStringPairVector;

enum class CaseSensitivity { CaseInsensitive, CaseSensitive };

/**
 * @brief String class that is used inside ZNC.
 *
 * All strings that are used in ZNC and its modules should use instances of this
 * class. It provides helpful functions for parsing input like Token() and
 * Split().
 */
class NO_EXPORT NoString : public std::string
{
public:
    typedef enum {
        EASCII,
        EURL,
        EHTML,
        ESQL,
        ENAMEDFMT,
        EDEBUG,
        EMSGTAG,
        EHEXCOLON,
    } EEscape;

    static const CaseSensitivity CaseSensitive = CaseSensitivity::CaseSensitive;
    static const CaseSensitivity CaseInsensitive = CaseSensitivity::CaseInsensitive;

    NoString();
    NoString(const char* c);
    NoString(const char* c, size_t l);
    NoString(const std::string& s);
    NoString(size_t n, char c);
    explicit NoString(bool b);
    explicit NoString(char c);
    explicit NoString(uchar c);
    explicit NoString(short i);
    explicit NoString(ushort i);
    explicit NoString(int i);
    explicit NoString(uint i);
    explicit NoString(long i);
    explicit NoString(ulong i);
    explicit NoString(long long i);
    explicit NoString(ulonglong i);
    explicit NoString(double i, int precision = 2);
    explicit NoString(float i, int precision = 2);

    /**
     * Casts a NoString to another type.  Implemented via std::stringstream, you use this
     * for any class that has an operator<<(std::ostream, YourClass).
     * @param target The object to cast into. If the cast fails, its state is unspecified.
     * @return True if the cast succeeds, and false if it fails.
     */
    template <typename T> bool Convert(T* target) const
    {
        std::stringstream ss(*this);
        ss >> *target;
        return (bool)ss; // we don't care why it failed, only whether it failed
    }

    /**
     * Joins a collection of objects together, using 'this' as a delimiter.
     * You can pass either pointers to arrays, or iterators to collections.
     * @param i_begin An iterator pointing to the beginning of a group of objects.
     * @param i_end An iterator pointing past the end of a group of objects.
     * @return The joined string
     */
    template <typename Iterator> NoString Join(Iterator i_start, const Iterator& i_end) const
    {
        if (i_start == i_end) return NoString("");
        std::ostringstream output;
        output << *i_start;
        while (true) {
            ++i_start;
            if (i_start == i_end) return NoString(output.str());
            output << *this;
            output << *i_start;
        }
    }

    /**
     * Compare this string to some other string.
     * @param s The string to compare to.
     * @param cs CaseSensitive if you want the comparison to be case
     *                       sensitive, CaseInsensitive (default) otherwise.
     * @return An integer less than, equal to, or greater than zero if this
     *         string smaller, equal.... to the given string.
     */
    int Compare(const NoString& s, CaseSensitivity cs = CaseInsensitive) const;
    /**
     * Check if this string is equal to some other string.
     * @param s The string to compare to.
     * @param cs CaseSensitive if you want the comparison to be case
     *                       sensitive, CaseInsensitive (default) otherwise.
     * @return True if the strings are equal.
     */
    bool Equals(const NoString& s, CaseSensitivity cs = CaseInsensitive) const;
    /**
     * Do a wildcard comparison between two strings.
     * For example, the following returns true:
     * <code>WildCmp("*!?bar@foo", "I_am!~bar@foo");</code>
     * @param sWild The wildcards used for the comparison.
     * @param sString The string that is used for comparing.
     * @param cs CaseSensitive (default) if you want the comparison
     *           to be case sensitive, CaseInsensitive otherwise.
     * @todo Make cs CaseInsensitive by default.
     * @return true if the wildcard matches.
     */
    static bool WildCmp(const NoString& sWild, const NoString& sString, CaseSensitivity cs = CaseSensitive);
    /**
     * Do a wild compare on this string.
     * @param sWild The wildcards used to for the comparison.
     * @param cs CaseSensitive (default) if you want the comparison
     *           to be case sensitive, CaseInsensitive otherwise.
     * @todo Make cs CaseInsensitive by default.
     * @return The result of <code>this->WildCmp(sWild, *this);</code>.
     */
    bool WildCmp(const NoString& sWild, CaseSensitivity cs = CaseSensitive) const;

    /**
     * Turn all characters in this string into their upper-case equivalent.
     * @returns A reference to *this.
     */
    NoString& MakeUpper();
    /**
     * Turn all characters in this string into their lower-case equivalent.
     * @returns A reference to *this.
     */
    NoString& MakeLower();
    /**
     * Return a copy of this string with all characters turned into
     * upper-case.
     * @return The new string.
     */
    NoString AsUpper() const;
    /**
     * Return a copy of this string with all characters turned into
     * lower-case.
     * @return The new string.
     */
    NoString AsLower() const;

    static EEscape ToEscape(const NoString& sEsc);
    NoString Escape_n(EEscape eFrom, EEscape eTo) const;
    NoString Escape_n(EEscape eTo) const;
    NoString& Escape(EEscape eFrom, EEscape eTo);
    NoString& Escape(EEscape eTo);

    /** Replace all occurrences in a string.
     *
     * You can specify a "safe zone" via sLeft and sRight. Anything inside
     * of such a zone will not be replaced. This does not do recursion, so
     * e.g. with <code>Replace("(a()a)", "a", "b", "(", ")", true)</code>
     * you would get "a(b)" as result. The second opening brace and the
     * second closing brace would not be seen as a delimitered and thus
     * wouldn't be removed. The first a is inside a "safe zone" and thus is
     * left alone, too.
     *
     * @param sStr The string to do the replacing on. This will also contain
     *             the result when this function returns.
     * @param sReplace The string that should be replaced.
     * @param sWith The replacement to use.
     * @param sLeft The string that marks the begin of the "safe zone".
     * @param sRight The string that marks the end of the "safe zone".
     * @param bRemoveDelims If this is true, all matches for sLeft and
     *                      sRight are removed.
     * @returns The number of replacements done.
     */
    static uint Replace(NoString& sStr,
                                const NoString& sReplace,
                                const NoString& sWith,
                                const NoString& sLeft = "",
                                const NoString& sRight = "",
                                bool bRemoveDelims = false);

    /** Replace all occurrences in the current string.
     * @see NoString::Replace
     * @param sReplace The string to look for.
     * @param sWith The replacement to use.
     * @param sLeft The delimiter at the beginning of a safe zone.
     * @param sRight The delimiter at the end of a safe zone.
     * @param bRemoveDelims If true, all matching delimiters are removed.
     * @return The result of the replacing. The current string is left
     *         unchanged.
     */
    NoString Replace_n(const NoString& sReplace,
                      const NoString& sWith,
                      const NoString& sLeft = "",
                      const NoString& sRight = "",
                      bool bRemoveDelims = false) const;
    /** Replace all occurrences in the current string.
     * @see NoString::Replace
     * @param sReplace The string to look for.
     * @param sWith The replacement to use.
     * @param sLeft The delimiter at the beginning of a safe zone.
     * @param sRight The delimiter at the end of a safe zone.
     * @param bRemoveDelims If true, all matching delimiters are removed.
     * @returns The number of replacements done.
     */
    uint Replace(const NoString& sReplace, const NoString& sWith, const NoString& sLeft = "", const NoString& sRight = "", bool bRemoveDelims = false);
    /** Ellipsize the current string.
     * For example, ellipsizing "Hello, I'm Bob" to the length 9 would
     * result in "Hello,...".
     * @param uLen The length to ellipsize to.
     * @return The ellipsized string.
     */
    NoString Ellipsize(uint uLen) const;
    /** Return the left part of the string.
     * @param uCount The number of characters to keep.
     * @return The resulting string.
     */
    NoString Left(size_type uCount) const;
    /** Return the right part of the string.
     * @param uCount The number of characters to keep.
     * @return The resulting string.
     */
    NoString Right(size_type uCount) const;

    /** Get the first line of this string.
     * @return The first line of text.
     */
    NoString FirstLine() const { return Token(0, false, "\n"); }

    /** Get a token out of this string. For example in the string "a bc d  e",
     *  each of "a", "bc", "d" and "e" are tokens.
     * @param uPos The number of the token you are interested. The first
     *             token has a position of 0.
     * @param bRest If false, only the token you asked for is returned. Else
     *              you get the substring starting from the beginning of
     *              your token.
     * @param sSep Seperator between tokens.
     * @param bAllowEmpty If this is true, empty tokens are allowed. In the
     *                    example from above this means that there is a
     *                    token "" before the "e" token.
     * @return The token you asked for and, if bRest is true, everything
     *         after it.
     * @see Split() if you need a string split into all of its tokens.
     */
    NoString Token(size_t uPos, bool bRest = false, const NoString& sSep = " ", bool bAllowEmpty = false) const;

    /** Get a token out of this string. This function behaves much like the
     *  other Token() function in this class. The extra arguments are
     *  handled similarly to Split().
     */
    NoString Token(size_t uPos, bool bRest, const NoString& sSep, bool bAllowEmpty, const NoString& sLeft, const NoString& sRight, bool bTrimQuotes = true) const;

    size_type OptionSplit(NoStringMap& msRet, bool bUpperKeys = false) const;
    size_type QuoteSplit(NoStringVector& vsRet) const;

    /** Split up this string into tokens.
     * Via sLeft and sRight you can define "markers" like with Replace().
     * Anything in such a marked section is treated as a single token. All
     * occurences of sDelim in such a block are ignored.
     * @param sDelim Delimiter between tokens.
     * @param vsRet Vector for returning the result.
     * @param bAllowEmpty Do empty tokens count as a valid token?
     * @param sLeft Left delimiter like with Replace().
     * @param sRight Right delimiter like with Replace().
     * @param bTrimQuotes Should sLeft and sRight be removed from the token
     *                    they mark?
     * @param bTrimWhiteSpace If this is true, NoString::Trim() is called on
     *                        each token.
     * @return The number of tokens found.
     */
    size_type Split(const NoString& sDelim,
                    NoStringVector& vsRet,
                    bool bAllowEmpty = true,
                    const NoString& sLeft = "",
                    const NoString& sRight = "",
                    bool bTrimQuotes = true,
                    bool bTrimWhiteSpace = false) const;

    /** Split up this string into tokens.
     * This function is identical to the other NoString::Split(), except that
     * the result is returned as a NoStringSet instead of a NoStringVector.
     */
    size_type Split(const NoString& sDelim,
                    NoStringSet& ssRet,
                    bool bAllowEmpty = true,
                    const NoString& sLeft = "",
                    const NoString& sRight = "",
                    bool bTrimQuotes = true,
                    bool bTrimWhiteSpace = false) const;

    /** Build a string from a format string, replacing values from a map.
     * The format specification can contain simple named parameters that match
     * keys in the given map. For example in the string "a {b} c", the key "b"
     * is looked up in the map, and inserted for "{b}".
     * @param sFormat The format specification.
     * @param msValues A map of named parameters to their values.
     * @return The string with named parameters replaced.
     */
    static NoString NamedFormat(const NoString& sFormat, const NoStringMap& msValues);

    /** Produces a random string.
     * @param uLength The length of the resulting string.
     * @return A random string.
     */
    static NoString RandomString(uint uLength);

    /** Treat this string as base64-encoded data and decode it.
     * @param sRet String to which the result of the decode is safed.
     * @return The length of the resulting string.
     */
    ulong Base64Decode(NoString& sRet) const;
    /** Treat this string as base64-encoded data and decode it.
     *  The result is saved in this NoString instance.
     * @return The length of the resulting string.
     */
    ulong Base64Decode();
    /** Treat this string as base64-encoded data and decode it.
     * @return The decoded string.
     */
    NoString Base64Decode_n() const;
    /** Base64-encode the current string.
     * @param sRet String where the result is saved.
     * @param uWrap A boolean(!?!) that decides if the result should be
     *              wrapped after everywhere 57 characters.
     * @return true unless this code is buggy.
     * @todo WTF @ uWrap.
     * @todo This only returns false if some formula we use was wrong?!
     */
    bool Base64Encode(NoString& sRet, uint uWrap = 0) const;
    /** Base64-encode the current string.
     *  This string is overwritten with the result of the encode.
     *  @todo return value and param are as with Base64Encode() from above.
     */
    bool Base64Encode(uint uWrap = 0);
    /** Base64-encode the current string
     * @todo uWrap is as broken as Base64Encode()'s uWrap.
     * @return The encoded string.
     */
    NoString Base64Encode_n(uint uWrap = 0) const;

    /** Pretty-print a percent value.
     * @param d The percent value. This should be in range 0-100.
     * @return The "pretty" string.
     */
    static NoString ToPercent(double d);

    /** @return True if this string is not "false". */
    bool ToBool() const;
    /** @return The numerical value of this string similar to atoi(). */
    short ToShort() const;
    /** @return The numerical value of this string similar to atoi(). */
    ushort ToUShort() const;
    /** @return The numerical value of this string similar to atoi(). */
    int ToInt() const;
    /** @return The numerical value of this string similar to atoi(). */
    long ToLong() const;
    /** @return The numerical value of this string similar to atoi(). */
    uint ToUInt() const;
    /** @return The numerical value of this string similar to atoi(). */
    ulong ToULong() const;
    /** @return The numerical value of this string similar to atoi(). */
    ulonglong ToULongLong() const;
    /** @return The numerical value of this string similar to atoi(). */
    long long ToLongLong() const;
    /** @return The numerical value of this string similar to atoi(). */
    double ToDouble() const;

    /** Trim this string. All leading/trailing occurences of characters from
     *  s are removed.
     * @param s A list of characters that should be trimmed.
     * @return true if this string was modified.
     */
    bool Trim(const NoString& s = " \t\r\n");
    /** Trim this string. All leading occurences of characters from s are
     *  removed.
     * @param s A list of characters that should be trimmed.
     * @return true if this string was modified.
     */
    bool TrimLeft(const NoString& s = " \t\r\n");
    /** Trim this string. All trailing occurences of characters from s are
     *  removed.
     * @param s A list of characters that should be trimmed.
     * @return true if this string was modified.
     */
    bool TrimRight(const NoString& s = " \t\r\n");
    /** Trim this string. All leading/trailing occurences of characters from
     *  s are removed. This NoString instance is not modified.
     * @param s A list of characters that should be trimmed.
     * @return The trimmed string.
     */
    NoString Trim_n(const NoString& s = " \t\r\n") const;
    /** Trim this string. All leading occurences of characters from s are
     *  removed. This NoString instance is not modified.
     * @param s A list of characters that should be trimmed.
     * @return The trimmed string.
     */
    NoString TrimLeft_n(const NoString& s = " \t\r\n") const;
    /** Trim this string. All trailing occurences of characters from s are
     *  removed. This NoString instance is not modified.
     * @param s A list of characters that should be trimmed.
     * @return The trimmed string.
     */
    NoString TrimRight_n(const NoString& s = " \t\r\n") const;

    /** Trim a given prefix.
     * @param sPrefix The prefix that should be removed.
     * @return True if this string was modified.
     */
    bool TrimPrefix(const NoString& sPrefix = ":");
    /** Trim a given suffix.
     * @param sSuffix The suffix that should be removed.
     * @return True if this string was modified.
     */
    bool TrimSuffix(const NoString& sSuffix);
    /** Trim a given prefix.
     * @param sPrefix The prefix that should be removed.
     * @return A copy of this string without the prefix.
     */
    NoString TrimPrefix_n(const NoString& sPrefix = ":") const;
    /** Trim a given suffix.
     * @param sSuffix The suffix that should be removed.
     * @return A copy of this string without the prefix.
     */
    NoString TrimSuffix_n(const NoString& sSuffix) const;

    /** Find the position of the given substring.
     * @param s The substring to search for.
     * @param cs CaseSensitive if you want the comparison to be case
     *                       sensitive, CaseInsensitive (default) otherwise.
     * @return The position of the substring if found, NoString::npos otherwise.
     */
    size_t Find(const NoString& s, CaseSensitivity cs = CaseInsensitive) const;
    /** Check whether the string starts with a given prefix.
     * @param sPrefix The prefix.
     * @param cs CaseSensitive if you want the comparison to be case
     *                       sensitive, CaseInsensitive (default) otherwise.
     * @return True if the string starts with prefix, false otherwise.
     */
    bool StartsWith(const NoString& sPrefix, CaseSensitivity cs = CaseInsensitive) const;
    /** Check whether the string ends with a given suffix.
     * @param sSuffix The suffix.
     * @param cs CaseSensitive if you want the comparison to be case
     *                       sensitive, CaseInsensitive (default) otherwise.
     * @return True if the string ends with suffix, false otherwise.
     */
    bool EndsWith(const NoString& sSuffix, CaseSensitivity cs = CaseInsensitive) const;
    /**
     * Check whether the string contains a given string.
     * @param s The string to search.
     * @param bCaseSensitive Whether the search is case sensitive.
     * @return True if this string contains the other string, falser otherwise.
     */
    bool Contains(const NoString& s, CaseSensitivity cs = CaseInsensitive) const;

    /** Remove characters from the beginning of this string.
     * @param uLen The number of characters to remove.
     * @return true if this string was modified.
     */
    bool LeftChomp(size_type uLen = 1);
    /** Remove characters from the end of this string.
     * @param uLen The number of characters to remove.
     * @return true if this string was modified.
     */
    bool RightChomp(size_type uLen = 1);
    /** Remove characters from the beginning of this string.
     * This string object isn't modified.
     * @param uLen The number of characters to remove.
     * @return The result of the conversion.
     */
    NoString LeftChomp_n(size_type uLen = 1) const;
    /** Remove characters from the end of this string.
     * This string object isn't modified.
     * @param uLen The number of characters to remove.
     * @return The result of the conversion.
     */
    NoString RightChomp_n(size_type uLen = 1) const;

private:
    uchar* strnchr(const uchar* src,
                           uchar c,
                           uint iMaxBytes,
                           uchar* pFill = nullptr,
                           uint* piCount = nullptr) const;
};

#endif // NOSTRING_H
