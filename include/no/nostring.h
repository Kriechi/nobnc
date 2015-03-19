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
#include <no/nonamespace.h>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <sstream>
#include <cstring>

class NoString;

typedef std::set<NoString> NoStringSet;
typedef std::vector<NoString> NoStringVector;
typedef std::map<NoString, NoString> NoStringMap;
typedef std::pair<NoString, NoString> NoStringPair;
typedef std::vector<NoStringPair> NoStringPairVector;

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
    int Compare(const NoString& s, No::CaseSensitivity cs = No::CaseInsensitive) const;
    /**
     * Check if this string is equal to some other string.
     * @param s The string to compare to.
     * @param cs CaseSensitive if you want the comparison to be case
     *                       sensitive, CaseInsensitive (default) otherwise.
     * @return True if the strings are equal.
     */
    bool Equals(const NoString& s, No::CaseSensitivity cs = No::CaseInsensitive) const;
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
    bool WildCmp(const NoString& sWild, No::CaseSensitivity cs = No::CaseSensitive) const;

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

    /** Replace all occurrences in the current string.
     * You can specify a "safe zone" via sLeft and sRight. Anything inside
     * of such a zone will not be replaced. This does not do recursion, so
     * e.g. with <code>Replace("(a()a)", "a", "b", "(", ")", true)</code>
     * you would get "a(b)" as result. The second opening brace and the
     * second closing brace would not be seen as a delimitered and thus
     * wouldn't be removed. The first a is inside a "safe zone" and thus is
     * left alone, too.
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
     * You can specify a "safe zone" via sLeft and sRight. Anything inside
     * of such a zone will not be replaced. This does not do recursion, so
     * e.g. with <code>Replace("(a()a)", "a", "b", "(", ")", true)</code>
     * you would get "a(b)" as result. The second opening brace and the
     * second closing brace would not be seen as a delimitered and thus
     * wouldn't be removed. The first a is inside a "safe zone" and thus is
     * left alone, too.
     * @see NoString::Replace
     * @param sReplace The string to look for.
     * @param sWith The replacement to use.
     * @param sLeft The delimiter at the beginning of a safe zone.
     * @param sRight The delimiter at the end of a safe zone.
     * @param bRemoveDelims If true, all matching delimiters are removed.
     * @returns The number of replacements done.
     */
    uint Replace(const NoString& sReplace,
                 const NoString& sWith,
                 const NoString& sLeft = "",
                 const NoString& sRight = "",
                 bool bRemoveDelims = false);
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
    NoString Token(size_t uPos, bool bRest = false, const NoString& sSep = " ") const;

    /** Get a token out of this string. This function behaves much like the
     *  other Token() function in this class. The extra arguments are
     *  handled similarly to Split().
     */
    NoString Token(size_t uPos, bool bRest, const NoString& sSep, const NoString& sLeft, const NoString& sRight) const;

    /** Split up this string into tokens.
     * @param separator The separator between tokens.
     * @param behavior If behavior is No::SkipEmptyParts, empty entries don't
                       appear in the result. By default, empty entries are kept.
     * @return A vector of tokens.
     */
    NoStringVector Split(const NoString& separator, No::SplitBehavior behavior = No::KeepEmptyParts) const;

    /** Decode the give base64-encoded string.
     * @return The decoded string.
     */
    static NoString FromBase64(const NoString& base64);
    /** Base64-encode the current string
     * @todo uWrap is as broken as Base64Encode()'s uWrap.
     * @return The encoded string.
     */
    NoString ToBase64(uint uWrap = 0) const;

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
    size_t Find(const NoString& s, No::CaseSensitivity cs = No::CaseInsensitive) const;
    /** Check whether the string starts with a given prefix.
     * @param sPrefix The prefix.
     * @param cs CaseSensitive if you want the comparison to be case
     *                       sensitive, CaseInsensitive (default) otherwise.
     * @return True if the string starts with prefix, false otherwise.
     */
    bool StartsWith(const NoString& sPrefix, No::CaseSensitivity cs = No::CaseInsensitive) const;
    /** Check whether the string ends with a given suffix.
     * @param sSuffix The suffix.
     * @param cs CaseSensitive if you want the comparison to be case
     *                       sensitive, CaseInsensitive (default) otherwise.
     * @return True if the string ends with suffix, false otherwise.
     */
    bool EndsWith(const NoString& sSuffix, No::CaseSensitivity cs = No::CaseInsensitive) const;
    /**
     * Check whether the string contains a given string.
     * @param s The string to search.
     * @param bCaseSensitive Whether the search is case sensitive.
     * @return True if this string contains the other string, falser otherwise.
     */
    bool Contains(const NoString& s, No::CaseSensitivity cs = No::CaseInsensitive) const;

    /** Remove characters from the beginning of this string.
     * @param uLen The number of characters to remove.
     * @return true if this string was modified.
     */
    bool LeftChomp(size_type uLen);
    /** Remove characters from the end of this string.
     * @param uLen The number of characters to remove.
     * @return true if this string was modified.
     */
    bool RightChomp(size_type uLen);
    /** Remove characters from the beginning of this string.
     * This string object isn't modified.
     * @param uLen The number of characters to remove.
     * @return The result of the conversion.
     */
    NoString LeftChomp_n(size_type uLen) const;
    /** Remove characters from the end of this string.
     * This string object isn't modified.
     * @param uLen The number of characters to remove.
     * @return The result of the conversion.
     */
    NoString RightChomp_n(size_type uLen) const;
};

#endif // NOSTRING_H
