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

#ifndef NOSTRING_H
#define NOSTRING_H

#include <nobnc/noglobal.h>
#include <nobnc/nonamespace.h>
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
    NoString(const char* str);
    NoString(const char* str, uint size);
    NoString(const std::string& str);
    NoString(uint size, char ch);
    explicit NoString(bool b);
    explicit NoString(char ch);
    explicit NoString(uchar ch);
    explicit NoString(short num);
    explicit NoString(ushort num);
    explicit NoString(int num);
    explicit NoString(uint num);
    explicit NoString(long num);
    explicit NoString(ulong num);
    explicit NoString(long long num);
    explicit NoString(ulonglong num);
    explicit NoString(double num, int precision = 2);
    explicit NoString(float num, int precision = 2);

    /**
     * Casts a NoString to another type.  Implemented via std::stringstream, you use this
     * for any class that has an operator<<(std::ostream, YourClass).
     * @param target The object to cast into. If the cast fails, its state is unspecified.
     * @return True if the cast succeeds, and false if it fails.
     */
    template <typename T>
    bool convert(T* target) const
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
    template <typename Iterator>
    NoString join(Iterator i_start, const Iterator& i_end) const
    {
        if (i_start == i_end)
            return NoString("");
        std::ostringstream output;
        output << *i_start;
        while (true) {
            ++i_start;
            if (i_start == i_end)
                return NoString(output.str());
            output << *this;
            output << *i_start;
        }
    }

    /**
     * Compare this string to some other string.
     * @param str The string to compare to.
     * @param cs CaseSensitive if you want the comparison to be case
     *                       sensitive, CaseInsensitive (default) otherwise.
     * @return An integer less than, equal to, or greater than zero if this
     *         string smaller, equal.... to the given string.
     */
    int compare(const NoString& str, No::CaseSensitivity cs = No::CaseInsensitive) const;
    /**
     * Check if this string is equal to some other string.
     * @param str The string to compare to.
     * @param cs CaseSensitive if you want the comparison to be case
     *                       sensitive, CaseInsensitive (default) otherwise.
     * @return True if the strings are equal.
     */
    bool equals(const NoString& str, No::CaseSensitivity cs = No::CaseInsensitive) const;

    /**
     * Return a copy of this string with all characters turned into
     * upper-case.
     * @return The new string.
     */
    NoString toUpper() const;
    /**
     * Return a copy of this string with all characters turned into
     * lower-case.
     * @return The new string.
     */
    NoString toLower() const;

    /** Replace all occurrences in the current string.
     * @see NoString::Replace
     * @param replace The string to look for.
     * @param with The replacement to use.
     * @return The result of the replacing. The current string is left
     *         unchanged.
     */
    NoString replace_n(const NoString& replace, const NoString& with) const;
    /** Replace all occurrences in the current string.
     * @see NoString::Replace
     * @param replace The string to look for.
     * @param with The replacement to use.
     * @returns The number of replacements done.
     */
    uint replace(const NoString& replace, const NoString& with);
    /** Return the left part of the string.
     * @param len The number of characters to keep.
     * @return The resulting string.
     */
    NoString left(uint len) const;
    /** Return the right part of the string.
     * @param len The number of characters to keep.
     * @return The resulting string.
     */
    NoString right(uint lent) const;

    /** Split up this string into tokens.
     * @param separator The separator between tokens.
     * @param behavior If behavior is No::SkipEmptyParts, empty entries don't
                       appear in the result. By default, empty entries are kept.
     * @return A vector of tokens.
     */
    NoStringVector split(const NoString& separator, No::SplitBehavior behavior = No::KeepEmptyParts) const;

    /** Decode the give base64-encoded string.
     * @return The decoded string.
     */
    static NoString fromBase64(const NoString& base64);
    /** Base64-encode the current string
     * @todo wrap broken...
     * @return The encoded string.
     */
    NoString toBase64(uint wrap = 0) const;

    /** @return True if this string is not "false". */
    bool toBool() const;
    /** @return The numerical value of this string similar to atoi(). */
    short toShort() const;
    /** @return The numerical value of this string similar to atoi(). */
    ushort toUShort() const;
    /** @return The numerical value of this string similar to atoi(). */
    int toInt() const;
    /** @return The numerical value of this string similar to atoi(). */
    long toLong() const;
    /** @return The numerical value of this string similar to atoi(). */
    uint toUInt() const;
    /** @return The numerical value of this string similar to atoi(). */
    ulong toULong() const;
    /** @return The numerical value of this string similar to atoi(). */
    ulonglong toULongLong() const;
    /** @return The numerical value of this string similar to atoi(). */
    long long toLongLong() const;
    /** @return The numerical value of this string similar to atoi(). */
    double toDouble() const;

    /** Trim this string. All leading/trailing occurences of characters from
     *  s are removed.
     * @param str A list of characters that should be trimmed.
     * @return true if this string was modified.
     */
    bool trim(const NoString& str = " \t\r\n");
    /** Trim this string. All leading occurences of characters from s are
     *  removed.
     * @param str A list of characters that should be trimmed.
     * @return true if this string was modified.
     */
    bool trimLeft(const NoString& str = " \t\r\n");
    /** Trim this string. All trailing occurences of characters from s are
     *  removed.
     * @param str A list of characters that should be trimmed.
     * @return true if this string was modified.
     */
    bool trimRight(const NoString& str = " \t\r\n");
    /** Trim this string. All leading/trailing occurences of characters from
     *  s are removed. This NoString instance is not modified.
     * @param str A list of characters that should be trimmed.
     * @return The trimmed string.
     */
    NoString trim_n(const NoString& str = " \t\r\n") const;
    /** Trim this string. All leading occurences of characters from s are
     *  removed. This NoString instance is not modified.
     * @param str A list of characters that should be trimmed.
     * @return The trimmed string.
     */
    NoString trimLeft_n(const NoString& str = " \t\r\n") const;
    /** Trim this string. All trailing occurences of characters from s are
     *  removed. This NoString instance is not modified.
     * @param str A list of characters that should be trimmed.
     * @return The trimmed string.
     */
    NoString trimRight_n(const NoString& str = " \t\r\n") const;

    /** Trim a given prefix.
     * @param prefix The prefix that should be removed.
     * @return True if this string was modified.
     */
    bool trimPrefix(const NoString& prefix = ":");
    /** Trim a given suffix.
     * @param suffix The suffix that should be removed.
     * @return True if this string was modified.
     */
    bool trimSuffix(const NoString& suffix);
    /** Trim a given prefix.
     * @param prefix The prefix that should be removed.
     * @return A copy of this string without the prefix.
     */
    NoString trimPrefix_n(const NoString& prefix = ":") const;
    /** Trim a given suffix.
     * @param suffix The suffix that should be removed.
     * @return A copy of this string without the prefix.
     */
    NoString trimSuffix_n(const NoString& suffix) const;

    /** Find the position of the given substring.
     * @param str The substring to search for.
     * @param cs CaseSensitive if you want the comparison to be case
     *                       sensitive, CaseInsensitive (default) otherwise.
     * @return The position of the substring if found, NoString::npos otherwise.
     */
    ulong find(char ch, No::CaseSensitivity cs = No::CaseInsensitive) const;
    ulong find(const NoString& str, No::CaseSensitivity cs = No::CaseInsensitive) const;
    ulong find(const NoString& str, uint pos, No::CaseSensitivity cs = No::CaseInsensitive) const;
    /** Check whether the string starts with a given prefix.
     * @param prefix The prefix.
     * @param cs CaseSensitive if you want the comparison to be case
     *                       sensitive, CaseInsensitive (default) otherwise.
     * @return True if the string starts with prefix, false otherwise.
     */
    bool startsWith(const NoString& prefix, No::CaseSensitivity cs = No::CaseInsensitive) const;
    /** Check whether the string ends with a given suffix.
     * @param suffix The suffix.
     * @param cs CaseSensitive if you want the comparison to be case
     *                       sensitive, CaseInsensitive (default) otherwise.
     * @return True if the string ends with suffix, false otherwise.
     */
    bool endsWith(const NoString& suffix, No::CaseSensitivity cs = No::CaseInsensitive) const;
    /**
     * Check whether the string contains a given string.
     * @param str The string to search.
     * @param cs Whether the search is case sensitive.
     * @return True if this string contains the other string, falser otherwise.
     */
    bool contains(char ch, No::CaseSensitivity cs = No::CaseInsensitive) const;
    bool contains(const NoString& str, No::CaseSensitivity cs = No::CaseInsensitive) const;

    /** Remove characters from the beginning of this string.
     * @param len The number of characters to remove.
     * @return true if this string was modified.
     */
    bool leftChomp(uint len);
    /** Remove characters from the end of this string.
     * @param len The number of characters to remove.
     * @return true if this string was modified.
     */
    bool rightChomp(uint len);
    /** Remove characters from the beginning of this string.
     * This string object isn't modified.
     * @param len The number of characters to remove.
     * @return The result of the conversion.
     */
    NoString leftChomp_n(uint len) const;
    /** Remove characters from the end of this string.
     * This string object isn't modified.
     * @param len The number of characters to remove.
     * @return The result of the conversion.
     */
    NoString rightChomp_n(uint len) const;
};

#endif // NOSTRING_H
