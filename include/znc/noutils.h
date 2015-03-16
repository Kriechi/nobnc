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

#include <znc/noconfig.h>
#include <znc/nostring.h>
#include <assert.h>
#include <cstdio>
#include <fcntl.h>
#include <map>
#include <sys/file.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

static inline void SetFdCloseOnExec(int fd)
{
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0) return; // Ignore errors
    // When we execve() a new process this fd is now automatically closed.
    fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static const char g_HexDigits[] = "0123456789abcdef";

class NoUtils
{
public:
    NoUtils();
    ~NoUtils();

    static NoString GetIP(unsigned long addr);
    static unsigned long GetLongIP(const NoString& sIP);

    static void PrintError(const NoString& sMessage);
    static void PrintMessage(const NoString& sMessage, bool bStrong = false);
    static void PrintPrompt(const NoString& sMessage);
    static void PrintAction(const NoString& sMessage);
    static void PrintStatus(bool bSuccess, const NoString& sMessage = "");

    // TODO refactor this
    static const NoString sDefaultHash;

    static NoString GetSaltedHashPass(NoString& sSalt);
    static NoString GetSalt();
    static NoString SaltedMD5Hash(const NoString& sPass, const NoString& sSalt);
    static NoString SaltedSHA256Hash(const NoString& sPass, const NoString& sSalt);
    static NoString GetPass(const NoString& sPrompt);
    static bool GetInput(const NoString& sPrompt, NoString& sRet, const NoString& sDefault = "", const NoString& sHint = "");
    static bool GetBoolInput(const NoString& sPrompt, bool bDefault);
    static bool GetBoolInput(const NoString& sPrompt, bool* pbDefault = nullptr);
    static bool
    GetNumInput(const NoString& sPrompt, unsigned int& uRet, unsigned int uMin = 0, unsigned int uMax = ~0, unsigned int uDefault = ~0);

    static unsigned long long GetMillTime()
    {
        struct timeval tv;
        unsigned long long iTime = 0;
        gettimeofday(&tv, nullptr);
        iTime = (unsigned long long)tv.tv_sec * 1000;
        iTime += ((unsigned long long)tv.tv_usec / 1000);
        return iTime;
    }
#ifdef HAVE_LIBSSL
    static void GenerateCert(FILE* pOut, const NoString& sHost = "");
#endif /* HAVE_LIBSSL */

    static NoString CTime(time_t t, const NoString& sTZ);
    static NoString FormatTime(time_t t, const NoString& sFormat, const NoString& sTZ);
    static NoString FormatServerTime(const timeval& tv);
    static NoStringSet GetTimezones();
    static NoStringSet GetEncodings();

    static NoStringMap GetMessageTags(const NoString& sLine);
    static void SetMessageTags(NoString& sLine, const NoStringMap& mssTags);
};

class NoException
{
public:
    typedef enum { EX_Shutdown, EX_Restart } EType;

    NoException(EType e) : m_eType(e) {}
    virtual ~NoException() {}

    EType GetType() const { return m_eType; }

private:
    EType m_eType;
};


/** Generate a grid-like output from a given input.
 *
 *  @code
 *  NoTable table;
 *  table.AddColumn("a");
 *  table.AddColumn("b");
 *  table.AddRow();
 *  table.SetCell("a", "hello");
 *  table.SetCell("b", "world");
 *
 *  unsigned int idx = 0;
 *  NoString tmp;
 *  while (table.GetLine(idx++, tmp)) {
 *      // Output tmp somehow
 *  }
 *  @endcode
 *
 *  The above code would generate the following output:
 *  @verbatim
+-------+-------+
| a     | b     |
+-------+-------+
| hello | world |
+-------+-------+@endverbatim
 */
class NoTable : protected std::vector<std::vector<NoString>>
{
public:
    /** Constructor
     *
     *  @param uPreferredWidth If width of table is bigger than this, text in cells will be wrapped to several lines, if
     *possible
     */
    explicit NoTable(size_type uPreferredWidth = 110)
        : m_vsHeaders(), m_vuMaxWidths(), m_vuMinWidths(), m_vbWrappable(), m_uPreferredWidth(uPreferredWidth), m_vsOutput()
    {
    }
    virtual ~NoTable() {}

    /** Adds a new column to the table.
     *  Please note that you should add all columns before starting to fill
     *  the table!
     *  @param sName The name of the column.
     *  @param bWrappable True if long lines can be wrapped in the same cell.
     *  @return false if a column by that name already existed.
     */
    bool AddColumn(const NoString& sName, bool bWrappable = true);

    /** Adds a new row to the table.
     *  After calling this you can fill the row with content.
     *  @return The index of this row
     */
    size_type AddRow();

    /** Sets a given cell in the table to a value.
     *  @param sColumn The name of the column you want to fill.
     *  @param sValue The value to write into that column.
     *  @param uRowIdx The index of the row to use as returned by AddRow().
     *                 If this is not given, the last row will be used.
     *  @return True if setting the cell was successful.
     */
    bool SetCell(const NoString& sColumn, const NoString& sValue, size_type uRowIdx = ~0);

    /** Get a line of the table's output
     *  @param uIdx The index of the line you want.
     *  @param sLine This string will receive the output.
     *  @return True unless uIdx is past the end of the table.
     */
    bool GetLine(unsigned int uIdx, NoString& sLine) const;

    /** Return the width of the given column.
     *  Please note that adding and filling new rows might change the
     *  result of this function!
     *  @param uIdx The index of the column you are interested in.
     *  @return The width of the column.
     */
    NoString::size_type GetColumnWidth(unsigned int uIdx) const;

    /// Completely clear the table.
    void Clear();

    /// @return The number of rows in this table, not counting the header.
    using std::vector<std::vector<NoString>>::size;

    /// @return True if this table doesn't contain any rows.
    using std::vector<std::vector<NoString>>::empty;

private:
    unsigned int GetColumnIndex(const NoString& sName) const;
    NoStringVector Render() const;
    static NoStringVector WrapWords(const NoString& s, size_type uWidth);

private:
    NoStringVector m_vsHeaders;
    std::vector<NoString::size_type> m_vuMaxWidths; // Column don't need to be bigger than this
    std::vector<NoString::size_type> m_vuMinWidths; // Column can't be thiner than this
    std::vector<bool> m_vbWrappable;
    size_type m_uPreferredWidth;
    mutable NoStringVector m_vsOutput; // Rendered table
};


#ifdef HAVE_LIBSSL
#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/md5.h>
//! does Blowfish w/64 bit feedback, no padding
class NoBlowfish
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
    static unsigned char* MD5(const unsigned char* input, u_int ilen);

    //! returns an md5 of the NoString (not hex encoded)
    static NoString MD5(const NoString& sInput, bool bHexEncode = false);

    //! output must be the same size as input
    void Crypt(unsigned char* input, unsigned char* output, u_int ibytes);

    //! must free result
    unsigned char* Crypt(unsigned char* input, u_int ibytes);
    NoString Crypt(const NoString& sData);

private:
    unsigned char* m_ivec;
    BF_KEY m_bkey;
    int m_iEncrypt, m_num;
};

#endif /* HAVE_LIBSSL */

/**
 * @class TCacheMap
 * @author prozac <prozac@rottenboy.com>
 * @brief Insert an object with a time-to-live and check later if it still exists
 */
template <typename K, typename V = bool> class TCacheMap
{
public:
    TCacheMap(unsigned int uTTL = 5000) : m_mItems(), m_uTTL(uTTL) {}

    virtual ~TCacheMap() {}

    /**
     * @brief This function adds an item to the cache using the default time-to-live value
     * @param Item the item to add to the cache
     */
    void AddItem(const K& Item) { AddItem(Item, m_uTTL); }

    /**
     * @brief This function adds an item to the cache using a custom time-to-live value
     * @param Item the item to add to the cache
     * @param uTTL the time-to-live for this specific item
     */
    void AddItem(const K& Item, unsigned int uTTL) { AddItem(Item, V(), uTTL); }

    /**
     * @brief This function adds an item to the cache using the default time-to-live value
     * @param Item the item to add to the cache
     * @param Val The value associated with the key Item
     */
    void AddItem(const K& Item, const V& Val) { AddItem(Item, Val, m_uTTL); }

    /**
     * @brief This function adds an item to the cache using a custom time-to-live value
     * @param Item the item to add to the cache
     * @param Val The value associated with the key Item
     * @param uTTL the time-to-live for this specific item
     */
    void AddItem(const K& Item, const V& Val, unsigned int uTTL)
    {
        if (!uTTL) { // If time-to-live is zero we don't want to waste our time adding it
            RemItem(Item); // Remove the item incase it already exists
            return;
        }

        m_mItems[Item] = value(NoUtils::GetMillTime() + uTTL, Val);
    }

    /**
     * @brief Performs a Cleanup() and then checks to see if your item exists
     * @param Item The item to check for
     * @return true if item exists
     */
    bool HasItem(const K& Item)
    {
        Cleanup();
        return (m_mItems.find(Item) != m_mItems.end());
    }

    /**
     * @brief Performs a Cleanup() and returns a pointer to the object, or nullptr
     * @param Item The item to check for
     * @return Pointer to the item or nullptr if there is no suitable one
     */
    V* GetItem(const K& Item)
    {
        Cleanup();
        iterator it = m_mItems.find(Item);
        if (it == m_mItems.end()) return nullptr;
        return &it->second.second;
    }

    /**
     * @brief Removes a specific item from the cache
     * @param Item The item to be removed
     * @return true if item existed and was removed, false if it never existed
     */
    bool RemItem(const K& Item) { return (m_mItems.erase(Item) != 0); }

    /**
     * @brief Cycles through the queue removing all of the stale entries
     */
    void Cleanup()
    {
        iterator it = m_mItems.begin();

        while (it != m_mItems.end()) {
            if (NoUtils::GetMillTime() > (it->second.first)) {
                m_mItems.erase(it++);
            } else {
                ++it;
            }
        }
    }

    /**
     * @brief Clear all entries
     */
    void Clear() { m_mItems.clear(); }

    unsigned int GetTTL() const { return m_uTTL; }
    void SetTTL(unsigned int u) { m_uTTL = u; }

protected:
    typedef std::pair<unsigned long long, V> value;
    typedef typename std::map<K, value>::iterator iterator;
    std::map<K, value> m_mItems; //!< Map of cached items.  The value portion of the map is for the expire time
private:
    unsigned int m_uTTL; //!< Default time-to-live duration
};

#endif // NOUTILS_H
