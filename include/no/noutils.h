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
#include <assert.h>
#include <cstdio>
#include <map>
#include <sys/file.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

class NO_EXPORT NoUtils
{
public:
    NoUtils();
    ~NoUtils();

    static NoString GetIP(ulong addr);
    static ulong GetLongIP(const NoString& sIP);

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
    GetNumInput(const NoString& sPrompt, uint& uRet, uint uMin = 0, uint uMax = ~0, uint uDefault = ~0);

    static ulonglong GetMillTime()
    {
        struct timeval tv;
        ulonglong iTime = 0;
        gettimeofday(&tv, nullptr);
        iTime = (ulonglong)tv.tv_sec * 1000;
        iTime += ((ulonglong)tv.tv_usec / 1000);
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

/**
 * @class NoCacheMap
 * @author prozac <prozac@rottenboy.com>
 * @brief Insert an object with a time-to-live and check later if it still exists
 */
template <typename K, typename V = bool> class NoCacheMap
{
public:
    NoCacheMap(uint uTTL = 5000) : m_mItems(), m_uTTL(uTTL) {}

    virtual ~NoCacheMap() {}

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
    void AddItem(const K& Item, uint uTTL) { AddItem(Item, V(), uTTL); }

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
    void AddItem(const K& Item, const V& Val, uint uTTL)
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

    uint GetTTL() const { return m_uTTL; }
    void SetTTL(uint u) { m_uTTL = u; }

protected:
    typedef std::pair<ulonglong, V> value;
    typedef typename std::map<K, value>::iterator iterator;
    std::map<K, value> m_mItems; //!< Map of cached items.  The value portion of the map is for the expire time
private:
    uint m_uTTL; //!< Default time-to-live duration
};

#endif // NOUTILS_H
