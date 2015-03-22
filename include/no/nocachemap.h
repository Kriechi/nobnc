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

#ifndef NOCACHEMAP_H
#define NOCACHEMAP_H

#include <no/noglobal.h>
#include <map>
#include <utility>

/**
 * @class NoCacheMap
 * @author prozac <prozac@rottenboy.com>
 * @brief Insert an object with a time-to-live and check later if it still exists
 */
template <typename K, typename V = bool> class NoCacheMap
{
public:
    NoCacheMap(uint uTTL = 5000) : m_items(), m_ttl(uTTL) {}

    virtual ~NoCacheMap() {}

    /**
     * @brief This function adds an item to the cache using the default time-to-live value
     * @param Item the item to add to the cache
     */
    void AddItem(const K& Item) { AddItem(Item, m_ttl); }

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
    void AddItem(const K& Item, const V& Val) { AddItem(Item, Val, m_ttl); }

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

        m_items[Item] = value(No::millTime() + uTTL, Val);
    }

    /**
     * @brief Performs a Cleanup() and then checks to see if your item exists
     * @param Item The item to check for
     * @return true if item exists
     */
    bool HasItem(const K& Item)
    {
        Cleanup();
        return (m_items.find(Item) != m_items.end());
    }

    /**
     * @brief Performs a Cleanup() and returns a pointer to the object, or nullptr
     * @param Item The item to check for
     * @return Pointer to the item or nullptr if there is no suitable one
     */
    V* GetItem(const K& Item)
    {
        Cleanup();
        iterator it = m_items.find(Item);
        if (it == m_items.end()) return nullptr;
        return &it->second.second;
    }

    /**
     * @brief Removes a specific item from the cache
     * @param Item The item to be removed
     * @return true if item existed and was removed, false if it never existed
     */
    bool RemItem(const K& Item) { return (m_items.erase(Item) != 0); }

    /**
     * @brief Cycles through the queue removing all of the stale entries
     */
    void Cleanup()
    {
        iterator it = m_items.begin();

        while (it != m_items.end()) {
            if (No::millTime() > (it->second.first)) {
                m_items.erase(it++);
            } else {
                ++it;
            }
        }
    }

    /**
     * @brief Clear all entries
     */
    void Clear() { m_items.clear(); }

    uint GetTTL() const { return m_ttl; }
    void SetTTL(uint u) { m_ttl = u; }

protected:
    typedef std::pair<ulonglong, V> value;
    typedef typename std::map<K, value>::iterator iterator;
    std::map<K, value> m_items; //!< Map of cached items.  The value portion of the map is for the expire time
private:
    uint m_ttl; //!< Default time-to-live duration
};

#endif // NOCACHEMAP_H
