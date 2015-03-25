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
    NoCacheMap(uint ttl = 5000) : m_items(), m_ttl(ttl) { }
    ~NoCacheMap() { }

    /**
     * @brief This function adds an item to the cache using a custom time-to-live value
     * @param key The item to add to the cache
     * @param value The value associated with the key Item
     */
    void insert(const K& key, const V& value = V())
    {
        if (!m_ttl) { // If time-to-live is zero we don't want to waste our time adding it
            remove(key); // Remove the item incase it already exists
            return;
        }
        m_items[key] = VP(No::millTime() + m_ttl, value);
    }

    /**
     * @brief Performs a Cleanup() and then checks to see if your item exists
     * @param Item The item to check for
     * @return true if item exists
     */
    bool contains(const K& key) const
    {
        const_cast<NoCacheMap*>(this)->cleanup();
        return (m_items.find(key) != m_items.end());
    }

    /**
     * @brief Performs a Cleanup() and returns a pointer to the object, or nullptr
     * @param Item The item to check for
     * @return Pointer to the item or nullptr if there is no suitable one
     */
    const V* value(const K& key) const
    {
        const_cast<NoCacheMap*>(this)->cleanup();
        const_iterator it = m_items.find(key);
        if (it == m_items.end())
            return nullptr;
        return &it->second.second; // TODO: a pointer :/
    }

    V* value(const K& key)
    {
        cleanup();
        iterator it = m_items.find(key);
        if (it == m_items.end())
            return nullptr;
        return &it->second.second; // TODO: a pointer :/
    }

    /**
     * @brief Removes a specific item from the cache
     * @param Item The item to be removed
     * @return true if item existed and was removed, false if it never existed
     */
    bool remove(const K& key) { return m_items.erase(key) != 0; }

    /**
     * @brief Cycles through the queue removing all of the stale entries
     */
    void cleanup()
    {
        iterator it = m_items.begin();
        while (it != m_items.end()) {
            if (No::millTime() > it->second.first)
                m_items.erase(it++);
            else
                ++it;
        }
    }

    /**
     * @brief Clear all entries
     */
    void clear() { m_items.clear(); }

    uint ttl() const { return m_ttl; }
    void setTtl(uint ttl) { m_ttl = ttl; }

    typedef std::pair<ulonglong, V> VP;
    typedef typename std::map<K, VP>::iterator iterator;
    typedef typename std::map<K, VP>::const_iterator const_iterator;

    iterator begin() { return m_items.begin(); }
    const_iterator begin() const { return m_items.begin(); }

    iterator end() { return m_items.end(); }
    const_iterator end() const { return m_items.end(); }

    void erase(iterator it) { m_items.erase(it); }

private:
    uint m_ttl;
    std::map<K, VP> m_items;
};

#endif // NOCACHEMAP_H
