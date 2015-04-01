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

#ifndef NOTABLE_H
#define NOTABLE_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
#include <memory>

class NoTablePrivate;

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
 *  uint idx = 0;
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
class NO_EXPORT NoTable
{
public:
    /** Constructor
     *
     *  @param uPreferredWidth If width of table is bigger than this, text in cells will be wrapped to several lines, if
     *possible
     */
    explicit NoTable(ulong preferredWidth = 110);
    NoTable(const NoTable& other);
    NoTable& operator=(const NoTable& other);
    ~NoTable();

    /** Adds a new column to the table.
     *  Please note that you should add all columns before starting to fill
     *  the table!
     *  @param name The name of the column.
     *  @param wrap True if long lines can be wrapped in the same cell.
     *  @return false if a column by that name already existed.
     */
    bool addColumn(const NoString& name, bool wrap = true);

    /** Adds a new row to the table.
     *  After calling this you can fill the row with content.
     */
    void addRow();

    /** Sets a given cell in the table to a value.
     *  @param sColumn The name of the column you want to fill.
     *  @param value The value to write into that column.
     *  @param uRowIdx The index of the row to use as returned by AddRow().
     *                 If this is not given, the last row will be used.
     *  @return True if setting the cell was successful.
     */
    bool setValue(const NoString& column, const NoString& value);

    /// @return The table as a string.
    NoStringVector toString() const;

    /// Completely clear the table.
    void clear();

    /// @return The number of rows in this table, not counting the header.
    uint size() const;

    /// @return True if this table doesn't contain any rows.
    bool isEmpty() const;

private:
    std::shared_ptr<NoTablePrivate> d;
};

#endif // NOTABLE_H
