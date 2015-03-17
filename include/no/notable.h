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

#ifndef NOTABLE_H
#define NOTABLE_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <vector>

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
class NO_EXPORT NoTable : protected std::vector<std::vector<NoString>>
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
    bool GetLine(uint uIdx, NoString& sLine) const;

    /** Return the width of the given column.
     *  Please note that adding and filling new rows might change the
     *  result of this function!
     *  @param uIdx The index of the column you are interested in.
     *  @return The width of the column.
     */
    NoString::size_type GetColumnWidth(uint uIdx) const;

    /// Completely clear the table.
    void Clear();

    /// @return The number of rows in this table, not counting the header.
    using std::vector<std::vector<NoString>>::size;

    /// @return True if this table doesn't contain any rows.
    using std::vector<std::vector<NoString>>::empty;

private:
    uint GetColumnIndex(const NoString& sName) const;
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

#endif // NOTABLE_H
