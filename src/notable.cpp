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

#include "notable.h"
#include "nodebug.h"
#include <iomanip>

NoTable::NoTable(ulong uPreferredWidth)
    : m_headers(), m_maxWidths(), m_minWidths(), m_wrappable(), m_preferredWidth(uPreferredWidth), m_output()
{
}

uint NoTable::size() const
{
    return m_rows.size();
}

bool NoTable::empty() const
{
    return m_rows.empty();
}

bool NoTable::AddColumn(const NoString& sName, bool bWrappable)
{
    for (const NoString& sHeader : m_headers) {
        if (sHeader.equals(sName)) {
            return false;
        }
    }

    m_headers.push_back(sName);
    m_maxWidths.push_back(sName.size());
    // TODO: Maybe headers can be wrapped too?
    m_minWidths.push_back(sName.size());
    m_wrappable.push_back(bWrappable);

    return true;
}

uint NoTable::AddRow()
{
    // Don't add a row if no headers are defined
    if (m_headers.empty()) {
        return -1;
    }

    // Add a vector with enough space for each column
    m_rows.push_back(NoStringVector(m_headers.size()));
    return m_rows.size() - 1;
}

bool NoTable::SetCell(const NoString& sColumn, const NoString& sValue, uint uRowIdx)
{
    if (uRowIdx == ~0) {
        if (empty()) {
            return false;
        }

        uRowIdx = size() - 1;
    }

    uint uColIdx = GetColumnIndex(sColumn);

    if (uColIdx == (uint)-1) return false;

    m_rows[uRowIdx][uColIdx] = sValue;

    if (sValue.length() > m_maxWidths[uColIdx]) {
        m_maxWidths[uColIdx] = sValue.length();
    }

    if (m_wrappable[uColIdx]) {
        NoStringVector vsWords = sValue.split(" ");
        uint uMaxWord = 0;
        for (const NoString& sWord : vsWords) {
            if (sWord.length() > uMaxWord) {
                uMaxWord = sWord.length();
            }
        }
        // We can't shrink column further than the longest word in it
        if (uMaxWord > m_minWidths[uColIdx]) {
            m_minWidths[uColIdx] = uMaxWord;
        }
    } else {
        m_minWidths[uColIdx] = m_maxWidths[uColIdx];
    }

    return true;
}

bool NoTable::GetLine(uint uIdx, NoString& sLine) const
{
    if (empty()) {
        return false;
    }
    if (m_output.empty()) {
        m_output = Render();
    }
    if (uIdx >= m_output.size()) {
        return false;
    }
    sLine = m_output[uIdx];
    return true;
}

NoStringVector NoTable::Render() const
{
    uint uTotalWidth = 1; // '|'
    for (uint uWidth : m_maxWidths) {
        uTotalWidth += uWidth + 3; // '|', ' 'x2
    }

    std::vector<uint> vuWidth = m_maxWidths;

    std::map<int, int> miColumnSpace;
    for (uint i = 0; i < m_headers.size(); ++i) {
        int iSpace = m_maxWidths[i] - m_minWidths[i];
        if (iSpace > 0) {
            miColumnSpace[i] = iSpace;
        }
    }

    // Not very efficient algorithm, and doesn't produce very good results...
    while (uTotalWidth > m_preferredWidth) {
        std::vector<int> viToErase;
        for (auto& i : miColumnSpace) {
            uTotalWidth--;
            i.second--;
            vuWidth[i.first]--;
            if (i.second == 0) {
                viToErase.push_back(i.first);
            }
            if (uTotalWidth == m_preferredWidth) {
                break;
            }
        }
        for (int iCol : viToErase) {
            miColumnSpace.erase(iCol);
        }
        if (miColumnSpace.empty()) {
            // Every column is at its minimum width now, but total width is still more than preferred width
            break;
        }
    }

    NoString sHorizontal;
    {
        std::ostringstream ssLine;
        ssLine << std::setfill('-');
        ssLine << "+";
        for (uint uWidth : vuWidth) {
            ssLine << std::setw(uWidth + 2) << std::left << "-";
            ssLine << "+";
        }
        sHorizontal = ssLine.str();
    }
    NoStringVector vsOutput;
    vsOutput.emplace_back(sHorizontal.replace_n("-", "="));
    {
        std::ostringstream ssLine;
        ssLine << "|";
        for (uint iCol = 0; iCol < vuWidth.size(); ++iCol) {
            ssLine << " ";
            ssLine << std::setw(vuWidth[iCol]) << std::left;
            ssLine << m_headers[iCol] << " |";
        }
        vsOutput.emplace_back(ssLine.str());
    }
    vsOutput.emplace_back(vsOutput[0]);
    for (const NoStringVector& vsRow : m_rows) {
        // Wrap words
        std::vector<NoStringVector> vvsColumns;
        vvsColumns.reserve(m_headers.size());
        uint uRowNum = 1;
        for (uint iCol = 0; iCol < vuWidth.size(); ++iCol) {
            if (m_wrappable[iCol]) {
                vvsColumns.emplace_back(WrapWords(vsRow[iCol], vuWidth[iCol]));
            } else {
                vvsColumns.push_back({ vsRow[iCol] });
            }
            if (vvsColumns.back().size() > uRowNum) {
                uRowNum = vvsColumns.back().size();
            }
        }
        NoString sEmpty;
        for (uint uCurrentLine = 0; uCurrentLine < uRowNum; ++uCurrentLine) {
            std::ostringstream ssLine;
            ssLine << "|";
            for (uint iCol = 0; iCol < vvsColumns.size(); ++iCol) {
                const NoString& sData = uCurrentLine < vvsColumns[iCol].size() ? vvsColumns[iCol][uCurrentLine] : sEmpty;
                ssLine << " ";
                ssLine << std::setw(vuWidth[iCol]) << std::left;
                ssLine << sData << " |";
            }
            vsOutput.emplace_back(ssLine.str());
        }
        vsOutput.emplace_back(sHorizontal);
    }
    vsOutput.pop_back();
    vsOutput.emplace_back(vsOutput[0]);
    return vsOutput;
}

NoStringVector NoTable::WrapWords(const NoString& s, uint uWidth)
{
    NoStringVector vsWords = s.split(" ");
    NoStringVector vsResult;
    vsResult.emplace_back("");
    for (const NoString& sWord : vsWords) {
        uint uOldLen = vsResult.back().length();
        if (uOldLen != 0) {
            uOldLen++; // ' '
        }
        if (uOldLen + sWord.length() > uWidth) {
            vsResult.emplace_back(sWord);
        } else {
            if (uOldLen != 0) {
                vsResult.back() += " ";
            }
            vsResult.back() += sWord;
        }
    }
    return vsResult;
}

uint NoTable::GetColumnIndex(const NoString& sName) const
{
    for (uint i = 0; i < m_headers.size(); i++) {
        if (m_headers[i] == sName) return i;
    }

    NO_DEBUG("NoTable::GetColumnIndex(" + sName + ") failed");

    return (uint)-1;
}

NoString::size_type NoTable::GetColumnWidth(uint uIdx) const
{
    if (uIdx >= m_headers.size()) {
        return 0;
    }
    return m_maxWidths[uIdx];
}

void NoTable::Clear()
{
    m_rows.clear();
    m_headers.clear();
    m_maxWidths.clear();
    m_minWidths.clear();
    m_wrappable.clear();
    m_output.clear();
}
