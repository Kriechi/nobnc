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

#include "notable.h"
#include "nodebug.h"
#include <iomanip>

NoTable::NoTable(ulong uPreferredWidth)
    : m_vsHeaders(), m_vuMaxWidths(), m_vuMinWidths(), m_vbWrappable(), m_uPreferredWidth(uPreferredWidth), m_vsOutput()
{
}

bool NoTable::AddColumn(const NoString& sName, bool bWrappable)
{
    for (const NoString& sHeader : m_vsHeaders) {
        if (sHeader.Equals(sName)) {
            return false;
        }
    }

    m_vsHeaders.push_back(sName);
    m_vuMaxWidths.push_back(sName.size());
    // TODO: Maybe headers can be wrapped too?
    m_vuMinWidths.push_back(sName.size());
    m_vbWrappable.push_back(bWrappable);

    return true;
}

NoTable::size_type NoTable::AddRow()
{
    // Don't add a row if no headers are defined
    if (m_vsHeaders.empty()) {
        return (size_type)-1;
    }

    // Add a vector with enough space for each column
    push_back(vector<NoString>(m_vsHeaders.size()));
    return size() - 1;
}

bool NoTable::SetCell(const NoString& sColumn, const NoString& sValue, size_type uRowIdx)
{
    if (uRowIdx == (size_type)~0) {
        if (empty()) {
            return false;
        }

        uRowIdx = size() - 1;
    }

    uint uColIdx = GetColumnIndex(sColumn);

    if (uColIdx == (uint)-1) return false;

    (*this)[uRowIdx][uColIdx] = sValue;

    if (sValue.length() > m_vuMaxWidths[uColIdx]) {
        m_vuMaxWidths[uColIdx] = sValue.length();
    }

    if (m_vbWrappable[uColIdx]) {
        NoStringVector vsWords = sValue.Split(" ");
        size_type uMaxWord = 0;
        for (const NoString& sWord : vsWords) {
            if (sWord.length() > uMaxWord) {
                uMaxWord = sWord.length();
            }
        }
        // We can't shrink column further than the longest word in it
        if (uMaxWord > m_vuMinWidths[uColIdx]) {
            m_vuMinWidths[uColIdx] = uMaxWord;
        }
    } else {
        m_vuMinWidths[uColIdx] = m_vuMaxWidths[uColIdx];
    }

    return true;
}

bool NoTable::GetLine(uint uIdx, NoString& sLine) const
{
    if (empty()) {
        return false;
    }
    if (m_vsOutput.empty()) {
        m_vsOutput = Render();
    }
    if (uIdx >= m_vsOutput.size()) {
        return false;
    }
    sLine = m_vsOutput[uIdx];
    return true;
}

NoStringVector NoTable::Render() const
{
    size_type uTotalWidth = 1; // '|'
    for (size_type uWidth : m_vuMaxWidths) {
        uTotalWidth += uWidth + 3; // '|', ' 'x2
    }

    std::vector<size_type> vuWidth = m_vuMaxWidths;

    std::map<int, int> miColumnSpace;
    for (uint i = 0; i < m_vsHeaders.size(); ++i) {
        int iSpace = m_vuMaxWidths[i] - m_vuMinWidths[i];
        if (iSpace > 0) {
            miColumnSpace[i] = iSpace;
        }
    }

    // Not very efficient algorithm, and doesn't produce very good results...
    while (uTotalWidth > m_uPreferredWidth) {
        std::vector<int> viToErase;
        for (auto& i : miColumnSpace) {
            uTotalWidth--;
            i.second--;
            vuWidth[i.first]--;
            if (i.second == 0) {
                viToErase.push_back(i.first);
            }
            if (uTotalWidth == m_uPreferredWidth) {
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
        for (size_type uWidth : vuWidth) {
            ssLine << std::setw(uWidth + 2) << std::left << "-";
            ssLine << "+";
        }
        sHorizontal = ssLine.str();
    }
    NoStringVector vsOutput;
    vsOutput.emplace_back(sHorizontal.Replace_n("-", "="));
    {
        std::ostringstream ssLine;
        ssLine << "|";
        for (uint iCol = 0; iCol < vuWidth.size(); ++iCol) {
            ssLine << " ";
            ssLine << std::setw(vuWidth[iCol]) << std::left;
            ssLine << m_vsHeaders[iCol] << " |";
        }
        vsOutput.emplace_back(ssLine.str());
    }
    vsOutput.emplace_back(vsOutput[0]);
    for (const NoStringVector& vsRow : *this) {
        // Wrap words
        std::vector<NoStringVector> vvsColumns;
        vvsColumns.reserve(m_vsHeaders.size());
        uint uRowNum = 1;
        for (uint iCol = 0; iCol < vuWidth.size(); ++iCol) {
            if (m_vbWrappable[iCol]) {
                vvsColumns.emplace_back(WrapWords(vsRow[iCol], vuWidth[iCol]));
            } else {
                vvsColumns.push_back({ vsRow[iCol] });
            }
            if (vvsColumns.back().size() > uRowNum) {
                uRowNum = vvsColumns.back().size();
            }
        }
        NoString sEmpty;
        for (size_type uCurrentLine = 0; uCurrentLine < uRowNum; ++uCurrentLine) {
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

NoStringVector NoTable::WrapWords(const NoString& s, size_type uWidth)
{
    NoStringVector vsWords = s.Split(" ");
    NoStringVector vsResult;
    vsResult.emplace_back("");
    for (const NoString& sWord : vsWords) {
        size_type uOldLen = vsResult.back().length();
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
    for (uint i = 0; i < m_vsHeaders.size(); i++) {
        if (m_vsHeaders[i] == sName) return i;
    }

    DEBUG("NoTable::GetColumnIndex(" + sName + ") failed");

    return (uint)-1;
}

NoString::size_type NoTable::GetColumnWidth(uint uIdx) const
{
    if (uIdx >= m_vsHeaders.size()) {
        return 0;
    }
    return m_vuMaxWidths[uIdx];
}

void NoTable::Clear()
{
    clear();
    m_vsHeaders.clear();
    m_vuMaxWidths.clear();
    m_vuMinWidths.clear();
    m_vbWrappable.clear();
    m_vsOutput.clear();
}
