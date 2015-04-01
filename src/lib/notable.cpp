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

class NoTablePrivate
{
public:
    uint GetColumnWidth(uint uIdx) const;
    uint GetColumnIndex(const NoString& name) const;
    NoStringVector Render() const;
    static NoStringVector WrapWords(const NoString& s, uint uWidth);

    NoStringVector headers;
    std::vector<NoStringVector> rows;
    std::vector<uint> maxWidths; // Column don't need to be bigger than this
    std::vector<uint> minWidths; // Column can't be thiner than this
    std::vector<bool> wrappable;
    uint preferredWidth;
    mutable NoStringVector output; // Rendered table
};

NoTable::NoTable(ulong uPreferredWidth) : d(new NoTablePrivate)
{
    d->preferredWidth = uPreferredWidth;
}

NoTable::NoTable(const NoTable& other) : d(new NoTablePrivate)
{
    d->headers = other.d->headers;
    d->rows = other.d->rows;
    d->maxWidths = other.d->maxWidths;
    d->minWidths = other.d->minWidths;
    d->wrappable = other.d->wrappable;
    d->preferredWidth = other.d->preferredWidth;
    d->output = other.d->output;
}

NoTable& NoTable::operator=(const NoTable& other)
{
    if (this != &other) {
        d->headers = other.d->headers;
        d->rows = other.d->rows;
        d->maxWidths = other.d->maxWidths;
        d->minWidths = other.d->minWidths;
        d->wrappable = other.d->wrappable;
        d->preferredWidth = other.d->preferredWidth;
        d->output = other.d->output;
    }
    return *this;
}

NoTable::~NoTable()
{
}

uint NoTable::size() const
{
    return d->rows.size();
}

bool NoTable::isEmpty() const
{
    return d->rows.empty();
}

bool NoTable::addColumn(const NoString& name, bool bWrappable)
{
    for (const NoString& sHeader : d->headers) {
        if (sHeader.equals(name)) {
            return false;
        }
    }

    d->headers.push_back(name);
    d->maxWidths.push_back(name.size());
    // TODO: Maybe headers can be wrapped too?
    d->minWidths.push_back(name.size());
    d->wrappable.push_back(bWrappable);

    return true;
}

void NoTable::addRow()
{
    // Add a vector with enough space for each column
    d->rows.push_back(NoStringVector(d->headers.size()));
}

bool NoTable::setValue(const NoString& sColumn, const NoString& value)
{
    uint uRowIdx = size() - 1;
    uint uColIdx = d->GetColumnIndex(sColumn);

    if (uColIdx == (uint)-1)
        return false;

    d->rows[uRowIdx][uColIdx] = value;

    if (value.length() > d->maxWidths[uColIdx]) {
        d->maxWidths[uColIdx] = value.length();
    }

    if (d->wrappable[uColIdx]) {
        NoStringVector vsWords = value.split(" ");
        uint uMaxWord = 0;
        for (const NoString& sWord : vsWords) {
            if (sWord.length() > uMaxWord) {
                uMaxWord = sWord.length();
            }
        }
        // We can't shrink column further than the longest word in it
        if (uMaxWord > d->minWidths[uColIdx]) {
            d->minWidths[uColIdx] = uMaxWord;
        }
    } else {
        d->minWidths[uColIdx] = d->maxWidths[uColIdx];
    }

    return true;
}

NoStringVector NoTable::toString() const
{
    if (d->output.empty())
        d->output = d->Render();
    return d->output;
}

NoStringVector NoTablePrivate::Render() const
{
    uint uTotalWidth = 1; // '|'
    for (uint uWidth : maxWidths) {
        uTotalWidth += uWidth + 3; // '|', ' 'x2
    }

    std::vector<uint> vuWidth = maxWidths;

    std::map<int, int> miColumnSpace;
    for (uint i = 0; i < headers.size(); ++i) {
        int iSpace = maxWidths[i] - minWidths[i];
        if (iSpace > 0) {
            miColumnSpace[i] = iSpace;
        }
    }

    // Not very efficient algorithm, and doesn't produce very good results...
    while (uTotalWidth > preferredWidth) {
        std::vector<int> viToErase;
        for (auto& i : miColumnSpace) {
            uTotalWidth--;
            i.second--;
            vuWidth[i.first]--;
            if (i.second == 0) {
                viToErase.push_back(i.first);
            }
            if (uTotalWidth == preferredWidth) {
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
            ssLine << headers[iCol] << " |";
        }
        vsOutput.emplace_back(ssLine.str());
    }
    vsOutput.emplace_back(vsOutput[0]);
    for (const NoStringVector& vsRow : rows) {
        // Wrap words
        std::vector<NoStringVector> vvsColumns;
        vvsColumns.reserve(headers.size());
        uint uRowNum = 1;
        for (uint iCol = 0; iCol < vuWidth.size(); ++iCol) {
            if (wrappable[iCol]) {
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
                const NoString& data = uCurrentLine < vvsColumns[iCol].size() ? vvsColumns[iCol][uCurrentLine] : sEmpty;
                ssLine << " ";
                ssLine << std::setw(vuWidth[iCol]) << std::left;
                ssLine << data << " |";
            }
            vsOutput.emplace_back(ssLine.str());
        }
        vsOutput.emplace_back(sHorizontal);
    }
    vsOutput.pop_back();
    vsOutput.emplace_back(vsOutput[0]);
    return vsOutput;
}

NoStringVector NoTablePrivate::WrapWords(const NoString& s, uint uWidth)
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

uint NoTablePrivate::GetColumnIndex(const NoString& name) const
{
    for (uint i = 0; i < headers.size(); i++) {
        if (headers[i] == name)
            return i;
    }

    NO_DEBUG("NoTable::GetColumnIndex(" + name + ") failed");

    return (uint)-1;
}

uint NoTablePrivate::GetColumnWidth(uint uIdx) const
{
    if (uIdx >= headers.size()) {
        return 0;
    }
    return maxWidths[uIdx];
}

void NoTable::clear()
{
    d->rows.clear();
    d->headers.clear();
    d->maxWidths.clear();
    d->minWidths.clear();
    d->wrappable.clear();
    d->output.clear();
}
