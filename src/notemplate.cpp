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

#include "notemplate.h"
#include "nofile.h"
#include "nodir.h"
#include "nodebug.h"
#include "noutils.h"
#include "noescape.h"
#include <algorithm>
#include <list>

class NoTemplateOptions
{
public:
    NoTemplateOptions() : m_eEscapeFrom(No::AsciiFormat), m_eEscapeTo(No::AsciiFormat)
    {
    }

    virtual ~NoTemplateOptions()
    {
    }

    void Parse(const NoString& sLine);

    No::EscapeFormat GetEscapeFrom() const
    {
        return m_eEscapeFrom;
    }
    No::EscapeFormat GetEscapeTo() const
    {
        return m_eEscapeTo;
    }

private:
    No::EscapeFormat m_eEscapeFrom;
    No::EscapeFormat m_eEscapeTo;
};

class NoTemplateLoopContext
{
public:
    NoTemplateLoopContext(ulong uFilePos, const NoString& sLoopName, bool bReverse, std::vector<NoTemplate*>* pRows)
        : m_bReverse(bReverse), m_bHasData(false), m_sName(sLoopName), m_uRowIndex(0), m_uFilePosition(uFilePos), m_pvRows(pRows)
    {
    }

    virtual ~NoTemplateLoopContext()
    {
    }

    NoTemplateLoopContext(const NoTemplateLoopContext&) = default;
    NoTemplateLoopContext& operator=(const NoTemplateLoopContext&) = default;

    void SetHasData(bool b = true)
    {
        m_bHasData = b;
    }
    void SetName(const NoString& s)
    {
        m_sName = s;
    }
    void SetRowIndex(uint u)
    {
        m_uRowIndex = u;
    }
    uint IncRowIndex()
    {
        return ++m_uRowIndex;
    }
    uint DecRowIndex()
    {
        if (m_uRowIndex == 0) {
            return 0;
        }
        return --m_uRowIndex;
    }
    void SetFilePosition(uint u)
    {
        m_uFilePosition = u;
    }

    bool HasData() const
    {
        return m_bHasData;
    }
    const NoString& GetName() const
    {
        return m_sName;
    }
    ulong GetFilePosition() const
    {
        return m_uFilePosition;
    }
    uint GetRowIndex() const
    {
        return m_uRowIndex;
    }
    size_t GetRowCount()
    {
        return m_pvRows->size();
    }
    std::vector<NoTemplate*>* GetRows()
    {
        return m_pvRows;
    }
    NoTemplate* GetNextRow()
    {
        return GetRow(IncRowIndex());
    }
    NoTemplate* GetCurRow()
    {
        return GetRow(m_uRowIndex);
    }

    NoTemplate* GetRow(uint uIndex);
    NoString GetValue(const NoString& sName, bool bFromIf = false);

private:
    bool m_bReverse; //!< Iterate through this loop in reverse order
    bool m_bHasData; //!< Tells whether this loop has real data or not
    NoString m_sName; //!< The name portion of the <?LOOP name?> tag
    uint m_uRowIndex; //!< The index of the current row we're on
    ulong m_uFilePosition; //!< The file position of the opening <?LOOP?> tag
    std::vector<NoTemplate*>* m_pvRows; //!< This holds pointers to the templates associated with this loop
};

class NoTemplatePrivate
{
public:
    NoString fileName;
    NoTemplate* parent = nullptr;
    std::list<std::pair<NoString, bool>> paths;
    std::map<NoString, std::vector<NoTemplate*>> loops;
    std::vector<NoTemplateLoopContext*> loopContexts;
    std::shared_ptr<NoTemplateOptions> options;
    std::vector<std::shared_ptr<NoTemplateTagHandler>> tagHandlers;
};

static No::EscapeFormat ToEscapeFormat(const NoString& sEsc)
{
    if (sEsc.equals("ASCII")) {
        return No::AsciiFormat;
    } else if (sEsc.equals("HTML")) {
        return No::HtmlFormat;
    } else if (sEsc.equals("URL")) {
        return No::UrlFormat;
    } else if (sEsc.equals("SQL")) {
        return No::SqlFormat;
    } else if (sEsc.equals("NAMEDFMT")) {
        return No::NamedFormat;
    } else if (sEsc.equals("DEBUG")) {
        return No::DebugFormat;
    } else if (sEsc.equals("MSGTAG")) {
        return No::MsgTagFormat;
    } else if (sEsc.equals("HEXCOLON")) {
        return No::HexColonFormat;
    }

    return No::AsciiFormat;
}

static uint SafeReplace(NoString& str, const NoString& sReplace, const NoString& sWith, const NoString& sLeft, const NoString& sRight)
{
    uint uRet = 0;
    NoString sCopy = str;
    str.clear();

    NoString::size_type uReplaceWidth = sReplace.length();
    NoString::size_type uLeftWidth = sLeft.length();
    NoString::size_type uRightWidth = sRight.length();
    const char* p = sCopy.c_str();
    bool bInside = false;

    while (*p) {
        if (!bInside && uLeftWidth && strncmp(p, sLeft.c_str(), uLeftWidth) == 0) {
            str.append(sLeft);

            p += uLeftWidth - 1;
            bInside = true;
        } else if (bInside && uRightWidth && strncmp(p, sRight.c_str(), uRightWidth) == 0) {
            str.append(sRight);

            p += uRightWidth - 1;
            bInside = false;
        } else if (!bInside && strncmp(p, sReplace.c_str(), uReplaceWidth) == 0) {
            str.append(sWith);
            p += uReplaceWidth - 1;
            uRet++;
        } else {
            str.append(p, 1);
        }

        p++;
    }

    return uRet;
}

void NoTemplateOptions::Parse(const NoString& sLine)
{
    NoString sName = No::token(sLine, 0, "=").trim_n().toUpper();
    NoString sValue = No::tokens(sLine, 1, "=").trim_n();

    if (sName == "ESC") {
        m_eEscapeTo = ToEscapeFormat(sValue);
    } else if (sName == "ESCFROM") {
        m_eEscapeFrom = ToEscapeFormat(sValue);
    }
}

NoTemplate* NoTemplateLoopContext::GetRow(uint uIndex)
{
    size_t uSize = m_pvRows->size();

    if (uIndex < uSize) {
        if (m_bReverse) {
            return (*m_pvRows)[uSize - uIndex - 1];
        } else {
            return (*m_pvRows)[uIndex];
        }
    }

    return nullptr;
}

NoString NoTemplateLoopContext::GetValue(const NoString& sName, bool bFromIf)
{
    NoTemplate* pTemplate = GetCurRow();

    if (!pTemplate) {
        NO_DEBUG("Loop [" + GetName() + "] has no row index [" + NoString(GetRowIndex()) + "]");
        return "";
    }

    if (sName.equals("__ID__")) {
        return NoString(GetRowIndex() + 1);
    } else if (sName.equals("__COUNT__")) {
        return NoString(GetRowCount());
    } else if (sName.equals("__ODD__")) {
        return ((GetRowIndex() % 2) ? "" : "1");
    } else if (sName.equals("__EVEN__")) {
        return ((GetRowIndex() % 2) ? "1" : "");
    } else if (sName.equals("__FIRST__")) {
        return ((GetRowIndex() == 0) ? "1" : "");
    } else if (sName.equals("__LAST__")) {
        return ((GetRowIndex() == m_pvRows->size() - 1) ? "1" : "");
    } else if (sName.equals("__OUTER__")) {
        return ((GetRowIndex() == 0 || GetRowIndex() == m_pvRows->size() - 1) ? "1" : "");
    } else if (sName.equals("__INNER__")) {
        return ((GetRowIndex() == 0 || GetRowIndex() == m_pvRows->size() - 1) ? "" : "1");
    }

    return pTemplate->value(sName, bFromIf);
}

NoTemplate::NoTemplate(const NoString& sFileName) : d(new NoTemplatePrivate)
{
    d->fileName = sFileName;
    d->options.reset(new NoTemplateOptions);
}

NoTemplate::NoTemplate(const std::shared_ptr<NoTemplateOptions>& options, NoTemplate* parent) : d(new NoTemplatePrivate)
{
    d->options = options;
    d->parent = parent;
}

NoTemplate::~NoTemplate()
{
    for (const auto& it : d->loops) {
        const std::vector<NoTemplate*>& vLoop = it.second;
        for (NoTemplate* pTemplate : vLoop) {
            delete pTemplate;
        }
    }

    for (NoTemplateLoopContext* pContext : d->loopContexts) {
        delete pContext;
    }
}

void NoTemplate::addTagHandler(std::shared_ptr<NoTemplateTagHandler> spTagHandler)
{
    d->tagHandlers.push_back(spTagHandler);
}

std::vector<std::shared_ptr<NoTemplateTagHandler>>& NoTemplate::tagHandlers()
{
    if (d->parent) {
        return d->parent->tagHandlers();
    }

    return d->tagHandlers;
}

void NoTemplate::init()
{
    /* We have no NoSettings in ZNC land
     * Hmm... Actually, we do have it now.
    NoString sPath(NoSettings::GetValue("WebFilesPath"));

    if (!sPath.empty()) {
        SetPath(sPath);
    }
    */

    clearPaths();
    d->parent = nullptr;
}

NoString NoTemplate::expandFile(const NoString& sFilename, bool bFromInc)
{
    /*if (sFilename.Left(1) == "/" || sFilename.Left(2) == "./") {
        return sFilename;
    }*/

    NoString sFile(resolveLiteral(sFilename).trimLeft_n("/"));

    for (auto& it : d->paths) {
        NoString& sRoot = it.first;
        NoString sFilePath = NoDir(sRoot).filePath(sFile);

        // Make sure path ends with a slash because "/foo/pub*" matches "/foo/public_keep_out/" but "/foo/pub/*" doesn't
        if (!sRoot.empty() && sRoot.right(1) != "/") {
            sRoot += "/";
        }

        if (it.second && !bFromInc) {
            NO_DEBUG("\t\tSkipping path (not from INC)  [" + sFilePath + "]");
            continue;
        }

        if (NoFile::Exists(sFilePath)) {
            if (sRoot.empty() || sFilePath.left(sRoot.length()) == sRoot) {
                NO_DEBUG("    Found  [" + sFilePath + "]");
                return sFilePath;
            } else {
                NO_DEBUG("\t\tOutside of root [" + sFilePath + "] !~ [" + sRoot + "]");
            }
        }
    }

    switch (d->paths.size()) {
    case 0:
        NO_DEBUG("Unable to find [" + sFile + "] using the current directory");
        break;
    case 1:
        NO_DEBUG("Unable to find [" + sFile + "] in the defined path [" + d->paths.begin()->first + "]");
        break;
    default:
        NO_DEBUG("Unable to find [" + sFile + "] in any of the " + NoString(d->paths.size()) + " defined paths");
    }

    return "";
}

void NoTemplate::setPath(const NoString& sPaths)
{
    NoStringVector vsDirs = sPaths.split(":", No::SkipEmptyParts);

    for (const NoString& sDir : vsDirs) {
        appendPath(sDir, false);
    }
}

NoString NoTemplate::makePath(const NoString& sPath) const
{
    NoString sRet = NoDir("./").filePath(sPath + "/");

    if (!sRet.empty() && sRet.right(1) != "/") {
        sRet += "/";
    }

    return sRet;
}

void NoTemplate::prependPath(const NoString& sPath, bool bIncludesOnly)
{
    NO_DEBUG("NoTemplate::PrependPath(" + sPath + ") == [" + makePath(sPath) + "]");
    d->paths.push_front(make_pair(makePath(sPath), bIncludesOnly));
}

void NoTemplate::appendPath(const NoString& sPath, bool bIncludesOnly)
{
    NO_DEBUG("NoTemplate::AppendPath(" + sPath + ") == [" + makePath(sPath) + "]");
    d->paths.push_back(make_pair(makePath(sPath), bIncludesOnly));
}

void NoTemplate::removePath(const NoString& sPath)
{
    NO_DEBUG("NoTemplate::RemovePath(" + sPath + ") == [" + NoDir("./").filePath(sPath + "/") + "]");

    for (const auto& it : d->paths) {
        if (it.first == sPath) {
            d->paths.remove(it);
            removePath(sPath); // @todo probably shouldn't use recursion, being lazy
            return;
        }
    }
}

void NoTemplate::clearPaths()
{
    d->paths.clear();
}

bool NoTemplate::setFile(const NoString& sFileName)
{
    d->fileName = expandFile(sFileName, false);
    prependPath(sFileName + "/..");

    if (sFileName.empty()) {
        NO_DEBUG("NoTemplate::SetFile() - Filename is empty");
        return false;
    }

    if (d->fileName.empty()) {
        NO_DEBUG("NoTemplate::SetFile() - [" + sFileName + "] does not exist");
        return false;
    }

    NO_DEBUG("Set template file to [" + d->fileName + "]");

    return true;
}

class NoLoopSorter
{
    NoString m_sType;

public:
    NoLoopSorter(const NoString& sType) : m_sType(sType)
    {
    }
    bool operator()(NoTemplate* pTemplate1, NoTemplate* pTemplate2)
    {
        return (pTemplate1->value(m_sType, false) < pTemplate2->value(m_sType, false));
    }
};

NoTemplate& NoTemplate::addRow(const NoString& sName)
{
    NoTemplate* pTmpl = new NoTemplate(d->options, this);
    d->loops[sName].push_back(pTmpl);

    return *pTmpl;
}

NoTemplate* NoTemplate::row(const NoString& sName, uint uIndex)
{
    std::vector<NoTemplate*>* pvLoop = loop(sName);

    if (pvLoop) {
        if (pvLoop->size() > uIndex) {
            return (*pvLoop)[uIndex];
        }
    }

    return nullptr;
}

std::vector<NoTemplate*>* NoTemplate::loop(const NoString& sName)
{
    NoTemplateLoopContext* pContext = currentLoopContext();

    if (pContext) {
        NoTemplate* pTemplate = pContext->GetCurRow();

        if (pTemplate) {
            return pTemplate->loop(sName);
        }
    }

    std::map<NoString, std::vector<NoTemplate*>>::iterator it = d->loops.find(sName);

    if (it != d->loops.end()) {
        return &(it->second);
    }

    return nullptr;
}

bool NoTemplate::printString(NoString& sRet)
{
    sRet.clear();
    std::stringstream sStream;
    bool bRet = print(sStream);

    sRet = sStream.str();

    return bRet;
}

bool NoTemplate::print(std::ostream& oOut)
{
    return print(d->fileName, oOut);
}

bool NoTemplate::print(const NoString& sFileName, std::ostream& oOut)
{
    if (sFileName.empty()) {
        NO_DEBUG("Empty filename in NoTemplate::Print()");
        return false;
    }

    NoFile File(sFileName);

    if (!File.Open()) {
        NO_DEBUG("Unable to open file [" + sFileName + "] in NoTemplate::Print()");
        return false;
    }

    NoString sLine;
    NoString sSetBlockVar;
    bool bValidLastIf = false;
    bool bInSetBlock = false;
    ulong uFilePos = 0;
    ulong uCurPos = 0;
    uint uLineNum = 0;
    uint uNestedIfs = 0;
    uint uSkip = 0;
    bool bLoopCont = false;
    bool bLoopBreak = false;
    bool bExit = false;

    while (File.ReadLine(sLine)) {
        NoString sOutput;
        bool bFoundATag = false;
        bool bTmplLoopHasData = false;
        uLineNum++;
        NoString::size_type iPos = 0;
        uCurPos = uFilePos;
        NoString::size_type uLineSize = sLine.size();
        bool bBroke = false;

        while (1) {
            iPos = sLine.find("<?");

            if (iPos == NoString::npos) {
                break;
            }

            uCurPos += iPos;
            bFoundATag = true;

            if (!uSkip) {
                sOutput += sLine.substr(0, iPos);
            }

            sLine = sLine.substr(iPos + 2);

            NoString::size_type iPos2 = sLine.find("?>");

            // Make sure our tmpl tag is ended properly
            if (iPos2 == NoString::npos) {
                NO_DEBUG("Template tag not ended properly in file [" + sFileName + "] [<?" + sLine + "]");
                return false;
            }

            uCurPos += iPos2 + 4;

            NoString sMid = NoString(sLine.substr(0, iPos2)).trim_n();

            // Make sure we don't have a nested tag
            if (!sMid.contains("<?")) {
                sLine = sLine.substr(iPos2 + 2);
                NoString sAction = No::token(sMid, 0);
                NoString sArgs = No::tokens(sMid, 1);
                bool bNotFound = false;

                // If we're breaking or continuing from within a loop, skip all tags that aren't ENDLOOP
                if ((bLoopCont || bLoopBreak) && !sAction.equals("ENDLOOP")) {
                    continue;
                }

                if (!uSkip) {
                    if (sAction.equals("INC")) {
                        if (!print(expandFile(sArgs, true), oOut)) {
                            NO_DEBUG("Unable to print INC'd file [" + sArgs + "]");
                            return false;
                        }
                    } else if (sAction.equals("SETOPTION")) {
                        d->options->Parse(sArgs);
                    } else if (sAction.equals("ADDROW")) {
                        NoString sLoopName = No::token(sArgs, 0);
                        NoStringMap msRow = No::optionSplit(No::tokens(sArgs, 1, " "));
                        if (!msRow.empty()) {
                            NoTemplate& NewRow = addRow(sLoopName);

                            for (const auto& it : msRow) {
                                NewRow[it.first] = it.second;
                            }
                        }
                    } else if (sAction.equals("SET")) {
                        NoString sName = No::token(sArgs, 0);
                        NoString sValue = No::tokens(sArgs, 1);

                        (*this)[sName] = sValue;
                    } else if (sAction.equals("JOIN")) {
                        NoStringVector vsArgs = No::quoteSplit(sArgs);
                        if (vsArgs.size() > 1) {
                            NoString sDelim = vsArgs[0].trim_n("\"");
                            bool bFoundOne = false;
                            No::EscapeFormat eEscape = No::AsciiFormat;

                            for (const NoString& sArg : vsArgs) {
                                if (sArg.startsWith("ESC=")) {
                                    eEscape = ToEscapeFormat(sArg.leftChomp_n(4));
                                } else {
                                    NoString sValue = value(sArg);

                                    if (!sValue.empty()) {
                                        if (bFoundOne) {
                                            sOutput += sDelim;
                                        }

                                        sOutput += No::escape(sValue, eEscape);
                                        bFoundOne = true;
                                    }
                                }
                            }
                        }
                    } else if (sAction.equals("SETBLOCK")) {
                        sSetBlockVar = sArgs;
                        bInSetBlock = true;
                    } else if (sAction.equals("EXPAND")) {
                        sOutput += expandFile(sArgs, true);
                    } else if (sAction.equals("VAR")) {
                        sOutput += value(sArgs);
                    } else if (sAction.equals("LT")) {
                        sOutput += "<?";
                    } else if (sAction.equals("GT")) {
                        sOutput += "?>";
                    } else if (sAction.equals("CONTINUE")) {
                        NoTemplateLoopContext* pContext = currentLoopContext();

                        if (pContext) {
                            uSkip++;
                            bLoopCont = true;

                            break;
                        } else {
                            NO_DEBUG("[" + sFileName + ":" + NoString(uCurPos - iPos2 - 4) +
                                     "] <? CONTINUE ?> must be used inside of a loop!");
                        }
                    } else if (sAction.equals("BREAK")) {
                        // break from loop
                        NoTemplateLoopContext* pContext = currentLoopContext();

                        if (pContext) {
                            uSkip++;
                            bLoopBreak = true;

                            break;
                        } else {
                            NO_DEBUG("[" + sFileName + ":" + NoString(uCurPos - iPos2 - 4) +
                                     "] <? BREAK ?> must be used inside of a loop!");
                        }
                    } else if (sAction.equals("EXIT")) {
                        bExit = true;
                    } else if (sAction.equals("DEBUG")) {
                        NO_DEBUG("NoTemplate DEBUG [" + sFileName + "@" + NoString(uCurPos - iPos2 - 4) + "b] -> [" + sArgs + "]");
                    } else if (sAction.equals("LOOP")) {
                        NoTemplateLoopContext* pContext = currentLoopContext();

                        if (!pContext || pContext->GetFilePosition() != uCurPos) {
                            // we are at a brand new loop (be it new or a first pass at an inner loop)

                            NoString sLoopName = No::token(sArgs, 0);
                            bool bReverse = (No::token(sArgs, 1).equals("REVERSE"));
                            bool bSort = (No::token(sArgs, 1).left(4).equals("SORT"));
                            std::vector<NoTemplate*>* pvLoop = loop(sLoopName);

                            if (bSort && pvLoop != nullptr && pvLoop->size() > 1) {
                                NoString sKey;

                                if (No::token(sArgs, 1).trimPrefix_n("SORT").left(4).equals("ASC=")) {
                                    sKey = No::token(sArgs, 1).trimPrefix_n("SORTASC=");
                                } else if (No::token(sArgs, 1).trimPrefix_n("SORT").left(5).equals("DESC=")) {
                                    sKey = No::token(sArgs, 1).trimPrefix_n("SORTDESC=");
                                    bReverse = true;
                                }

                                if (!sKey.empty()) {
                                    std::sort(pvLoop->begin(), pvLoop->end(), NoLoopSorter(sKey));
                                }
                            }

                            if (pvLoop) {
                                // If we found data for this loop, add it to our context vector
                                // ulong uBeforeLoopTag = uCurPos - iPos2 - 4;
                                ulong uAfterLoopTag = uCurPos;

                                for (NoString::size_type t = 0; t < sLine.size(); t++) {
                                    char c = sLine[t];
                                    if (c == '\r' || c == '\n') {
                                        uAfterLoopTag++;
                                    } else {
                                        break;
                                    }
                                }

                                d->loopContexts.push_back(new NoTemplateLoopContext(uAfterLoopTag, sLoopName, bReverse, pvLoop));
                            } else { // If we don't have data, just skip this loop and everything inside
                                uSkip++;
                            }
                        }
                    } else if (sAction.equals("IF")) {
                        if (validIf(sArgs)) {
                            uNestedIfs++;
                            bValidLastIf = true;
                        } else {
                            uSkip++;
                            bValidLastIf = false;
                        }
                    } else if (sAction.equals("REM")) {
                        uSkip++;
                    } else {
                        bNotFound = true;
                    }
                } else if (sAction.equals("REM")) {
                    uSkip++;
                } else if (sAction.equals("IF")) {
                    uSkip++;
                } else if (sAction.equals("LOOP")) {
                    uSkip++;
                }

                if (sAction.equals("ENDIF")) {
                    if (uSkip) {
                        uSkip--;
                    } else {
                        uNestedIfs--;
                    }
                } else if (sAction.equals("ENDREM")) {
                    if (uSkip) {
                        uSkip--;
                    }
                } else if (sAction.equals("ENDSETBLOCK")) {
                    bInSetBlock = false;
                    sSetBlockVar = "";
                } else if (sAction.equals("ENDLOOP")) {
                    if (bLoopCont && uSkip == 1) {
                        uSkip--;
                        bLoopCont = false;
                    }

                    if (bLoopBreak && uSkip == 1) {
                        uSkip--;
                    }

                    if (uSkip) {
                        uSkip--;
                    } else {
                        // We are at the end of the loop so we need to inc the index
                        NoTemplateLoopContext* pContext = currentLoopContext();

                        if (pContext) {
                            pContext->IncRowIndex();

                            // If we didn't go out of bounds we need to seek back to the top of our loop
                            if (!bLoopBreak && pContext->GetCurRow()) {
                                uCurPos = pContext->GetFilePosition();
                                uFilePos = uCurPos;
                                uLineSize = 0;

                                File.Seek(uCurPos);
                                bBroke = true;

                                if (!sOutput.trim_n().empty()) {
                                    pContext->SetHasData();
                                }

                                break;
                            } else {
                                if (sOutput.trim_n().empty()) {
                                    sOutput.clear();
                                }

                                bTmplLoopHasData = pContext->HasData();
                                deleteCurLoopContext();
                                bLoopBreak = false;
                            }
                        }
                    }
                } else if (sAction.equals("ELSE")) {
                    if (!bValidLastIf && uSkip == 1) {
                        NoString sArg = No::token(sArgs, 0);

                        if (sArg.empty() || (sArg.equals("IF") && validIf(No::tokens(sArgs, 1)))) {
                            uSkip = 0;
                            bValidLastIf = true;
                        }
                    } else if (!uSkip) {
                        uSkip = 1;
                    }
                } else if (bNotFound) {
                    // Unknown tag that isn't being skipped...
                    std::vector<std::shared_ptr<NoTemplateTagHandler>>& vspTagHandlers = tagHandlers();

                    if (!vspTagHandlers.empty()) { // @todo this should go up to the top to grab handlers
                        NoTemplate* pTmpl = currentTemplate();
                        NoString sCustomOutput;

                        for (const auto& spTagHandler : vspTagHandlers) {
                            if (spTagHandler->handleTag(*pTmpl, sAction, sArgs, sCustomOutput)) {
                                sOutput += sCustomOutput;
                                bNotFound = false;
                                break;
                            }
                        }

                        if (bNotFound) {
                            NO_DEBUG("Unknown/Unhandled tag [" + sAction + "]");
                        }
                    }
                }

                continue;
            }

            NO_DEBUG("Malformed tag on line " + NoString(uLineNum) + " of [" << File.GetLongName() + "]");
            NO_DEBUG("--------------- [" + sLine + "]");
        }

        if (!bBroke) {
            uFilePos += uLineSize;

            if (!uSkip) {
                sOutput += sLine;
            }
        }

        if (!bFoundATag || bTmplLoopHasData || sOutput.find_first_not_of(" \t\r\n") != NoString::npos) {
            if (bInSetBlock) {
                NoString sName = No::token(sSetBlockVar, 0);
                // NoString sValue = No::tokens(sSetBlockVar, 1);
                (*this)[sName] += sOutput;
            } else {
                oOut << sOutput;
            }
        }

        if (bExit) {
            break;
        }
    }

    oOut.flush();

    return true;
}

void NoTemplate::deleteCurLoopContext()
{
    if (d->loopContexts.empty()) {
        return;
    }

    delete d->loopContexts.back();
    d->loopContexts.pop_back();
}

NoTemplateLoopContext* NoTemplate::currentLoopContext()
{
    if (!d->loopContexts.empty()) {
        return d->loopContexts.back();
    }

    return nullptr;
}

bool NoTemplate::validIf(const NoString& sArgs)
{
    NoString sArgStr = sArgs;
    // SafeReplace(sArgStr, " ", "", "\"", "\"", true);
    SafeReplace(sArgStr, " &&", "&&", "\"", "\"");
    SafeReplace(sArgStr, "&& ", "&&", "\"", "\"");
    SafeReplace(sArgStr, " ||", "||", "\"", "\"");
    SafeReplace(sArgStr, "|| ", "||", "\"", "\"");

    NoString::size_type uOrPos = sArgStr.find("||");
    NoString::size_type uAndPos = sArgStr.find("&&");

    while (uOrPos != NoString::npos || uAndPos != NoString::npos || !sArgStr.empty()) {
        bool bAnd = false;

        if (uAndPos < uOrPos) {
            bAnd = true;
        }

        NoString sExpr = No::token(sArgStr, 0, ((bAnd) ? "&&" : "||"));
        sArgStr = No::tokens(sArgStr, 1, ((bAnd) ? "&&" : "||"));

        if (validExpr(sExpr)) {
            if (!bAnd) {
                return true;
            }
        } else {
            if (bAnd) {
                return false;
            }
        }

        uOrPos = sArgStr.find("||");
        uAndPos = sArgStr.find("&&");
    }

    return false;
}

// TODO: cleanup
extern NoString
Token_helper(const NoString& str, size_t uPos, bool bRest, const NoString& sSep, const NoString& sLeft, const NoString& sRight);

bool NoTemplate::validExpr(const NoString& sExpression)
{
    bool bNegate = false;
    NoString sExpr(sExpression);
    NoString sName;
    NoString sValue;

    if (sExpr.left(1) == "!") {
        bNegate = true;
        sExpr.leftChomp(1);
    }

    if (sExpr.contains("!=")) {
        sName = No::token(sExpr, 0, "!=").trim_n();
        sValue = Token_helper(sExpr, 1, true, "!=", "\"", "\"").trim_n().trim_n("\"");
        bNegate = !bNegate;
    } else if (sExpr.contains("==")) {
        sName = No::token(sExpr, 0, "==").trim_n();
        sValue = Token_helper(sExpr, 1, true, "==", "\"", "\"").trim_n().trim_n("\"");
    } else if (sExpr.contains(">=")) {
        sName = No::token(sExpr, 0, ">=").trim_n();
        sValue = Token_helper(sExpr, 1, true, ">=", "\"", "\"").trim_n().trim_n("\"");
        return (value(sName, true).toLong() >= sValue.toLong());
    } else if (sExpr.contains("<=")) {
        sName = No::token(sExpr, 0, "<=").trim_n();
        sValue = Token_helper(sExpr, 1, true, "<=", "\"", "\"").trim_n().trim_n("\"");
        return (value(sName, true).toLong() <= sValue.toLong());
    } else if (sExpr.contains(">")) {
        sName = No::token(sExpr, 0, ">").trim_n();
        sValue = Token_helper(sExpr, 1, true, ">", "\"", "\"").trim_n().trim_n("\"");
        return (value(sName, true).toLong() > sValue.toLong());
    } else if (sExpr.contains("<")) {
        sName = No::token(sExpr, 0, "<").trim_n();
        sValue = Token_helper(sExpr, 1, true, "<", "\"", "\"").trim_n().trim_n("\"");
        return (value(sName, true).toLong() < sValue.toLong());
    } else {
        sName = sExpr.trim_n();
    }

    if (sValue.empty()) {
        return (bNegate != isTrue(sName));
    }

    sValue = resolveLiteral(sValue);

    return (bNegate != value(sName, true).equals(sValue));
}

bool NoTemplate::isTrue(const NoString& sName)
{
    if (hasLoop(sName)) {
        return true;
    }

    return value(sName, true).toBool();
}

bool NoTemplate::hasLoop(const NoString& sName)
{
    return (loop(sName) != nullptr);
}

NoTemplate* NoTemplate::parent(bool bRoot)
{
    if (!bRoot) {
        return d->parent;
    }

    return (d->parent) ? d->parent->parent(bRoot) : this;
}

NoTemplate* NoTemplate::currentTemplate()
{
    NoTemplateLoopContext* pContext = currentLoopContext();

    if (!pContext) {
        return this;
    }

    return pContext->GetCurRow();
}

NoString NoTemplate::fileName() const
{
    return d->fileName;
}

NoString NoTemplate::resolveLiteral(const NoString& sString)
{
    if (sString.left(2) == "**") {
        // Allow string to start with a literal * by using two in a row
        return sString.substr(1);
    } else if (sString.left(1) == "*") {
        // If it starts with only one * then treat it as a var and do a lookup
        return value(sString.substr(1));
    }

    return sString;
}

NoString NoTemplate::value(const NoString& sArgs, bool bFromIf)
{
    NoTemplateLoopContext* pContext = currentLoopContext();
    NoString sName = No::token(sArgs, 0);
    NoString sRest = No::tokens(sArgs, 1);
    NoString sRet;

    while (SafeReplace(sRest, " =", "=", "\"", "\"")) {
    }
    while (SafeReplace(sRest, "= ", "=", "\"", "\"")) {
    }

    NoStringVector vArgs = No::quoteSplit(sRest);
    NoStringMap msArgs;

    for (NoString& sArg : vArgs) {
        sArg.trim("\"");
        msArgs[No::token(sArg, 0, "=").toUpper()] = No::tokens(sArg, 1, "=");
    }

    /* We have no NoSettings in ZNC land
	 * Hmm... Actually, we do have it now.
	if (msArgs.find("CONFIG") != msArgs.end()) {
		sRet = NoSettings::GetValue(sName);
	} else*/ if (msArgs.find("ROWS") != msArgs.end()) {
        std::vector<NoTemplate*>* pLoop = loop(sName);
        sRet = NoString((pLoop) ? pLoop->size() : 0);
    } else if (msArgs.find("TOP") == msArgs.end() && pContext) {
        sRet = pContext->GetValue(sArgs, bFromIf);

        if (!sRet.empty()) {
            return sRet;
        }
    } else {
        if (sName.left(1) == "*") {
            sName.leftChomp(1);
            NoStringMap::iterator it = find(sName);
            sName = (it != end()) ? it->second : "";
        }

        NoStringMap::iterator it = find(sName);
        sRet = (it != end()) ? it->second : "";
    }

    std::vector<std::shared_ptr<NoTemplateTagHandler>>& vspTagHandlers = tagHandlers();

    if (!vspTagHandlers.empty()) { // @todo this should go up to the top to grab handlers
        NoTemplate* pTmpl = currentTemplate();

        if (sRet.empty()) {
            for (const auto& spTagHandler : vspTagHandlers) {
                NoString sCustomOutput;

                if (!bFromIf && spTagHandler->handleVar(*pTmpl, No::token(sArgs, 0), No::tokens(sArgs, 1), sCustomOutput)) {
                    sRet = sCustomOutput;
                    break;
                } else if (bFromIf && spTagHandler->handleIf(*pTmpl, No::token(sArgs, 0), No::tokens(sArgs, 1), sCustomOutput)) {
                    sRet = sCustomOutput;
                    break;
                }
            }
        }

        for (const auto& spTagHandler : vspTagHandlers) {
            if (spTagHandler->handleValue(*pTmpl, sRet, msArgs)) {
                break;
            }
        }
    }

    if (!bFromIf) {
        if (sRet.empty()) {
            sRet = resolveLiteral(msArgs["DEFAULT"]);
        }

        NoStringMap::iterator it = msArgs.find("ESC");

        if (it != msArgs.end()) {
            NoStringVector vsEscs = it->second.split(",", No::SkipEmptyParts);

            for (const NoString& sEsc : vsEscs) {
                sRet = No::escape(sRet, ToEscapeFormat(sEsc));
            }
        } else {
            sRet = No::escape(sRet, d->options->GetEscapeFrom(), d->options->GetEscapeTo());
        }
    }

    return sRet;
}
