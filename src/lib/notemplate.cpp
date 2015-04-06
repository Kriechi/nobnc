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

    void Parse(const NoString& line);

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

    NoTemplate* GetRow(uint index);
    NoString GetValue(const NoString& name, bool bFromIf = false);

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

void NoTemplateOptions::Parse(const NoString& line)
{
    NoString name = No::token(line, 0, "=").trim_n().toUpper();
    NoString value = No::tokens(line, 1, "=").trim_n();

    if (name == "ESC") {
        m_eEscapeTo = ToEscapeFormat(value);
    } else if (name == "ESCFROM") {
        m_eEscapeFrom = ToEscapeFormat(value);
    }
}

NoTemplate* NoTemplateLoopContext::GetRow(uint index)
{
    size_t uSize = m_pvRows->size();

    if (index < uSize) {
        if (m_bReverse) {
            return (*m_pvRows)[uSize - index - 1];
        } else {
            return (*m_pvRows)[index];
        }
    }

    return nullptr;
}

NoString NoTemplateLoopContext::GetValue(const NoString& name, bool bFromIf)
{
    NoTemplate* pTemplate = GetCurRow();

    if (!pTemplate) {
        NO_DEBUG("Loop [" + GetName() + "] has no row index [" + NoString(GetRowIndex()) + "]");
        return "";
    }

    if (name.equals("__ID__")) {
        return NoString(GetRowIndex() + 1);
    } else if (name.equals("__COUNT__")) {
        return NoString(GetRowCount());
    } else if (name.equals("__ODD__")) {
        return ((GetRowIndex() % 2) ? "" : "1");
    } else if (name.equals("__EVEN__")) {
        return ((GetRowIndex() % 2) ? "1" : "");
    } else if (name.equals("__FIRST__")) {
        return ((GetRowIndex() == 0) ? "1" : "");
    } else if (name.equals("__LAST__")) {
        return ((GetRowIndex() == m_pvRows->size() - 1) ? "1" : "");
    } else if (name.equals("__OUTER__")) {
        return ((GetRowIndex() == 0 || GetRowIndex() == m_pvRows->size() - 1) ? "1" : "");
    } else if (name.equals("__INNER__")) {
        return ((GetRowIndex() == 0 || GetRowIndex() == m_pvRows->size() - 1) ? "" : "1");
    }

    return pTemplate->value(name, bFromIf);
}

NoTemplate::NoTemplate(const NoString& fileName) : d(new NoTemplatePrivate)
{
    d->fileName = fileName;
    d->options.reset(new NoTemplateOptions);
}

NoTemplate::NoTemplate(std::shared_ptr<NoTemplateOptions> options, NoTemplate* parent) : d(new NoTemplatePrivate)
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
    NoString path(NoSettings::GetValue("WebFilesPath"));

    if (!path.empty()) {
        SetPath(path);
    }
    */

    clearPaths();
    d->parent = nullptr;
}

NoString NoTemplate::expandFile(const NoString& sFilename, bool bFromInc)
{
    /*if (sFilename.startsWith("/") || sFilename.startsWith("./")) {
        return sFilename;
    }*/

    NoString sFile(resolveLiteral(sFilename).trimLeft_n("/"));

    for (auto& it : d->paths) {
        NoString& sRoot = it.first;
        NoString sFilePath = NoDir(sRoot).filePath(sFile);

        // Make sure path ends with a slash because "/foo/pub*" matches "/foo/public_keep_out/" but "/foo/pub/*" doesn't
        if (!sRoot.empty() && !sRoot.endsWith("/")) {
            sRoot += "/";
        }

        if (it.second && !bFromInc) {
            NO_DEBUG("\t\tSkipping path (not from INC)  [" + sFilePath + "]");
            continue;
        }

        if (NoFile::Exists(sFilePath)) {
            if (sRoot.empty() || sFilePath.startsWith(sRoot)) {
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

NoString NoTemplate::makePath(const NoString& path) const
{
    NoString ret = NoDir("./").filePath(path + "/");

    if (!ret.empty() && !ret.endsWith("/")) {
        ret += "/";
    }

    return ret;
}

void NoTemplate::prependPath(const NoString& path, bool includesOnly)
{
    NO_DEBUG("NoTemplate::PrependPath(" + path + ") == [" + makePath(path) + "]");
    d->paths.push_front(make_pair(makePath(path), includesOnly));
}

void NoTemplate::appendPath(const NoString& path, bool includesOnly)
{
    NO_DEBUG("NoTemplate::AppendPath(" + path + ") == [" + makePath(path) + "]");
    d->paths.push_back(make_pair(makePath(path), includesOnly));
}

void NoTemplate::removePath(const NoString& path)
{
    NO_DEBUG("NoTemplate::RemovePath(" + path + ") == [" + NoDir("./").filePath(path + "/") + "]");

    for (const auto& it : d->paths) {
        if (it.first == path) {
            d->paths.remove(it);
            removePath(path); // @todo probably shouldn't use recursion, being lazy
            return;
        }
    }
}

void NoTemplate::clearPaths()
{
    d->paths.clear();
}

bool NoTemplate::setFile(const NoString& fileName)
{
    d->fileName = expandFile(fileName, false);
    prependPath(fileName + "/..");

    if (fileName.empty()) {
        NO_DEBUG("NoTemplate::SetFile() - Filename is empty");
        return false;
    }

    if (d->fileName.empty()) {
        NO_DEBUG("NoTemplate::SetFile() - [" + fileName + "] does not exist");
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

NoTemplate& NoTemplate::addRow(const NoString& name)
{
    NoTemplate* pTmpl = new NoTemplate(d->options, this);
    d->loops[name].push_back(pTmpl);

    return *pTmpl;
}

NoTemplate* NoTemplate::row(const NoString& name, uint index)
{
    std::vector<NoTemplate*>* pvLoop = loop(name);

    if (pvLoop) {
        if (pvLoop->size() > index) {
            return (*pvLoop)[index];
        }
    }

    return nullptr;
}

std::vector<NoTemplate*>* NoTemplate::loop(const NoString& name)
{
    NoTemplateLoopContext* pContext = currentLoopContext();

    if (pContext) {
        NoTemplate* pTemplate = pContext->GetCurRow();

        if (pTemplate) {
            return pTemplate->loop(name);
        }
    }

    std::map<NoString, std::vector<NoTemplate*>>::iterator it = d->loops.find(name);

    if (it != d->loops.end()) {
        return &(it->second);
    }

    return nullptr;
}

bool NoTemplate::printString(NoString& ret)
{
    ret.clear();
    std::stringstream sStream;
    bool bRet = print(sStream);

    ret = sStream.str();

    return bRet;
}

bool NoTemplate::print(std::ostream& oOut)
{
    return print(d->fileName, oOut);
}

bool NoTemplate::print(const NoString& fileName, std::ostream& oOut)
{
    if (fileName.empty()) {
        NO_DEBUG("Empty filename in NoTemplate::Print()");
        return false;
    }

    NoFile File(fileName);

    if (!File.Open()) {
        NO_DEBUG("Unable to open file [" + fileName + "] in NoTemplate::Print()");
        return false;
    }

    NoString line;
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

    while (File.ReadLine(line)) {
        NoString sOutput;
        bool bFoundATag = false;
        bool bTmplLoopHasData = false;
        uLineNum++;
        NoString::size_type iPos = 0;
        uCurPos = uFilePos;
        NoString::size_type uLineSize = line.size();
        bool bBroke = false;

        while (1) {
            iPos = line.find("<?");

            if (iPos == NoString::npos) {
                break;
            }

            uCurPos += iPos;
            bFoundATag = true;

            if (!uSkip) {
                sOutput += line.substr(0, iPos);
            }

            line = line.substr(iPos + 2);

            NoString::size_type iPos2 = line.find("?>");

            // Make sure our tmpl tag is ended properly
            if (iPos2 == NoString::npos) {
                NO_DEBUG("Template tag not ended properly in file [" + fileName + "] [<?" + line + "]");
                return false;
            }

            uCurPos += iPos2 + 4;

            NoString sMid = NoString(line.substr(0, iPos2)).trim_n();

            // Make sure we don't have a nested tag
            if (!sMid.contains("<?")) {
                line = line.substr(iPos2 + 2);
                NoString action = No::token(sMid, 0);
                NoString args = No::tokens(sMid, 1);
                bool bNotFound = false;

                // If we're breaking or continuing from within a loop, skip all tags that aren't ENDLOOP
                if ((bLoopCont || bLoopBreak) && !action.equals("ENDLOOP")) {
                    continue;
                }

                if (!uSkip) {
                    if (action.equals("INC")) {
                        if (!print(expandFile(args, true), oOut)) {
                            NO_DEBUG("Unable to print INC'd file [" + args + "]");
                            return false;
                        }
                    } else if (action.equals("SETOPTION")) {
                        d->options->Parse(args);
                    } else if (action.equals("ADDROW")) {
                        NoString sLoopName = No::token(args, 0);
                        NoStringMap msRow = No::optionSplit(No::tokens(args, 1, " "));
                        if (!msRow.empty()) {
                            NoTemplate& NewRow = addRow(sLoopName);

                            for (const auto& it : msRow) {
                                NewRow[it.first] = it.second;
                            }
                        }
                    } else if (action.equals("SET")) {
                        NoString name = No::token(args, 0);
                        NoString value = No::tokens(args, 1);

                        (*this)[name] = value;
                    } else if (action.equals("JOIN")) {
                        NoStringVector vsArgs = No::quoteSplit(args);
                        if (vsArgs.size() > 1) {
                            NoString sDelim = vsArgs[0].trim_n("\"");
                            bool bFoundOne = false;
                            No::EscapeFormat eEscape = No::AsciiFormat;

                            for (const NoString& arg : vsArgs) {
                                if (arg.startsWith("ESC=")) {
                                    eEscape = ToEscapeFormat(arg.leftChomp_n(4));
                                } else {
                                    NoString value = NoTemplate::value(arg);

                                    if (!value.empty()) {
                                        if (bFoundOne) {
                                            sOutput += sDelim;
                                        }

                                        sOutput += No::escape(value, eEscape);
                                        bFoundOne = true;
                                    }
                                }
                            }
                        }
                    } else if (action.equals("SETBLOCK")) {
                        sSetBlockVar = args;
                        bInSetBlock = true;
                    } else if (action.equals("EXPAND")) {
                        sOutput += expandFile(args, true);
                    } else if (action.equals("VAR")) {
                        sOutput += value(args);
                    } else if (action.equals("LT")) {
                        sOutput += "<?";
                    } else if (action.equals("GT")) {
                        sOutput += "?>";
                    } else if (action.equals("Continue")) {
                        NoTemplateLoopContext* pContext = currentLoopContext();

                        if (pContext) {
                            uSkip++;
                            bLoopCont = true;

                            break;
                        } else {
                            NO_DEBUG("[" + fileName + ":" + NoString(uCurPos - iPos2 - 4) +
                                     "] <? Continue ?> must be used inside of a loop!");
                        }
                    } else if (action.equals("BREAK")) {
                        // break from loop
                        NoTemplateLoopContext* pContext = currentLoopContext();

                        if (pContext) {
                            uSkip++;
                            bLoopBreak = true;

                            break;
                        } else {
                            NO_DEBUG("[" + fileName + ":" + NoString(uCurPos - iPos2 - 4) +
                                     "] <? BREAK ?> must be used inside of a loop!");
                        }
                    } else if (action.equals("EXIT")) {
                        bExit = true;
                    } else if (action.equals("DEBUG")) {
                        NO_DEBUG("NoTemplate DEBUG [" + fileName + "@" + NoString(uCurPos - iPos2 - 4) + "b] -> [" + args + "]");
                    } else if (action.equals("LOOP")) {
                        NoTemplateLoopContext* pContext = currentLoopContext();

                        if (!pContext || pContext->GetFilePosition() != uCurPos) {
                            // we are at a brand new loop (be it new or a first pass at an inner loop)

                            NoString sLoopName = No::token(args, 0);
                            bool bReverse = (No::token(args, 1).equals("REVERSE"));
                            bool bSort = (No::token(args, 1).startsWith("SORT"));
                            std::vector<NoTemplate*>* pvLoop = loop(sLoopName);

                            if (bSort && pvLoop != nullptr && pvLoop->size() > 1) {
                                NoString key;

                                if (No::token(args, 1).trimPrefix_n("SORT").startsWith("ASC=")) {
                                    key = No::token(args, 1).trimPrefix_n("SORTASC=");
                                } else if (No::token(args, 1).trimPrefix_n("SORT").startsWith("DESC=")) {
                                    key = No::token(args, 1).trimPrefix_n("SORTDESC=");
                                    bReverse = true;
                                }

                                if (!key.empty()) {
                                    std::sort(pvLoop->begin(), pvLoop->end(), NoLoopSorter(key));
                                }
                            }

                            if (pvLoop) {
                                // If we found data for this loop, add it to our context vector
                                // ulong uBeforeLoopTag = uCurPos - iPos2 - 4;
                                ulong uAfterLoopTag = uCurPos;

                                for (NoString::size_type t = 0; t < line.size(); t++) {
                                    char c = line[t];
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
                    } else if (action.equals("IF")) {
                        if (validIf(args)) {
                            uNestedIfs++;
                            bValidLastIf = true;
                        } else {
                            uSkip++;
                            bValidLastIf = false;
                        }
                    } else if (action.equals("REM")) {
                        uSkip++;
                    } else {
                        bNotFound = true;
                    }
                } else if (action.equals("REM")) {
                    uSkip++;
                } else if (action.equals("IF")) {
                    uSkip++;
                } else if (action.equals("LOOP")) {
                    uSkip++;
                }

                if (action.equals("ENDIF")) {
                    if (uSkip) {
                        uSkip--;
                    } else {
                        uNestedIfs--;
                    }
                } else if (action.equals("ENDREM")) {
                    if (uSkip) {
                        uSkip--;
                    }
                } else if (action.equals("ENDSETBLOCK")) {
                    bInSetBlock = false;
                    sSetBlockVar = "";
                } else if (action.equals("ENDLOOP")) {
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
                } else if (action.equals("ELSE")) {
                    if (!bValidLastIf && uSkip == 1) {
                        NoString arg = No::token(args, 0);

                        if (arg.empty() || (arg.equals("IF") && validIf(No::tokens(args, 1)))) {
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
                            if (spTagHandler->handleTag(*pTmpl, action, args, sCustomOutput)) {
                                sOutput += sCustomOutput;
                                bNotFound = false;
                                break;
                            }
                        }

                        if (bNotFound) {
                            NO_DEBUG("Unknown/Unhandled tag [" + action + "]");
                        }
                    }
                }

                continue;
            }

            NO_DEBUG("Malformed tag on line " + NoString(uLineNum) + " of [" << File.GetLongName() + "]");
            NO_DEBUG("--------------- [" + line + "]");
        }

        if (!bBroke) {
            uFilePos += uLineSize;

            if (!uSkip) {
                sOutput += line;
            }
        }

        if (!bFoundATag || bTmplLoopHasData || sOutput.find_first_not_of(" \t\r\n") != NoString::npos) {
            if (bInSetBlock) {
                NoString name = No::token(sSetBlockVar, 0);
                // NoString value = No::tokens(sSetBlockVar, 1);
                (*this)[name] += sOutput;
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

bool NoTemplate::validIf(const NoString& args)
{
    NoString argStr = args;
    // SafeReplace(argStr, " ", "", "\"", "\"", true);
    SafeReplace(argStr, " &&", "&&", "\"", "\"");
    SafeReplace(argStr, "&& ", "&&", "\"", "\"");
    SafeReplace(argStr, " ||", "||", "\"", "\"");
    SafeReplace(argStr, "|| ", "||", "\"", "\"");

    NoString::size_type uOrPos = argStr.find("||");
    NoString::size_type uAndPos = argStr.find("&&");

    while (uOrPos != NoString::npos || uAndPos != NoString::npos || !argStr.empty()) {
        bool bAnd = false;

        if (uAndPos < uOrPos) {
            bAnd = true;
        }

        NoString sExpr = No::token(argStr, 0, ((bAnd) ? "&&" : "||"));
        argStr = No::tokens(argStr, 1, ((bAnd) ? "&&" : "||"));

        if (validExpr(sExpr)) {
            if (!bAnd) {
                return true;
            }
        } else {
            if (bAnd) {
                return false;
            }
        }

        uOrPos = argStr.find("||");
        uAndPos = argStr.find("&&");
    }

    return false;
}

// TODO: cleanup
extern NoString
Token_helper(const NoString& str, size_t pos, bool bRest, const NoString& sep, const NoString& sLeft, const NoString& sRight);

bool NoTemplate::validExpr(const NoString& sExpression)
{
    bool bNegate = false;
    NoString sExpr(sExpression);
    NoString name;
    NoString value;

    if (sExpr.startsWith("!")) {
        bNegate = true;
        sExpr.leftChomp(1);
    }

    if (sExpr.contains("!=")) {
        name = No::token(sExpr, 0, "!=").trim_n();
        value = Token_helper(sExpr, 1, true, "!=", "\"", "\"").trim_n().trim_n("\"");
        bNegate = !bNegate;
    } else if (sExpr.contains("==")) {
        name = No::token(sExpr, 0, "==").trim_n();
        value = Token_helper(sExpr, 1, true, "==", "\"", "\"").trim_n().trim_n("\"");
    } else if (sExpr.contains(">=")) {
        name = No::token(sExpr, 0, ">=").trim_n();
        value = Token_helper(sExpr, 1, true, ">=", "\"", "\"").trim_n().trim_n("\"");
        return (NoTemplate::value(name, true).toLong() >= value.toLong());
    } else if (sExpr.contains("<=")) {
        name = No::token(sExpr, 0, "<=").trim_n();
        value = Token_helper(sExpr, 1, true, "<=", "\"", "\"").trim_n().trim_n("\"");
        return (NoTemplate::value(name, true).toLong() <= value.toLong());
    } else if (sExpr.contains(">")) {
        name = No::token(sExpr, 0, ">").trim_n();
        value = Token_helper(sExpr, 1, true, ">", "\"", "\"").trim_n().trim_n("\"");
        return (NoTemplate::value(name, true).toLong() > value.toLong());
    } else if (sExpr.contains("<")) {
        name = No::token(sExpr, 0, "<").trim_n();
        value = Token_helper(sExpr, 1, true, "<", "\"", "\"").trim_n().trim_n("\"");
        return (NoTemplate::value(name, true).toLong() < value.toLong());
    } else {
        name = sExpr.trim_n();
    }

    if (value.empty()) {
        return (bNegate != isTrue(name));
    }

    value = resolveLiteral(value);

    return (bNegate != NoTemplate::value(name, true).equals(value));
}

bool NoTemplate::isTrue(const NoString& name)
{
    if (hasLoop(name)) {
        return true;
    }

    return value(name, true).toBool();
}

bool NoTemplate::hasLoop(const NoString& name)
{
    return (loop(name) != nullptr);
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
    if (sString.startsWith("**")) {
        // Allow string to start with a literal * by using two in a row
        return sString.substr(1);
    } else if (sString.startsWith("*")) {
        // If it starts with only one * then treat it as a var and do a lookup
        return value(sString.substr(1));
    }

    return sString;
}

NoString NoTemplate::value(const NoString& args, bool bFromIf)
{
    NoTemplateLoopContext* pContext = currentLoopContext();
    NoString name = No::token(args, 0);
    NoString sRest = No::tokens(args, 1);
    NoString ret;

    while (SafeReplace(sRest, " =", "=", "\"", "\"")) {
    }
    while (SafeReplace(sRest, "= ", "=", "\"", "\"")) {
    }

    NoStringVector vArgs = No::quoteSplit(sRest);
    NoStringMap msArgs;

    for (NoString& arg : vArgs) {
        arg.trim("\"");
        msArgs[No::token(arg, 0, "=").toUpper()] = No::tokens(arg, 1, "=");
    }

    /* We have no NoSettings in ZNC land
	 * Hmm... Actually, we do have it now.
	if (msArgs.find("CONFIG") != msArgs.end()) {
		ret = NoSettings::GetValue(name);
	} else*/ if (msArgs.find("ROWS") != msArgs.end()) {
        std::vector<NoTemplate*>* pLoop = loop(name);
        ret = NoString((pLoop) ? pLoop->size() : 0);
    } else if (msArgs.find("TOP") == msArgs.end() && pContext) {
        ret = pContext->GetValue(args, bFromIf);

        if (!ret.empty()) {
            return ret;
        }
    } else {
        if (name.startsWith("*")) {
            name.leftChomp(1);
            NoStringMap::iterator it = find(name);
            name = (it != end()) ? it->second : "";
        }

        NoStringMap::iterator it = find(name);
        ret = (it != end()) ? it->second : "";
    }

    std::vector<std::shared_ptr<NoTemplateTagHandler>>& vspTagHandlers = tagHandlers();

    if (!vspTagHandlers.empty()) { // @todo this should go up to the top to grab handlers
        NoTemplate* pTmpl = currentTemplate();

        if (ret.empty()) {
            for (const auto& spTagHandler : vspTagHandlers) {
                NoString sCustomOutput;

                if (!bFromIf && spTagHandler->handleVar(*pTmpl, No::token(args, 0), No::tokens(args, 1), sCustomOutput)) {
                    ret = sCustomOutput;
                    break;
                } else if (bFromIf && spTagHandler->handleIf(*pTmpl, No::token(args, 0), No::tokens(args, 1), sCustomOutput)) {
                    ret = sCustomOutput;
                    break;
                }
            }
        }

        for (const auto& spTagHandler : vspTagHandlers) {
            if (spTagHandler->handleValue(*pTmpl, ret, msArgs)) {
                break;
            }
        }
    }

    if (!bFromIf) {
        if (ret.empty()) {
            ret = resolveLiteral(msArgs["DEFAULT"]);
        }

        NoStringMap::iterator it = msArgs.find("ESC");

        if (it != msArgs.end()) {
            NoStringVector vsEscs = it->second.split(",", No::SkipEmptyParts);

            for (const NoString& sEsc : vsEscs) {
                ret = No::escape(ret, ToEscapeFormat(sEsc));
            }
        } else {
            ret = No::escape(ret, d->options->GetEscapeFrom(), d->options->GetEscapeTo());
        }
    }

    return ret;
}
