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

#include "notemplate.h"
#include "nofile.h"
#include "nodir.h"
#include "nodebug.h"
#include "noutils.h"
#include <algorithm>

static No::EscapeFormat ToEscapeFormat(const NoString& sEsc)
{
    if (sEsc.Equals("ASCII")) {
        return No::AsciiFormat;
    } else if (sEsc.Equals("HTML")) {
        return No::HtmlFormat;
    } else if (sEsc.Equals("URL")) {
        return No::UrlFormat;
    } else if (sEsc.Equals("SQL")) {
        return No::SqlFormat;
    } else if (sEsc.Equals("NAMEDFMT")) {
        return No::NamedFormat;
    } else if (sEsc.Equals("DEBUG")) {
        return No::DebugFormat;
    } else if (sEsc.Equals("MSGTAG")) {
        return No::MsgTagFormat;
    } else if (sEsc.Equals("HEXCOLON")) {
        return No::HexColonFormat;
    }

    return No::AsciiFormat;
}

void NoTemplateOptions::Parse(const NoString& sLine)
{
    NoString sName = sLine.Token(0, false, "=").Trim_n().AsUpper();
    NoString sValue = sLine.Token(1, true, "=").Trim_n();

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
        DEBUG("Loop [" + GetName() + "] has no row index [" + NoString(GetRowIndex()) + "]");
        return "";
    }

    if (sName.Equals("__ID__")) {
        return NoString(GetRowIndex() + 1);
    } else if (sName.Equals("__COUNT__")) {
        return NoString(GetRowCount());
    } else if (sName.Equals("__ODD__")) {
        return ((GetRowIndex() % 2) ? "" : "1");
    } else if (sName.Equals("__EVEN__")) {
        return ((GetRowIndex() % 2) ? "1" : "");
    } else if (sName.Equals("__FIRST__")) {
        return ((GetRowIndex() == 0) ? "1" : "");
    } else if (sName.Equals("__LAST__")) {
        return ((GetRowIndex() == m_pvRows->size() - 1) ? "1" : "");
    } else if (sName.Equals("__OUTER__")) {
        return ((GetRowIndex() == 0 || GetRowIndex() == m_pvRows->size() - 1) ? "1" : "");
    } else if (sName.Equals("__INNER__")) {
        return ((GetRowIndex() == 0 || GetRowIndex() == m_pvRows->size() - 1) ? "" : "1");
    }

    return pTemplate->GetValue(sName, bFromIf);
}

NoTemplate::~NoTemplate()
{
    for (const auto& it : m_mvLoops) {
        const std::vector<NoTemplate*>& vLoop = it.second;
        for (NoTemplate* pTemplate : vLoop) {
            delete pTemplate;
        }
    }

    for (NoTemplateLoopContext* pContext : m_vLoopContexts) {
        delete pContext;
    }
}

void NoTemplate::Init()
{
    /* We have no NoSettings in ZNC land
     * Hmm... Actually, we do have it now.
    NoString sPath(NoSettings::GetValue("WebFilesPath"));

    if (!sPath.empty()) {
        SetPath(sPath);
    }
    */

    ClearPaths();
    m_pParent = nullptr;
}

NoString NoTemplate::ExpandFile(const NoString& sFilename, bool bFromInc)
{
    /*if (sFilename.Left(1) == "/" || sFilename.Left(2) == "./") {
        return sFilename;
    }*/

    NoString sFile(ResolveLiteral(sFilename).TrimLeft_n("/"));

    for (auto& it : m_lsbPaths) {
        NoString& sRoot = it.first;
        NoString sFilePath(NoDir::ChangeDir(sRoot, sFile));

        // Make sure path ends with a slash because "/foo/pub*" matches "/foo/public_keep_out/" but "/foo/pub/*" doesn't
        if (!sRoot.empty() && sRoot.Right(1) != "/") {
            sRoot += "/";
        }

        if (it.second && !bFromInc) {
            DEBUG("\t\tSkipping path (not from INC)  [" + sFilePath + "]");
            continue;
        }

        if (NoFile::Exists(sFilePath)) {
            if (sRoot.empty() || sFilePath.Left(sRoot.length()) == sRoot) {
                DEBUG("    Found  [" + sFilePath + "]");
                return sFilePath;
            } else {
                DEBUG("\t\tOutside of root [" + sFilePath + "] !~ [" + sRoot + "]");
            }
        }
    }

    switch (m_lsbPaths.size()) {
    case 0:
        DEBUG("Unable to find [" + sFile + "] using the current directory");
        break;
    case 1:
        DEBUG("Unable to find [" + sFile + "] in the defined path [" + m_lsbPaths.begin()->first + "]");
        break;
    default:
        DEBUG("Unable to find [" + sFile + "] in any of the " + NoString(m_lsbPaths.size()) + " defined paths");
    }

    return "";
}

void NoTemplate::SetPath(const NoString& sPaths)
{
    NoStringVector vsDirs = sPaths.Split(":", No::SkipEmptyParts);

    for (const NoString& sDir : vsDirs) {
        AppendPath(sDir, false);
    }
}

NoString NoTemplate::MakePath(const NoString& sPath) const
{
    NoString sRet(NoDir::ChangeDir("./", sPath + "/"));

    if (!sRet.empty() && sRet.Right(1) != "/") {
        sRet += "/";
    }

    return sRet;
}

void NoTemplate::PrependPath(const NoString& sPath, bool bIncludesOnly)
{
    DEBUG("NoTemplate::PrependPath(" + sPath + ") == [" + MakePath(sPath) + "]");
    m_lsbPaths.push_front(make_pair(MakePath(sPath), bIncludesOnly));
}

void NoTemplate::AppendPath(const NoString& sPath, bool bIncludesOnly)
{
    DEBUG("NoTemplate::AppendPath(" + sPath + ") == [" + MakePath(sPath) + "]");
    m_lsbPaths.push_back(make_pair(MakePath(sPath), bIncludesOnly));
}

void NoTemplate::RemovePath(const NoString& sPath)
{
    DEBUG("NoTemplate::RemovePath(" + sPath + ") == [" + NoDir::ChangeDir("./", sPath + "/") + "]");

    for (const auto& it : m_lsbPaths) {
        if (it.first == sPath) {
            m_lsbPaths.remove(it);
            RemovePath(sPath); // @todo probably shouldn't use recursion, being lazy
            return;
        }
    }
}

void NoTemplate::ClearPaths() { m_lsbPaths.clear(); }

bool NoTemplate::SetFile(const NoString& sFileName)
{
    m_sFileName = ExpandFile(sFileName, false);
    PrependPath(sFileName + "/..");

    if (sFileName.empty()) {
        DEBUG("NoTemplate::SetFile() - Filename is empty");
        return false;
    }

    if (m_sFileName.empty()) {
        DEBUG("NoTemplate::SetFile() - [" + sFileName + "] does not exist");
        return false;
    }

    DEBUG("Set template file to [" + m_sFileName + "]");

    return true;
}

class NoLoopSorter
{
    NoString m_sType;

public:
    NoLoopSorter(const NoString& sType) : m_sType(sType) {}
    bool operator()(NoTemplate* pTemplate1, NoTemplate* pTemplate2)
    {
        return (pTemplate1->GetValue(m_sType, false) < pTemplate2->GetValue(m_sType, false));
    }
};

NoTemplate& NoTemplate::AddRow(const NoString& sName)
{
    NoTemplate* pTmpl = new NoTemplate(m_spOptions, this);
    m_mvLoops[sName].push_back(pTmpl);

    return *pTmpl;
}

NoTemplate* NoTemplate::GetRow(const NoString& sName, uint uIndex)
{
    std::vector<NoTemplate*>* pvLoop = GetLoop(sName);

    if (pvLoop) {
        if (pvLoop->size() > uIndex) {
            return (*pvLoop)[uIndex];
        }
    }

    return nullptr;
}

std::vector<NoTemplate*>* NoTemplate::GetLoop(const NoString& sName)
{
    NoTemplateLoopContext* pContext = GetCurLoopContext();

    if (pContext) {
        NoTemplate* pTemplate = pContext->GetCurRow();

        if (pTemplate) {
            return pTemplate->GetLoop(sName);
        }
    }

    std::map<NoString, std::vector<NoTemplate*>>::iterator it = m_mvLoops.find(sName);

    if (it != m_mvLoops.end()) {
        return &(it->second);
    }

    return nullptr;
}

bool NoTemplate::PrintString(NoString& sRet)
{
    sRet.clear();
    std::stringstream sStream;
    bool bRet = Print(sStream);

    sRet = sStream.str();

    return bRet;
}

bool NoTemplate::Print(std::ostream& oOut) { return Print(m_sFileName, oOut); }

bool NoTemplate::Print(const NoString& sFileName, std::ostream& oOut)
{
    if (sFileName.empty()) {
        DEBUG("Empty filename in NoTemplate::Print()");
        return false;
    }

    NoFile File(sFileName);

    if (!File.Open()) {
        DEBUG("Unable to open file [" + sFileName + "] in NoTemplate::Print()");
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
                DEBUG("Template tag not ended properly in file [" + sFileName + "] [<?" + sLine + "]");
                return false;
            }

            uCurPos += iPos2 + 4;

            NoString sMid = NoString(sLine.substr(0, iPos2)).Trim_n();

            // Make sure we don't have a nested tag
            if (sMid.find("<?") == NoString::npos) {
                sLine = sLine.substr(iPos2 + 2);
                NoString sAction = sMid.Token(0);
                NoString sArgs = sMid.Token(1, true);
                bool bNotFound = false;

                // If we're breaking or continuing from within a loop, skip all tags that aren't ENDLOOP
                if ((bLoopCont || bLoopBreak) && !sAction.Equals("ENDLOOP")) {
                    continue;
                }

                if (!uSkip) {
                    if (sAction.Equals("INC")) {
                        if (!Print(ExpandFile(sArgs, true), oOut)) {
                            DEBUG("Unable to print INC'd file [" + sArgs + "]");
                            return false;
                        }
                    } else if (sAction.Equals("SETOPTION")) {
                        m_spOptions->Parse(sArgs);
                    } else if (sAction.Equals("ADDROW")) {
                        NoString sLoopName = sArgs.Token(0);
                        NoStringMap msRow = NoUtils::OptionSplit(sArgs.Token(1, true, " "));
                        if (!msRow.empty()) {
                            NoTemplate& NewRow = AddRow(sLoopName);

                            for (const auto& it : msRow) {
                                NewRow[it.first] = it.second;
                            }
                        }
                    } else if (sAction.Equals("SET")) {
                        NoString sName = sArgs.Token(0);
                        NoString sValue = sArgs.Token(1, true);

                        (*this)[sName] = sValue;
                    } else if (sAction.Equals("JOIN")) {
                        NoStringVector vsArgs = NoUtils::QuoteSplit(sArgs);
                        if (vsArgs.size() > 1) {
                            NoString sDelim = vsArgs[0];
                            bool bFoundOne = false;
                            No::EscapeFormat eEscape = No::AsciiFormat;

                            for (const NoString& sArg : vsArgs) {
                                if (sArg.StartsWith("ESC=")) {
                                    eEscape = ToEscapeFormat(sArg.LeftChomp_n(4));
                                } else {
                                    NoString sValue = GetValue(sArg);

                                    if (!sValue.empty()) {
                                        if (bFoundOne) {
                                            sOutput += sDelim;
                                        }

                                        sOutput += No::Escape_n(sValue, eEscape);
                                        bFoundOne = true;
                                    }
                                }
                            }
                        }
                    } else if (sAction.Equals("SETBLOCK")) {
                        sSetBlockVar = sArgs;
                        bInSetBlock = true;
                    } else if (sAction.Equals("EXPAND")) {
                        sOutput += ExpandFile(sArgs, true);
                    } else if (sAction.Equals("VAR")) {
                        sOutput += GetValue(sArgs);
                    } else if (sAction.Equals("LT")) {
                        sOutput += "<?";
                    } else if (sAction.Equals("GT")) {
                        sOutput += "?>";
                    } else if (sAction.Equals("CONTINUE")) {
                        NoTemplateLoopContext* pContext = GetCurLoopContext();

                        if (pContext) {
                            uSkip++;
                            bLoopCont = true;

                            break;
                        } else {
                            DEBUG("[" + sFileName + ":" + NoString(uCurPos - iPos2 - 4) +
                                  "] <? CONTINUE ?> must be used inside of a loop!");
                        }
                    } else if (sAction.Equals("BREAK")) {
                        // break from loop
                        NoTemplateLoopContext* pContext = GetCurLoopContext();

                        if (pContext) {
                            uSkip++;
                            bLoopBreak = true;

                            break;
                        } else {
                            DEBUG("[" + sFileName + ":" + NoString(uCurPos - iPos2 - 4) +
                                  "] <? BREAK ?> must be used inside of a loop!");
                        }
                    } else if (sAction.Equals("EXIT")) {
                        bExit = true;
                    } else if (sAction.Equals("DEBUG")) {
                        DEBUG("NoTemplate DEBUG [" + sFileName + "@" + NoString(uCurPos - iPos2 - 4) + "b] -> [" + sArgs + "]");
                    } else if (sAction.Equals("LOOP")) {
                        NoTemplateLoopContext* pContext = GetCurLoopContext();

                        if (!pContext || pContext->GetFilePosition() != uCurPos) {
                            // we are at a brand new loop (be it new or a first pass at an inner loop)

                            NoString sLoopName = sArgs.Token(0);
                            bool bReverse = (sArgs.Token(1).Equals("REVERSE"));
                            bool bSort = (sArgs.Token(1).Left(4).Equals("SORT"));
                            std::vector<NoTemplate*>* pvLoop = GetLoop(sLoopName);

                            if (bSort && pvLoop != nullptr && pvLoop->size() > 1) {
                                NoString sKey;

                                if (sArgs.Token(1).TrimPrefix_n("SORT").Left(4).Equals("ASC=")) {
                                    sKey = sArgs.Token(1).TrimPrefix_n("SORTASC=");
                                } else if (sArgs.Token(1).TrimPrefix_n("SORT").Left(5).Equals("DESC=")) {
                                    sKey = sArgs.Token(1).TrimPrefix_n("SORTDESC=");
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

                                m_vLoopContexts.push_back(new NoTemplateLoopContext(uAfterLoopTag, sLoopName, bReverse, pvLoop));
                            } else { // If we don't have data, just skip this loop and everything inside
                                uSkip++;
                            }
                        }
                    } else if (sAction.Equals("IF")) {
                        if (ValidIf(sArgs)) {
                            uNestedIfs++;
                            bValidLastIf = true;
                        } else {
                            uSkip++;
                            bValidLastIf = false;
                        }
                    } else if (sAction.Equals("REM")) {
                        uSkip++;
                    } else {
                        bNotFound = true;
                    }
                } else if (sAction.Equals("REM")) {
                    uSkip++;
                } else if (sAction.Equals("IF")) {
                    uSkip++;
                } else if (sAction.Equals("LOOP")) {
                    uSkip++;
                }

                if (sAction.Equals("ENDIF")) {
                    if (uSkip) {
                        uSkip--;
                    } else {
                        uNestedIfs--;
                    }
                } else if (sAction.Equals("ENDREM")) {
                    if (uSkip) {
                        uSkip--;
                    }
                } else if (sAction.Equals("ENDSETBLOCK")) {
                    bInSetBlock = false;
                    sSetBlockVar = "";
                } else if (sAction.Equals("ENDLOOP")) {
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
                        NoTemplateLoopContext* pContext = GetCurLoopContext();

                        if (pContext) {
                            pContext->IncRowIndex();

                            // If we didn't go out of bounds we need to seek back to the top of our loop
                            if (!bLoopBreak && pContext->GetCurRow()) {
                                uCurPos = pContext->GetFilePosition();
                                uFilePos = uCurPos;
                                uLineSize = 0;

                                File.Seek(uCurPos);
                                bBroke = true;

                                if (!sOutput.Trim_n().empty()) {
                                    pContext->SetHasData();
                                }

                                break;
                            } else {
                                if (sOutput.Trim_n().empty()) {
                                    sOutput.clear();
                                }

                                bTmplLoopHasData = pContext->HasData();
                                DelCurLoopContext();
                                bLoopBreak = false;
                            }
                        }
                    }
                } else if (sAction.Equals("ELSE")) {
                    if (!bValidLastIf && uSkip == 1) {
                        NoString sArg = sArgs.Token(0);

                        if (sArg.empty() || (sArg.Equals("IF") && ValidIf(sArgs.Token(1, true)))) {
                            uSkip = 0;
                            bValidLastIf = true;
                        }
                    } else if (!uSkip) {
                        uSkip = 1;
                    }
                } else if (bNotFound) {
                    // Unknown tag that isn't being skipped...
                    std::vector<std::shared_ptr<NoTemplateTagHandler>>& vspTagHandlers = GetTagHandlers();

                    if (!vspTagHandlers.empty()) { // @todo this should go up to the top to grab handlers
                        NoTemplate* pTmpl = GetCurTemplate();
                        NoString sCustomOutput;

                        for (const auto& spTagHandler : vspTagHandlers) {
                            if (spTagHandler->HandleTag(*pTmpl, sAction, sArgs, sCustomOutput)) {
                                sOutput += sCustomOutput;
                                bNotFound = false;
                                break;
                            }
                        }

                        if (bNotFound) {
                            DEBUG("Unknown/Unhandled tag [" + sAction + "]");
                        }
                    }
                }

                continue;
            }

            DEBUG("Malformed tag on line " + NoString(uLineNum) + " of [" << File.GetLongName() + "]");
            DEBUG("--------------- [" + sLine + "]");
        }

        if (!bBroke) {
            uFilePos += uLineSize;

            if (!uSkip) {
                sOutput += sLine;
            }
        }

        if (!bFoundATag || bTmplLoopHasData || sOutput.find_first_not_of(" \t\r\n") != NoString::npos) {
            if (bInSetBlock) {
                NoString sName = sSetBlockVar.Token(0);
                // NoString sValue = sSetBlockVar.Token(1, true);
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

void NoTemplate::DelCurLoopContext()
{
    if (m_vLoopContexts.empty()) {
        return;
    }

    delete m_vLoopContexts.back();
    m_vLoopContexts.pop_back();
}

NoTemplateLoopContext* NoTemplate::GetCurLoopContext()
{
    if (!m_vLoopContexts.empty()) {
        return m_vLoopContexts.back();
    }

    return nullptr;
}

bool NoTemplate::ValidIf(const NoString& sArgs)
{
    NoString sArgStr = sArgs;
    // sArgStr.Replace(" ", "", "\"", "\"", true);
    sArgStr.Replace(" &&", "&&", "\"", "\"", false);
    sArgStr.Replace("&& ", "&&", "\"", "\"", false);
    sArgStr.Replace(" ||", "||", "\"", "\"", false);
    sArgStr.Replace("|| ", "||", "\"", "\"", false);

    NoString::size_type uOrPos = sArgStr.find("||");
    NoString::size_type uAndPos = sArgStr.find("&&");

    while (uOrPos != NoString::npos || uAndPos != NoString::npos || !sArgStr.empty()) {
        bool bAnd = false;

        if (uAndPos < uOrPos) {
            bAnd = true;
        }

        NoString sExpr = sArgStr.Token(0, false, ((bAnd) ? "&&" : "||"));
        sArgStr = sArgStr.Token(1, true, ((bAnd) ? "&&" : "||"));

        if (ValidExpr(sExpr)) {
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

bool NoTemplate::ValidExpr(const NoString& sExpression)
{
    bool bNegate = false;
    NoString sExpr(sExpression);
    NoString sName;
    NoString sValue;

    if (sExpr.Left(1) == "!") {
        bNegate = true;
        sExpr.LeftChomp(1);
    }

    if (sExpr.find("!=") != NoString::npos) {
        sName = sExpr.Token(0, false, "!=").Trim_n();
        sValue = sExpr.Token(1, true, "!=", false, "\"", "\"", true).Trim_n();
        bNegate = !bNegate;
    } else if (sExpr.find("==") != NoString::npos) {
        sName = sExpr.Token(0, false, "==").Trim_n();
        sValue = sExpr.Token(1, true, "==", false, "\"", "\"", true).Trim_n();
    } else if (sExpr.find(">=") != NoString::npos) {
        sName = sExpr.Token(0, false, ">=").Trim_n();
        sValue = sExpr.Token(1, true, ">=", false, "\"", "\"", true).Trim_n();
        return (GetValue(sName, true).ToLong() >= sValue.ToLong());
    } else if (sExpr.find("<=") != NoString::npos) {
        sName = sExpr.Token(0, false, "<=").Trim_n();
        sValue = sExpr.Token(1, true, "<=", false, "\"", "\"", true).Trim_n();
        return (GetValue(sName, true).ToLong() <= sValue.ToLong());
    } else if (sExpr.find(">") != NoString::npos) {
        sName = sExpr.Token(0, false, ">").Trim_n();
        sValue = sExpr.Token(1, true, ">", false, "\"", "\"", true).Trim_n();
        return (GetValue(sName, true).ToLong() > sValue.ToLong());
    } else if (sExpr.find("<") != NoString::npos) {
        sName = sExpr.Token(0, false, "<").Trim_n();
        sValue = sExpr.Token(1, true, "<", false, "\"", "\"", true).Trim_n();
        return (GetValue(sName, true).ToLong() < sValue.ToLong());
    } else {
        sName = sExpr.Trim_n();
    }

    if (sValue.empty()) {
        return (bNegate != IsTrue(sName));
    }

    sValue = ResolveLiteral(sValue);

    return (bNegate != GetValue(sName, true).Equals(sValue));
}

bool NoTemplate::IsTrue(const NoString& sName)
{
    if (HasLoop(sName)) {
        return true;
    }

    return GetValue(sName, true).ToBool();
}

bool NoTemplate::HasLoop(const NoString& sName) { return (GetLoop(sName) != nullptr); }

NoTemplate* NoTemplate::GetParent(bool bRoot)
{
    if (!bRoot) {
        return m_pParent;
    }

    return (m_pParent) ? m_pParent->GetParent(bRoot) : this;
}

NoTemplate* NoTemplate::GetCurTemplate()
{
    NoTemplateLoopContext* pContext = GetCurLoopContext();

    if (!pContext) {
        return this;
    }

    return pContext->GetCurRow();
}

NoString NoTemplate::ResolveLiteral(const NoString& sString)
{
    if (sString.Left(2) == "**") {
        // Allow string to start with a literal * by using two in a row
        return sString.substr(1);
    } else if (sString.Left(1) == "*") {
        // If it starts with only one * then treat it as a var and do a lookup
        return GetValue(sString.substr(1));
    }

    return sString;
}

NoString NoTemplate::GetValue(const NoString& sArgs, bool bFromIf)
{
    NoTemplateLoopContext* pContext = GetCurLoopContext();
    NoString sName = sArgs.Token(0);
    NoString sRest = sArgs.Token(1, true);
    NoString sRet;

    while (sRest.Replace(" =", "=", "\"", "\"")) {
    }
    while (sRest.Replace("= ", "=", "\"", "\"")) {
    }

    NoStringVector vArgs = NoUtils::QuoteSplit(sRest);
    NoStringMap msArgs;

    for (const NoString& sArg : vArgs) {
        msArgs[sArg.Token(0, false, "=").AsUpper()] = sArg.Token(1, true, "=");
    }

    /* We have no NoSettings in ZNC land
	 * Hmm... Actually, we do have it now.
	if (msArgs.find("CONFIG") != msArgs.end()) {
		sRet = NoSettings::GetValue(sName);
	} else*/ if (msArgs.find("ROWS") != msArgs.end()) {
        std::vector<NoTemplate*>* pLoop = GetLoop(sName);
        sRet = NoString((pLoop) ? pLoop->size() : 0);
    } else if (msArgs.find("TOP") == msArgs.end() && pContext) {
        sRet = pContext->GetValue(sArgs, bFromIf);

        if (!sRet.empty()) {
            return sRet;
        }
    } else {
        if (sName.Left(1) == "*") {
            sName.LeftChomp(1);
            NoStringMap::iterator it = find(sName);
            sName = (it != end()) ? it->second : "";
        }

        NoStringMap::iterator it = find(sName);
        sRet = (it != end()) ? it->second : "";
    }

    std::vector<std::shared_ptr<NoTemplateTagHandler>>& vspTagHandlers = GetTagHandlers();

    if (!vspTagHandlers.empty()) { // @todo this should go up to the top to grab handlers
        NoTemplate* pTmpl = GetCurTemplate();

        if (sRet.empty()) {
            for (const auto& spTagHandler : vspTagHandlers) {
                NoString sCustomOutput;

                if (!bFromIf && spTagHandler->HandleVar(*pTmpl, sArgs.Token(0), sArgs.Token(1, true), sCustomOutput)) {
                    sRet = sCustomOutput;
                    break;
                } else if (bFromIf && spTagHandler->HandleIf(*pTmpl, sArgs.Token(0), sArgs.Token(1, true), sCustomOutput)) {
                    sRet = sCustomOutput;
                    break;
                }
            }
        }

        for (const auto& spTagHandler : vspTagHandlers) {
            if (spTagHandler->HandleValue(*pTmpl, sRet, msArgs)) {
                break;
            }
        }
    }

    if (!bFromIf) {
        if (sRet.empty()) {
            sRet = ResolveLiteral(msArgs["DEFAULT"]);
        }

        NoStringMap::iterator it = msArgs.find("ESC");

        if (it != msArgs.end()) {
            NoStringVector vsEscs = it->second.Split(",", No::SkipEmptyParts);

            for (const NoString& sEsc : vsEscs) {
                sRet = No::Escape_n(sRet, ToEscapeFormat(sEsc));
            }
        } else {
            sRet = No::Escape_n(sRet, m_spOptions->GetEscapeFrom(), m_spOptions->GetEscapeTo());
        }
    }

    return sRet;
}
