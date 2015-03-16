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

#ifndef NOTEMPLATE_H
#define NOTEMPLATE_H

#include <no/noconfig.h>
#include <no/nostring.h>
#include <iostream>
#include <list>
#include <memory>

class NoTemplate;

class NoTemplateTagHandler
{
public:
    NoTemplateTagHandler() {}
    virtual ~NoTemplateTagHandler() {}

    virtual bool HandleVar(NoTemplate& Tmpl, const NoString& sName, const NoString& sArgs, NoString& sOutput)
    {
        return false;
    }

    virtual bool HandleTag(NoTemplate& Tmpl, const NoString& sName, const NoString& sArgs, NoString& sOutput)
    {
        return false;
    }

    virtual bool HandleIf(NoTemplate& Tmpl, const NoString& sName, const NoString& sArgs, NoString& sOutput)
    {
        return HandleVar(Tmpl, sName, sArgs, sOutput);
    }

    virtual bool HandleValue(NoTemplate& Tmpl, NoString& sValue, const NoStringMap& msOptions) { return false; }

private:
};
class NoTemplate;

class NoTemplateOptions
{
public:
    NoTemplateOptions() : m_eEscapeFrom(NoString::EASCII), m_eEscapeTo(NoString::EASCII) {}

    virtual ~NoTemplateOptions() {}

    void Parse(const NoString& sLine);

    NoString::EEscape GetEscapeFrom() const { return m_eEscapeFrom; }
    NoString::EEscape GetEscapeTo() const { return m_eEscapeTo; }

private:
    NoString::EEscape m_eEscapeFrom;
    NoString::EEscape m_eEscapeTo;
};


class NoTemplateLoopContext
{
public:
    NoTemplateLoopContext(unsigned long uFilePos, const NoString& sLoopName, bool bReverse, std::vector<NoTemplate*>* pRows)
        : m_bReverse(bReverse), m_bHasData(false), m_sName(sLoopName), m_uRowIndex(0), m_uFilePosition(uFilePos),
          m_pvRows(pRows)
    {
    }

    virtual ~NoTemplateLoopContext() {}

    NoTemplateLoopContext(const NoTemplateLoopContext&) = default;
    NoTemplateLoopContext& operator=(const NoTemplateLoopContext&) = default;

    void SetHasData(bool b = true) { m_bHasData = b; }
    void SetName(const NoString& s) { m_sName = s; }
    void SetRowIndex(unsigned int u) { m_uRowIndex = u; }
    unsigned int IncRowIndex() { return ++m_uRowIndex; }
    unsigned int DecRowIndex()
    {
        if (m_uRowIndex == 0) {
            return 0;
        }
        return --m_uRowIndex;
    }
    void SetFilePosition(unsigned int u) { m_uFilePosition = u; }

    bool HasData() const { return m_bHasData; }
    const NoString& GetName() const { return m_sName; }
    unsigned long GetFilePosition() const { return m_uFilePosition; }
    unsigned int GetRowIndex() const { return m_uRowIndex; }
    size_t GetRowCount() { return m_pvRows->size(); }
    std::vector<NoTemplate*>* GetRows() { return m_pvRows; }
    NoTemplate* GetNextRow() { return GetRow(IncRowIndex()); }
    NoTemplate* GetCurRow() { return GetRow(m_uRowIndex); }

    NoTemplate* GetRow(unsigned int uIndex);
    NoString GetValue(const NoString& sName, bool bFromIf = false);

private:
    bool m_bReverse; //!< Iterate through this loop in reverse order
    bool m_bHasData; //!< Tells whether this loop has real data or not
    NoString m_sName; //!< The name portion of the <?LOOP name?> tag
    unsigned int m_uRowIndex; //!< The index of the current row we're on
    unsigned long m_uFilePosition; //!< The file position of the opening <?LOOP?> tag
    std::vector<NoTemplate*>* m_pvRows; //!< This holds pointers to the templates associated with this loop
};


class NoTemplate : public NoStringMap
{
public:
    NoTemplate() : NoTemplate("") {}

    NoTemplate(const NoString& sFileName)
        : NoStringMap(), m_pParent(nullptr), m_sFileName(sFileName), m_lsbPaths(), m_mvLoops(), m_vLoopContexts(),
          m_spOptions(new NoTemplateOptions), m_vspTagHandlers()
    {
    }

    NoTemplate(const std::shared_ptr<NoTemplateOptions>& Options, NoTemplate* pParent = nullptr)
        : NoStringMap(), m_pParent(pParent), m_sFileName(""), m_lsbPaths(), m_mvLoops(), m_vLoopContexts(),
          m_spOptions(Options), m_vspTagHandlers()
    {
    }

    virtual ~NoTemplate();

    NoTemplate(const NoTemplate& other) = default;
    NoTemplate& operator=(const NoTemplate& other) = default;

    //! Class for implementing custom tags in subclasses
    void AddTagHandler(std::shared_ptr<NoTemplateTagHandler> spTagHandler) { m_vspTagHandlers.push_back(spTagHandler); }

    std::vector<std::shared_ptr<NoTemplateTagHandler>>& GetTagHandlers()
    {
        if (m_pParent) {
            return m_pParent->GetTagHandlers();
        }

        return m_vspTagHandlers;
    }

    NoString ResolveLiteral(const NoString& sString);

    void Init();

    NoTemplate* GetParent(bool bRoot);
    NoString ExpandFile(const NoString& sFilename, bool bFromInc = false);
    bool SetFile(const NoString& sFileName);

    void SetPath(const NoString& sPath); // Sets the dir:dir:dir type path to look at for templates, as of right now no
    // ../../.. protection
    NoString MakePath(const NoString& sPath) const;
    void PrependPath(const NoString& sPath, bool bIncludesOnly = false);
    void AppendPath(const NoString& sPath, bool bIncludesOnly = false);
    void RemovePath(const NoString& sPath);
    void ClearPaths();
    bool PrintString(NoString& sRet);
    bool Print(std::ostream& oOut);
    bool Print(const NoString& sFileName, std::ostream& oOut);
    bool ValidIf(const NoString& sArgs);
    bool ValidExpr(const NoString& sExpr);
    bool IsTrue(const NoString& sName);
    bool HasLoop(const NoString& sName);
    NoString GetValue(const NoString& sName, bool bFromIf = false);
    NoTemplate& AddRow(const NoString& sName);
    NoTemplate* GetRow(const NoString& sName, unsigned int uIndex);
    std::vector<NoTemplate*>* GetLoop(const NoString& sName);
    void DelCurLoopContext();
    NoTemplateLoopContext* GetCurLoopContext();
    NoTemplate* GetCurTemplate();

    const NoString& GetFileName() const { return m_sFileName; }

private:
    NoTemplate* m_pParent;
    NoString m_sFileName;
    std::list<std::pair<NoString, bool>> m_lsbPaths;
    std::map<NoString, std::vector<NoTemplate*>> m_mvLoops;
    std::vector<NoTemplateLoopContext*> m_vLoopContexts;
    std::shared_ptr<NoTemplateOptions> m_spOptions;
    std::vector<std::shared_ptr<NoTemplateTagHandler>> m_vspTagHandlers;
};

#endif // NOTEMPLATE_H
