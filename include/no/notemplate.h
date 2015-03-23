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

#ifndef NOTEMPLATE_H
#define NOTEMPLATE_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <memory>

class NoTemplate;
class NoTemplatePrivate;
class NoTemplateOptions;
class NoTemplateLoopContext;

class NO_EXPORT NoTemplateTagHandler
{
public:
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
};

class NO_EXPORT NoTemplate : public NoStringMap
{
public:
    NoTemplate(const NoString& sFileName = "");
    NoTemplate(const std::shared_ptr<NoTemplateOptions>& Options, NoTemplate* pParent = nullptr);
    NoTemplate(const NoTemplate& other);
    NoTemplate& operator=(const NoTemplate& other);
    ~NoTemplate();

    //! Class for implementing custom tags in subclasses
    void AddTagHandler(std::shared_ptr<NoTemplateTagHandler> spTagHandler);

    std::vector<std::shared_ptr<NoTemplateTagHandler>>& GetTagHandlers();

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
    NoTemplate* GetRow(const NoString& sName, uint uIndex);
    std::vector<NoTemplate*>* GetLoop(const NoString& sName);
    void DelCurLoopContext();
    NoTemplateLoopContext* GetCurLoopContext();
    NoTemplate* GetCurTemplate();

    const NoString& GetFileName() const;

private:
    std::shared_ptr<NoTemplatePrivate> d;
};

#endif // NOTEMPLATE_H
