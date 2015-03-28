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

    virtual bool handleVar(NoTemplate& Tmpl, const NoString& sName, const NoString& sArgs, NoString& sOutput)
    {
        return false;
    }

    virtual bool handleTag(NoTemplate& Tmpl, const NoString& sName, const NoString& sArgs, NoString& sOutput)
    {
        return false;
    }

    virtual bool handleIf(NoTemplate& Tmpl, const NoString& sName, const NoString& sArgs, NoString& sOutput)
    {
        return handleVar(Tmpl, sName, sArgs, sOutput);
    }

    virtual bool handleValue(NoTemplate& Tmpl, NoString& sValue, const NoStringMap& msOptions) { return false; }
};

class NO_EXPORT NoTemplate : public NoStringMap
{
public:
    NoTemplate(const NoString& sFileName = "");
    NoTemplate(const std::shared_ptr<NoTemplateOptions>& Options, NoTemplate* pParent = nullptr);
    ~NoTemplate();

    //! Class for implementing custom tags in subclasses
    void addTagHandler(std::shared_ptr<NoTemplateTagHandler> spTagHandler);

    std::vector<std::shared_ptr<NoTemplateTagHandler>>& tagHandlers();

    NoString resolveLiteral(const NoString& sString);

    void init();

    NoTemplate* parent(bool bRoot);
    NoString expandFile(const NoString& sFilename, bool bFromInc = false);
    bool setFile(const NoString& sFileName);

    void setPath(const NoString& sPath); // Sets the dir:dir:dir type path to look at for templates, as of right now no
    // ../../.. protection
    NoString makePath(const NoString& sPath) const;
    void prependPath(const NoString& sPath, bool bIncludesOnly = false);
    void appendPath(const NoString& sPath, bool bIncludesOnly = false);
    void removePath(const NoString& sPath);
    void clearPaths();
    bool printString(NoString& sRet);
    bool print(std::ostream& oOut);
    bool print(const NoString& sFileName, std::ostream& oOut);
    bool validIf(const NoString& sArgs);
    bool validExpr(const NoString& sExpr);
    bool isTrue(const NoString& sName);
    bool hasLoop(const NoString& sName);
    NoString value(const NoString& sName, bool bFromIf = false);
    NoTemplate& addRow(const NoString& sName);
    NoTemplate* row(const NoString& sName, uint uIndex);
    std::vector<NoTemplate*>* loop(const NoString& sName);
    void deleteCurLoopContext();
    NoTemplateLoopContext* currentLoopContext();
    NoTemplate* currentTemplate();

    const NoString& fileName() const;

private:
    NoTemplate(const NoTemplate& other) = delete;
    NoTemplate& operator=(const NoTemplate& other) = delete;
    std::unique_ptr<NoTemplatePrivate> d;
};

#endif // NOTEMPLATE_H
