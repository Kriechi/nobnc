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

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
#include <memory>

class NoTemplate;
class NoTemplatePrivate;
class NoTemplateOptions;
class NoTemplateLoopContext;

class NO_EXPORT NoTemplateTagHandler
{
public:
    virtual ~NoTemplateTagHandler()
    {
    }

    virtual bool handleVar(NoTemplate& tmpl, const NoString& name, const NoString& args, NoString& sOutput)
    {
        return false;
    }

    virtual bool handleTag(NoTemplate& tmpl, const NoString& name, const NoString& args, NoString& sOutput)
    {
        return false;
    }

    virtual bool handleIf(NoTemplate& tmpl, const NoString& name, const NoString& args, NoString& sOutput)
    {
        return handleVar(tmpl, name, args, sOutput);
    }

    virtual bool handleValue(NoTemplate& tmpl, NoString& value, const NoStringMap& msOptions)
    {
        return false;
    }
};

class NO_EXPORT NoTemplate : public NoStringMap
{
public:
    NoTemplate(const NoString& fileName = "");
    NoTemplate(std::shared_ptr<NoTemplateOptions> options, NoTemplate* pParent = nullptr);
    ~NoTemplate();

    //! Class for implementing custom tags in subclasses
    void addTagHandler(std::shared_ptr<NoTemplateTagHandler> spTagHandler);

    std::vector<std::shared_ptr<NoTemplateTagHandler>>& tagHandlers();

    NoString resolveLiteral(const NoString& sString);

    void init();

    NoTemplate* parent(bool bRoot);
    NoString expandFile(const NoString& sFilename, bool bFromInc = false);
    bool setFile(const NoString& fileName);

    void setPath(const NoString& path); // Sets the dir:dir:dir type path to look at for templates, as of right now no
    // ../../.. protection
    NoString makePath(const NoString& path) const;
    void prependPath(const NoString& path, bool includesOnly = false);
    void appendPath(const NoString& path, bool includesOnly = false);
    void removePath(const NoString& path);
    void clearPaths();
    bool printString(NoString& ret);
    bool print(std::ostream& oOut);
    bool print(const NoString& fileName, std::ostream& oOut);
    bool validIf(const NoString& args);
    bool validExpr(const NoString& sExpr);
    bool isTrue(const NoString& name);
    bool hasLoop(const NoString& name);
    NoString value(const NoString& name, bool bFromIf = false);
    NoTemplate& addRow(const NoString& name);
    NoTemplate* row(const NoString& name, uint uIndex);
    std::vector<NoTemplate*>* loop(const NoString& name);
    void deleteCurLoopContext();
    NoTemplateLoopContext* currentLoopContext();
    NoTemplate* currentTemplate();

    NoString fileName() const;

private:
    NoTemplate(const NoTemplate& other) = delete;
    NoTemplate& operator=(const NoTemplate& other) = delete;
    std::unique_ptr<NoTemplatePrivate> d;
};

#endif // NOTEMPLATE_H
