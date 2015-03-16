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

#ifndef NOWEBMODULES_H
#define NOWEBMODULES_H

#include <znc/noconfig.h>
#include <znc/notemplate.h>
#include <znc/nohttpsock.h>
#include <znc/noutils.h>

class NoAuthBase;
class NoUser;
class NoWebSock;
class NoModule;
class NoWebSubPage;

typedef std::shared_ptr<NoWebSubPage> TWebSubPage;
typedef std::vector<TWebSubPage> VWebSubPages;

class NoTagHandler : public NoTemplateTagHandler
{
public:
    NoTagHandler(NoWebSock& pWebSock);
    virtual ~NoTagHandler() {}

    bool HandleTag(NoTemplate& Tmpl, const NoString& sName, const NoString& sArgs, NoString& sOutput) override;

private:
    NoWebSock& m_WebSock;
};


class NoWebSession
{
public:
    NoWebSession(const NoString& sId, const NoString& sIP);
    ~NoWebSession();

    NoWebSession(const NoWebSession&) = delete;
    NoWebSession& operator=(const NoWebSession&) = delete;

    const NoString& GetId() const { return m_sId; }
    const NoString& GetIP() const { return m_sIP; }
    NoUser* GetUser() const { return m_pUser; }
    time_t GetLastActive() const { return m_tmLastActive; }
    bool IsLoggedIn() const { return m_pUser != nullptr; }
    bool IsAdmin() const;
    void UpdateLastActive();

    NoUser* SetUser(NoUser* p)
    {
        m_pUser = p;
        return m_pUser;
    }

    void ClearMessageLoops();
    void FillMessageLoops(NoTemplate& Tmpl);
    size_t AddError(const NoString& sMessage);
    size_t AddSuccess(const NoString& sMessage);

private:
    NoString m_sId;
    NoString m_sIP;
    NoUser* m_pUser;
    NoStringVector m_vsErrorMsgs;
    NoStringVector m_vsSuccessMsgs;
    time_t m_tmLastActive;
};


class NoWebSubPage
{
public:
    NoWebSubPage(const NoString& sName, const NoString& sTitle = "", unsigned int uFlags = 0)
        : m_uFlags(uFlags), m_sName(sName), m_sTitle(sTitle), m_vParams()
    {
    }

    NoWebSubPage(const NoString& sName, const NoString& sTitle, const NoStringPairVector& vParams, unsigned int uFlags = 0)
        : m_uFlags(uFlags), m_sName(sName), m_sTitle(sTitle), m_vParams(vParams)
    {
    }

    virtual ~NoWebSubPage() {}

    enum { F_ADMIN = 1 };

    void SetName(const NoString& s) { m_sName = s; }
    void SetTitle(const NoString& s) { m_sTitle = s; }
    void AddParam(const NoString& sName, const NoString& sValue) { m_vParams.push_back(make_pair(sName, sValue)); }

    bool RequiresAdmin() const { return m_uFlags & F_ADMIN; }

    const NoString& GetName() const { return m_sName; }
    const NoString& GetTitle() const { return m_sTitle; }
    const NoStringPairVector& GetParams() const { return m_vParams; }

private:
    unsigned int m_uFlags;
    NoString m_sName;
    NoString m_sTitle;
    NoStringPairVector m_vParams;
};

class NoWebSessionMap : public TCacheMap<NoString, std::shared_ptr<NoWebSession>>
{
public:
    NoWebSessionMap(unsigned int uTTL = 5000) : TCacheMap<NoString, std::shared_ptr<NoWebSession>>(uTTL) {}
    void FinishUserSessions(const NoUser& User);
};

class NoWebSock : public NoHttpSock
{
public:
    enum EPageReqResult {
        PAGE_NOTFOUND, // print 404 and Close()
        PAGE_PRINT, // print page contents and Close()
        PAGE_DEFERRED, // async processing, Close() will be called from a different place
        PAGE_DONE // all stuff has been done
    };

    NoWebSock(const NoString& sURIPrefix);
    virtual ~NoWebSock();

    bool ForceLogin() override;
    bool OnLogin(const NoString& sUser, const NoString& sPass, bool bBasic) override;
    void OnPageRequest(const NoString& sURI) override;

    EPageReqResult PrintTemplate(const NoString& sPageName, NoString& sPageRet, NoModule* pModule = nullptr);
    EPageReqResult PrintStaticFile(const NoString& sPath, NoString& sPageRet, NoModule* pModule = nullptr);

    NoString FindTmpl(NoModule* pModule, const NoString& sName);

    void PrintErrorPage(const NoString& sMessage);

    std::shared_ptr<NoWebSession> GetSession();

    Csock* GetSockObj(const NoString& sHost, unsigned short uPort) override;
    static NoString GetSkinPath(const NoString& sSkinName);
    void GetAvailSkins(NoStringVector& vRet) const;
    NoString GetSkinName();

    NoString GetRequestCookie(const NoString& sKey);
    bool SendCookie(const NoString& sKey, const NoString& sValue);

    static void FinishUserSessions(const NoUser& User);

protected:
    using NoHttpSock::PrintErrorPage;

    bool AddModLoop(const NoString& sLoopName, NoModule& Module, NoTemplate* pTemplate = nullptr);
    NoStringVector GetDirs(NoModule* pModule, bool bIsTemplate);
    void SetPaths(NoModule* pModule, bool bIsTemplate = false);
    void SetVars();
    NoString GetCSRFCheck();

private:
    EPageReqResult OnPageRequestInternal(const NoString& sURI, NoString& sPageRet);

    bool m_bPathsSet;
    NoTemplate m_Template;
    std::shared_ptr<NoAuthBase> m_spAuth;
    NoString m_sModName;
    NoString m_sPath;
    NoString m_sPage;
    std::shared_ptr<NoWebSession> m_spSession;

    static const unsigned int m_uiMaxSessions;
};

#endif // NOWEBMODULES_H
