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

#include <no/noglobal.h>
#include <no/notemplate.h>
#include <no/nohttpsocket.h>
#include <no/noutils.h>
#include <no/nocachemap.h>

class NoAuthenticator;
class NoUser;
class NoWebSock;
class NoModule;
class NoWebSubPage;

typedef std::shared_ptr<NoWebSubPage> TWebSubPage;
typedef std::vector<TWebSubPage> VWebSubPages;

class NO_EXPORT NoWebSession
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


class NO_EXPORT NoWebSubPage
{
public:
    NoWebSubPage(const NoString& sName, const NoString& sTitle = "", uint uFlags = 0)
        : m_uFlags(uFlags), m_sName(sName), m_sTitle(sTitle), m_vParams()
    {
    }

    NoWebSubPage(const NoString& sName, const NoString& sTitle, const NoStringPairVector& vParams, uint uFlags = 0)
        : m_uFlags(uFlags), m_sName(sName), m_sTitle(sTitle), m_vParams(vParams)
    {
    }

    enum { Admin = 1 };

    void SetName(const NoString& s) { m_sName = s; }
    void SetTitle(const NoString& s) { m_sTitle = s; }
    void AddParam(const NoString& sName, const NoString& sValue) { m_vParams.push_back(make_pair(sName, sValue)); }

    bool RequiresAdmin() const { return m_uFlags & Admin; }

    const NoString& GetName() const { return m_sName; }
    const NoString& GetTitle() const { return m_sTitle; }
    const NoStringPairVector& GetParams() const { return m_vParams; }

private:
    uint m_uFlags;
    NoString m_sName;
    NoString m_sTitle;
    NoStringPairVector m_vParams;
};

class NO_EXPORT NoWebSock : public NoHttpSocket
{
public:
    enum PageRequest {
        NotFound, // print 404 and Close()
        Print, // print page contents and Close()
        Deferred, // async processing, Close() will be called from a different place
        Done // all stuff has been done
    };

    NoWebSock(const NoString& sURIPrefix);
    virtual ~NoWebSock();

    bool ForceLogin() override;
    bool OnLogin(const NoString& sUser, const NoString& sPass, bool bBasic) override;
    void OnPageRequest(const NoString& sURI) override;

    PageRequest PrintTemplate(const NoString& sPageName, NoString& sPageRet, NoModule* pModule = nullptr);
    PageRequest PrintStaticFile(const NoString& sPath, NoString& sPageRet, NoModule* pModule = nullptr);

    NoString FindTmpl(NoModule* pModule, const NoString& sName);

    void PrintErrorPage(const NoString& sMessage);

    std::shared_ptr<NoWebSession> GetSession();

    NoSocket* GetSockObjImpl(const NoString& sHost, ushort uPort) override;
    static NoString GetSkinPath(const NoString& sSkinName);
    void GetAvailSkins(NoStringVector& vRet) const;
    NoString GetSkinName();

    NoString GetRequestCookie(const NoString& sKey);
    bool SendCookie(const NoString& sKey, const NoString& sValue);

    static void FinishUserSessions(const NoUser& User);

protected:
    using NoHttpSocket::PrintErrorPage;

    bool AddModLoop(const NoString& sLoopName, NoModule& Module, NoTemplate* pTemplate = nullptr);
    NoStringVector GetDirs(NoModule* pModule, bool bIsTemplate);
    void SetPaths(NoModule* pModule, bool bIsTemplate = false);
    void SetVars();
    NoString GetCSRFCheck();

private:
    PageRequest OnPageRequestInternal(const NoString& sURI, NoString& sPageRet);

    bool m_bPathsSet;
    NoTemplate m_Template;
    std::shared_ptr<NoAuthenticator> m_spAuth;
    NoString m_sModName;
    NoString m_sPath;
    NoString m_sPage;
    std::shared_ptr<NoWebSession> m_spSession;

    static const uint m_uiMaxSessions;
};

#endif // NOWEBMODULES_H
