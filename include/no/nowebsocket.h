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

#ifndef NOWEBSOCKET_H
#define NOWEBSOCKET_H

#include <no/noglobal.h>
#include <no/nohttpsocket.h>
#include <no/notemplate.h>

class NoUser;
class NoWebSession;
class NoAuthenticator;

class NO_EXPORT NoWebSocket : public NoHttpSocket
{
public:
    enum PageRequest {
        NotFound, // print 404 and Close()
        Print, // print page contents and Close()
        Deferred, // async processing, Close() will be called from a different place
        Done // all stuff has been done
    };

    NoWebSocket(const NoString& sURIPrefix);
    virtual ~NoWebSocket();

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

    bool m_pathsSet;
    NoTemplate m_template;
    std::shared_ptr<NoAuthenticator> m_authenticator;
    NoString m_modName;
    NoString m_path;
    NoString m_page;
    std::shared_ptr<NoWebSession> m_session;

    static const uint m_maxSessions;
};

#endif // NOWEBSOCKET_H
