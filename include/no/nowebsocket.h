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

    bool forceLogin() override;
    bool onLogin(const NoString& sUser, const NoString& pass, bool bBasic) override;
    void onPageRequest(const NoString& sURI) override;

    PageRequest printTemplate(const NoString& sPageName, NoString& sPageRet, NoModule* pModule = nullptr);
    PageRequest printStaticFile(const NoString& sPath, NoString& sPageRet, NoModule* pModule = nullptr);

    NoString findTemplate(NoModule* pModule, const NoString& name);

    void printErrorPage(const NoString& sMessage);

    std::shared_ptr<NoWebSession> session();

    NoSocket* createSocket(const NoString& host, ushort port) override;
    static NoString skinPath(const NoString& sSkinName);
    void availableSkins(NoStringVector& vRet) const;
    NoString skinName();

    NoString requestCookie(const NoString& sKey);
    bool sendCookie(const NoString& sKey, const NoString& sValue);

    static void finishUserSessions(const NoUser& User);

protected:
    using NoHttpSocket::printErrorPage;

    bool addModuleLoop(const NoString& sLoopName, NoModule& Module, NoTemplate* pTemplate = nullptr);
    NoStringVector directories(NoModule* pModule, bool bIsTemplate);
    void setPaths(NoModule* pModule, bool bIsTemplate = false);
    void setVars();
    NoString csrfCheck(); // TODO: wat?

private:
    PageRequest onPageRequestInternal(const NoString& sURI, NoString& sPageRet);

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
