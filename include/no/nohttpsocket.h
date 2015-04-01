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

#ifndef NOHTTPSOCKET_H
#define NOHTTPSOCKET_H

#include <no/noglobal.h>
#include <no/nomodulesocket.h>

class NoFile;
class NoModule;

class NO_EXPORT NoHttpSocket : public NoModuleSocket
{
public:
    NoHttpSocket(NoModule* mod, const NoString& uriPrefix);
    NoHttpSocket(NoModule* mod, const NoString& uriPrefix, const NoString& hostname, ushort port);
    virtual ~NoHttpSocket();

    void readData(const char* data, size_t len) override;
    void readLine(const NoString& data) override;
    void onConnected() override;
    NoSocket* createSocket(const NoString& host, ushort port) override = 0;

    virtual bool forceLogin();
    virtual bool onLogin(const NoString& sUser, const NoString& pass, bool bBasic);
    virtual void onPageRequest(const NoString& sURI) = 0;
    virtual bool printFile(const NoString& fileName, NoString sContentType = "");

    void checkPost();
    bool sentHeader() const;
    bool printHeader(off_t uContentLength, const NoString& sContentType = "", uint uStatusId = 200, const NoString& sStatusMsg = "OK");
    void addHeader(const NoString& name, const NoString& value);
    void setContentType(const NoString& sContentType);

    bool printNotFound();
    bool redirect(const NoString& sURL);
    bool printErrorPage(uint uStatusId, const NoString& sStatusMsg, const NoString& message);
    static void parseParams(const NoString& sParams, std::map<NoString, NoStringVector>& msvsParams);
    void parseUri();
    void requestPage();
    static NoString formatDate(time_t tm = 0);
    NoString remoteAddress() const override;

    NoString requestCookie(const NoString& key) const;
    bool sendCookie(const NoString& key, const NoString& value);

    void setLoggedIn(bool b);

    NoString path() const;
    bool isLoggedIn() const;
    NoString username() const;
    NoString password() const;
    NoString paramString() const;
    NoString contentType() const;
    NoString uriPrefix() const;
    bool isPost() const;

    NoString param(const NoString& name, bool bPost = true, const NoString& filter = "\r\n") const;
    NoString rawParam(const NoString& name, bool bPost = true) const;
    bool hasParam(const NoString& name, bool bPost = true) const;
    const std::map<NoString, NoStringVector>& params(bool bPost = true) const;
    size_t paramValues(const NoString& name, NoStringVector& vsRet, bool bPost = true, const NoString& filter = "\r\n") const;
    size_t paramValues(const NoString& name, std::set<NoString>& ssRet, bool bPost = true, const NoString& filter = "\r\n") const;

private:
    static NoString rawParam(const NoString& name, const std::map<NoString, NoStringVector>& msvsParams);
    static NoString param(const NoString& name, const std::map<NoString, NoStringVector>& msvsParams, const NoString& filter);
    static size_t paramValues(const NoString& name,
                                 NoStringVector& vsRet,
                                 const std::map<NoString, NoStringVector>& msvsParams,
                                 const NoString& filter);
    static size_t paramValues(const NoString& name,
                                 std::set<NoString>& ssRet,
                                 const std::map<NoString, NoStringVector>& msvsParams,
                                 const NoString& filter);

    void writeUncompressedFile(NoFile& File);
    void writeCompressedFile(NoFile& File);

protected:
    void printPage(const NoString& sPage);
    void init();

    bool m_sentHeader;
    bool m_gotHeader;
    bool m_loggedIn;
    bool m_post;
    bool m_done;
    ulong m_postLen;
    NoString m_postData;
    NoString m_uri;
    NoString m_username;
    NoString m_password;
    NoString m_contentType;
    NoString m_forwardedIp;
    std::map<NoString, NoStringVector> m_postParams;
    std::map<NoString, NoStringVector> m_getParams;
    NoStringMap m_headers;
    bool m_http10Client;
    NoString m_ifNoneMatch;
    bool m_acceptGzip;
    NoStringMap m_requestCookies;
    NoStringMap m_responseCookies;
    NoString m_uriPrefix;
};

#endif // NOHTTPSOCKET_H
