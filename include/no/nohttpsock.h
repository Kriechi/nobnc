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

#ifndef NOHTTPSOCK_H
#define NOHTTPSOCK_H

#include <no/noconfig.h>
#include <no/nosocket.h>
#include <no/nofile.h>

class NoModule;

class NoHttpSock : public NoSocket
{
public:
    NoHttpSock(NoModule* pMod, const NoString& sURIPrefix);
    NoHttpSock(NoModule* pMod, const NoString& sURIPrefix, const NoString& sHostname, unsigned short uPort, int iTimeout = 60);
    virtual ~NoHttpSock();

    void ReadData(const char* data, size_t len) override;
    void ReadLine(const NoString& sData) override;
    void Connected() override;
    Csock* GetSockObj(const NoString& sHost, unsigned short uPort) override = 0;

    virtual bool ForceLogin();
    virtual bool OnLogin(const NoString& sUser, const NoString& sPass, bool bBasic);
    virtual void OnPageRequest(const NoString& sURI) = 0;
    virtual bool PrintFile(const NoString& sFileName, NoString sContentType = "");

    void CheckPost();
    bool SentHeader() const;
    bool PrintHeader(off_t uContentLength, const NoString& sContentType = "", unsigned int uStatusId = 200, const NoString& sStatusMsg = "OK");
    void AddHeader(const NoString& sName, const NoString& sValue);
    void SetContentType(const NoString& sContentType);

    bool PrintNotFound();
    bool Redirect(const NoString& sURL);
    bool PrintErrorPage(unsigned int uStatusId, const NoString& sStatusMsg, const NoString& sMessage);
    static void ParseParams(const NoString& sParams, std::map<NoString, NoStringVector>& msvsParams);
    void ParseURI();
    void GetPage();
    static NoString GetDate(time_t tm = 0);
    NoString GetRemoteIP() const override;

    NoString GetRequestCookie(const NoString& sKey) const;
    bool SendCookie(const NoString& sKey, const NoString& sValue);

    void SetDocRoot(const NoString& s);
    void SetLoggedIn(bool b) { m_bLoggedIn = b; }

    NoString GetPath() const;
    bool IsLoggedIn() const { return m_bLoggedIn; }
    const NoString& GetDocRoot() const;
    const NoString& GetUser() const;
    const NoString& GetPass() const;
    const NoString& GetParamString() const;
    const NoString& GetContentType() const;
    const NoString& GetURIPrefix() const;
    bool IsPost() const;

    NoString GetParam(const NoString& sName, bool bPost = true, const NoString& sFilter = "\r\n") const;
    NoString GetRawParam(const NoString& sName, bool bPost = true) const;
    bool HasParam(const NoString& sName, bool bPost = true) const;
    const std::map<NoString, NoStringVector>& GetParams(bool bPost = true) const;
    size_t GetParamValues(const NoString& sName, NoStringVector& vsRet, bool bPost = true, const NoString& sFilter = "\r\n") const;
    size_t GetParamValues(const NoString& sName, std::set<NoString>& ssRet, bool bPost = true, const NoString& sFilter = "\r\n") const;

private:
    static NoString GetRawParam(const NoString& sName, const std::map<NoString, NoStringVector>& msvsParams);
    static NoString GetParam(const NoString& sName, const std::map<NoString, NoStringVector>& msvsParams, const NoString& sFilter);
    static size_t
    GetParamValues(const NoString& sName, NoStringVector& vsRet, const std::map<NoString, NoStringVector>& msvsParams, const NoString& sFilter);
    static size_t
    GetParamValues(const NoString& sName, std::set<NoString>& ssRet, const std::map<NoString, NoStringVector>& msvsParams, const NoString& sFilter);

    void WriteFileUncompressed(NoFile& File);
    void WriteFileGzipped(NoFile& File);

protected:
    void PrintPage(const NoString& sPage);
    void Init();

    bool m_bSentHeader;
    bool m_bGotHeader;
    bool m_bLoggedIn;
    bool m_bPost;
    bool m_bDone;
    unsigned long m_uPostLen;
    NoString m_sPostData;
    NoString m_sURI;
    NoString m_sUser;
    NoString m_sPass;
    NoString m_sContentType;
    NoString m_sDocRoot;
    NoString m_sForwardedIP;
    std::map<NoString, NoStringVector> m_msvsPOSTParams;
    std::map<NoString, NoStringVector> m_msvsGETParams;
    NoStringMap m_msHeaders;
    bool m_bHTTP10Client;
    NoString m_sIfNoneMatch;
    bool m_bAcceptGzip;
    NoStringMap m_msRequestCookies;
    NoStringMap m_msResponseCookies;
    NoString m_sURIPrefix;
};

#endif // NOHTTPSOCK_H
