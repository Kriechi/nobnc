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

#include "nohttpsocket.h"
#include "nodebug.h"
#include "nofile.h"
#include "nodir.h"
#include "noapp.h"
#include "noescape.h"
#include <iomanip>
#include <algorithm>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#define MAX_POST_SIZE 1024 * 1024

NoHttpSocket::NoHttpSocket(NoModule* pMod, const NoString& sURIPrefix) : NoHttpSocket(pMod, sURIPrefix, "", 0) { Init(); }

NoHttpSocket::NoHttpSocket(NoModule* pMod, const NoString& sURIPrefix, const NoString& sHostname, ushort uPort, int iTimeout)
    : NoModuleSocket(pMod, sHostname, uPort, iTimeout), m_bSentHeader(false), m_bGotHeader(false), m_bLoggedIn(false), m_bPost(false),
      m_bDone(false), m_uPostLen(0), m_sPostData(""), m_sURI(""), m_sUser(""), m_sPass(""), m_sContentType(""),
      m_sDocRoot(""), m_sForwardedIP(""), m_msvsPOSTParams(), m_msvsGETParams(), m_msHeaders(), m_bHTTP10Client(false),
      m_sIfNoneMatch(""), m_bAcceptGzip(false), m_msRequestCookies(), m_msResponseCookies(), m_sURIPrefix(sURIPrefix)
{
    Init();
}

void NoHttpSocket::Init()
{
    EnableReadLine();
    SetMaxBufferThreshold(10240);
}

NoHttpSocket::~NoHttpSocket() {}

void NoHttpSocket::ReadDataImpl(const char* data, size_t len)
{
    if (!m_bDone && m_bGotHeader && m_bPost) {
        m_sPostData.append(data, len);
        CheckPost();
    }
}

bool NoHttpSocket::SendCookie(const NoString& sKey, const NoString& sValue)
{
    if (!sKey.empty() && !sValue.empty()) {
        // only queue a Set-Cookie to be sent if the client didn't send a Cookie header of the same name+value.
        m_msResponseCookies[sKey] = sValue;
        return true;
    }

    return false;
}

NoString NoHttpSocket::GetRequestCookie(const NoString& sKey) const
{
    NoStringMap::const_iterator it = m_msRequestCookies.find(sKey);

    return it != m_msRequestCookies.end() ? it->second : "";
}

void NoHttpSocket::CheckPost()
{
    if (m_sPostData.size() >= m_uPostLen) {
        ParseParams(m_sPostData.left(m_uPostLen), m_msvsPOSTParams);
        GetPage();
        m_sPostData.clear();
        m_bDone = true;
    }
}

void NoHttpSocket::ReadLineImpl(const NoString& sData)
{
    if (m_bGotHeader) {
        return;
    }

    NoString sLine = sData;
    sLine.trimRight("\r\n");

    NoString sName = No::token(sLine, 0);

    if (sName.equals("GET")) {
        m_bPost = false;
        m_sURI = No::token(sLine, 1);
        m_bHTTP10Client = No::token(sLine, 2).equals("HTTP/1.0");
        ParseURI();
    } else if (sName.equals("POST")) {
        m_bPost = true;
        m_sURI = No::token(sLine, 1);
        ParseURI();
    } else if (sName.equals("Cookie:")) {
        NoStringVector vsNV = No::tokens(sLine, 1).split(";", No::SkipEmptyParts);

        for (NoString& s : vsNV) {
            s.trim();
            m_msRequestCookies[No::escape(No::token(s, 0, "="), No::UrlFormat, No::AsciiFormat)] =
            No::escape(No::tokens(s, 1, "="), No::UrlFormat, No::AsciiFormat);
        }
    } else if (sName.equals("Authorization:")) {
        NoString sUnhashed = NoString::fromBase64(No::token(sLine, 2));
        m_sUser = No::token(sUnhashed, 0, ":");
        m_sPass = No::tokens(sUnhashed, 1, ":");
        m_bLoggedIn = OnLogin(m_sUser, m_sPass, true);
    } else if (sName.equals("Content-Length:")) {
        m_uPostLen = No::token(sLine, 1).toULong();
        if (m_uPostLen > MAX_POST_SIZE)
            PrintErrorPage(413, "Request Entity Too Large", "The request you sent was too large.");
    } else if (sName.equals("X-Forwarded-For:")) {
        // X-Forwarded-For: client, proxy1, proxy2
        if (m_sForwardedIP.empty()) {
            const NoStringVector& vsTrustedProxies = NoApp::Get().GetTrustedProxies();
            NoString sIP = GetRemoteIP();

            NoStringVector vsIPs = No::tokens(sLine, 1).split(",", No::SkipEmptyParts);

            while (!vsIPs.empty()) {
                // sIP told us that it got connection from vsIPs.back()
                // check if sIP is trusted proxy
                bool bTrusted = false;
                for (const NoString& sTrustedProxy : vsTrustedProxies) {
                    if (No::wildCmp(sIP, sTrustedProxy)) {
                        bTrusted = true;
                        break;
                    }
                }
                if (bTrusted) {
                    // sIP is trusted proxy, so use vsIPs.back() as new sIP
                    sIP = vsIPs.back().trim_n();
                    vsIPs.pop_back();
                } else {
                    break;
                }
            }

            // either sIP is not trusted proxy, or it's in the beginning of the X-Forwarded-For list
            // in both cases use it as the endpoind
            m_sForwardedIP = sIP;
        }
    } else if (sName.equals("If-None-Match:")) {
        // this is for proper client cache support (HTTP 304) on static files:
        m_sIfNoneMatch = No::tokens(sLine, 1);
    } else if (sName.equals("Accept-Encoding:") && !m_bHTTP10Client) {
        // trimming whitespace from the tokens is important:
        NoStringVector vsEncodings = No::tokens(sLine, 1).split(",", No::SkipEmptyParts);
        for (NoString& sEncoding : vsEncodings) {
            if (sEncoding.trim_n().equals("gzip"))
                m_bAcceptGzip = true;
        }
    } else if (sLine.empty()) {
        m_bGotHeader = true;

        if (m_bPost) {
            m_sPostData = GetInternalReadBuffer();
            CheckPost();
        } else {
            GetPage();
        }

        DisableReadLine();
    }
}

NoString NoHttpSocket::GetRemoteIP() const
{
    if (!m_sForwardedIP.empty()) {
        return m_sForwardedIP;
    }

    return NoModuleSocket::GetRemoteIP();
}

NoString NoHttpSocket::GetDate(time_t stamp)
{
    struct tm tm;
    std::stringstream stream;
    const char* wkday[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const char* month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    if (stamp == 0) time(&stamp);
    gmtime_r(&stamp, &tm);

    stream << wkday[tm.tm_wday] << ", ";
    stream << std::setfill('0') << std::setw(2) << tm.tm_mday << " ";
    stream << month[tm.tm_mon] << " ";
    stream << std::setfill('0') << std::setw(4) << tm.tm_year + 1900 << " ";
    stream << std::setfill('0') << std::setw(2) << tm.tm_hour << ":";
    stream << std::setfill('0') << std::setw(2) << tm.tm_min << ":";
    stream << std::setfill('0') << std::setw(2) << tm.tm_sec << " GMT";

    return stream.str();
}

void NoHttpSocket::GetPage()
{
    NO_DEBUG("Page Request [" << m_sURI << "] ");

    // Check that the requested path starts with the prefix. Strip it if so.
    if (!m_sURI.trimPrefix(m_sURIPrefix)) {
        NO_DEBUG("INVALID path => Does not start with prefix [" + m_sURIPrefix + "]");
        NO_DEBUG("Expected prefix:   " << m_sURIPrefix);
        NO_DEBUG("Requested path:    " << m_sURI);
        Redirect("/");
    } else {
        OnPageRequest(m_sURI);
    }
}

#ifdef HAVE_ZLIB
static bool InitZlibStream(z_stream* zStrm, const char* buf)
{
    memset(zStrm, 0, sizeof(z_stream));
    zStrm->next_in = (Bytef*)buf;

    // "15" is the default value for good compression,
    // the weird "+ 16" means "please generate a gzip header and trailer".
    const int WINDOW_BITS = 15 + 16;
    const int MEMLEVEL = 8;

    return (deflateInit2(zStrm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, WINDOW_BITS, MEMLEVEL, Z_DEFAULT_STRATEGY) == Z_OK);
}
#endif

void NoHttpSocket::PrintPage(const NoString& sPage)
{
#ifdef HAVE_ZLIB
    if (m_bAcceptGzip && !SentHeader()) {
        char szBuf[4096];
        z_stream zStrm;
        int zStatus, zFlush = Z_NO_FLUSH;

        if (InitZlibStream(&zStrm, sPage.c_str())) {
            NO_DEBUG("- Sending gzip-compressed.");
            AddHeader("Content-Encoding", "gzip");
            PrintHeader(0); // we do not know the compressed data's length

            zStrm.avail_in = sPage.size();
            do {
                if (zStrm.avail_in == 0) {
                    zFlush = Z_FINISH;
                }

                zStrm.next_out = (Bytef*)szBuf;
                zStrm.avail_out = sizeof(szBuf);

                zStatus = deflate(&zStrm, zFlush);

                if ((zStatus == Z_OK || zStatus == Z_STREAM_END) && zStrm.avail_out < sizeof(szBuf)) {
                    Write(szBuf, sizeof(szBuf) - zStrm.avail_out);
                }
            } while (zStatus == Z_OK);

            Close(NoSocket::CLT_AFTERWRITE);
            deflateEnd(&zStrm);
            return;
        }

    } // else: fall through
#endif
    if (!SentHeader()) {
        PrintHeader(sPage.length());
    } else {
        NO_DEBUG("PrintPage(): Header was already sent");
    }

    Write(sPage);
    Close(NoSocket::CLT_AFTERWRITE);
}

bool NoHttpSocket::PrintFile(const NoString& sFileName, NoString sContentType)
{
    NoString sFilePath = sFileName;

    if (!m_sDocRoot.empty()) {
        sFilePath.trimLeft("/");

        sFilePath = NoDir::CheckPathPrefix(m_sDocRoot, sFilePath, m_sDocRoot);

        if (sFilePath.empty()) {
            PrintErrorPage(403, "Forbidden", "You don't have permission to access that file on this server.");
            NO_DEBUG("THIS FILE:     [" << sFilePath << "] does not live in ...");
            NO_DEBUG("DOCUMENT ROOT: [" << m_sDocRoot << "]");
            return false;
        }
    }

    NoFile File(sFilePath);

    if (!File.Open()) {
        PrintNotFound();
        return false;
    }

    if (sContentType.empty()) {
        if (sFileName.right(5).equals(".html") || sFileName.right(4).equals(".htm")) {
            sContentType = "text/html; charset=utf-8";
        } else if (sFileName.right(4).equals(".css")) {
            sContentType = "text/css; charset=utf-8";
        } else if (sFileName.right(3).equals(".js")) {
            sContentType = "application/x-javascript; charset=utf-8";
        } else if (sFileName.right(4).equals(".jpg")) {
            sContentType = "image/jpeg";
        } else if (sFileName.right(4).equals(".gif")) {
            sContentType = "image/gif";
        } else if (sFileName.right(4).equals(".ico")) {
            sContentType = "image/x-icon";
        } else if (sFileName.right(4).equals(".png")) {
            sContentType = "image/png";
        } else if (sFileName.right(4).equals(".bmp")) {
            sContentType = "image/bmp";
        } else {
            sContentType = "text/plain; charset=utf-8";
        }
    }

    const time_t iMTime = File.GetMTime();
    bool bNotModified = false;
    NoString sETag;

    if (iMTime > 0 && !m_bHTTP10Client) {
        sETag = "-" + NoString(iMTime); // lighttpd style ETag

        AddHeader("Last-Modified", GetDate(iMTime));
        AddHeader("ETag", "\"" + sETag + "\"");
        AddHeader("Cache-Control", "public");

        if (!m_sIfNoneMatch.empty()) {
            m_sIfNoneMatch.trim("\\\"'");
            bNotModified = (m_sIfNoneMatch.equals(sETag, No::CaseSensitive));
        }
    }

    if (bNotModified) {
        PrintHeader(0, sContentType, 304, "Not Modified");
    } else {
        off_t iSize = File.GetSize();

        // Don't try to send files over 16 MiB, because it might block
        // the whole process and use huge amounts of memory.
        if (iSize > 16 * 1024 * 1024) {
            NO_DEBUG("- Abort: File is over 16 MiB big: " << iSize);
            PrintErrorPage(500, "Internal Server Error", "File too big");
            return true;
        }

#ifdef HAVE_ZLIB
        bool bGzip = m_bAcceptGzip && (sContentType.left(5).equals("text/") || sFileName.right(3).equals(".js"));

        if (bGzip) {
            NO_DEBUG("- Sending gzip-compressed.");
            AddHeader("Content-Encoding", "gzip");
            PrintHeader(0, sContentType); // we do not know the compressed data's length
            WriteFileGzipped(File);
        } else
#endif
        {
            PrintHeader(iSize, sContentType);
            WriteFileUncompressed(File);
        }
    }

    NO_DEBUG("- ETag: [" << sETag << "] / If-None-Match [" << m_sIfNoneMatch << "]");

    Close(NoSocket::CLT_AFTERWRITE);

    return true;
}

void NoHttpSocket::WriteFileUncompressed(NoFile& File)
{
    char szBuf[4096];
    off_t iLen = 0;
    ssize_t i = 0;
    off_t iSize = File.GetSize();

    // while we haven't reached iSize and read() succeeds...
    while (iLen < iSize && (i = File.Read(szBuf, sizeof(szBuf))) > 0) {
        Write(szBuf, i);
        iLen += i;
    }

    if (i < 0) {
        NO_DEBUG("- Error while reading file: " << strerror(errno));
    }
}

#ifdef HAVE_ZLIB
void NoHttpSocket::WriteFileGzipped(NoFile& File)
{
    char szBufIn[8192];
    char szBufOut[8192];
    off_t iFileSize = File.GetSize(), iFileReadTotal = 0;
    z_stream zStrm;
    int zFlush = Z_NO_FLUSH;
    int zStatus;

    if (!InitZlibStream(&zStrm, szBufIn)) {
        NO_DEBUG("- Error initializing zlib!");
        return;
    }

    do {
        ssize_t iFileRead = 0;

        if (zStrm.avail_in == 0) {
            // input buffer is empty, try to read more data from file.
            // if there is no more data, finish the stream.

            if (iFileReadTotal < iFileSize) {
                iFileRead = File.Read(szBufIn, sizeof(szBufIn));

                if (iFileRead < 1) {
                    // wtf happened? better quit compressing.
                    iFileReadTotal = iFileSize;
                    zFlush = Z_FINISH;
                } else {
                    iFileReadTotal += iFileRead;

                    zStrm.next_in = (Bytef*)szBufIn;
                    zStrm.avail_in = iFileRead;
                }
            } else {
                zFlush = Z_FINISH;
            }
        }

        zStrm.next_out = (Bytef*)szBufOut;
        zStrm.avail_out = sizeof(szBufOut);

        zStatus = deflate(&zStrm, zFlush);

        if ((zStatus == Z_OK || zStatus == Z_STREAM_END) && zStrm.avail_out < sizeof(szBufOut)) {
            // there's data in the buffer:
            Write(szBufOut, sizeof(szBufOut) - zStrm.avail_out);
        }

    } while (zStatus == Z_OK);

    deflateEnd(&zStrm);
}
#endif

void NoHttpSocket::ParseURI()
{
    ParseParams(No::tokens(m_sURI, 1, "?"), m_msvsGETParams);
    m_sURI = No::token(m_sURI, 0, "?");
}

NoString NoHttpSocket::GetPath() const { return No::token(m_sURI, 0, "?"); }

bool NoHttpSocket::IsLoggedIn() const { return m_bLoggedIn; }

void NoHttpSocket::ParseParams(const NoString& sParams, std::map<NoString, NoStringVector>& msvsParams)
{
    msvsParams.clear();

    NoStringVector vsPairs = sParams.split("&");

    for (const NoString& sPair : vsPairs) {
        NoString sName = No::escape(No::token(sPair, 0, "="), No::UrlFormat, No::AsciiFormat);
        NoString sValue = No::escape(No::tokens(sPair, 1, "="), No::UrlFormat, No::AsciiFormat);

        msvsParams[sName].push_back(sValue);
    }
}

void NoHttpSocket::SetDocRoot(const NoString& s)
{
    m_sDocRoot = s + "/";
    m_sDocRoot.replace("//", "/");
}

void NoHttpSocket::SetLoggedIn(bool b) { m_bLoggedIn = b; }

const NoString& NoHttpSocket::GetDocRoot() const { return m_sDocRoot; }

const NoString& NoHttpSocket::GetUser() const { return m_sUser; }

const NoString& NoHttpSocket::GetPass() const { return m_sPass; }

const NoString& NoHttpSocket::GetContentType() const { return m_sContentType; }

const NoString& NoHttpSocket::GetParamString() const { return m_sPostData; }

const NoString& NoHttpSocket::GetURIPrefix() const { return m_sURIPrefix; }

bool NoHttpSocket::HasParam(const NoString& sName, bool bPost) const
{
    if (bPost) return (m_msvsPOSTParams.find(sName) != m_msvsPOSTParams.end());
    return (m_msvsGETParams.find(sName) != m_msvsGETParams.end());
}

NoString NoHttpSocket::GetRawParam(const NoString& sName, bool bPost) const
{
    if (bPost) return GetRawParam(sName, m_msvsPOSTParams);
    return GetRawParam(sName, m_msvsGETParams);
}

NoString NoHttpSocket::GetRawParam(const NoString& sName, const std::map<NoString, NoStringVector>& msvsParams)
{
    NoString sRet;

    std::map<NoString, NoStringVector>::const_iterator it = msvsParams.find(sName);

    if (it != msvsParams.end() && it->second.size() > 0) {
        sRet = it->second[0];
    }

    return sRet;
}

NoString NoHttpSocket::GetParam(const NoString& sName, bool bPost, const NoString& sFilter) const
{
    if (bPost) return GetParam(sName, m_msvsPOSTParams, sFilter);
    return GetParam(sName, m_msvsGETParams, sFilter);
}

NoString NoHttpSocket::GetParam(const NoString& sName, const std::map<NoString, NoStringVector>& msvsParams, const NoString& sFilter)
{
    NoString sRet = GetRawParam(sName, msvsParams);
    sRet.trim();

    for (size_t i = 0; i < sFilter.length(); i++) {
        sRet.replace(NoString(sFilter.at(i)), "");
    }

    return sRet;
}

size_t NoHttpSocket::GetParamValues(const NoString& sName, std::set<NoString>& ssRet, bool bPost, const NoString& sFilter) const
{
    if (bPost) return GetParamValues(sName, ssRet, m_msvsPOSTParams, sFilter);
    return GetParamValues(sName, ssRet, m_msvsGETParams, sFilter);
}

size_t NoHttpSocket::GetParamValues(const NoString& sName, std::set<NoString>& ssRet, const std::map<NoString, NoStringVector>& msvsParams, const NoString& sFilter)
{
    ssRet.clear();

    std::map<NoString, NoStringVector>::const_iterator it = msvsParams.find(sName);

    if (it != msvsParams.end()) {
        for (NoString sParam : it->second) {
            sParam.trim();

            for (size_t i = 0; i < sFilter.length(); i++) {
                sParam.replace(NoString(sFilter.at(i)), "");
            }
            ssRet.insert(sParam);
        }
    }

    return ssRet.size();
}

size_t NoHttpSocket::GetParamValues(const NoString& sName, NoStringVector& vsRet, bool bPost, const NoString& sFilter) const
{
    if (bPost) return GetParamValues(sName, vsRet, m_msvsPOSTParams, sFilter);
    return GetParamValues(sName, vsRet, m_msvsGETParams, sFilter);
}

size_t NoHttpSocket::GetParamValues(const NoString& sName, NoStringVector& vsRet, const std::map<NoString, NoStringVector>& msvsParams, const NoString& sFilter)
{
    vsRet.clear();

    std::map<NoString, NoStringVector>::const_iterator it = msvsParams.find(sName);

    if (it != msvsParams.end()) {
        for (NoString sParam : it->second) {
            sParam.trim();

            for (size_t i = 0; i < sFilter.length(); i++) {
                sParam.replace(NoString(sFilter.at(i)), "");
            }
            vsRet.push_back(sParam);
        }
    }

    return vsRet.size();
}

const std::map<NoString, NoStringVector>& NoHttpSocket::GetParams(bool bPost) const
{
    if (bPost) return m_msvsPOSTParams;
    return m_msvsGETParams;
}

bool NoHttpSocket::IsPost() const { return m_bPost; }

bool NoHttpSocket::PrintNotFound()
{
    return PrintErrorPage(404, "Not Found", "The requested URL was not found on this server.");
}

bool NoHttpSocket::PrintErrorPage(uint uStatusId, const NoString& sStatusMsg, const NoString& sMessage)
{
    if (SentHeader()) {
        NO_DEBUG("PrintErrorPage(): Header was already sent");
        return false;
    }

    NoString sPage = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
                    "<!DOCTYPE html>\r\n"
                    "<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\" xml:lang=\"en\">\r\n"
                    "<head>\r\n"
                    "<meta charset=\"UTF-8\"/>\r\n"
                    "<title>" +
                    NoString(uStatusId) + " " + No::escape(sStatusMsg, No::HtmlFormat) + "</title>\r\n"
                                                                                     "</head>\r\n"
                                                                                     "<body>\r\n"
                                                                                     "<h1>" +
                    No::escape(sStatusMsg, No::HtmlFormat) + "</h1>\r\n"
                                                          "<p>" +
                    No::escape(sMessage, No::HtmlFormat) + "</p>\r\n"
                                                        "<hr/>\r\n"
                                                        "<address>" +
                    NoApp::GetTag(false, /* bHTML = */ true) + " at " + No::escape(GetLocalIP(), No::HtmlFormat) +
                    " Port " + NoString(GetLocalPort()) + "</address>\r\n"
                                                         "</body>\r\n"
                                                         "</html>\r\n";

    PrintHeader(sPage.length(), "text/html; charset=utf-8", uStatusId, sStatusMsg);
    Write(sPage);
    Close(NoSocket::CLT_AFTERWRITE);

    return true;
}

bool NoHttpSocket::ForceLogin()
{
    if (m_bLoggedIn) {
        return true;
    }

    if (SentHeader()) {
        NO_DEBUG("ForceLogin(): Header was already sent!");
        return false;
    }

    AddHeader("WWW-Authenticate", "Basic realm=\"" + NoApp::GetTag(false) + "\"");
    PrintErrorPage(401, "Unauthorized", "You need to login to view this page.");

    return false;
}

bool NoHttpSocket::OnLogin(const NoString& sUser, const NoString& sPass, bool bBasic) { return false; }

bool NoHttpSocket::SentHeader() const { return m_bSentHeader; }

bool NoHttpSocket::PrintHeader(off_t uContentLength, const NoString& sContentType, uint uStatusId, const NoString& sStatusMsg)
{
    if (SentHeader()) {
        NO_DEBUG("PrintHeader(): Header was already sent!");
        return false;
    }

    if (!sContentType.empty()) {
        m_sContentType = sContentType;
    }

    if (m_sContentType.empty()) {
        m_sContentType = "text/html; charset=utf-8";
    }

    NO_DEBUG("- " << uStatusId << " (" << sStatusMsg << ") [" << m_sContentType << "]");

    Write("HTTP/" + NoString(m_bHTTP10Client ? "1.0 " : "1.1 ") + NoString(uStatusId) + " " + sStatusMsg + "\r\n");
    Write("Date: " + GetDate() + "\r\n");
    Write("Server: " + NoApp::GetTag(false) + "\r\n");
    if (uContentLength > 0) {
        Write("Content-Length: " + NoString(uContentLength) + "\r\n");
    }
    Write("Content-Type: " + m_sContentType + "\r\n");

    for (const auto& it : m_msResponseCookies) {
        Write("Set-Cookie: " + No::escape(it.first, No::UrlFormat) + "=" + No::escape(it.second, No::UrlFormat) +
              "; path=/;" + (GetSSL() ? "Secure;" : "") + "\r\n");
    }

    for (const auto& it : m_msHeaders) {
        Write(it.first + ": " + it.second + "\r\n");
    }

    Write("Connection: Close\r\n");

    Write("\r\n");
    m_bSentHeader = true;

    return true;
}

void NoHttpSocket::SetContentType(const NoString& sContentType) { m_sContentType = sContentType; }

void NoHttpSocket::AddHeader(const NoString& sName, const NoString& sValue) { m_msHeaders[sName] = sValue; }

bool NoHttpSocket::Redirect(const NoString& sURL)
{
    if (SentHeader()) {
        NO_DEBUG("Redirect() - Header was already sent");
        return false;
    } else if (!sURL.startsWith("/")) {
        // HTTP/1.1 only admits absolute URIs for the Location header.
        NO_DEBUG("Redirect to relative URI [" + sURL + "] is not allowed.");
        return false;
    } else {
        NoString location = m_sURIPrefix + sURL;

        NO_DEBUG("- Redirect to [" << location << "] with prefix [" + m_sURIPrefix + "]");
        AddHeader("Location", location);
        PrintErrorPage(302,
                       "Found",
                       "The document has moved <a href=\"" + No::escape(location, No::HtmlFormat) + "\">here</a>.");

        return true;
    }
}

void NoHttpSocket::ConnectedImpl() { SetTimeout(120); }
