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

#include "nowebsession.h"
#include "nowebsocket.h"
#include "nomodule_p.h"
#include "nocachemap.h"
#include "notemplate.h"
#include "noauthenticator.h"
#include "nofile.h"
#include "nodir.h"
#include "noclient.h"
#include "nouser.h"
#include "nonetwork.h"
#include "nodebug.h"
#include "noapp.h"
#include "noescape.h"
#include <algorithm>

/// @todo Do we want to make this a configure option?
#define _SKINDIR_ _DATADIR_ "/webskins"

const uint NoWebSocket::m_maxSessions = 5;

class NoWebSessionMap : public NoCacheMap<NoString, std::shared_ptr<NoWebSession>>
{
public:
    NoWebSessionMap(uint uTTL = 5000) : NoCacheMap<NoString, std::shared_ptr<NoWebSession>>(uTTL)
    {
    }
    void FinishUserSessions(const NoUser& User)
    {
        iterator it = begin();

        while (it != end()) {
            if (it->second.second->user() == &User) {
                remove(it++);
            } else {
                ++it;
            }
        }
    }
};

// We need this class to make sure the contained maps and their content is
// destroyed in the order that we want.
struct NoWebSessionManager
{
    // Sessions are valid for a day, (24h, ...)
    NoWebSessionManager() : m_mspSessions(24 * 60 * 60 * 1000), m_mIPSessions()
    {
    }
    ~NoWebSessionManager()
    {
        // Make sure all sessions are destroyed before any of our maps
        // are destroyed
        m_mspSessions.clear();
    }

    NoWebSessionMap m_mspSessions;
    std::multimap<NoString, NoWebSession*> m_mIPSessions;
};
typedef std::multimap<NoString, NoWebSession*>::iterator mIPSessionsIterator;

static NoWebSessionManager Sessions;

class NoTagHandler : public NoTemplateTagHandler
{
public:
    NoTagHandler(NoWebSocket& WebSock) : NoTemplateTagHandler(), m_WebSock(WebSock)
    {
    }

    bool handleTag(NoTemplate& Tmpl, const NoString& sName, const NoString& sArgs, NoString& sOutput) override
    {
        if (sName.equals("URLPARAM")) {
            // sOutput = NoApp::Get()
            sOutput = m_WebSock.GetParam(No::token(sArgs, 0), false);
            return true;
        }
        return false;
    }

private:
    NoWebSocket& m_WebSock;
};

class NoWebAuth : public NoAuthenticator
{
public:
    NoWebAuth(NoWebSocket* pWebSock, const NoString& sUsername, const NoString& sPassword, bool bBasic);

    NoWebAuth(const NoWebAuth&) = delete;
    NoWebAuth& operator=(const NoWebAuth&) = delete;

    void SetWebSock(NoWebSocket* pWebSock)
    {
        m_pWebSock = pWebSock;
    }
    void invalidate() override;

protected:
    void loginAccepted(NoUser* user) override;
    void loginRefused(NoUser* user, const NoString& reason) override;

private:
    NoWebSocket* m_pWebSock;
    bool m_bBasic;
};

class NoWebSessionPrivate
{
public:
    NoString id = "";
    NoString ip = "";
    NoUser* user = nullptr;
    NoStringVector errorMsgs;
    NoStringVector successMsgs;
    time_t lastActive;
};

NoWebSession::NoWebSession(const NoString& sId, const NoString& sIP) : d(new NoWebSessionPrivate)
{
    d->id = sId;
    d->ip = sIP;
    Sessions.m_mIPSessions.insert(make_pair(sIP, this));
    updateLastActive();
}

NoWebSession::~NoWebSession()
{
    // Find our entry in mIPSessions
    std::pair<mIPSessionsIterator, mIPSessionsIterator> p = Sessions.m_mIPSessions.equal_range(d->ip);
    mIPSessionsIterator it = p.first;
    mIPSessionsIterator end = p.second;

    while (it != end) {
        if (it->second == this) {
            Sessions.m_mIPSessions.erase(it++);
        } else {
            ++it;
        }
    }
}

NoString NoWebSession::identifier() const
{
    return d->id;
}

NoString NoWebSession::host() const
{
    return d->ip;
}

NoUser* NoWebSession::user() const
{
    return d->user;
}

time_t NoWebSession::lastActive() const
{
    return d->lastActive;
}

bool NoWebSession::isLoggedIn() const
{
    return d->user != nullptr;
}

void NoWebSession::updateLastActive()
{
    time(&d->lastActive);
}

NoUser* NoWebSession::setUser(NoUser* p)
{
    d->user = p;
    return d->user;
}

bool NoWebSession::isAdmin() const
{
    return isLoggedIn() && d->user->isAdmin();
}

void NoWebSession::clearMessageLoops()
{
    d->errorMsgs.clear();
    d->successMsgs.clear();
}

void NoWebSession::fillMessageLoops(NoTemplate& Tmpl)
{
    for (const NoString& sMessage : d->errorMsgs) {
        NoTemplate& Row = Tmpl.addRow("ErrorLoop");
        Row["Message"] = sMessage;
    }

    for (const NoString& sMessage : d->successMsgs) {
        NoTemplate& Row = Tmpl.addRow("SuccessLoop");
        Row["Message"] = sMessage;
    }
}

size_t NoWebSession::addError(const NoString& sMessage)
{
    d->errorMsgs.push_back(sMessage);
    return d->errorMsgs.size();
}

size_t NoWebSession::addSuccess(const NoString& sMessage)
{
    d->successMsgs.push_back(sMessage);
    return d->successMsgs.size();
}

NoWebAuth::NoWebAuth(NoWebSocket* pWebSock, const NoString& sUsername, const NoString& sPassword, bool bBasic)
    : NoAuthenticator(sUsername, sPassword, pWebSock), m_pWebSock(pWebSock), m_bBasic(bBasic)
{
}

void NoWebAuth::loginAccepted(NoUser* user)
{
    if (m_pWebSock) {
        std::shared_ptr<NoWebSession> spSession = m_pWebSock->GetSession();

        spSession->setUser(user);

        m_pWebSock->SetLoggedIn(true);
        m_pWebSock->UnPauseRead();
        if (!m_bBasic) {
            m_pWebSock->Redirect("/?cookie_check=true");
        }

        NO_DEBUG("Successful login attempt ==> USER [" + user->userName() + "] ==> SESSION [" + spSession->identifier() + "]");
    }
}

void NoWebAuth::loginRefused(NoUser* user, const NoString& reason)
{
    if (m_pWebSock) {
        std::shared_ptr<NoWebSession> spSession = m_pWebSock->GetSession();

        spSession->addError("Invalid login!");
        spSession->setUser(nullptr);

        m_pWebSock->SetLoggedIn(false);
        m_pWebSock->UnPauseRead();
        m_pWebSock->Redirect("/?cookie_check=true");

        NO_DEBUG("UNSUCCESSFUL login attempt ==> REASON [" + reason + "] ==> SESSION [" + spSession->identifier() + "]");
    }
}

void NoWebAuth::invalidate()
{
    NoAuthenticator::invalidate();
    m_pWebSock = nullptr;
}

NoWebSocket::NoWebSocket(const NoString& sURIPrefix)
    : NoHttpSocket(nullptr, sURIPrefix), m_pathsSet(false), m_template(), m_authenticator(), m_modName(""), m_path(""), m_page(""), m_session()
{
    m_template.addTagHandler(std::make_shared<NoTagHandler>(*this));
}

NoWebSocket::~NoWebSocket()
{
    if (m_authenticator) {
        m_authenticator->invalidate();
    }

    // we have to account for traffic here because NoSocket does
    // not have a valid NoModule* pointer.
    NoUser* pUser = GetSession()->user();
    if (pUser) {
        pUser->addBytesWritten(GetBytesWritten());
        pUser->addBytesRead(GetBytesRead());
    } else {
        NoApp::Get().AddBytesWritten(GetBytesWritten());
        NoApp::Get().AddBytesRead(GetBytesRead());
    }

    // bytes have been accounted for, so make sure they don't get again:
    ResetBytesWritten();
    ResetBytesRead();
}

void NoWebSocket::FinishUserSessions(const NoUser& User)
{
    Sessions.m_mspSessions.FinishUserSessions(User);
}

void NoWebSocket::GetAvailSkins(NoStringVector& vRet) const
{
    vRet.clear();

    NoString sRoot(GetSkinPath("_default_"));

    sRoot.trimRight("/");
    sRoot.trimRight("_default_");
    sRoot.trimRight("/");

    if (!sRoot.empty()) {
        sRoot += "/";
    }

    if (!sRoot.empty() && NoFile(sRoot).IsDir()) {
        NoDir Dir(sRoot);

        for (const NoFile* pSubDir : Dir.files()) {
            if (pSubDir->IsDir() && pSubDir->GetShortName() == "_default_") {
                vRet.push_back(pSubDir->GetShortName());
                break;
            }
        }

        for (const NoFile* pSubDir : Dir.files()) {
            if (pSubDir->IsDir() && pSubDir->GetShortName() != "_default_" && pSubDir->GetShortName() != ".svn") {
                vRet.push_back(pSubDir->GetShortName());
            }
        }
    }
}

NoStringVector NoWebSocket::GetDirs(NoModule* pModule, bool bIsTemplate)
{
    NoString sHomeSkinsDir(NoApp::Get().GetZNCPath() + "/webskins/");
    NoString sSkinName(GetSkinName());
    NoStringVector vsResult;

    // Module specific paths

    if (pModule) {
        const NoString& sModName(pModule->moduleName());

        // 1. ~/.znc/webskins/<user_skin_setting>/mods/<mod_name>/
        //
        if (!sSkinName.empty()) {
            vsResult.push_back(GetSkinPath(sSkinName) + "/mods/" + sModName + "/");
        }

        // 2. ~/.znc/webskins/_default_/mods/<mod_name>/
        //
        vsResult.push_back(GetSkinPath("_default_") + "/mods/" + sModName + "/");

        // 3. ./modules/<mod_name>/tmpl/
        //
        vsResult.push_back(pModule->moduleDataDir() + "/tmpl/");

        // 4. ~/.znc/webskins/<user_skin_setting>/mods/<mod_name>/
        //
        if (!sSkinName.empty()) {
            vsResult.push_back(GetSkinPath(sSkinName) + "/mods/" + sModName + "/");
        }

        // 5. ~/.znc/webskins/_default_/mods/<mod_name>/
        //
        vsResult.push_back(GetSkinPath("_default_") + "/mods/" + sModName + "/");
    }

    // 6. ~/.znc/webskins/<user_skin_setting>/
    //
    if (!sSkinName.empty()) {
        vsResult.push_back(GetSkinPath(sSkinName) + NoString(bIsTemplate ? "/tmpl/" : "/"));
    }

    // 7. ~/.znc/webskins/_default_/
    //
    vsResult.push_back(GetSkinPath("_default_") + NoString(bIsTemplate ? "/tmpl/" : "/"));

    return vsResult;
}

NoString NoWebSocket::FindTmpl(NoModule* pModule, const NoString& sName)
{
    NoStringVector vsDirs = GetDirs(pModule, true);
    NoString sFile = pModule->moduleName() + "_" + sName;
    for (const NoString& sDir : vsDirs) {
        if (NoFile::Exists(NoDir(sDir).filePath(sFile))) {
            m_template.appendPath(sDir);
            return sFile;
        }
    }
    return sName;
}

void NoWebSocket::SetPaths(NoModule* pModule, bool bIsTemplate)
{
    m_template.clearPaths();

    NoStringVector vsDirs = GetDirs(pModule, bIsTemplate);
    for (const NoString& sDir : vsDirs) {
        m_template.appendPath(sDir);
    }

    m_pathsSet = true;
}

void NoWebSocket::SetVars()
{
    m_template["SessionUser"] = user();
    m_template["SessionIP"] = GetRemoteIP();
    m_template["Tag"] = NoApp::GetTag(GetSession()->user() != nullptr, true);
    m_template["Version"] = NoApp::GetVersion();
    m_template["SkinName"] = GetSkinName();
    m_template["_CSRF_Check"] = GetCSRFCheck();
    m_template["URIPrefix"] = GetURIPrefix();

    if (GetSession()->isAdmin()) {
        m_template["IsAdmin"] = "true";
    }

    GetSession()->fillMessageLoops(m_template);
    GetSession()->clearMessageLoops();

    // Global Mods
    NoModuleLoader* vgMods = NoApp::Get().GetLoader();
    for (NoModule* pgMod : vgMods->modules()) {
        AddModLoop("GlobalModLoop", *pgMod);
    }

    // User Mods
    if (IsLoggedIn()) {
        NoModuleLoader* vMods = GetSession()->user()->loader();

        for (NoModule* pMod : vMods->modules()) {
            AddModLoop("UserModLoop", *pMod);
        }

        std::vector<NoNetwork*> vNetworks = GetSession()->user()->networks();
        for (NoNetwork* pNetwork : vNetworks) {
            NoModuleLoader* vnMods = pNetwork->loader();

            NoTemplate& Row = m_template.addRow("NetworkModLoop");
            Row["NetworkName"] = pNetwork->name();

            for (NoModule* pnMod : vnMods->modules()) {
                AddModLoop("ModLoop", *pnMod, &Row);
            }
        }
    }

    if (IsLoggedIn()) {
        m_template["LoggedIn"] = "true";
    }
}

bool NoWebSocket::AddModLoop(const NoString& sLoopName, NoModule& Module, NoTemplate* pTemplate)
{
    if (!pTemplate) {
        pTemplate = &m_template;
    }

    NoString sTitle(Module.webMenuTitle());

    if (!sTitle.empty() && (IsLoggedIn() || (!Module.webRequiresLogin() && !Module.webRequiresAdmin())) &&
        (GetSession()->isAdmin() || !Module.webRequiresAdmin())) {
        NoTemplate& Row = pTemplate->addRow(sLoopName);
        bool bActiveModule = false;

        Row["ModName"] = Module.moduleName();
        Row["ModPath"] = Module.webPath();
        Row["Title"] = sTitle;

        if (m_modName == Module.moduleName()) {
            NoString sModuleType = No::token(GetPath(), 1, "/");
            if (sModuleType == "global" && Module.type() == No::GlobalModule) {
                bActiveModule = true;
            } else if (sModuleType == "user" && Module.type() == No::UserModule) {
                bActiveModule = true;
            } else if (sModuleType == "network" && Module.type() == No::NetworkModule) {
                NoNetwork* Network = Module.network();
                if (Network) {
                    NoString sNetworkName = No::token(GetPath(), 2, "/");
                    if (sNetworkName == Network->name()) {
                        bActiveModule = true;
                    }
                } else {
                    bActiveModule = true;
                }
            }
        }

        if (bActiveModule) {
            Row["Active"] = "true";
        }

        if (Module.user()) {
            Row["Username"] = Module.user()->userName();
        }

        for (std::shared_ptr<NoWebPage>& SubPage : NoModulePrivate::get(&Module)->subPages) {
            // bActive is whether or not the current url matches this subpage (params will be checked below)
            bool bActive = (m_modName == Module.moduleName() && m_page == SubPage->name() && bActiveModule);

            if ((SubPage->flags() & NoWebPage::Admin) && !GetSession()->isAdmin()) {
                continue; // Don't add admin-only subpages to requests from non-admin users
            }

            NoTemplate& SubRow = Row.addRow("SubPageLoop");

            SubRow["ModName"] = Module.moduleName();
            SubRow["ModPath"] = Module.webPath();
            SubRow["PageName"] = SubPage->name();
            SubRow["Title"] = SubPage->title().empty() ? SubPage->name() : SubPage->title();

            NoString& sParams = SubRow["Params"];

            const NoStringPairVector& vParams = SubPage->params();
            for (const std::pair<NoString, NoString>& ssNV : vParams) {
                if (!sParams.empty()) {
                    sParams += "&";
                }

                if (!ssNV.first.empty()) {
                    if (!ssNV.second.empty()) {
                        sParams += No::escape(ssNV.first, No::UrlFormat);
                        sParams += "=";
                        sParams += No::escape(ssNV.second, No::UrlFormat);
                    }

                    if (bActive && GetParam(ssNV.first, false) != ssNV.second) {
                        bActive = false;
                    }
                }
            }

            if (bActive) {
                SubRow["Active"] = "true";
            }
        }

        return true;
    }

    return false;
}

NoWebSocket::PageRequest NoWebSocket::PrintStaticFile(const NoString& sPath, NoString& sPageRet, NoModule* pModule)
{
    SetPaths(pModule);
    NoString sFile = m_template.expandFile(sPath.trimLeft_n("/"));
    NO_DEBUG("About to print [" + sFile + "]");
    // Either PrintFile() fails and sends an error page or it suceeds and
    // sends a result. In both cases we don't have anything more to do.
    PrintFile(sFile);
    return Done;
}

NoWebSocket::PageRequest NoWebSocket::PrintTemplate(const NoString& sPageName, NoString& sPageRet, NoModule* pModule)
{
    SetVars();

    m_template["PageName"] = sPageName;

    if (pModule) {
        NoUser* pUser = pModule->user();
        m_template["ModUser"] = pUser ? pUser->userName() : "";
        m_template["ModName"] = pModule->moduleName();

        if (m_template.find("Title") == m_template.end()) {
            m_template["Title"] = pModule->webMenuTitle();
        }
    }

    if (!m_pathsSet) {
        SetPaths(pModule, true);
    }

    if (m_template.fileName().empty() && !m_template.setFile(sPageName + ".tmpl")) {
        return NotFound;
    }

    if (m_template.printString(sPageRet)) {
        return Print;
    } else {
        return NotFound;
    }
}

NoString NoWebSocket::GetSkinPath(const NoString& sSkinName)
{
    NoString sRet = NoApp::Get().GetZNCPath() + "/webskins/" + sSkinName;

    if (!NoFile(sRet).IsDir()) {
        sRet = NoApp::Get().GetCurPath() + "/webskins/" + sSkinName;

        if (!NoFile(sRet).IsDir()) {
            sRet = NoString(_SKINDIR_) + "/" + sSkinName;
        }
    }

    return sRet + "/";
}

bool NoWebSocket::ForceLogin()
{
    if (GetSession()->isLoggedIn()) {
        return true;
    }

    GetSession()->addError("You must login to view that page");
    Redirect("/");
    return false;
}

NoString NoWebSocket::GetRequestCookie(const NoString& sKey)
{
    const NoString sPrefixedKey = NoString(GetLocalPort()) + "-" + sKey;
    NoString sRet;

    if (!m_modName.empty()) {
        sRet = NoHttpSocket::GetRequestCookie("Mod-" + m_modName + "-" + sPrefixedKey);
    }

    if (sRet.empty()) {
        return NoHttpSocket::GetRequestCookie(sPrefixedKey);
    }

    return sRet;
}

bool NoWebSocket::SendCookie(const NoString& sKey, const NoString& sValue)
{
    const NoString sPrefixedKey = NoString(GetLocalPort()) + "-" + sKey;

    if (!m_modName.empty()) {
        return NoHttpSocket::SendCookie("Mod-" + m_modName + "-" + sPrefixedKey, sValue);
    }

    return NoHttpSocket::SendCookie(sPrefixedKey, sValue);
}

void NoWebSocket::OnPageRequest(const NoString& sURI)
{
    NoString sPageRet;
    PageRequest eRet = OnPageRequestInternal(sURI, sPageRet);
    switch (eRet) {
    case Print:
        PrintPage(sPageRet);
        break;
    case Deferred:
        // Something else will later call Close()
        break;
    case Done:
        // Redirect or something like that, it's done, just make sure
        // the connection will be closed
        Close(CLT_AFTERWRITE);
        break;
    case NotFound:
    default:
        PrintNotFound();
        break;
    }
}

NoWebSocket::PageRequest NoWebSocket::OnPageRequestInternal(const NoString& sURI, NoString& sPageRet)
{
    // Check that their session really belongs to their IP address. IP-based
    // authentication is bad, but here it's just an extra layer that makes
    // stealing cookies harder to pull off.
    //
    // When their IP is wrong, we give them an invalid cookie. This makes
    // sure that they will get a new cookie on their next request.
    if (NoApp::Get().GetProtectWebSessions() && GetSession()->host() != GetRemoteIP()) {
        NO_DEBUG("Expected IP: " << GetSession()->host());
        NO_DEBUG("Remote IP:   " << GetRemoteIP());
        SendCookie("SessionId", "WRONG_IP_FOR_SESSION");
        PrintErrorPage(403, "Access denied", "This session does not belong to your IP.");
        return Done;
    }

    // Check that they really POSTed from one our forms by checking if they
    // know the "secret" CSRF check value. Don't do this for login since
    // CSRF against the login form makes no sense and the login form does a
    // cookies-enabled check which would break otherwise.
    if (IsPost() && GetParam("_CSRF_Check") != GetCSRFCheck() && sURI != "/login") {
        NO_DEBUG("Expected _CSRF_Check: " << GetCSRFCheck());
        NO_DEBUG("Actual _CSRF_Check:   " << GetParam("_CSRF_Check"));
        PrintErrorPage(403,
                       "Access denied",
                       "POST requests need to send "
                       "a secret token to prevent cross-site request forgery attacks.");
        return Done;
    }

    SendCookie("SessionId", GetSession()->identifier());

    if (GetSession()->isLoggedIn()) {
        m_username = GetSession()->user()->userName();
        m_loggedIn = true;
    }

    // Handle the static pages that don't require a login
    if (sURI == "/") {
        if (!m_loggedIn && GetParam("cookie_check", false).toBool() && GetRequestCookie("SessionId").empty()) {
            GetSession()->addError("Your browser does not have cookies enabled for this site!");
        }
        return PrintTemplate("index", sPageRet);
    } else if (sURI == "/favicon.ico") {
        return PrintStaticFile("/pub/favicon.ico", sPageRet);
    } else if (sURI == "/robots.txt") {
        return PrintStaticFile("/pub/robots.txt", sPageRet);
    } else if (sURI == "/logout") {
        GetSession()->setUser(nullptr);
        SetLoggedIn(false);
        Redirect("/");

        // We already sent a reply
        return Done;
    } else if (sURI == "/login") {
        if (GetParam("submitted").toBool()) {
            m_username = GetParam("user");
            m_password = GetParam("pass");
            m_loggedIn = OnLogin(m_username, m_password, false);

            // AcceptedLogin()/RefusedLogin() will call Redirect()
            return Deferred;
        }

        Redirect("/"); // the login form is here
        return Done;
    } else if (sURI.left(5) == "/pub/") {
        return PrintStaticFile(sURI, sPageRet);
    } else if (sURI.left(11) == "/skinfiles/") {
        NoString sSkinName = sURI.substr(11);
        NoString::size_type uPathStart = sSkinName.find("/");
        if (uPathStart != NoString::npos) {
            NoString sFilePath = sSkinName.substr(uPathStart + 1);
            sSkinName.erase(uPathStart);

            m_template.clearPaths();
            m_template.appendPath(GetSkinPath(sSkinName) + "pub");

            if (PrintFile(m_template.expandFile(sFilePath))) {
                return Done;
            } else {
                return NotFound;
            }
        }
        return NotFound;
    } else if (sURI.left(6) == "/mods/" || sURI.left(10) == "/modfiles/") {
        // Make sure modules are treated as directories
        if (sURI.right(1) != "/" && !sURI.contains(".") && !sURI.trimLeft_n("/mods/").trimLeft_n("/").contains("/")) {
            Redirect(sURI + "/");
            return Done;
        }

        // The URI looks like:
        // /mods/[type]/([network]/)?[module][/page][?arg1=val1&arg2=val2...]

        m_path = GetPath().trimLeft_n("/");

        m_path.trimPrefix("mods/");
        m_path.trimPrefix("modfiles/");

        NoString sType = No::token(m_path, 0, "/");
        m_path = No::tokens(m_path, 1, "/");

        No::ModuleType eModType;
        if (sType.equals("global")) {
            eModType = No::GlobalModule;
        } else if (sType.equals("user")) {
            eModType = No::UserModule;
        } else if (sType.equals("network")) {
            eModType = No::NetworkModule;
        } else {
            PrintErrorPage(403, "Forbidden", "Unknown module type [" + sType + "]");
            return Done;
        }

        if ((eModType != No::GlobalModule) && !ForceLogin()) {
            // Make sure we have a valid user
            return Done;
        }

        NoNetwork* pNetwork = nullptr;
        if (eModType == No::NetworkModule) {
            NoString sNetwork = No::token(m_path, 0, "/");
            m_path = No::tokens(m_path, 1, "/");

            pNetwork = GetSession()->user()->findNetwork(sNetwork);

            if (!pNetwork) {
                PrintErrorPage(404, "Not Found", "Network [" + sNetwork + "] not found.");
                return Done;
            }
        }

        m_modName = No::token(m_path, 0, "/");
        m_page = No::tokens(m_path, 1, "/");

        if (m_page.empty()) {
            m_page = "index";
        }

        NO_DEBUG("Path [" + m_path + "], Module [" + m_modName + "], Page [" + m_page + "]");

        NoModule* pModule = nullptr;

        switch (eModType) {
        case No::GlobalModule:
            pModule = NoApp::Get().GetLoader()->findModule(m_modName);
            break;
        case No::UserModule:
            pModule = GetSession()->user()->loader()->findModule(m_modName);
            break;
        case No::NetworkModule:
            pModule = pNetwork->loader()->findModule(m_modName);
            break;
        }

        if (!pModule)
            return NotFound;

        m_template["ModPath"] = pModule->webPath();
        m_template["ModFilesPath"] = pModule->webFilesPath();

        if (pModule->webRequiresLogin() && !ForceLogin()) {
            return Print;
        } else if (pModule->webRequiresAdmin() && !GetSession()->isAdmin()) {
            PrintErrorPage(403, "Forbidden", "You need to be an admin to access this module");
            return Done;
        } else if (pModule->type() != No::GlobalModule && pModule->user() != GetSession()->user()) {
            PrintErrorPage(403,
                           "Forbidden",
                           "You must login as " + pModule->user()->userName() + " in order to view this page");
            return Done;
        } else if (pModule->onWebPreRequest(*this, m_page)) {
            return Deferred;
        }

        for (std::shared_ptr<NoWebPage>& SubPage : NoModulePrivate::get(pModule)->subPages) {
            bool bActive = (m_modName == pModule->moduleName() && m_page == SubPage->name());

            if (bActive && (SubPage->flags() & NoWebPage::Admin) && !GetSession()->isAdmin()) {
                PrintErrorPage(403, "Forbidden", "You need to be an admin to access this page");
                return Done;
            }
        }

        if (pModule && pModule->type() != No::GlobalModule && (!IsLoggedIn() || pModule->user() != GetSession()->user())) {
            AddModLoop("UserModLoop", *pModule);
        }

        if (sURI.left(10) == "/modfiles/") {
            m_template.appendPath(GetSkinPath(GetSkinName()) + "/mods/" + m_modName + "/files/");
            m_template.appendPath(pModule->moduleDataDir() + "/files/");

            if (PrintFile(m_template.expandFile(m_page.trimLeft_n("/")))) {
                return Print;
            } else {
                return NotFound;
            }
        } else {
            SetPaths(pModule, true);

            /* if a module returns false from OnWebRequest, it does not
               want the template to be printed, usually because it did a redirect. */
            if (pModule->onWebRequest(*this, m_page, m_template)) {
                // If they already sent a reply, let's assume
                // they did what they wanted to do.
                if (SentHeader()) {
                    return Done;
                }
                return PrintTemplate(m_page, sPageRet, pModule);
            }

            if (!SentHeader()) {
                PrintErrorPage(404, "Not Implemented", "The requested module does not acknowledge web requests");
            }
            return Done;
        }
    } else {
        NoString sPage(sURI.trim_n("/"));
        if (sPage.length() < 32) {
            for (uint a = 0; a < sPage.length(); a++) {
                uchar c = sPage[a];

                if ((c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '_') {
                    return NotFound;
                }
            }

            return PrintTemplate(sPage, sPageRet);
        }
    }

    return NotFound;
}

void NoWebSocket::PrintErrorPage(const NoString& sMessage)
{
    m_template.setFile("Error.tmpl");

    m_template["Action"] = "error";
    m_template["Title"] = "Error";
    m_template["Error"] = sMessage;
}

static inline bool compareLastActive(const std::pair<const NoString, NoWebSession*>& first,
                                     const std::pair<const NoString, NoWebSession*>& second)
{
    return first.second->lastActive() < second.second->lastActive();
}

std::shared_ptr<NoWebSession> NoWebSocket::GetSession()
{
    if (m_session) {
        return m_session;
    }

    const NoString sCookieSessionId = GetRequestCookie("SessionId");
    std::shared_ptr<NoWebSession>* pSession = Sessions.m_mspSessions.value(sCookieSessionId);

    if (pSession != nullptr) {
        // Refresh the timeout
        Sessions.m_mspSessions.insert((*pSession)->identifier(), *pSession);
        (*pSession)->updateLastActive();
        m_session = *pSession;
        NO_DEBUG("Found existing session from cookie: [" + sCookieSessionId + "] IsLoggedIn(" +
                 NoString((*pSession)->isLoggedIn() ? "true, " + ((*pSession)->user()->userName()) : "false") + ")");
        return *pSession;
    }

    if (Sessions.m_mIPSessions.count(GetRemoteIP()) > m_maxSessions) {
        std::pair<mIPSessionsIterator, mIPSessionsIterator> p = Sessions.m_mIPSessions.equal_range(GetRemoteIP());
        mIPSessionsIterator it = std::min_element(p.first, p.second, compareLastActive);
        NO_DEBUG("Remote IP:   " << GetRemoteIP() << "; discarding session [" << it->second->identifier() << "]");
        Sessions.m_mspSessions.remove(it->second->identifier());
    }

    NoString sSessionID;
    do {
        sSessionID = No::randomString(32);
        sSessionID += ":" + GetRemoteIP() + ":" + NoString(GetRemotePort());
        sSessionID += ":" + GetLocalIP() + ":" + NoString(GetLocalPort());
        sSessionID += ":" + NoString(time(nullptr));
        sSessionID = No::sha256(sSessionID);

        NO_DEBUG("Auto generated session: [" + sSessionID + "]");
    } while (Sessions.m_mspSessions.contains(sSessionID));

    std::shared_ptr<NoWebSession> spSession(new NoWebSession(sSessionID, GetRemoteIP()));
    Sessions.m_mspSessions.insert(spSession->identifier(), spSession);

    m_session = spSession;

    return spSession;
}

NoString NoWebSocket::GetCSRFCheck()
{
    std::shared_ptr<NoWebSession> pSession = GetSession();
    return No::md5(pSession->identifier());
}

bool NoWebSocket::OnLogin(const NoString& sUser, const NoString& sPass, bool bBasic)
{
    NO_DEBUG("=================== NoWebSocket::OnLogin(), basic auth? " << std::boolalpha << bBasic);
    m_authenticator = std::make_shared<NoWebAuth>(this, sUser, sPass, bBasic);

    // Some authentication module could need some time, block this socket
    // until then. CWebAuth will UnPauseRead().
    PauseRead();
    NoApp::Get().AuthUser(m_authenticator);

    // If CWebAuth already set this, don't change it.
    return IsLoggedIn();
}

NoSocket* NoWebSocket::GetSockObjImpl(const NoString& sHost, ushort uPort)
{
    // All listening is done by NoListener, thus NoWebSocket should never have
    // to listen, but since GetSockObj() is pure virtual...
    NO_DEBUG("NoWebSocket::GetSockObj() called - this should never happen!");
    return nullptr;
}

NoString NoWebSocket::GetSkinName()
{
    std::shared_ptr<NoWebSession> spSession = GetSession();

    if (spSession->isLoggedIn() && !spSession->user()->skinName().empty()) {
        return spSession->user()->skinName();
    }

    return NoApp::Get().GetSkinName();
}
