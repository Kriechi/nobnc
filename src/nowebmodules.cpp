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

#include "nowebmodules.h"
#include "nofile.h"
#include "nodir.h"
#include "nouser.h"
#include "nonetwork.h"
#include "noapp.h"
#include <algorithm>
#include <sstream>

using std::pair;
using std::vector;

/// @todo Do we want to make this a configure option?
#define _SKINDIR_ _DATADIR_ "/webskins"

const unsigned int NoWebSock::m_uiMaxSessions = 5;

// We need this class to make sure the contained maps and their content is
// destroyed in the order that we want.
struct CSessionManager
{
    // Sessions are valid for a day, (24h, ...)
    CSessionManager() : m_mspSessions(24 * 60 * 60 * 1000), m_mIPSessions() {}
    ~CSessionManager()
    {
        // Make sure all sessions are destroyed before any of our maps
        // are destroyed
        m_mspSessions.Clear();
    }

    NoWebSessionMap m_mspSessions;
    std::multimap<NoString, NoWebSession*> m_mIPSessions;
};
typedef std::multimap<NoString, NoWebSession*>::iterator mIPSessionsIterator;

static CSessionManager Sessions;

class NoWebAuth : public NoAuthBase
{
public:
    NoWebAuth(NoWebSock* pWebSock, const NoString& sUsername, const NoString& sPassword, bool bBasic);
    virtual ~NoWebAuth() {}

    NoWebAuth(const NoWebAuth&) = delete;
    NoWebAuth& operator=(const NoWebAuth&) = delete;

    void SetWebSock(NoWebSock* pWebSock) { m_pWebSock = pWebSock; }
    void AcceptedLogin(NoUser& User) override;
    void RefusedLogin(const NoString& sReason) override;
    void Invalidate() override;

private:
protected:
    NoWebSock* m_pWebSock;
    bool m_bBasic;
};

void NoWebSock::FinishUserSessions(const NoUser& User) { Sessions.m_mspSessions.FinishUserSessions(User); }

NoWebSession::~NoWebSession()
{
    // Find our entry in mIPSessions
    pair<mIPSessionsIterator, mIPSessionsIterator> p = Sessions.m_mIPSessions.equal_range(m_sIP);
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

NoTagHandler::NoTagHandler(NoWebSock& WebSock) : NoTemplateTagHandler(), m_WebSock(WebSock) {}

bool NoTagHandler::HandleTag(NoTemplate& Tmpl, const NoString& sName, const NoString& sArgs, NoString& sOutput)
{
    if (sName.Equals("URLPARAM")) {
        // sOutput = NoApp::Get()
        sOutput = m_WebSock.GetParam(sArgs.Token(0), false);
        return true;
    }

    return false;
}

NoWebSession::NoWebSession(const NoString& sId, const NoString& sIP)
    : m_sId(sId), m_sIP(sIP), m_pUser(nullptr), m_vsErrorMsgs(), m_vsSuccessMsgs(), m_tmLastActive()
{
    Sessions.m_mIPSessions.insert(make_pair(sIP, this));
    UpdateLastActive();
}

void NoWebSession::UpdateLastActive() { time(&m_tmLastActive); }

bool NoWebSession::IsAdmin() const { return IsLoggedIn() && m_pUser->IsAdmin(); }

NoWebAuth::NoWebAuth(NoWebSock* pWebSock, const NoString& sUsername, const NoString& sPassword, bool bBasic)
    : NoAuthBase(sUsername, sPassword, pWebSock), m_pWebSock(pWebSock), m_bBasic(bBasic)
{
}

void NoWebSession::ClearMessageLoops()
{
    m_vsErrorMsgs.clear();
    m_vsSuccessMsgs.clear();
}

void NoWebSession::FillMessageLoops(NoTemplate& Tmpl)
{
    for (const NoString& sMessage : m_vsErrorMsgs) {
        NoTemplate& Row = Tmpl.AddRow("ErrorLoop");
        Row["Message"] = sMessage;
    }

    for (const NoString& sMessage : m_vsSuccessMsgs) {
        NoTemplate& Row = Tmpl.AddRow("SuccessLoop");
        Row["Message"] = sMessage;
    }
}

size_t NoWebSession::AddError(const NoString& sMessage)
{
    m_vsErrorMsgs.push_back(sMessage);
    return m_vsErrorMsgs.size();
}

size_t NoWebSession::AddSuccess(const NoString& sMessage)
{
    m_vsSuccessMsgs.push_back(sMessage);
    return m_vsSuccessMsgs.size();
}

void NoWebSessionMap::FinishUserSessions(const NoUser& User)
{
    iterator it = m_mItems.begin();

    while (it != m_mItems.end()) {
        if (it->second.second->GetUser() == &User) {
            m_mItems.erase(it++);
        } else {
            ++it;
        }
    }
}

void NoWebAuth::AcceptedLogin(NoUser& User)
{
    if (m_pWebSock) {
        std::shared_ptr<NoWebSession> spSession = m_pWebSock->GetSession();

        spSession->SetUser(&User);

        m_pWebSock->SetLoggedIn(true);
        m_pWebSock->UnPauseRead();
        if (!m_bBasic) {
            m_pWebSock->Redirect("/?cookie_check=true");
        }

        DEBUG("Successful login attempt ==> USER [" + User.GetUserName() + "] ==> SESSION [" + spSession->GetId() + "]");
    }
}

void NoWebAuth::RefusedLogin(const NoString& sReason)
{
    if (m_pWebSock) {
        std::shared_ptr<NoWebSession> spSession = m_pWebSock->GetSession();

        spSession->AddError("Invalid login!");
        spSession->SetUser(nullptr);

        m_pWebSock->SetLoggedIn(false);
        m_pWebSock->UnPauseRead();
        m_pWebSock->Redirect("/?cookie_check=true");

        DEBUG("UNSUCCESSFUL login attempt ==> REASON [" + sReason + "] ==> SESSION [" + spSession->GetId() + "]");
    }
}

void NoWebAuth::Invalidate()
{
    NoAuthBase::Invalidate();
    m_pWebSock = nullptr;
}

NoWebSock::NoWebSock(const NoString& sURIPrefix)
    : NoHttpSock(nullptr, sURIPrefix), m_bPathsSet(false), m_Template(), m_spAuth(), m_sModName(""), m_sPath(""),
      m_sPage(""), m_spSession()
{
    m_Template.AddTagHandler(std::make_shared<NoTagHandler>(*this));
}

NoWebSock::~NoWebSock()
{
    if (m_spAuth) {
        m_spAuth->Invalidate();
    }

    // we have to account for traffic here because NoSocket does
    // not have a valid NoModule* pointer.
    NoUser* pUser = GetSession()->GetUser();
    if (pUser) {
        pUser->AddBytesWritten(GetBytesWritten());
        pUser->AddBytesRead(GetBytesRead());
    } else {
        NoApp::Get().AddBytesWritten(GetBytesWritten());
        NoApp::Get().AddBytesRead(GetBytesRead());
    }

    // bytes have been accounted for, so make sure they don't get again:
    ResetBytesWritten();
    ResetBytesRead();
}

void NoWebSock::GetAvailSkins(NoStringVector& vRet) const
{
    vRet.clear();

    NoString sRoot(GetSkinPath("_default_"));

    sRoot.TrimRight("/");
    sRoot.TrimRight("_default_");
    sRoot.TrimRight("/");

    if (!sRoot.empty()) {
        sRoot += "/";
    }

    if (!sRoot.empty() && NoFile::IsDir(sRoot)) {
        NoDir Dir(sRoot);

        for (const NoFile* pSubDir : Dir) {
            if (pSubDir->IsDir() && pSubDir->GetShortName() == "_default_") {
                vRet.push_back(pSubDir->GetShortName());
                break;
            }
        }

        for (const NoFile* pSubDir : Dir) {
            if (pSubDir->IsDir() && pSubDir->GetShortName() != "_default_" && pSubDir->GetShortName() != ".svn") {
                vRet.push_back(pSubDir->GetShortName());
            }
        }
    }
}

NoStringVector NoWebSock::GetDirs(NoModule* pModule, bool bIsTemplate)
{
    NoString sHomeSkinsDir(NoApp::Get().GetZNCPath() + "/webskins/");
    NoString sSkinName(GetSkinName());
    NoStringVector vsResult;

    // Module specific paths

    if (pModule) {
        const NoString& sModName(pModule->GetModName());

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
        vsResult.push_back(pModule->GetModDataDir() + "/tmpl/");

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

NoString NoWebSock::FindTmpl(NoModule* pModule, const NoString& sName)
{
    NoStringVector vsDirs = GetDirs(pModule, true);
    NoString sFile = pModule->GetModName() + "_" + sName;
    for (const NoString& sDir : vsDirs) {
        if (NoFile::Exists(NoDir::ChangeDir(sDir, sFile))) {
            m_Template.AppendPath(sDir);
            return sFile;
        }
    }
    return sName;
}

void NoWebSock::SetPaths(NoModule* pModule, bool bIsTemplate)
{
    m_Template.ClearPaths();

    NoStringVector vsDirs = GetDirs(pModule, bIsTemplate);
    for (const NoString& sDir : vsDirs) {
        m_Template.AppendPath(sDir);
    }

    m_bPathsSet = true;
}

void NoWebSock::SetVars()
{
    m_Template["SessionUser"] = GetUser();
    m_Template["SessionIP"] = GetRemoteIP();
    m_Template["Tag"] = NoApp::GetTag(GetSession()->GetUser() != nullptr, true);
    m_Template["Version"] = NoApp::GetVersion();
    m_Template["SkinName"] = GetSkinName();
    m_Template["_CSRF_Check"] = GetCSRFCheck();
    m_Template["URIPrefix"] = GetURIPrefix();

    if (GetSession()->IsAdmin()) {
        m_Template["IsAdmin"] = "true";
    }

    GetSession()->FillMessageLoops(m_Template);
    GetSession()->ClearMessageLoops();

    // Global Mods
    NoModules& vgMods = NoApp::Get().GetModules();
    for (NoModule* pgMod : vgMods) {
        AddModLoop("GlobalModLoop", *pgMod);
    }

    // User Mods
    if (IsLoggedIn()) {
        NoModules& vMods = GetSession()->GetUser()->GetModules();

        for (NoModule* pMod : vMods) {
            AddModLoop("UserModLoop", *pMod);
        }

        vector<NoNetwork*> vNetworks = GetSession()->GetUser()->GetNetworks();
        for (NoNetwork* pNetwork : vNetworks) {
            NoModules& vnMods = pNetwork->GetModules();

            NoTemplate& Row = m_Template.AddRow("NetworkModLoop");
            Row["NetworkName"] = pNetwork->GetName();

            for (NoModule* pnMod : vnMods) {
                AddModLoop("ModLoop", *pnMod, &Row);
            }
        }
    }

    if (IsLoggedIn()) {
        m_Template["LoggedIn"] = "true";
    }
}

bool NoWebSock::AddModLoop(const NoString& sLoopName, NoModule& Module, NoTemplate* pTemplate)
{
    if (!pTemplate) {
        pTemplate = &m_Template;
    }

    NoString sTitle(Module.GetWebMenuTitle());

    if (!sTitle.empty() && (IsLoggedIn() || (!Module.WebRequiresLogin() && !Module.WebRequiresAdmin())) &&
        (GetSession()->IsAdmin() || !Module.WebRequiresAdmin())) {
        NoTemplate& Row = pTemplate->AddRow(sLoopName);
        bool bActiveModule = false;

        Row["ModName"] = Module.GetModName();
        Row["ModPath"] = Module.GetWebPath();
        Row["Title"] = sTitle;

        if (m_sModName == Module.GetModName()) {
            NoString sModuleType = GetPath().Token(1, false, "/");
            if (sModuleType == "global" && Module.GetType() == NoModInfo::GlobalModule) {
                bActiveModule = true;
            } else if (sModuleType == "user" && Module.GetType() == NoModInfo::UserModule) {
                bActiveModule = true;
            } else if (sModuleType == "network" && Module.GetType() == NoModInfo::NetworkModule) {
                NoNetwork* Network = Module.GetNetwork();
                if (Network) {
                    NoString sNetworkName = GetPath().Token(2, false, "/");
                    if (sNetworkName == Network->GetName()) {
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

        if (Module.GetUser()) {
            Row["Username"] = Module.GetUser()->GetUserName();
        }

        VWebSubPages& vSubPages = Module.GetSubPages();

        for (TWebSubPage& SubPage : vSubPages) {
            // bActive is whether or not the current url matches this subpage (params will be checked below)
            bool bActive = (m_sModName == Module.GetModName() && m_sPage == SubPage->GetName() && bActiveModule);

            if (SubPage->RequiresAdmin() && !GetSession()->IsAdmin()) {
                continue; // Don't add admin-only subpages to requests from non-admin users
            }

            NoTemplate& SubRow = Row.AddRow("SubPageLoop");

            SubRow["ModName"] = Module.GetModName();
            SubRow["ModPath"] = Module.GetWebPath();
            SubRow["PageName"] = SubPage->GetName();
            SubRow["Title"] = SubPage->GetTitle().empty() ? SubPage->GetName() : SubPage->GetTitle();

            NoString& sParams = SubRow["Params"];

            const NoStringPairVector& vParams = SubPage->GetParams();
            for (const pair<NoString, NoString>& ssNV : vParams) {
                if (!sParams.empty()) {
                    sParams += "&";
                }

                if (!ssNV.first.empty()) {
                    if (!ssNV.second.empty()) {
                        sParams += ssNV.first.Escape_n(NoString::EURL);
                        sParams += "=";
                        sParams += ssNV.second.Escape_n(NoString::EURL);
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

NoWebSock::EPageReqResult NoWebSock::PrintStaticFile(const NoString& sPath, NoString& sPageRet, NoModule* pModule)
{
    SetPaths(pModule);
    NoString sFile = m_Template.ExpandFile(sPath.TrimLeft_n("/"));
    DEBUG("About to print [" + sFile + "]");
    // Either PrintFile() fails and sends an error page or it suceeds and
    // sends a result. In both cases we don't have anything more to do.
    PrintFile(sFile);
    return PAGE_DONE;
}

NoWebSock::EPageReqResult NoWebSock::PrintTemplate(const NoString& sPageName, NoString& sPageRet, NoModule* pModule)
{
    SetVars();

    m_Template["PageName"] = sPageName;

    if (pModule) {
        NoUser* pUser = pModule->GetUser();
        m_Template["ModUser"] = pUser ? pUser->GetUserName() : "";
        m_Template["ModName"] = pModule->GetModName();

        if (m_Template.find("Title") == m_Template.end()) {
            m_Template["Title"] = pModule->GetWebMenuTitle();
        }
    }

    if (!m_bPathsSet) {
        SetPaths(pModule, true);
    }

    if (m_Template.GetFileName().empty() && !m_Template.SetFile(sPageName + ".tmpl")) {
        return PAGE_NOTFOUND;
    }

    if (m_Template.PrintString(sPageRet)) {
        return PAGE_PRINT;
    } else {
        return PAGE_NOTFOUND;
    }
}

NoString NoWebSock::GetSkinPath(const NoString& sSkinName)
{
    NoString sRet = NoApp::Get().GetZNCPath() + "/webskins/" + sSkinName;

    if (!NoFile::IsDir(sRet)) {
        sRet = NoApp::Get().GetCurPath() + "/webskins/" + sSkinName;

        if (!NoFile::IsDir(sRet)) {
            sRet = NoString(_SKINDIR_) + "/" + sSkinName;
        }
    }

    return sRet + "/";
}

bool NoWebSock::ForceLogin()
{
    if (GetSession()->IsLoggedIn()) {
        return true;
    }

    GetSession()->AddError("You must login to view that page");
    Redirect("/");
    return false;
}

NoString NoWebSock::GetRequestCookie(const NoString& sKey)
{
    const NoString sPrefixedKey = NoString(GetLocalPort()) + "-" + sKey;
    NoString sRet;

    if (!m_sModName.empty()) {
        sRet = NoHttpSock::GetRequestCookie("Mod-" + m_sModName + "-" + sPrefixedKey);
    }

    if (sRet.empty()) {
        return NoHttpSock::GetRequestCookie(sPrefixedKey);
    }

    return sRet;
}

bool NoWebSock::SendCookie(const NoString& sKey, const NoString& sValue)
{
    const NoString sPrefixedKey = NoString(GetLocalPort()) + "-" + sKey;

    if (!m_sModName.empty()) {
        return NoHttpSock::SendCookie("Mod-" + m_sModName + "-" + sPrefixedKey, sValue);
    }

    return NoHttpSock::SendCookie(sPrefixedKey, sValue);
}

void NoWebSock::OnPageRequest(const NoString& sURI)
{
    NoString sPageRet;
    EPageReqResult eRet = OnPageRequestInternal(sURI, sPageRet);
    switch (eRet) {
    case PAGE_PRINT:
        PrintPage(sPageRet);
        break;
    case PAGE_DEFERRED:
        // Something else will later call Close()
        break;
    case PAGE_DONE:
        // Redirect or something like that, it's done, just make sure
        // the connection will be closed
        Close(CLT_AFTERWRITE);
        break;
    case PAGE_NOTFOUND:
    default:
        PrintNotFound();
        break;
    }
}

NoWebSock::EPageReqResult NoWebSock::OnPageRequestInternal(const NoString& sURI, NoString& sPageRet)
{
    // Check that their session really belongs to their IP address. IP-based
    // authentication is bad, but here it's just an extra layer that makes
    // stealing cookies harder to pull off.
    //
    // When their IP is wrong, we give them an invalid cookie. This makes
    // sure that they will get a new cookie on their next request.
    if (NoApp::Get().GetProtectWebSessions() && GetSession()->GetIP() != GetRemoteIP()) {
        DEBUG("Expected IP: " << GetSession()->GetIP());
        DEBUG("Remote IP:   " << GetRemoteIP());
        SendCookie("SessionId", "WRONG_IP_FOR_SESSION");
        PrintErrorPage(403, "Access denied", "This session does not belong to your IP.");
        return PAGE_DONE;
    }

    // Check that they really POSTed from one our forms by checking if they
    // know the "secret" CSRF check value. Don't do this for login since
    // CSRF against the login form makes no sense and the login form does a
    // cookies-enabled check which would break otherwise.
    if (IsPost() && GetParam("_CSRF_Check") != GetCSRFCheck() && sURI != "/login") {
        DEBUG("Expected _CSRF_Check: " << GetCSRFCheck());
        DEBUG("Actual _CSRF_Check:   " << GetParam("_CSRF_Check"));
        PrintErrorPage(403,
                       "Access denied",
                       "POST requests need to send "
                       "a secret token to prevent cross-site request forgery attacks.");
        return PAGE_DONE;
    }

    SendCookie("SessionId", GetSession()->GetId());

    if (GetSession()->IsLoggedIn()) {
        m_sUser = GetSession()->GetUser()->GetUserName();
        m_bLoggedIn = true;
    }

    // Handle the static pages that don't require a login
    if (sURI == "/") {
        if (!m_bLoggedIn && GetParam("cookie_check", false).ToBool() && GetRequestCookie("SessionId").empty()) {
            GetSession()->AddError("Your browser does not have cookies enabled for this site!");
        }
        return PrintTemplate("index", sPageRet);
    } else if (sURI == "/favicon.ico") {
        return PrintStaticFile("/pub/favicon.ico", sPageRet);
    } else if (sURI == "/robots.txt") {
        return PrintStaticFile("/pub/robots.txt", sPageRet);
    } else if (sURI == "/logout") {
        GetSession()->SetUser(nullptr);
        SetLoggedIn(false);
        Redirect("/");

        // We already sent a reply
        return PAGE_DONE;
    } else if (sURI == "/login") {
        if (GetParam("submitted").ToBool()) {
            m_sUser = GetParam("user");
            m_sPass = GetParam("pass");
            m_bLoggedIn = OnLogin(m_sUser, m_sPass, false);

            // AcceptedLogin()/RefusedLogin() will call Redirect()
            return PAGE_DEFERRED;
        }

        Redirect("/"); // the login form is here
        return PAGE_DONE;
    } else if (sURI.Left(5) == "/pub/") {
        return PrintStaticFile(sURI, sPageRet);
    } else if (sURI.Left(11) == "/skinfiles/") {
        NoString sSkinName = sURI.substr(11);
        NoString::size_type uPathStart = sSkinName.find("/");
        if (uPathStart != NoString::npos) {
            NoString sFilePath = sSkinName.substr(uPathStart + 1);
            sSkinName.erase(uPathStart);

            m_Template.ClearPaths();
            m_Template.AppendPath(GetSkinPath(sSkinName) + "pub");

            if (PrintFile(m_Template.ExpandFile(sFilePath))) {
                return PAGE_DONE;
            } else {
                return PAGE_NOTFOUND;
            }
        }
        return PAGE_NOTFOUND;
    } else if (sURI.Left(6) == "/mods/" || sURI.Left(10) == "/modfiles/") {
        // Make sure modules are treated as directories
        if (sURI.Right(1) != "/" && sURI.find(".") == NoString::npos &&
            sURI.TrimLeft_n("/mods/").TrimLeft_n("/").find("/") == NoString::npos) {
            Redirect(sURI + "/");
            return PAGE_DONE;
        }

        // The URI looks like:
        // /mods/[type]/([network]/)?[module][/page][?arg1=val1&arg2=val2...]

        m_sPath = GetPath().TrimLeft_n("/");

        m_sPath.TrimPrefix("mods/");
        m_sPath.TrimPrefix("modfiles/");

        NoString sType = m_sPath.Token(0, false, "/");
        m_sPath = m_sPath.Token(1, true, "/");

        NoModInfo::EModuleType eModType;
        if (sType.Equals("global")) {
            eModType = NoModInfo::GlobalModule;
        } else if (sType.Equals("user")) {
            eModType = NoModInfo::UserModule;
        } else if (sType.Equals("network")) {
            eModType = NoModInfo::NetworkModule;
        } else {
            PrintErrorPage(403, "Forbidden", "Unknown module type [" + sType + "]");
            return PAGE_DONE;
        }

        if ((eModType != NoModInfo::GlobalModule) && !ForceLogin()) {
            // Make sure we have a valid user
            return PAGE_DONE;
        }

        NoNetwork* pNetwork = nullptr;
        if (eModType == NoModInfo::NetworkModule) {
            NoString sNetwork = m_sPath.Token(0, false, "/");
            m_sPath = m_sPath.Token(1, true, "/");

            pNetwork = GetSession()->GetUser()->FindNetwork(sNetwork);

            if (!pNetwork) {
                PrintErrorPage(404, "Not Found", "Network [" + sNetwork + "] not found.");
                return PAGE_DONE;
            }
        }

        m_sModName = m_sPath.Token(0, false, "/");
        m_sPage = m_sPath.Token(1, true, "/");

        if (m_sPage.empty()) {
            m_sPage = "index";
        }

        DEBUG("Path [" + m_sPath + "], Module [" + m_sModName + "], Page [" + m_sPage + "]");

        NoModule* pModule = nullptr;

        switch (eModType) {
        case NoModInfo::GlobalModule:
            pModule = NoApp::Get().GetModules().FindModule(m_sModName);
            break;
        case NoModInfo::UserModule:
            pModule = GetSession()->GetUser()->GetModules().FindModule(m_sModName);
            break;
        case NoModInfo::NetworkModule:
            pModule = pNetwork->GetModules().FindModule(m_sModName);
            break;
        }

        if (!pModule) return PAGE_NOTFOUND;

        m_Template["ModPath"] = pModule->GetWebPath();
        m_Template["ModFilesPath"] = pModule->GetWebFilesPath();

        if (pModule->WebRequiresLogin() && !ForceLogin()) {
            return PAGE_PRINT;
        } else if (pModule->WebRequiresAdmin() && !GetSession()->IsAdmin()) {
            PrintErrorPage(403, "Forbidden", "You need to be an admin to access this module");
            return PAGE_DONE;
        } else if (pModule->GetType() != NoModInfo::GlobalModule && pModule->GetUser() != GetSession()->GetUser()) {
            PrintErrorPage(403,
                           "Forbidden",
                           "You must login as " + pModule->GetUser()->GetUserName() + " in order to view this page");
            return PAGE_DONE;
        } else if (pModule->OnWebPreRequest(*this, m_sPage)) {
            return PAGE_DEFERRED;
        }

        VWebSubPages& vSubPages = pModule->GetSubPages();

        for (TWebSubPage& SubPage : vSubPages) {
            bool bActive = (m_sModName == pModule->GetModName() && m_sPage == SubPage->GetName());

            if (bActive && SubPage->RequiresAdmin() && !GetSession()->IsAdmin()) {
                PrintErrorPage(403, "Forbidden", "You need to be an admin to access this page");
                return PAGE_DONE;
            }
        }

        if (pModule && pModule->GetType() != NoModInfo::GlobalModule &&
            (!IsLoggedIn() || pModule->GetUser() != GetSession()->GetUser())) {
            AddModLoop("UserModLoop", *pModule);
        }

        if (sURI.Left(10) == "/modfiles/") {
            m_Template.AppendPath(GetSkinPath(GetSkinName()) + "/mods/" + m_sModName + "/files/");
            m_Template.AppendPath(pModule->GetModDataDir() + "/files/");

            if (PrintFile(m_Template.ExpandFile(m_sPage.TrimLeft_n("/")))) {
                return PAGE_PRINT;
            } else {
                return PAGE_NOTFOUND;
            }
        } else {
            SetPaths(pModule, true);

            /* if a module returns false from OnWebRequest, it does not
               want the template to be printed, usually because it did a redirect. */
            if (pModule->OnWebRequest(*this, m_sPage, m_Template)) {
                // If they already sent a reply, let's assume
                // they did what they wanted to do.
                if (SentHeader()) {
                    return PAGE_DONE;
                }
                return PrintTemplate(m_sPage, sPageRet, pModule);
            }

            if (!SentHeader()) {
                PrintErrorPage(404, "Not Implemented", "The requested module does not acknowledge web requests");
            }
            return PAGE_DONE;
        }
    } else {
        NoString sPage(sURI.Trim_n("/"));
        if (sPage.length() < 32) {
            for (unsigned int a = 0; a < sPage.length(); a++) {
                unsigned char c = sPage[a];

                if ((c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '_') {
                    return PAGE_NOTFOUND;
                }
            }

            return PrintTemplate(sPage, sPageRet);
        }
    }

    return PAGE_NOTFOUND;
}

void NoWebSock::PrintErrorPage(const NoString& sMessage)
{
    m_Template.SetFile("Error.tmpl");

    m_Template["Action"] = "error";
    m_Template["Title"] = "Error";
    m_Template["Error"] = sMessage;
}

static inline bool compareLastActive(const std::pair<const NoString, NoWebSession*>& first,
                                     const std::pair<const NoString, NoWebSession*>& second)
{
    return first.second->GetLastActive() < second.second->GetLastActive();
}

std::shared_ptr<NoWebSession> NoWebSock::GetSession()
{
    if (m_spSession) {
        return m_spSession;
    }

    const NoString sCookieSessionId = GetRequestCookie("SessionId");
    std::shared_ptr<NoWebSession>* pSession = Sessions.m_mspSessions.GetItem(sCookieSessionId);

    if (pSession != nullptr) {
        // Refresh the timeout
        Sessions.m_mspSessions.AddItem((*pSession)->GetId(), *pSession);
        (*pSession)->UpdateLastActive();
        m_spSession = *pSession;
        DEBUG("Found existing session from cookie: [" + sCookieSessionId + "] IsLoggedIn(" +
              NoString((*pSession)->IsLoggedIn() ? "true, " + ((*pSession)->GetUser()->GetUserName()) : "false") + ")");
        return *pSession;
    }

    if (Sessions.m_mIPSessions.count(GetRemoteIP()) > m_uiMaxSessions) {
        pair<mIPSessionsIterator, mIPSessionsIterator> p = Sessions.m_mIPSessions.equal_range(GetRemoteIP());
        mIPSessionsIterator it = std::min_element(p.first, p.second, compareLastActive);
        DEBUG("Remote IP:   " << GetRemoteIP() << "; discarding session [" << it->second->GetId() << "]");
        Sessions.m_mspSessions.RemItem(it->second->GetId());
    }

    NoString sSessionID;
    do {
        sSessionID = NoString::RandomString(32);
        sSessionID += ":" + GetRemoteIP() + ":" + NoString(GetRemotePort());
        sSessionID += ":" + GetLocalIP() + ":" + NoString(GetLocalPort());
        sSessionID += ":" + NoString(time(nullptr));
        sSessionID = sSessionID.SHA256();

        DEBUG("Auto generated session: [" + sSessionID + "]");
    } while (Sessions.m_mspSessions.HasItem(sSessionID));

    std::shared_ptr<NoWebSession> spSession(new NoWebSession(sSessionID, GetRemoteIP()));
    Sessions.m_mspSessions.AddItem(spSession->GetId(), spSession);

    m_spSession = spSession;

    return spSession;
}

NoString NoWebSock::GetCSRFCheck()
{
    std::shared_ptr<NoWebSession> pSession = GetSession();
    return pSession->GetId().MD5();
}

bool NoWebSock::OnLogin(const NoString& sUser, const NoString& sPass, bool bBasic)
{
    DEBUG("=================== NoWebSock::OnLogin(), basic auth? " << std::boolalpha << bBasic);
    m_spAuth = std::make_shared<NoWebAuth>(this, sUser, sPass, bBasic);

    // Some authentication module could need some time, block this socket
    // until then. CWebAuth will UnPauseRead().
    PauseRead();
    NoApp::Get().AuthUser(m_spAuth);

    // If CWebAuth already set this, don't change it.
    return IsLoggedIn();
}

Csock* NoWebSock::GetSockObj(const NoString& sHost, unsigned short uPort)
{
    // All listening is done by NoListener, thus NoWebSock should never have
    // to listen, but since GetSockObj() is pure virtual...
    DEBUG("NoWebSock::GetSockObj() called - this should never happen!");
    return nullptr;
}

NoString NoWebSock::GetSkinName()
{
    std::shared_ptr<NoWebSession> spSession = GetSession();

    if (spSession->IsLoggedIn() && !spSession->GetUser()->GetSkinName().empty()) {
        return spSession->GetUser()->GetSkinName();
    }

    return NoApp::Get().GetSkinName();
}
