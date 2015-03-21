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

#include <no/nomodule.h>
#include <no/nomodules.h>
#include <no/nochannel.h>
#include <no/noserver.h>
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/noircconnection.h>
#include <no/nodebug.h>
#include <no/noapp.h>
#include <no/nowebsocket.h>
#include <no/nowebsession.h>
#include <no/noescape.h>
#include <no/nolistener.h>

/* Stuff to be able to write this:
   // i will be name of local variable, see below
   // pUser can be nullptr if only global modules are needed
   FOR_EACH_MODULE(i, pUser) {
       // i is local variable of type NoModules::iterator,
       // so *i has type NoModule*
   }
*/
struct FOR_EACH_MODULE_Type
{
    enum {
        AtGlobal,
        AtUser,
        AtNetwork,
    } where;
    NoModules CMtemp;
    NoModules& CMuser;
    NoModules& CMnet;
    FOR_EACH_MODULE_Type(NoUser* pUser) : CMuser(pUser ? pUser->GetModules() : CMtemp), CMnet(CMtemp)
    {
        where = AtGlobal;
    }
    FOR_EACH_MODULE_Type(NoNetwork* pNetwork)
        : CMuser(pNetwork ? pNetwork->GetUser()->GetModules() : CMtemp), CMnet(pNetwork ? pNetwork->GetModules() : CMtemp)
    {
        where = AtGlobal;
    }
    FOR_EACH_MODULE_Type(std::pair<NoUser*, NoNetwork*> arg)
        : CMuser(arg.first ? arg.first->GetModules() : CMtemp), CMnet(arg.second ? arg.second->GetModules() : CMtemp)
    {
        where = AtGlobal;
    }
    operator bool() { return false; }
};

inline bool FOR_EACH_MODULE_CanContinue(FOR_EACH_MODULE_Type& state, NoModules::iterator& i)
{
    if (state.where == FOR_EACH_MODULE_Type::AtGlobal && i == NoApp::Get().GetModules().end()) {
        i = state.CMuser.begin();
        state.where = FOR_EACH_MODULE_Type::AtUser;
    }
    if (state.where == FOR_EACH_MODULE_Type::AtUser && i == state.CMuser.end()) {
        i = state.CMnet.begin();
        state.where = FOR_EACH_MODULE_Type::AtNetwork;
    }
    return !(state.where == FOR_EACH_MODULE_Type::AtNetwork && i == state.CMnet.end());
}

#define FOR_EACH_MODULE(I, pUserOrNetwork)                           \
    if (FOR_EACH_MODULE_Type FOR_EACH_MODULE_Var = pUserOrNetwork) { \
    } else                                                           \
        for (NoModules::iterator I = NoApp::Get().GetModules().begin(); FOR_EACH_MODULE_CanContinue(FOR_EACH_MODULE_Var, I); ++I)

class NoWebAdminMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoWebAdminMod)
    {
        NoStringPairVector vParams;
        vParams.push_back(std::make_pair("user", ""));
        AddSubPage(std::make_shared<NoWebPage>("settings", "Global Settings", NoWebPage::Admin));
        AddSubPage(std::make_shared<NoWebPage>("edituser", "Your Settings", vParams));
        AddSubPage(std::make_shared<NoWebPage>("traffic", "Traffic Info", NoWebPage::Admin));
        AddSubPage(std::make_shared<NoWebPage>("listusers", "Manage Users", NoWebPage::Admin));
    }

    bool OnLoad(const NoString& sArgStr, NoString& sMessage) override
    {
        if (sArgStr.empty() || No::GlobalModule != GetType()) return true;

        // We don't accept any arguments, but for backwards
        // compatibility we have to do some magic here.
        sMessage = "Arguments converted to new syntax";

        bool bSSL = false;
        bool bIPv6 = false;
        bool bShareIRCPorts = true;
        ushort uPort = 8080;
        NoString sArgs(sArgStr);
        NoString sPort;
        NoString sListenHost;
        NoString sURIPrefix;

        while (sArgs.left(1) == "-") {
            NoString sOpt = No::token(sArgs, 0);
            sArgs = No::tokens(sArgs, 1);

            if (sOpt.equals("-IPV6")) {
                bIPv6 = true;
            } else if (sOpt.equals("-IPV4")) {
                bIPv6 = false;
            } else if (sOpt.equals("-noircport")) {
                bShareIRCPorts = false;
            } else {
                // Uhm... Unknown option? Let's just ignore all
                // arguments, older versions would have returned
                // an error and denied loading
                return true;
            }
        }

        // No arguments left: Only port sharing
        if (sArgs.empty() && bShareIRCPorts) return true;

        if (sArgs.find(" ") != NoString::npos) {
            sListenHost = No::token(sArgs, 0);
            sPort = No::tokens(sArgs, 1);
        } else {
            sPort = sArgs;
        }

        if (sPort.left(1) == "+") {
            sPort.trimLeft("+");
            bSSL = true;
        }

        if (!sPort.empty()) {
            uPort = sPort.toUShort();
        }

        if (!bShareIRCPorts) {
            // Make all existing listeners IRC-only
            const std::vector<NoListener*>& vListeners = NoApp::Get().GetListeners();
            std::vector<NoListener*>::const_iterator it;
            for (it = vListeners.begin(); it != vListeners.end(); ++it) {
                (*it)->setAcceptType(No::AcceptIrc);
            }
        }

        // Now turn that into a listener instance
        NoListener* pListener = new NoListener(uPort, sListenHost);
        pListener->setUriPrefix(sURIPrefix);
        pListener->setSsl(bSSL);
        pListener->setAddressType(!bIPv6 ? No::Ipv4Address : No::Ipv4AndIpv6Address);
        pListener->setAcceptType(No::AcceptHttp);

        if (!pListener->listen()) {
            sMessage = "Failed to add backwards-compatible listener";
            return false;
        }
        NoApp::Get().AddListener(pListener);

        SetArgs("");
        return true;
    }

    NoUser* GetNewUser(NoWebSocket& WebSock, NoUser* pUser)
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.GetSession();
        NoString sUsername = WebSock.GetParam("newuser");

        if (sUsername.empty()) {
            sUsername = WebSock.GetParam("user");
        }

        if (sUsername.empty()) {
            WebSock.PrintErrorPage("Invalid Submission [Username is required]");
            return nullptr;
        }

        if (pUser) {
            /* If we are editing a user we must not change the user name */
            sUsername = pUser->GetUserName();
        }

        NoString sArg = WebSock.GetParam("password");

        if (sArg != WebSock.GetParam("password2")) {
            WebSock.PrintErrorPage("Invalid Submission [Passwords do not match]");
            return nullptr;
        }

        NoUser* pNewUser = new NoUser(sUsername);

        if (!sArg.empty()) {
            NoString sSalt = No::salt();
            NoString sHash = NoUser::SaltedHash(sArg, sSalt);
            pNewUser->SetPass(sHash, NoUser::HASH_DEFAULT, sSalt);
        }

        NoStringVector vsArgs = WebSock.GetRawParam("allowedips").split("\n");
        uint a = 0;

        if (vsArgs.size()) {
            for (a = 0; a < vsArgs.size(); a++) {
                pNewUser->AddAllowedHost(vsArgs[a].trim_n());
            }
        } else {
            pNewUser->AddAllowedHost("*");
        }

        vsArgs = WebSock.GetRawParam("ctcpreplies").split("\n");
        for (a = 0; a < vsArgs.size(); a++) {
            NoString sReply = vsArgs[a].trimRight_n("\r");
            pNewUser->AddCTCPReply(No::token(sReply, 0).trim_n(), No::tokens(sReply, 1).trim_n());
        }

        sArg = WebSock.GetParam("nick");
        if (!sArg.empty()) {
            pNewUser->SetNick(sArg);
        }
        sArg = WebSock.GetParam("altnick");
        if (!sArg.empty()) {
            pNewUser->SetAltNick(sArg);
        }
        sArg = WebSock.GetParam("statusprefix");
        if (!sArg.empty()) {
            pNewUser->SetStatusPrefix(sArg);
        }
        sArg = WebSock.GetParam("ident");
        if (!sArg.empty()) {
            pNewUser->SetIdent(sArg);
        }
        sArg = WebSock.GetParam("realname");
        if (!sArg.empty()) {
            pNewUser->SetRealName(sArg);
        }
        sArg = WebSock.GetParam("quitmsg");
        if (!sArg.empty()) {
            pNewUser->SetQuitMsg(sArg);
        }
        sArg = WebSock.GetParam("chanmodes");
        if (!sArg.empty()) {
            pNewUser->SetDefaultChanModes(sArg);
        }
        sArg = WebSock.GetParam("timestampformat");
        if (!sArg.empty()) {
            pNewUser->SetTimestampFormat(sArg);
        }

        sArg = WebSock.GetParam("bindhost");
        // To change BindHosts be admin or don't have DenySetBindHost
        if (spSession->IsAdmin() || !spSession->GetUser()->DenySetBindHost()) {
            NoString sArg2 = WebSock.GetParam("dccbindhost");
            if (!sArg.empty()) {
                pNewUser->SetBindHost(sArg);
            }
            if (!sArg2.empty()) {
                pNewUser->SetDCCBindHost(sArg2);
            }

            const NoStringVector& vsHosts = NoApp::Get().GetBindHosts();
            if (!spSession->IsAdmin() && !vsHosts.empty()) {
                NoStringVector::const_iterator it;
                bool bFound = false;
                bool bFoundDCC = false;

                for (it = vsHosts.begin(); it != vsHosts.end(); ++it) {
                    if (sArg.equals(*it)) {
                        bFound = true;
                    }
                    if (sArg2.equals(*it)) {
                        bFoundDCC = true;
                    }
                }

                if (!bFound) {
                    pNewUser->SetBindHost(pUser ? pUser->GetBindHost() : "");
                }
                if (!bFoundDCC) {
                    pNewUser->SetDCCBindHost(pUser ? pUser->GetDCCBindHost() : "");
                }
            }
        } else if (pUser) {
            pNewUser->SetBindHost(pUser->GetBindHost());
            pNewUser->SetDCCBindHost(pUser->GetDCCBindHost());
        }

        sArg = WebSock.GetParam("bufsize");
        if (!sArg.empty()) pNewUser->SetBufferCount(sArg.toUInt(), spSession->IsAdmin());
        if (!sArg.empty()) {
            // First apply the old limit in case the new one is too high
            if (pUser) pNewUser->SetBufferCount(pUser->GetBufferCount(), true);
            pNewUser->SetBufferCount(sArg.toUInt(), spSession->IsAdmin());
        }

        pNewUser->SetSkinName(WebSock.GetParam("skin"));
        pNewUser->SetAutoClearChanBuffer(WebSock.GetParam("autoclearchanbuffer").toBool());
        pNewUser->SetMultiClients(WebSock.GetParam("multiclients").toBool());
        pNewUser->SetTimestampAppend(WebSock.GetParam("appendtimestamp").toBool());
        pNewUser->SetTimestampPrepend(WebSock.GetParam("prependtimestamp").toBool());
        pNewUser->SetTimezone(WebSock.GetParam("timezone"));
        pNewUser->SetJoinTries(WebSock.GetParam("jointries").toUInt());
        pNewUser->SetMaxJoins(WebSock.GetParam("maxjoins").toUInt());
        pNewUser->SetAutoClearQueryBuffer(WebSock.GetParam("autoclearquerybuffer").toBool());
        pNewUser->SetMaxQueryBuffers(WebSock.GetParam("maxquerybuffers").toUInt());

#ifdef HAVE_ICU
        NoString sEncodingUtf = WebSock.GetParam("encoding_utf");
        if (sEncodingUtf == "legacy") {
            pNewUser->SetClientEncoding("");
        }
        NoString sEncoding = WebSock.GetParam("encoding");
        if (sEncoding.empty()) {
            sEncoding = "UTF-8";
        }
        if (sEncodingUtf == "send") {
            pNewUser->SetClientEncoding("^" + sEncoding);
        } else if (sEncodingUtf == "receive") {
            pNewUser->SetClientEncoding("*" + sEncoding);
        } else if (sEncodingUtf == "simple") {
            pNewUser->SetClientEncoding(sEncoding);
        }
#endif

        if (spSession->IsAdmin()) {
            pNewUser->SetDenyLoadMod(WebSock.GetParam("denyloadmod").toBool());
            pNewUser->SetDenySetBindHost(WebSock.GetParam("denysetbindhost").toBool());
            sArg = WebSock.GetParam("maxnetworks");
            if (!sArg.empty()) pNewUser->SetMaxNetworks(sArg.toUInt());
        } else if (pUser) {
            pNewUser->SetDenyLoadMod(pUser->DenyLoadMod());
            pNewUser->SetDenySetBindHost(pUser->DenySetBindHost());
            pNewUser->SetMaxNetworks(pUser->MaxNetworks());
        }

        // If pUser is not nullptr, we are editing an existing user.
        // Users must not be able to change their own admin flag.
        if (pUser != NoApp::Get().FindUser(WebSock.GetUser())) {
            pNewUser->SetAdmin(WebSock.GetParam("isadmin").toBool());
        } else if (pUser) {
            pNewUser->SetAdmin(pUser->IsAdmin());
        }

        if (spSession->IsAdmin() || (pUser && !pUser->DenyLoadMod())) {
            WebSock.GetParamValues("loadmod", vsArgs);

            // disallow unload webadmin from itself
            if (No::UserModule == GetType() && pUser == NoApp::Get().FindUser(WebSock.GetUser())) {
                bool bLoadedWebadmin = false;
                for (a = 0; a < vsArgs.size(); ++a) {
                    NoString sModName = vsArgs[a].trimRight_n("\r");
                    if (sModName == GetModName()) {
                        bLoadedWebadmin = true;
                        break;
                    }
                }
                if (!bLoadedWebadmin) {
                    vsArgs.push_back(GetModName());
                }
            }

            for (a = 0; a < vsArgs.size(); a++) {
                NoString sModRet;
                NoString sModName = vsArgs[a].trimRight_n("\r");
                NoString sModLoadError;

                if (!sModName.empty()) {
                    NoString sArgs = WebSock.GetParam("modargs_" + sModName);

                    try {
                        if (!pNewUser->GetModules().LoadModule(sModName, sArgs, No::UserModule, pNewUser, nullptr, sModRet)) {
                            sModLoadError = "Unable to load module [" + sModName + "] [" + sModRet + "]";
                        }
                    } catch (...) {
                        sModLoadError = "Unable to load module [" + sModName + "] [" + sArgs + "]";
                    }

                    if (!sModLoadError.empty()) {
                        NO_DEBUG(sModLoadError);
                        spSession->AddError(sModLoadError);
                    }
                }
            }
        } else if (pUser) {
            NoModules& Modules = pUser->GetModules();

            for (a = 0; a < Modules.size(); a++) {
                NoString sModName = Modules[a]->GetModName();
                NoString sArgs = Modules[a]->GetArgs();
                NoString sModRet;
                NoString sModLoadError;

                try {
                    if (!pNewUser->GetModules().LoadModule(sModName, sArgs, No::UserModule, pNewUser, nullptr, sModRet)) {
                        sModLoadError = "Unable to load module [" + sModName + "] [" + sModRet + "]";
                    }
                } catch (...) {
                    sModLoadError = "Unable to load module [" + sModName + "]";
                }

                if (!sModLoadError.empty()) {
                    NO_DEBUG(sModLoadError);
                    spSession->AddError(sModLoadError);
                }
            }
        }

        return pNewUser;
    }

    NoString SafeGetUserNameParam(NoWebSocket& WebSock)
    {
        NoString sUserName = WebSock.GetParam("user"); // check for POST param
        if (sUserName.empty() && !WebSock.IsPost()) {
            // if no POST param named user has been given and we are not
            // saving this form, fall back to using the GET parameter.
            sUserName = WebSock.GetParam("user", false);
        }
        return sUserName;
    }

    NoString SafeGetNetworkParam(NoWebSocket& WebSock)
    {
        NoString sNetwork = WebSock.GetParam("network"); // check for POST param
        if (sNetwork.empty() && !WebSock.IsPost()) {
            // if no POST param named user has been given and we are not
            // saving this form, fall back to using the GET parameter.
            sNetwork = WebSock.GetParam("network", false);
        }
        return sNetwork;
    }

    NoUser* SafeGetUserFromParam(NoWebSocket& WebSock) { return NoApp::Get().FindUser(SafeGetUserNameParam(WebSock)); }

    NoNetwork* SafeGetNetworkFromParam(NoWebSocket& WebSock)
    {
        NoUser* pUser = NoApp::Get().FindUser(SafeGetUserNameParam(WebSock));
        NoNetwork* pNetwork = nullptr;

        if (pUser) {
            pNetwork = pUser->FindNetwork(SafeGetNetworkParam(WebSock));
        }

        return pNetwork;
    }

    NoString GetWebMenuTitle() override { return "webadmin"; }
    bool OnWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.GetSession();

        if (sPageName == "settings") {
            // Admin Check
            if (!spSession->IsAdmin()) {
                return false;
            }

            return SettingsPage(WebSock, Tmpl);
        } else if (sPageName == "adduser") {
            // Admin Check
            if (!spSession->IsAdmin()) {
                return false;
            }

            return UserPage(WebSock, Tmpl);
        } else if (sPageName == "addnetwork") {
            NoUser* pUser = SafeGetUserFromParam(WebSock);

            // Admin||Self Check
            if (!spSession->IsAdmin() && (!spSession->GetUser() || spSession->GetUser() != pUser)) {
                return false;
            }

            if (pUser) {
                return NetworkPage(WebSock, Tmpl, pUser);
            }

            WebSock.PrintErrorPage("No such username");
            return true;
        } else if (sPageName == "editnetwork") {
            NoNetwork* pNetwork = SafeGetNetworkFromParam(WebSock);

            // Admin||Self Check
            if (!spSession->IsAdmin() && (!spSession->GetUser() || !pNetwork || spSession->GetUser() != pNetwork->GetUser())) {
                return false;
            }

            if (!pNetwork) {
                WebSock.PrintErrorPage("No such username or network");
                return true;
            }

            return NetworkPage(WebSock, Tmpl, pNetwork->GetUser(), pNetwork);

        } else if (sPageName == "delnetwork") {
            NoString sUser = WebSock.GetParam("user");
            if (sUser.empty() && !WebSock.IsPost()) {
                sUser = WebSock.GetParam("user", false);
            }

            NoUser* pUser = NoApp::Get().FindUser(sUser);

            // Admin||Self Check
            if (!spSession->IsAdmin() && (!spSession->GetUser() || spSession->GetUser() != pUser)) {
                return false;
            }

            return DelNetwork(WebSock, pUser, Tmpl);
        } else if (sPageName == "editchan") {
            NoNetwork* pNetwork = SafeGetNetworkFromParam(WebSock);

            // Admin||Self Check
            if (!spSession->IsAdmin() && (!spSession->GetUser() || !pNetwork || spSession->GetUser() != pNetwork->GetUser())) {
                return false;
            }

            if (!pNetwork) {
                WebSock.PrintErrorPage("No such username or network");
                return true;
            }

            NoString sChan = WebSock.GetParam("name");
            if (sChan.empty() && !WebSock.IsPost()) {
                sChan = WebSock.GetParam("name", false);
            }
            NoChannel* pChan = pNetwork->FindChan(sChan);
            if (!pChan) {
                WebSock.PrintErrorPage("No such channel");
                return true;
            }

            return ChanPage(WebSock, Tmpl, pNetwork, pChan);
        } else if (sPageName == "addchan") {
            NoNetwork* pNetwork = SafeGetNetworkFromParam(WebSock);

            // Admin||Self Check
            if (!spSession->IsAdmin() && (!spSession->GetUser() || !pNetwork || spSession->GetUser() != pNetwork->GetUser())) {
                return false;
            }

            if (pNetwork) {
                return ChanPage(WebSock, Tmpl, pNetwork);
            }

            WebSock.PrintErrorPage("No such username or network");
            return true;
        } else if (sPageName == "delchan") {
            NoNetwork* pNetwork = SafeGetNetworkFromParam(WebSock);

            // Admin||Self Check
            if (!spSession->IsAdmin() && (!spSession->GetUser() || !pNetwork || spSession->GetUser() != pNetwork->GetUser())) {
                return false;
            }

            if (pNetwork) {
                return DelChan(WebSock, pNetwork);
            }

            WebSock.PrintErrorPage("No such username or network");
            return true;
        } else if (sPageName == "deluser") {
            if (!spSession->IsAdmin()) {
                return false;
            }

            if (!WebSock.IsPost()) {
                // Show the "Are you sure?" page:

                NoString sUser = WebSock.GetParam("user", false);
                NoUser* pUser = NoApp::Get().FindUser(sUser);

                if (!pUser) {
                    WebSock.PrintErrorPage("No such username");
                    return true;
                }

                Tmpl.SetFile("del_user.tmpl");
                Tmpl["Username"] = sUser;
                return true;
            }

            // The "Are you sure?" page has been submitted with "Yes",
            // so we actually delete the user now:

            NoString sUser = WebSock.GetParam("user");
            NoUser* pUser = NoApp::Get().FindUser(sUser);

            if (pUser && pUser == spSession->GetUser()) {
                WebSock.PrintErrorPage("Please don't delete yourself, suicide is not the answer!");
                return true;
            } else if (NoApp::Get().DeleteUser(sUser)) {
                WebSock.Redirect(GetWebPath() + "listusers");
                return true;
            }

            WebSock.PrintErrorPage("No such username");
            return true;
        } else if (sPageName == "edituser") {
            NoString sUserName = SafeGetUserNameParam(WebSock);
            NoUser* pUser = NoApp::Get().FindUser(sUserName);

            if (!pUser) {
                if (sUserName.empty()) {
                    pUser = spSession->GetUser();
                } // else: the "no such user" message will be printed.
            }

            // Admin||Self Check
            if (!spSession->IsAdmin() && (!spSession->GetUser() || spSession->GetUser() != pUser)) {
                return false;
            }

            if (pUser) {
                return UserPage(WebSock, Tmpl, pUser);
            }

            WebSock.PrintErrorPage("No such username");
            return true;
        } else if (sPageName == "listusers" && spSession->IsAdmin()) {
            return ListUsersPage(WebSock, Tmpl);
        } else if (sPageName == "traffic" && spSession->IsAdmin()) {
            return TrafficPage(WebSock, Tmpl);
        } else if (sPageName == "index") {
            return true;
        } else if (sPageName == "add_listener") {
            // Admin Check
            if (!spSession->IsAdmin()) {
                return false;
            }

            return AddListener(WebSock, Tmpl);
        } else if (sPageName == "del_listener") {
            // Admin Check
            if (!spSession->IsAdmin()) {
                return false;
            }

            return DelListener(WebSock, Tmpl);
        }

        return false;
    }

    bool ChanPage(NoWebSocket& WebSock, NoTemplate& Tmpl, NoNetwork* pNetwork, NoChannel* pChan = nullptr)
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.GetSession();
        Tmpl.SetFile("add_edit_chan.tmpl");
        NoUser* pUser = pNetwork->GetUser();

        if (!pUser) {
            WebSock.PrintErrorPage("That user doesn't exist");
            return true;
        }

        if (!WebSock.GetParam("submitted").toUInt()) {
            Tmpl["User"] = pUser->GetUserName();
            Tmpl["Network"] = pNetwork->GetName();

            if (pChan) {
                Tmpl["Action"] = "editchan";
                Tmpl["Edit"] = "true";
                Tmpl["Title"] = "Edit Channel" + NoString(" [" + pChan->getName() + "]") + " of Network [" +
                                pNetwork->GetName() + "] of User [" + pNetwork->GetUser()->GetUserName() + "]";
                Tmpl["ChanName"] = pChan->getName();
                Tmpl["BufferCount"] = NoString(pChan->getBufferCount());
                Tmpl["DefModes"] = pChan->getDefaultModes();
                Tmpl["Key"] = pChan->getKey();

                if (pChan->inConfig()) {
                    Tmpl["InConfig"] = "true";
                }
            } else {
                Tmpl["Action"] = "addchan";
                Tmpl["Title"] = "Add Channel" + NoString(" for User [" + pUser->GetUserName() + "]");
                Tmpl["BufferCount"] = NoString(pUser->GetBufferCount());
                Tmpl["DefModes"] = NoString(pUser->GetDefaultChanModes());
                Tmpl["InConfig"] = "true";
            }

            // o1 used to be AutoCycle which was removed

            NoTemplate& o2 = Tmpl.AddRow("OptionLoop");
            o2["Name"] = "autoclearchanbuffer";
            o2["DisplayName"] = "Auto Clear Chan Buffer";
            o2["Tooltip"] = "Automatically Clear Channel Buffer After Playback";
            if ((pChan && pChan->autoClearChanBuffer()) || (!pChan && pUser->AutoClearChanBuffer())) {
                o2["Checked"] = "true";
            }

            NoTemplate& o3 = Tmpl.AddRow("OptionLoop");
            o3["Name"] = "detached";
            o3["DisplayName"] = "Detached";
            if (pChan && pChan->isDetached()) {
                o3["Checked"] = "true";
            }

            NoTemplate& o4 = Tmpl.AddRow("OptionLoop");
            o4["Name"] = "disabled";
            o4["DisplayName"] = "Disabled";
            if (pChan && pChan->isDisabled()) {
                o4["Checked"] = "true";
            }

            FOR_EACH_MODULE(i, pNetwork)
            {
                NoTemplate& mod = Tmpl.AddRow("EmbeddedModuleLoop");
                mod.insert(Tmpl.begin(), Tmpl.end());
                mod["WebadminAction"] = "display";
                if ((*i)->OnEmbeddedWebRequest(WebSock, "webadmin/channel", mod)) {
                    mod["Embed"] = WebSock.FindTmpl(*i, "WebadminChan.tmpl");
                    mod["ModName"] = (*i)->GetModName();
                }
            }

            return true;
        }

        NoString sChanName = WebSock.GetParam("name").trim_n();

        if (!pChan) {
            if (sChanName.empty()) {
                WebSock.PrintErrorPage("Channel name is a required argument");
                return true;
            }

            // This could change the channel name and e.g. add a "#" prefix
            pChan = new NoChannel(sChanName, pNetwork, true);

            if (pNetwork->FindChan(pChan->getName())) {
                WebSock.PrintErrorPage("Channel [" + pChan->getName() + "] already exists");
                delete pChan;
                return true;
            }

            if (!pNetwork->AddChan(pChan)) {
                WebSock.PrintErrorPage("Could not add channel [" + pChan->getName() + "]");
                return true;
            }
        }

        uint uBufferCount = WebSock.GetParam("buffercount").toUInt();
        if (pChan->getBufferCount() != uBufferCount) {
            pChan->setBufferCount(uBufferCount, spSession->IsAdmin());
        }
        pChan->setDefaultModes(WebSock.GetParam("defmodes"));
        pChan->setInConfig(WebSock.GetParam("save").toBool());
        bool bAutoClearChanBuffer = WebSock.GetParam("autoclearchanbuffer").toBool();
        if (pChan->autoClearChanBuffer() != bAutoClearChanBuffer) {
            pChan->setAutoClearChanBuffer(WebSock.GetParam("autoclearchanbuffer").toBool());
        }
        pChan->setKey(WebSock.GetParam("key"));

        bool bDetached = WebSock.GetParam("detached").toBool();
        if (pChan->isDetached() != bDetached) {
            if (bDetached) {
                pChan->detachUser();
            } else {
                pChan->attachUser();
            }
        }

        bool bDisabled = WebSock.GetParam("disabled").toBool();
        if (bDisabled)
            pChan->disable();
        else
            pChan->enable();

        NoTemplate TmplMod;
        TmplMod["User"] = pUser->GetUserName();
        TmplMod["ChanName"] = pChan->getName();
        TmplMod["WebadminAction"] = "change";
        FOR_EACH_MODULE(it, pNetwork) { (*it)->OnEmbeddedWebRequest(WebSock, "webadmin/channel", TmplMod); }

        if (!NoApp::Get().WriteConfig()) {
            WebSock.PrintErrorPage("Channel added/modified, but config was not written");
            return true;
        }

        if (WebSock.HasParam("submit_return")) {
            WebSock.Redirect(GetWebPath() + "editnetwork?user=" + No::escape(pUser->GetUserName(), No::UrlFormat) +
                             "&network=" + No::escape(pNetwork->GetName(), No::UrlFormat));
        } else {
            WebSock.Redirect(GetWebPath() + "editchan?user=" + No::escape(pUser->GetUserName(), No::UrlFormat) +
                             "&network=" + No::escape(pNetwork->GetName(), No::UrlFormat) + "&name=" +
                             No::escape(pChan->getName(), No::UrlFormat));
        }
        return true;
    }

    bool NetworkPage(NoWebSocket& WebSock, NoTemplate& Tmpl, NoUser* pUser, NoNetwork* pNetwork = nullptr)
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.GetSession();
        Tmpl.SetFile("add_edit_network.tmpl");

        if (!WebSock.GetParam("submitted").toUInt()) {
            Tmpl["Username"] = pUser->GetUserName();

            std::set<NoModuleInfo> ssNetworkMods;
            NoApp::Get().GetModules().GetAvailableMods(ssNetworkMods, No::NetworkModule);
            for (std::set<NoModuleInfo>::iterator it = ssNetworkMods.begin(); it != ssNetworkMods.end(); ++it) {
                const NoModuleInfo& Info = *it;
                NoTemplate& l = Tmpl.AddRow("ModuleLoop");

                l["Name"] = Info.GetName();
                l["Description"] = Info.GetDescription();
                l["Wiki"] = Info.GetWikiPage();
                l["HasArgs"] = NoString(Info.GetHasArgs());
                l["ArgsHelpText"] = Info.GetArgsHelpText();

                if (pNetwork) {
                    NoModule* pModule = pNetwork->GetModules().FindModule(Info.GetName());
                    if (pModule) {
                        l["Checked"] = "true";
                        l["Args"] = pModule->GetArgs();
                    }
                }

                // Check if module is loaded globally
                l["CanBeLoadedGlobally"] = NoString(Info.SupportsType(No::GlobalModule));
                l["LoadedGlobally"] = NoString(NoApp::Get().GetModules().FindModule(Info.GetName()) != nullptr);

                // Check if module is loaded by user
                l["CanBeLoadedByUser"] = NoString(Info.SupportsType(No::UserModule));
                l["LoadedByUser"] = NoString(pUser->GetModules().FindModule(Info.GetName()) != nullptr);

                if (!spSession->IsAdmin() && pUser->DenyLoadMod()) {
                    l["Disabled"] = "true";
                }
            }

            // To change BindHosts be admin or don't have DenySetBindHost
            if (spSession->IsAdmin() || !spSession->GetUser()->DenySetBindHost()) {
                Tmpl["BindHostEdit"] = "true";
                const NoStringVector& vsBindHosts = NoApp::Get().GetBindHosts();
                if (vsBindHosts.empty()) {
                    if (pNetwork) {
                        Tmpl["BindHost"] = pNetwork->GetBindHost();
                    }
                } else {
                    bool bFoundBindHost = false;
                    for (uint b = 0; b < vsBindHosts.size(); b++) {
                        const NoString& sBindHost = vsBindHosts[b];
                        NoTemplate& l = Tmpl.AddRow("BindHostLoop");

                        l["BindHost"] = sBindHost;

                        if (pNetwork && pNetwork->GetBindHost() == sBindHost) {
                            l["Checked"] = "true";
                            bFoundBindHost = true;
                        }
                    }

                    // If our current bindhost is not in the global list...
                    if (pNetwork && !bFoundBindHost && !pNetwork->GetBindHost().empty()) {
                        NoTemplate& l = Tmpl.AddRow("BindHostLoop");

                        l["BindHost"] = pNetwork->GetBindHost();
                        l["Checked"] = "true";
                    }
                }
            }

            if (pNetwork) {
                Tmpl["Action"] = "editnetwork";
                Tmpl["Edit"] = "true";
                Tmpl["Title"] =
                "Edit Network" + NoString(" [" + pNetwork->GetName() + "]") + " of User [" + pUser->GetUserName() + "]";
                Tmpl["Name"] = pNetwork->GetName();

                Tmpl["Nick"] = pNetwork->GetNick();
                Tmpl["AltNick"] = pNetwork->GetAltNick();
                Tmpl["Ident"] = pNetwork->GetIdent();
                Tmpl["RealName"] = pNetwork->GetRealName();

                Tmpl["QuitMsg"] = pNetwork->GetQuitMsg();

                Tmpl["FloodProtection"] = NoString(NoIrcConnection::IsFloodProtected(pNetwork->GetFloodRate()));
                Tmpl["FloodRate"] = NoString(pNetwork->GetFloodRate());
                Tmpl["FloodBurst"] = NoString(pNetwork->GetFloodBurst());

                Tmpl["JoinDelay"] = NoString(pNetwork->GetJoinDelay());

                Tmpl["IRCConnectEnabled"] = NoString(pNetwork->GetIRCConnectEnabled());

                const std::vector<NoServer*>& vServers = pNetwork->GetServers();
                for (uint a = 0; a < vServers.size(); a++) {
                    NoTemplate& l = Tmpl.AddRow("ServerLoop");
                    l["Server"] = vServers[a]->GetString();
                }

                const std::vector<NoChannel*>& Channels = pNetwork->GetChans();
                for (uint c = 0; c < Channels.size(); c++) {
                    NoChannel* pChan = Channels[c];
                    NoTemplate& l = Tmpl.AddRow("ChannelLoop");

                    l["Network"] = pNetwork->GetName();
                    l["Username"] = pUser->GetUserName();
                    l["Name"] = pChan->getName();
                    l["Perms"] = pChan->getPermStr();
                    l["CurModes"] = pChan->getModeString();
                    l["DefModes"] = pChan->getDefaultModes();
                    if (pChan->hasBufferCountSet()) {
                        l["BufferCount"] = NoString(pChan->getBufferCount());
                    } else {
                        l["BufferCount"] = NoString(pChan->getBufferCount()) + " (default)";
                    }
                    l["Options"] = pChan->getOptions();

                    if (pChan->inConfig()) {
                        l["InConfig"] = "true";
                    }
                }
                for (const NoString& sFP : pNetwork->GetTrustedFingerprints()) {
                    NoTemplate& l = Tmpl.AddRow("TrustedFingerprints");
                    l["FP"] = sFP;
                }
            } else {
                if (!spSession->IsAdmin() && !pUser->HasSpaceForNewNetwork()) {
                    WebSock.PrintErrorPage("Network number limit reached. Ask an admin to increase the limit for you, "
                                           "or delete unneeded networks from Your Settings.");
                    return true;
                }

                Tmpl["Action"] = "addnetwork";
                Tmpl["Title"] = "Add Network for User [" + pUser->GetUserName() + "]";
                Tmpl["IRCConnectEnabled"] = "true";
                Tmpl["FloodProtection"] = "true";
                Tmpl["FloodRate"] = "1.0";
                Tmpl["FloodBurst"] = "4";
                Tmpl["JoinDelay"] = "0";
            }

            FOR_EACH_MODULE(i, std::make_pair(pUser, pNetwork))
            {
                NoTemplate& mod = Tmpl.AddRow("EmbeddedModuleLoop");
                mod.insert(Tmpl.begin(), Tmpl.end());
                mod["WebadminAction"] = "display";
                if ((*i)->OnEmbeddedWebRequest(WebSock, "webadmin/network", mod)) {
                    mod["Embed"] = WebSock.FindTmpl(*i, "WebadminNetwork.tmpl");
                    mod["ModName"] = (*i)->GetModName();
                }
            }

#ifdef HAVE_ICU
            for (const NoString& sEncoding : No::encodings()) {
                NoTemplate& l = Tmpl.AddRow("EncodingLoop");
                l["Encoding"] = sEncoding;
            }
            const NoString sEncoding = pNetwork ? pNetwork->GetEncoding() : "^UTF-8";
            if (sEncoding.empty()) {
                Tmpl["EncodingUtf"] = "legacy";
            } else if (sEncoding[0] == '*') {
                Tmpl["EncodingUtf"] = "receive";
                Tmpl["Encoding"] = sEncoding.substr(1);
            } else if (sEncoding[0] == '^') {
                Tmpl["EncodingUtf"] = "send";
                Tmpl["Encoding"] = sEncoding.substr(1);
            } else {
                Tmpl["EncodingUtf"] = "simple";
                Tmpl["Encoding"] = sEncoding;
            }
#else
            Tmpl["EncodingDisabled"] = "true";
            Tmpl["EncodingUtf"] = "legacy";
#endif

            return true;
        }

        NoString sName = WebSock.GetParam("name").trim_n();
        if (sName.empty()) {
            WebSock.PrintErrorPage("Network name is a required argument");
            return true;
        }
        if (!pNetwork && !spSession->IsAdmin() && !pUser->HasSpaceForNewNetwork()) {
            WebSock.PrintErrorPage("Network number limit reached. Ask an admin to increase the limit for you, or "
                                   "delete few old ones from Your Settings");
            return true;
        }
        if (!pNetwork || pNetwork->GetName() != sName) {
            NoString sNetworkAddError;
            NoNetwork* pOldNetwork = pNetwork;
            pNetwork = pUser->AddNetwork(sName, sNetworkAddError);
            if (!pNetwork) {
                WebSock.PrintErrorPage(sNetworkAddError);
                return true;
            }
            if (pOldNetwork) {
                for (NoModule* pModule : pOldNetwork->GetModules()) {
                    NoString sPath = pUser->GetUserPath() + "/networks/" + sName + "/moddata/" + pModule->GetModName();
                    pModule->MoveRegistry(sPath);
                }
                pNetwork->Clone(*pOldNetwork, false);
                pUser->DeleteNetwork(pOldNetwork->GetName());
            }
        }

        NoString sArg;

        pNetwork->SetNick(WebSock.GetParam("nick"));
        pNetwork->SetAltNick(WebSock.GetParam("altnick"));
        pNetwork->SetIdent(WebSock.GetParam("ident"));
        pNetwork->SetRealName(WebSock.GetParam("realname"));

        pNetwork->SetQuitMsg(WebSock.GetParam("quitmsg"));

        pNetwork->SetIRCConnectEnabled(WebSock.GetParam("doconnect").toBool());

        sArg = WebSock.GetParam("bindhost");
        // To change BindHosts be admin or don't have DenySetBindHost
        if (spSession->IsAdmin() || !spSession->GetUser()->DenySetBindHost()) {
            NoString sHost = WebSock.GetParam("bindhost");
            const NoStringVector& vsHosts = NoApp::Get().GetBindHosts();
            if (!spSession->IsAdmin() && !vsHosts.empty()) {
                NoStringVector::const_iterator it;
                bool bFound = false;

                for (it = vsHosts.begin(); it != vsHosts.end(); ++it) {
                    if (sHost.equals(*it)) {
                        bFound = true;
                        break;
                    }
                }

                if (!bFound) {
                    sHost = pNetwork->GetBindHost();
                }
            }
            pNetwork->SetBindHost(sHost);
        }

        if (WebSock.GetParam("floodprotection").toBool()) {
            pNetwork->SetFloodRate(WebSock.GetParam("floodrate").toDouble());
            pNetwork->SetFloodBurst(WebSock.GetParam("floodburst").toUShort());
        } else {
            pNetwork->SetFloodRate(-1);
        }

        pNetwork->SetJoinDelay(WebSock.GetParam("joindelay").toUShort());

#ifdef HAVE_ICU
        NoString sEncodingUtf = WebSock.GetParam("encoding_utf");
        if (sEncodingUtf == "legacy") {
            pNetwork->SetEncoding("");
        }
        NoString sEncoding = WebSock.GetParam("encoding");
        if (sEncoding.empty()) {
            sEncoding = "UTF-8";
        }
        if (sEncodingUtf == "send") {
            pNetwork->SetEncoding("^" + sEncoding);
        } else if (sEncodingUtf == "receive") {
            pNetwork->SetEncoding("*" + sEncoding);
        } else if (sEncodingUtf == "simple") {
            pNetwork->SetEncoding(sEncoding);
        }
#endif

        pNetwork->DelServers();
        NoStringVector vsArgs = WebSock.GetRawParam("servers").split("\n");
        for (uint a = 0; a < vsArgs.size(); a++) {
            pNetwork->AddServer(vsArgs[a].trim_n());
        }

        vsArgs = WebSock.GetRawParam("fingerprints").split("\n");
        while (!pNetwork->GetTrustedFingerprints().empty()) {
            pNetwork->DelTrustedFingerprint(*pNetwork->GetTrustedFingerprints().begin());
        }
        for (const NoString& sFP : vsArgs) {
            pNetwork->AddTrustedFingerprint(sFP);
        }

        WebSock.GetParamValues("channel", vsArgs);
        for (uint a = 0; a < vsArgs.size(); a++) {
            const NoString& sChan = vsArgs[a];
            NoChannel* pChan = pNetwork->FindChan(sChan.trimRight_n("\r"));
            if (pChan) {
                pChan->setInConfig(WebSock.GetParam("save_" + sChan).toBool());
            }
        }

        std::set<NoString> ssArgs;
        WebSock.GetParamValues("loadmod", ssArgs);
        if (spSession->IsAdmin() || !pUser->DenyLoadMod()) {
            for (std::set<NoString>::iterator it = ssArgs.begin(); it != ssArgs.end(); ++it) {
                NoString sModRet;
                NoString sModName = (*it).trimRight_n("\r");
                NoString sModLoadError;

                if (!sModName.empty()) {
                    NoString sArgs = WebSock.GetParam("modargs_" + sModName);

                    NoModule* pMod = pNetwork->GetModules().FindModule(sModName);

                    if (!pMod) {
                        if (!pNetwork->GetModules().LoadModule(sModName, sArgs, No::NetworkModule, pUser, pNetwork, sModRet)) {
                            sModLoadError = "Unable to load module [" + sModName + "] [" + sModRet + "]";
                        }
                    } else if (pMod->GetArgs() != sArgs) {
                        if (!pNetwork->GetModules().ReloadModule(sModName, sArgs, pUser, pNetwork, sModRet)) {
                            sModLoadError = "Unable to reload module [" + sModName + "] [" + sModRet + "]";
                        }
                    }

                    if (!sModLoadError.empty()) {
                        NO_DEBUG(sModLoadError);
                        WebSock.GetSession()->AddError(sModLoadError);
                    }
                }
            }
        }

        const NoModules& vCurMods = pNetwork->GetModules();
        std::set<NoString> ssUnloadMods;

        for (uint a = 0; a < vCurMods.size(); a++) {
            NoModule* pCurMod = vCurMods[a];

            if (ssArgs.find(pCurMod->GetModName()) == ssArgs.end() && pCurMod->GetModName() != GetModName()) {
                ssUnloadMods.insert(pCurMod->GetModName());
            }
        }

        for (std::set<NoString>::iterator it2 = ssUnloadMods.begin(); it2 != ssUnloadMods.end(); ++it2) {
            pNetwork->GetModules().UnloadModule(*it2);
        }

        NoTemplate TmplMod;
        TmplMod["Username"] = pUser->GetUserName();
        TmplMod["Name"] = pNetwork->GetName();
        TmplMod["WebadminAction"] = "change";
        FOR_EACH_MODULE(it, std::make_pair(pUser, pNetwork))
        {
            (*it)->OnEmbeddedWebRequest(WebSock, "webadmin/network", TmplMod);
        }

        if (!NoApp::Get().WriteConfig()) {
            WebSock.PrintErrorPage("Network added/modified, but config was not written");
            return true;
        }

        if (WebSock.HasParam("submit_return")) {
            WebSock.Redirect(GetWebPath() + "edituser?user=" + No::escape(pUser->GetUserName(), No::UrlFormat));
        } else {
            WebSock.Redirect(GetWebPath() + "editnetwork?user=" + No::escape(pUser->GetUserName(), No::UrlFormat) +
                             "&network=" + No::escape(pNetwork->GetName(), No::UrlFormat));
        }
        return true;
    }

    bool DelNetwork(NoWebSocket& WebSock, NoUser* pUser, NoTemplate& Tmpl)
    {
        NoString sNetwork = WebSock.GetParam("name");
        if (sNetwork.empty() && !WebSock.IsPost()) {
            sNetwork = WebSock.GetParam("name", false);
        }

        if (!pUser) {
            WebSock.PrintErrorPage("That user doesn't exist");
            return true;
        }

        if (sNetwork.empty()) {
            WebSock.PrintErrorPage("That network doesn't exist for this user");
            return true;
        }

        if (!WebSock.IsPost()) {
            // Show the "Are you sure?" page:

            Tmpl.SetFile("del_network.tmpl");
            Tmpl["Username"] = pUser->GetUserName();
            Tmpl["Network"] = sNetwork;
            return true;
        }

        pUser->DeleteNetwork(sNetwork);

        if (!NoApp::Get().WriteConfig()) {
            WebSock.PrintErrorPage("Network deleted, but config was not written");
            return true;
        }

        WebSock.Redirect(GetWebPath() + "edituser?user=" + No::escape(pUser->GetUserName(), No::UrlFormat));
        return false;
    }

    bool DelChan(NoWebSocket& WebSock, NoNetwork* pNetwork)
    {
        NoString sChan = WebSock.GetParam("name", false);

        if (sChan.empty()) {
            WebSock.PrintErrorPage("That channel doesn't exist for this user");
            return true;
        }

        pNetwork->DelChan(sChan);
        pNetwork->PutIRC("PART " + sChan);

        if (!NoApp::Get().WriteConfig()) {
            WebSock.PrintErrorPage("Channel deleted, but config was not written");
            return true;
        }

        WebSock.Redirect(GetWebPath() + "editnetwork?user=" + No::escape(pNetwork->GetUser()->GetUserName(), No::UrlFormat) +
                         "&network=" + No::escape(pNetwork->GetName(), No::UrlFormat));
        return false;
    }

    bool UserPage(NoWebSocket& WebSock, NoTemplate& Tmpl, NoUser* pUser = nullptr)
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.GetSession();
        Tmpl.SetFile("add_edit_user.tmpl");

        if (!WebSock.GetParam("submitted").toUInt()) {
            if (pUser) {
                Tmpl["Action"] = "edituser";
                Tmpl["Title"] = "Edit User [" + pUser->GetUserName() + "]";
                Tmpl["Edit"] = "true";
            } else {
                NoString sUsername = WebSock.GetParam("clone", false);
                pUser = NoApp::Get().FindUser(sUsername);

                if (pUser) {
                    Tmpl["Title"] = "Clone User [" + pUser->GetUserName() + "]";
                    Tmpl["Clone"] = "true";
                    Tmpl["CloneUsername"] = pUser->GetUserName();
                }
            }

            Tmpl["ImAdmin"] = NoString(spSession->IsAdmin());

            if (pUser) {
                Tmpl["Username"] = pUser->GetUserName();
                Tmpl["Nick"] = pUser->GetNick();
                Tmpl["AltNick"] = pUser->GetAltNick();
                Tmpl["StatusPrefix"] = pUser->GetStatusPrefix();
                Tmpl["Ident"] = pUser->GetIdent();
                Tmpl["RealName"] = pUser->GetRealName();
                Tmpl["QuitMsg"] = pUser->GetQuitMsg();
                Tmpl["DefaultChanModes"] = pUser->GetDefaultChanModes();
                Tmpl["BufferCount"] = NoString(pUser->GetBufferCount());
                Tmpl["TimestampFormat"] = pUser->GetTimestampFormat();
                Tmpl["Timezone"] = pUser->GetTimezone();
                Tmpl["JoinTries"] = NoString(pUser->JoinTries());
                Tmpl["MaxNetworks"] = NoString(pUser->MaxNetworks());
                Tmpl["MaxJoins"] = NoString(pUser->MaxJoins());
                Tmpl["MaxQueryBuffers"] = NoString(pUser->MaxQueryBuffers());

                const std::set<NoString>& ssAllowedHosts = pUser->GetAllowedHosts();
                for (std::set<NoString>::const_iterator it = ssAllowedHosts.begin(); it != ssAllowedHosts.end(); ++it) {
                    NoTemplate& l = Tmpl.AddRow("AllowedHostLoop");
                    l["Host"] = *it;
                }

                const std::vector<NoNetwork*>& vNetworks = pUser->GetNetworks();
                for (uint a = 0; a < vNetworks.size(); a++) {
                    NoTemplate& l = Tmpl.AddRow("NetworkLoop");
                    l["Name"] = vNetworks[a]->GetName();
                    l["Username"] = pUser->GetUserName();
                    l["Clients"] = NoString(vNetworks[a]->GetClients().size());
                    l["IRCNick"] = vNetworks[a]->GetIRCNick().nick();
                    NoServer* pServer = vNetworks[a]->GetCurrentServer();
                    if (pServer) {
                        l["Server"] = pServer->GetName() + ":" + (pServer->IsSSL() ? "+" : "") + NoString(pServer->GetPort());
                    }
                }

                const NoStringMap& msCTCPReplies = pUser->GetCTCPReplies();
                for (NoStringMap::const_iterator it2 = msCTCPReplies.begin(); it2 != msCTCPReplies.end(); ++it2) {
                    NoTemplate& l = Tmpl.AddRow("CTCPLoop");
                    l["CTCP"] = it2->first + " " + it2->second;
                }
            } else {
                Tmpl["Action"] = "adduser";
                Tmpl["Title"] = "Add User";
                Tmpl["StatusPrefix"] = "*";
            }

            NoStringSet ssTimezones = No::timezones();
            for (NoStringSet::iterator i = ssTimezones.begin(); i != ssTimezones.end(); ++i) {
                NoTemplate& l = Tmpl.AddRow("TZLoop");
                l["TZ"] = *i;
            }

#ifdef HAVE_ICU
            for (const NoString& sEncoding : No::encodings()) {
                NoTemplate& l = Tmpl.AddRow("EncodingLoop");
                l["Encoding"] = sEncoding;
            }
            const NoString sEncoding = pUser ? pUser->GetClientEncoding() : "^UTF-8";
            if (sEncoding.empty()) {
                Tmpl["EncodingUtf"] = "legacy";
            } else if (sEncoding[0] == '*') {
                Tmpl["EncodingUtf"] = "receive";
                Tmpl["Encoding"] = sEncoding.substr(1);
            } else if (sEncoding[0] == '^') {
                Tmpl["EncodingUtf"] = "send";
                Tmpl["Encoding"] = sEncoding.substr(1);
            } else {
                Tmpl["EncodingUtf"] = "simple";
                Tmpl["Encoding"] = sEncoding;
            }
#else
            Tmpl["EncodingDisabled"] = "true";
            Tmpl["EncodingUtf"] = "legacy";
#endif

            // To change BindHosts be admin or don't have DenySetBindHost
            if (spSession->IsAdmin() || !spSession->GetUser()->DenySetBindHost()) {
                Tmpl["BindHostEdit"] = "true";
                const NoStringVector& vsBindHosts = NoApp::Get().GetBindHosts();
                if (vsBindHosts.empty()) {
                    if (pUser) {
                        Tmpl["BindHost"] = pUser->GetBindHost();
                        Tmpl["DCCBindHost"] = pUser->GetDCCBindHost();
                    }
                } else {
                    bool bFoundBindHost = false;
                    bool bFoundDCCBindHost = false;
                    for (uint b = 0; b < vsBindHosts.size(); b++) {
                        const NoString& sBindHost = vsBindHosts[b];
                        NoTemplate& l = Tmpl.AddRow("BindHostLoop");
                        NoTemplate& k = Tmpl.AddRow("DCCBindHostLoop");

                        l["BindHost"] = sBindHost;
                        k["BindHost"] = sBindHost;

                        if (pUser && pUser->GetBindHost() == sBindHost) {
                            l["Checked"] = "true";
                            bFoundBindHost = true;
                        }

                        if (pUser && pUser->GetDCCBindHost() == sBindHost) {
                            k["Checked"] = "true";
                            bFoundDCCBindHost = true;
                        }
                    }

                    // If our current bindhost is not in the global list...
                    if (pUser && !bFoundBindHost && !pUser->GetBindHost().empty()) {
                        NoTemplate& l = Tmpl.AddRow("BindHostLoop");

                        l["BindHost"] = pUser->GetBindHost();
                        l["Checked"] = "true";
                    }
                    if (pUser && !bFoundDCCBindHost && !pUser->GetDCCBindHost().empty()) {
                        NoTemplate& l = Tmpl.AddRow("DCCBindHostLoop");

                        l["BindHost"] = pUser->GetDCCBindHost();
                        l["Checked"] = "true";
                    }
                }
            }

            std::vector<NoString> vDirs;
            WebSock.GetAvailSkins(vDirs);

            for (uint d = 0; d < vDirs.size(); d++) {
                const NoString& SubDir = vDirs[d];
                NoTemplate& l = Tmpl.AddRow("SkinLoop");
                l["Name"] = SubDir;

                if (pUser && SubDir == pUser->GetSkinName()) {
                    l["Checked"] = "true";
                }
            }

            std::set<NoModuleInfo> ssUserMods;
            NoApp::Get().GetModules().GetAvailableMods(ssUserMods);

            for (std::set<NoModuleInfo>::iterator it = ssUserMods.begin(); it != ssUserMods.end(); ++it) {
                const NoModuleInfo& Info = *it;
                NoTemplate& l = Tmpl.AddRow("ModuleLoop");

                l["Name"] = Info.GetName();
                l["Description"] = Info.GetDescription();
                l["Wiki"] = Info.GetWikiPage();
                l["HasArgs"] = NoString(Info.GetHasArgs());
                l["ArgsHelpText"] = Info.GetArgsHelpText();

                NoModule* pModule = nullptr;
                if (pUser) {
                    pModule = pUser->GetModules().FindModule(Info.GetName());
                    // Check if module is loaded by all or some networks
                    const std::vector<NoNetwork*>& userNetworks = pUser->GetNetworks();
                    uint networksWithRenderedModuleCount = 0;
                    for (uint networkIndex = 0; networkIndex < userNetworks.size(); ++networkIndex) {
                        const NoNetwork* pCurrentNetwork = userNetworks[networkIndex];
                        const NoModules& networkModules = pCurrentNetwork->GetModules();
                        if (networkModules.FindModule(Info.GetName())) {
                            networksWithRenderedModuleCount++;
                        }
                    }
                    l["CanBeLoadedByNetwork"] = NoString(Info.SupportsType(No::NetworkModule));
                    l["LoadedByAllNetworks"] = NoString(networksWithRenderedModuleCount == userNetworks.size());
                    l["LoadedBySomeNetworks"] = NoString(networksWithRenderedModuleCount != 0);
                }
                if (pModule) {
                    l["Checked"] = "true";
                    l["Args"] = pModule->GetArgs();
                    if (No::UserModule == GetType() && Info.GetName() == GetModName()) {
                        l["Disabled"] = "true";
                    }
                }
                l["CanBeLoadedGlobally"] = NoString(Info.SupportsType(No::GlobalModule));
                // Check if module is loaded globally
                l["LoadedGlobally"] = NoString(NoApp::Get().GetModules().FindModule(Info.GetName()) != nullptr);

                if (!spSession->IsAdmin() && pUser && pUser->DenyLoadMod()) {
                    l["Disabled"] = "true";
                }
            }

            NoTemplate& o1 = Tmpl.AddRow("OptionLoop");
            o1["Name"] = "autoclearchanbuffer";
            o1["DisplayName"] = "Auto Clear Chan Buffer";
            o1["Tooltip"] = "Automatically Clear Channel Buffer After Playback (the default value for new channels)";
            if (!pUser || pUser->AutoClearChanBuffer()) {
                o1["Checked"] = "true";
            }

            /* o2 used to be auto cycle which was removed */

            NoTemplate& o4 = Tmpl.AddRow("OptionLoop");
            o4["Name"] = "multiclients";
            o4["DisplayName"] = "Multi Clients";
            if (!pUser || pUser->MultiClients()) {
                o4["Checked"] = "true";
            }

            NoTemplate& o7 = Tmpl.AddRow("OptionLoop");
            o7["Name"] = "appendtimestamp";
            o7["DisplayName"] = "Append Timestamps";
            if (pUser && pUser->GetTimestampAppend()) {
                o7["Checked"] = "true";
            }

            NoTemplate& o8 = Tmpl.AddRow("OptionLoop");
            o8["Name"] = "prependtimestamp";
            o8["DisplayName"] = "Prepend Timestamps";
            if (pUser && pUser->GetTimestampPrepend()) {
                o8["Checked"] = "true";
            }

            if (spSession->IsAdmin()) {
                NoTemplate& o9 = Tmpl.AddRow("OptionLoop");
                o9["Name"] = "denyloadmod";
                o9["DisplayName"] = "Deny LoadMod";
                if (pUser && pUser->DenyLoadMod()) {
                    o9["Checked"] = "true";
                }

                NoTemplate& o10 = Tmpl.AddRow("OptionLoop");
                o10["Name"] = "isadmin";
                o10["DisplayName"] = "Admin";
                if (pUser && pUser->IsAdmin()) {
                    o10["Checked"] = "true";
                }
                if (pUser && pUser == NoApp::Get().FindUser(WebSock.GetUser())) {
                    o10["Disabled"] = "true";
                }

                NoTemplate& o11 = Tmpl.AddRow("OptionLoop");
                o11["Name"] = "denysetbindhost";
                o11["DisplayName"] = "Deny SetBindHost";
                if (pUser && pUser->DenySetBindHost()) {
                    o11["Checked"] = "true";
                }
            }

            NoTemplate& o12 = Tmpl.AddRow("OptionLoop");
            o12["Name"] = "autoclearquerybuffer";
            o12["DisplayName"] = "Auto Clear Query Buffer";
            o12["Tooltip"] = "Automatically Clear Query Buffer After Playback";
            if (!pUser || pUser->AutoClearQueryBuffer()) {
                o12["Checked"] = "true";
            }

            FOR_EACH_MODULE(i, pUser)
            {
                NoTemplate& mod = Tmpl.AddRow("EmbeddedModuleLoop");
                mod.insert(Tmpl.begin(), Tmpl.end());
                mod["WebadminAction"] = "display";
                if ((*i)->OnEmbeddedWebRequest(WebSock, "webadmin/user", mod)) {
                    mod["Embed"] = WebSock.FindTmpl(*i, "WebadminUser.tmpl");
                    mod["ModName"] = (*i)->GetModName();
                }
            }

            return true;
        }

        /* If pUser is nullptr, we are adding a user, else we are editing this one */

        NoString sUsername = WebSock.GetParam("user");
        if (!pUser && NoApp::Get().FindUser(sUsername)) {
            WebSock.PrintErrorPage("Invalid Submission [User " + sUsername + " already exists]");
            return true;
        }

        NoUser* pNewUser = GetNewUser(WebSock, pUser);
        if (!pNewUser) {
            WebSock.PrintErrorPage("Invalid user settings");
            return true;
        }

        NoString sErr;
        NoString sAction;

        if (!pUser) {
            NoString sClone = WebSock.GetParam("clone");
            if (NoUser* pCloneUser = NoApp::Get().FindUser(sClone)) {
                pNewUser->CloneNetworks(*pCloneUser);
            }

            // Add User Submission
            if (!NoApp::Get().AddUser(pNewUser, sErr)) {
                delete pNewUser;
                WebSock.PrintErrorPage("Invalid submission [" + sErr + "]");
                return true;
            }

            pUser = pNewUser;
            sAction = "added";
        } else {
            // Edit User Submission
            if (!pUser->Clone(*pNewUser, sErr, false)) {
                delete pNewUser;
                WebSock.PrintErrorPage("Invalid Submission [" + sErr + "]");
                return true;
            }

            delete pNewUser;
            sAction = "edited";
        }

        NoTemplate TmplMod;
        TmplMod["Username"] = sUsername;
        TmplMod["WebadminAction"] = "change";
        FOR_EACH_MODULE(it, pUser) { (*it)->OnEmbeddedWebRequest(WebSock, "webadmin/user", TmplMod); }

        if (!NoApp::Get().WriteConfig()) {
            WebSock.PrintErrorPage("User " + sAction + ", but config was not written");
            return true;
        }

        if (spSession->IsAdmin() && WebSock.HasParam("submit_return")) {
            WebSock.Redirect(GetWebPath() + "listusers");
        } else {
            WebSock.Redirect(GetWebPath() + "edituser?user=" + pUser->GetUserName());
        }

        /* we don't want the template to be printed while we redirect */
        return false;
    }

    bool ListUsersPage(NoWebSocket& WebSock, NoTemplate& Tmpl)
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.GetSession();
        const std::map<NoString, NoUser*>& msUsers = NoApp::Get().GetUserMap();
        Tmpl["Title"] = "Manage Users";
        Tmpl["Action"] = "listusers";

        uint a = 0;

        for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it, a++) {
            NoTemplate& l = Tmpl.AddRow("UserLoop");
            NoUser& User = *it->second;

            l["Username"] = User.GetUserName();
            l["Clients"] = NoString(User.GetAllClients().size());
            l["Networks"] = NoString(User.GetNetworks().size());

            if (&User == spSession->GetUser()) {
                l["IsSelf"] = "true";
            }
        }

        return true;
    }

    bool TrafficPage(NoWebSocket& WebSock, NoTemplate& Tmpl)
    {
        Tmpl["Title"] = "Traffic Info";
        Tmpl["Uptime"] = NoApp::Get().GetUptime();

        const std::map<NoString, NoUser*>& msUsers = NoApp::Get().GetUserMap();
        Tmpl["TotalUsers"] = NoString(msUsers.size());

        size_t uiNetworks = 0, uiAttached = 0, uiClients = 0, uiServers = 0;

        for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it) {
            NoUser& User = *it->second;
            std::vector<NoNetwork*> vNetworks = User.GetNetworks();

            for (std::vector<NoNetwork*>::const_iterator it2 = vNetworks.begin(); it2 != vNetworks.end(); ++it2) {
                NoNetwork* pNetwork = *it2;
                uiNetworks++;

                if (pNetwork->IsIRCConnected()) {
                    uiServers++;
                }

                if (pNetwork->IsNetworkAttached()) {
                    uiAttached++;
                }

                uiClients += pNetwork->GetClients().size();
            }

            uiClients += User.GetUserClients().size();
        }

        Tmpl["TotalNetworks"] = NoString(uiNetworks);
        Tmpl["AttachedNetworks"] = NoString(uiAttached);
        Tmpl["TotalCConnections"] = NoString(uiClients);
        Tmpl["TotalIRCConnections"] = NoString(uiServers);

        NoApp::TrafficStatsPair Users, ZNC, Total;
        NoApp::TrafficStatsMap traffic = NoApp::Get().GetTrafficStats(Users, ZNC, Total);
        NoApp::TrafficStatsMap::const_iterator it;

        for (it = traffic.begin(); it != traffic.end(); ++it) {
            NoTemplate& l = Tmpl.AddRow("TrafficLoop");

            l["Username"] = it->first;
            l["In"] = No::toByteStr(it->second.first);
            l["Out"] = No::toByteStr(it->second.second);
            l["Total"] = No::toByteStr(it->second.first + it->second.second);
        }

        Tmpl["UserIn"] = No::toByteStr(Users.first);
        Tmpl["UserOut"] = No::toByteStr(Users.second);
        Tmpl["UserTotal"] = No::toByteStr(Users.first + Users.second);

        Tmpl["ZNCIn"] = No::toByteStr(ZNC.first);
        Tmpl["ZNCOut"] = No::toByteStr(ZNC.second);
        Tmpl["ZNCTotal"] = No::toByteStr(ZNC.first + ZNC.second);

        Tmpl["AllIn"] = No::toByteStr(Total.first);
        Tmpl["AllOut"] = No::toByteStr(Total.second);
        Tmpl["AllTotal"] = No::toByteStr(Total.first + Total.second);

        return true;
    }

    bool AddListener(NoWebSocket& WebSock, NoTemplate& Tmpl)
    {
        ushort uPort = WebSock.GetParam("port").toUShort();
        NoString sHost = WebSock.GetParam("host");
        NoString sURIPrefix = WebSock.GetParam("uriprefix");
        if (sHost == "*") sHost = "";
        bool bSSL = WebSock.GetParam("ssl").toBool();
        bool bIPv4 = WebSock.GetParam("ipv4").toBool();
        bool bIPv6 = WebSock.GetParam("ipv6").toBool();
        bool bIRC = WebSock.GetParam("irc").toBool();
        bool bWeb = WebSock.GetParam("web").toBool();

        No::AddressType eAddr = No::Ipv4AndIpv6Address;
        if (bIPv4) {
            if (bIPv6) {
                eAddr = No::Ipv4AndIpv6Address;
            } else {
                eAddr = No::Ipv4Address;
            }
        } else {
            if (bIPv6) {
                eAddr = No::Ipv6Address;
            } else {
                WebSock.GetSession()->AddError("Choose either IPv4 or IPv6 or both.");
                return SettingsPage(WebSock, Tmpl);
            }
        }

        No::AcceptType eAccept;
        if (bIRC) {
            if (bWeb) {
                eAccept = No::AcceptAll;
            } else {
                eAccept = No::AcceptIrc;
            }
        } else {
            if (bWeb) {
                eAccept = No::AcceptHttp;
            } else {
                WebSock.GetSession()->AddError("Choose either IRC or Web or both.");
                return SettingsPage(WebSock, Tmpl);
            }
        }

        NoString sMessage;
        if (NoApp::Get().AddListener(uPort, sHost, sURIPrefix, bSSL, eAddr, eAccept, sMessage)) {
            if (!sMessage.empty()) {
                WebSock.GetSession()->AddSuccess(sMessage);
            }
            if (!NoApp::Get().WriteConfig()) {
                WebSock.GetSession()->AddError("Port changed, but config was not written");
            }
        } else {
            WebSock.GetSession()->AddError(sMessage);
        }

        return SettingsPage(WebSock, Tmpl);
    }

    bool DelListener(NoWebSocket& WebSock, NoTemplate& Tmpl)
    {
        ushort uPort = WebSock.GetParam("port").toUShort();
        NoString sHost = WebSock.GetParam("host");
        bool bIPv4 = WebSock.GetParam("ipv4").toBool();
        bool bIPv6 = WebSock.GetParam("ipv6").toBool();

        No::AddressType eAddr = No::Ipv4AndIpv6Address;
        if (bIPv4) {
            if (bIPv6) {
                eAddr = No::Ipv4AndIpv6Address;
            } else {
                eAddr = No::Ipv4Address;
            }
        } else {
            if (bIPv6) {
                eAddr = No::Ipv6Address;
            } else {
                WebSock.GetSession()->AddError("Invalid request.");
                return SettingsPage(WebSock, Tmpl);
            }
        }

        NoListener* pListener = NoApp::Get().FindListener(uPort, sHost, eAddr);
        if (pListener) {
            NoApp::Get().DelListener(pListener);
            if (!NoApp::Get().WriteConfig()) {
                WebSock.GetSession()->AddError("Port changed, but config was not written");
            }
        } else {
            WebSock.GetSession()->AddError("The specified listener was not found.");
        }

        return SettingsPage(WebSock, Tmpl);
    }

    bool SettingsPage(NoWebSocket& WebSock, NoTemplate& Tmpl)
    {
        Tmpl.SetFile("settings.tmpl");
        if (!WebSock.GetParam("submitted").toUInt()) {
            Tmpl["Action"] = "settings";
            Tmpl["Title"] = "Settings";
            Tmpl["StatusPrefix"] = NoApp::Get().GetStatusPrefix();
            Tmpl["MaxBufferSize"] = NoString(NoApp::Get().GetMaxBufferSize());
            Tmpl["ConnectDelay"] = NoString(NoApp::Get().GetConnectDelay());
            Tmpl["ServerThrottle"] = NoString(NoApp::Get().GetServerThrottle());
            Tmpl["AnonIPLimit"] = NoString(NoApp::Get().GetAnonIPLimit());
            Tmpl["ProtectWebSessions"] = NoString(NoApp::Get().GetProtectWebSessions());
            Tmpl["HideVersion"] = NoString(NoApp::Get().GetHideVersion());

            const NoStringVector& vsBindHosts = NoApp::Get().GetBindHosts();
            for (uint a = 0; a < vsBindHosts.size(); a++) {
                NoTemplate& l = Tmpl.AddRow("BindHostLoop");
                l["BindHost"] = vsBindHosts[a];
            }

            const NoStringVector& vsMotd = NoApp::Get().GetMotd();
            for (uint b = 0; b < vsMotd.size(); b++) {
                NoTemplate& l = Tmpl.AddRow("MOTDLoop");
                l["Line"] = vsMotd[b];
            }

            const std::vector<NoListener*>& vpListeners = NoApp::Get().GetListeners();
            for (uint c = 0; c < vpListeners.size(); c++) {
                NoListener* pListener = vpListeners[c];
                NoTemplate& l = Tmpl.AddRow("ListenLoop");

                l["Port"] = NoString(pListener->port());
                l["BindHost"] = pListener->bindHost();

                l["IsWeb"] = NoString(pListener->acceptType() != No::AcceptIrc);
                l["IsIRC"] = NoString(pListener->acceptType() != No::AcceptHttp);

                l["URIPrefix"] = pListener->uriPrefix() + "/";

                // simple protection for user from shooting his own foot
                // TODO check also for hosts/families
                // such check is only here, user still can forge HTTP request to delete web port
                l["SuggestDeletion"] = NoString(pListener->port() != WebSock.GetLocalPort());

#ifdef HAVE_LIBSSL
                if (pListener->isSsl()) {
                    l["IsSSL"] = "true";
                }
#endif

#ifdef HAVE_IPV6
                switch (pListener->addressType()) {
                case No::Ipv4Address:
                    l["IsIPV4"] = "true";
                    break;
                case No::Ipv6Address:
                    l["IsIPV6"] = "true";
                    break;
                case No::Ipv4AndIpv6Address:
                    l["IsIPV4"] = "true";
                    l["IsIPV6"] = "true";
                    break;
                }
#else
                l["IsIPV4"] = "true";
#endif
            }

            std::vector<NoString> vDirs;
            WebSock.GetAvailSkins(vDirs);

            for (uint d = 0; d < vDirs.size(); d++) {
                const NoString& SubDir = vDirs[d];
                NoTemplate& l = Tmpl.AddRow("SkinLoop");
                l["Name"] = SubDir;

                if (SubDir == NoApp::Get().GetSkinName()) {
                    l["Checked"] = "true";
                }
            }

            std::set<NoModuleInfo> ssGlobalMods;
            NoApp::Get().GetModules().GetAvailableMods(ssGlobalMods, No::GlobalModule);

            for (std::set<NoModuleInfo>::iterator it = ssGlobalMods.begin(); it != ssGlobalMods.end(); ++it) {
                const NoModuleInfo& Info = *it;
                NoTemplate& l = Tmpl.AddRow("ModuleLoop");

                NoModule* pModule = NoApp::Get().GetModules().FindModule(Info.GetName());
                if (pModule) {
                    l["Checked"] = "true";
                    l["Args"] = pModule->GetArgs();
                    if (No::GlobalModule == GetType() && Info.GetName() == GetModName()) {
                        l["Disabled"] = "true";
                    }
                }

                l["Name"] = Info.GetName();
                l["Description"] = Info.GetDescription();
                l["Wiki"] = Info.GetWikiPage();
                l["HasArgs"] = NoString(Info.GetHasArgs());
                l["ArgsHelpText"] = Info.GetArgsHelpText();

                // Check if the module is loaded by all or some users, and/or by all or some networks
                uint usersWithRenderedModuleCount = 0;
                uint networksWithRenderedModuleCount = 0;
                uint networksCount = 0;
                const std::map<NoString, NoUser*>& allUsers = NoApp::Get().GetUserMap();
                for (std::map<NoString, NoUser*>::const_iterator usersIt = allUsers.begin(); usersIt != allUsers.end(); ++usersIt) {
                    const NoUser& User = *usersIt->second;

                    // Count users which has loaded a render module
                    const NoModules& userModules = User.GetModules();
                    if (userModules.FindModule(Info.GetName())) {
                        usersWithRenderedModuleCount++;
                    }
                    // Count networks which has loaded a render module
                    const std::vector<NoNetwork*>& userNetworks = User.GetNetworks();
                    networksCount += userNetworks.size();
                    for (uint networkIndex = 0; networkIndex < userNetworks.size(); ++networkIndex) {
                        const NoNetwork* pCurrentNetwork = userNetworks[networkIndex];
                        if (pCurrentNetwork->GetModules().FindModule(Info.GetName())) {
                            networksWithRenderedModuleCount++;
                        }
                    }
                }
                l["CanBeLoadedByNetwork"] = NoString(Info.SupportsType(No::NetworkModule));
                l["LoadedByAllNetworks"] = NoString(networksWithRenderedModuleCount == networksCount);
                l["LoadedBySomeNetworks"] = NoString(networksWithRenderedModuleCount != 0);

                l["CanBeLoadedByUser"] = NoString(Info.SupportsType(No::UserModule));
                l["LoadedByAllUsers"] = NoString(usersWithRenderedModuleCount == allUsers.size());
                l["LoadedBySomeUsers"] = NoString(usersWithRenderedModuleCount != 0);
            }

            return true;
        }

        NoString sArg;
        sArg = WebSock.GetParam("statusprefix");
        NoApp::Get().SetStatusPrefix(sArg);
        sArg = WebSock.GetParam("maxbufsize");
        NoApp::Get().SetMaxBufferSize(sArg.toUInt());
        sArg = WebSock.GetParam("connectdelay");
        NoApp::Get().SetConnectDelay(sArg.toUInt());
        sArg = WebSock.GetParam("serverthrottle");
        NoApp::Get().SetServerThrottle(sArg.toUInt());
        sArg = WebSock.GetParam("anoniplimit");
        NoApp::Get().SetAnonIPLimit(sArg.toUInt());
        sArg = WebSock.GetParam("protectwebsessions");
        NoApp::Get().SetProtectWebSessions(sArg.toBool());
        sArg = WebSock.GetParam("hideversion");
        NoApp::Get().SetHideVersion(sArg.toBool());

        NoStringVector vsArgs = WebSock.GetRawParam("motd").split("\n");
        NoApp::Get().ClearMotd();

        uint a = 0;
        for (a = 0; a < vsArgs.size(); a++) {
            NoApp::Get().AddMotd(vsArgs[a].trimRight_n());
        }

        vsArgs = WebSock.GetRawParam("bindhosts").split("\n");
        NoApp::Get().ClearBindHosts();

        for (a = 0; a < vsArgs.size(); a++) {
            NoApp::Get().AddBindHost(vsArgs[a].trim_n());
        }

        NoApp::Get().SetSkinName(WebSock.GetParam("skin"));

        std::set<NoString> ssArgs;
        WebSock.GetParamValues("loadmod", ssArgs);

        for (std::set<NoString>::iterator it = ssArgs.begin(); it != ssArgs.end(); ++it) {
            NoString sModRet;
            NoString sModName = (*it).trimRight_n("\r");
            NoString sModLoadError;

            if (!sModName.empty()) {
                NoString sArgs = WebSock.GetParam("modargs_" + sModName);

                NoModule* pMod = NoApp::Get().GetModules().FindModule(sModName);
                if (!pMod) {
                    if (!NoApp::Get().GetModules().LoadModule(sModName, sArgs, No::GlobalModule, nullptr, nullptr, sModRet)) {
                        sModLoadError = "Unable to load module [" + sModName + "] [" + sModRet + "]";
                    }
                } else if (pMod->GetArgs() != sArgs) {
                    if (!NoApp::Get().GetModules().ReloadModule(sModName, sArgs, nullptr, nullptr, sModRet)) {
                        sModLoadError = "Unable to reload module [" + sModName + "] [" + sModRet + "]";
                    }
                }

                if (!sModLoadError.empty()) {
                    NO_DEBUG(sModLoadError);
                    WebSock.GetSession()->AddError(sModLoadError);
                }
            }
        }

        const NoModules& vCurMods = NoApp::Get().GetModules();
        std::set<NoString> ssUnloadMods;

        for (a = 0; a < vCurMods.size(); a++) {
            NoModule* pCurMod = vCurMods[a];

            if (ssArgs.find(pCurMod->GetModName()) == ssArgs.end() &&
                (No::GlobalModule != GetType() || pCurMod->GetModName() != GetModName())) {
                ssUnloadMods.insert(pCurMod->GetModName());
            }
        }

        for (std::set<NoString>::iterator it2 = ssUnloadMods.begin(); it2 != ssUnloadMods.end(); ++it2) {
            NoApp::Get().GetModules().UnloadModule(*it2);
        }

        if (!NoApp::Get().WriteConfig()) {
            WebSock.GetSession()->AddError("Settings changed, but config was not written");
        }

        WebSock.Redirect(GetWebPath() + "settings");
        /* we don't want the template to be printed while we redirect */
        return false;
    }
};

template <> void no_moduleInfo<NoWebAdminMod>(NoModuleInfo& Info)
{
    Info.AddType(No::UserModule);
    Info.SetWikiPage("webadmin");
}

GLOBALMODULEDEFS(NoWebAdminMod, "Web based administration module.")
