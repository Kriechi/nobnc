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

#include <no/nomodule.h>
#include <no/nomoduleloader.h>
#include <no/nochannel.h>
#include <no/noserverinfo.h>
#include <no/nouser.h>
#include <no/nonetwork.h>
#include <no/noircsocket.h>
#include <no/nodebug.h>
#include <no/noapp.h>
#include <no/nowebsocket.h>
#include <no/nowebsession.h>
#include <no/noescape.h>
#include <no/nolistener.h>
#include <no/noregistry.h>
#include <no/nonick.h>

template <typename T>
static std::vector<NoModule*> allModules(T* p)
{
    std::vector<NoModule*> allMods;
    std::vector<NoModule*> globalMods = NoApp::Get().GetLoader()->modules();
    std::vector<NoModule*> typeMods = p->loader()->modules();
    allMods.reserve(globalMods.size() + typeMods.size());
    allMods.insert(allMods.end(), globalMods.begin(), globalMods.end());
    allMods.insert(allMods.end(), typeMods.begin(), typeMods.end());
    return allMods;
}

template <typename T1, typename T2>
static std::vector<NoModule*> allModules(T1* p1, T2* p2)
{
    std::vector<NoModule*> allMods = allModules(p1);
    std::vector<NoModule*> typeMods = p2->loader()->modules();
    allMods.reserve(allMods.size() + typeMods.size());
    allMods.insert(allMods.end(), typeMods.begin(), typeMods.end());
    return allMods;
}

class NoWebAdminMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoWebAdminMod)
    {
        std::shared_ptr<NoWebPage> settings = std::make_shared<NoWebPage>("settings");
        settings->setTitle("Global Settings");
        settings->setFlags(NoWebPage::Admin);
        AddSubPage(settings);

        std::shared_ptr<NoWebPage> edituser = std::make_shared<NoWebPage>("edituser");
        edituser->setTitle("Your Settings");
        edituser->addParam("user", "");
        AddSubPage(edituser);

        std::shared_ptr<NoWebPage> traffic = std::make_shared<NoWebPage>("traffic");
        traffic->setTitle("Traffic Info");
        traffic->setFlags(NoWebPage::Admin);
        AddSubPage(traffic);

        std::shared_ptr<NoWebPage> listusers = std::make_shared<NoWebPage>("listusers");
        listusers->setTitle("Manage Users");
        listusers->setFlags(NoWebPage::Admin);
        AddSubPage(listusers);
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

        if (sArgs.contains(" ")) {
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
        NoListener* pListener = new NoListener(sListenHost, uPort);
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
            sUsername = pUser->userName();
        }

        NoString sArg = WebSock.GetParam("password");

        if (sArg != WebSock.GetParam("password2")) {
            WebSock.PrintErrorPage("Invalid Submission [Passwords do not match]");
            return nullptr;
        }

        NoUser* pNewUser = new NoUser(sUsername);

        if (!sArg.empty()) {
            NoString sSalt = No::salt();
            NoString sHash = NoUser::saltedHash(sArg, sSalt);
            pNewUser->setPassword(sHash, NoUser::HashDefault, sSalt);
        }

        NoStringVector vsArgs = WebSock.GetRawParam("allowedips").split("\n");
        uint a = 0;

        if (vsArgs.size()) {
            for (a = 0; a < vsArgs.size(); a++) {
                pNewUser->addAllowedHost(vsArgs[a].trim_n());
            }
        } else {
            pNewUser->addAllowedHost("*");
        }

        vsArgs = WebSock.GetRawParam("ctcpreplies").split("\n");
        for (a = 0; a < vsArgs.size(); a++) {
            NoString sReply = vsArgs[a].trimRight_n("\r");
            pNewUser->addCtcpReply(No::token(sReply, 0).trim_n(), No::tokens(sReply, 1).trim_n());
        }

        sArg = WebSock.GetParam("nick");
        if (!sArg.empty()) {
            pNewUser->setNick(sArg);
        }
        sArg = WebSock.GetParam("altnick");
        if (!sArg.empty()) {
            pNewUser->setAltNick(sArg);
        }
        sArg = WebSock.GetParam("statusprefix");
        if (!sArg.empty()) {
            pNewUser->setStatusPrefix(sArg);
        }
        sArg = WebSock.GetParam("ident");
        if (!sArg.empty()) {
            pNewUser->setIdent(sArg);
        }
        sArg = WebSock.GetParam("realname");
        if (!sArg.empty()) {
            pNewUser->setRealName(sArg);
        }
        sArg = WebSock.GetParam("quitmsg");
        if (!sArg.empty()) {
            pNewUser->setQuitMsg(sArg);
        }
        sArg = WebSock.GetParam("chanmodes");
        if (!sArg.empty()) {
            pNewUser->setDefaultChanModes(sArg);
        }
        sArg = WebSock.GetParam("timestampformat");
        if (!sArg.empty()) {
            pNewUser->setTimestampFormat(sArg);
        }

        sArg = WebSock.GetParam("bindhost");
        // To change BindHosts be admin or don't have DenysetBindHost
        if (spSession->isAdmin() || !spSession->user()->denysetBindHost()) {
            NoString sArg2 = WebSock.GetParam("dccbindhost");
            if (!sArg.empty()) {
                pNewUser->setBindHost(sArg);
            }
            if (!sArg2.empty()) {
                pNewUser->setDccBindHost(sArg2);
            }

            const NoStringVector& vsHosts = NoApp::Get().bindHosts();
            if (!spSession->isAdmin() && !vsHosts.empty()) {
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
                    pNewUser->setBindHost(pUser ? pUser->bindHost() : "");
                }
                if (!bFoundDCC) {
                    pNewUser->setDccBindHost(pUser ? pUser->dccBindHost() : "");
                }
            }
        } else if (pUser) {
            pNewUser->setBindHost(pUser->bindHost());
            pNewUser->setDccBindHost(pUser->dccBindHost());
        }

        sArg = WebSock.GetParam("bufsize");
        if (!sArg.empty()) pNewUser->setBufferCount(sArg.toUInt(), spSession->isAdmin());
        if (!sArg.empty()) {
            // First apply the old limit in case the new one is too high
            if (pUser) pNewUser->setBufferCount(pUser->bufferCount(), true);
            pNewUser->setBufferCount(sArg.toUInt(), spSession->isAdmin());
        }

        pNewUser->setSkinName(WebSock.GetParam("skin"));
        pNewUser->setAutoClearChanBuffer(WebSock.GetParam("autoclearchanbuffer").toBool());
        pNewUser->setMultiClients(WebSock.GetParam("multiclients").toBool());
        pNewUser->setTimestampAppend(WebSock.GetParam("appendtimestamp").toBool());
        pNewUser->setTimestampPrepend(WebSock.GetParam("prependtimestamp").toBool());
        pNewUser->setTimezone(WebSock.GetParam("timezone"));
        pNewUser->setJoinTries(WebSock.GetParam("jointries").toUInt());
        pNewUser->setMaxJoins(WebSock.GetParam("maxjoins").toUInt());
        pNewUser->setAutoclearQueryBuffer(WebSock.GetParam("autoclearquerybuffer").toBool());
        pNewUser->setMaxQueryBuffers(WebSock.GetParam("maxquerybuffers").toUInt());

#ifdef HAVE_ICU
        NoString sEncodingUtf = WebSock.GetParam("encoding_utf");
        if (sEncodingUtf == "legacy") {
            pNewUser->setClientEncoding("");
        }
        NoString sEncoding = WebSock.GetParam("encoding");
        if (sEncoding.empty()) {
            sEncoding = "UTF-8";
        }
        if (sEncodingUtf == "send") {
            pNewUser->setClientEncoding("^" + sEncoding);
        } else if (sEncodingUtf == "receive") {
            pNewUser->setClientEncoding("*" + sEncoding);
        } else if (sEncodingUtf == "simple") {
            pNewUser->setClientEncoding(sEncoding);
        }
#endif

        if (spSession->isAdmin()) {
            pNewUser->setDenyLoadMod(WebSock.GetParam("denyloadmod").toBool());
            pNewUser->setDenysetBindHost(WebSock.GetParam("denysetbindhost").toBool());
            sArg = WebSock.GetParam("maxnetworks");
            if (!sArg.empty()) pNewUser->setMaxNetworks(sArg.toUInt());
        } else if (pUser) {
            pNewUser->setDenyLoadMod(pUser->denyLoadMod());
            pNewUser->setDenysetBindHost(pUser->denysetBindHost());
            pNewUser->setMaxNetworks(pUser->maxNetworks());
        }

        // If pUser is not nullptr, we are editing an existing user.
        // Users must not be able to change their own admin flag.
        if (pUser != NoApp::Get().FindUser(WebSock.GetUser())) {
            pNewUser->setAdmin(WebSock.GetParam("isadmin").toBool());
        } else if (pUser) {
            pNewUser->setAdmin(pUser->isAdmin());
        }

        if (spSession->isAdmin() || (pUser && !pUser->denyLoadMod())) {
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
                        if (!pNewUser->loader()->loadModule(sModName, sArgs, No::UserModule, pNewUser, nullptr, sModRet)) {
                            sModLoadError = "Unable to load module [" + sModName + "] [" + sModRet + "]";
                        }
                    } catch (...) {
                        sModLoadError = "Unable to load module [" + sModName + "] [" + sArgs + "]";
                    }

                    if (!sModLoadError.empty()) {
                        NO_DEBUG(sModLoadError);
                        spSession->addError(sModLoadError);
                    }
                }
            }
        } else if (pUser) {
            NoModuleLoader* Modules = pUser->loader();

            for (NoModule* pMod : Modules->modules()) {
                NoString sModName = pMod->GetModName();
                NoString sArgs = pMod->GetArgs();
                NoString sModRet;
                NoString sModLoadError;

                try {
                    if (!pNewUser->loader()->loadModule(sModName, sArgs, No::UserModule, pNewUser, nullptr, sModRet)) {
                        sModLoadError = "Unable to load module [" + sModName + "] [" + sModRet + "]";
                    }
                } catch (...) {
                    sModLoadError = "Unable to load module [" + sModName + "]";
                }

                if (!sModLoadError.empty()) {
                    NO_DEBUG(sModLoadError);
                    spSession->addError(sModLoadError);
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
            pNetwork = pUser->findNetwork(SafeGetNetworkParam(WebSock));
        }

        return pNetwork;
    }

    NoString GetWebMenuTitle() override { return "webadmin"; }
    bool OnWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.GetSession();

        if (sPageName == "settings") {
            // Admin Check
            if (!spSession->isAdmin()) {
                return false;
            }

            return SettingsPage(WebSock, Tmpl);
        } else if (sPageName == "adduser") {
            // Admin Check
            if (!spSession->isAdmin()) {
                return false;
            }

            return UserPage(WebSock, Tmpl);
        } else if (sPageName == "addnetwork") {
            NoUser* pUser = SafeGetUserFromParam(WebSock);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || spSession->user() != pUser)) {
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
            if (!spSession->isAdmin() && (!spSession->user() || !pNetwork || spSession->user() != pNetwork->user())) {
                return false;
            }

            if (!pNetwork) {
                WebSock.PrintErrorPage("No such username or network");
                return true;
            }

            return NetworkPage(WebSock, Tmpl, pNetwork->user(), pNetwork);

        } else if (sPageName == "delnetwork") {
            NoString sUser = WebSock.GetParam("user");
            if (sUser.empty() && !WebSock.IsPost()) {
                sUser = WebSock.GetParam("user", false);
            }

            NoUser* pUser = NoApp::Get().FindUser(sUser);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || spSession->user() != pUser)) {
                return false;
            }

            return DelNetwork(WebSock, pUser, Tmpl);
        } else if (sPageName == "editchan") {
            NoNetwork* pNetwork = SafeGetNetworkFromParam(WebSock);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || !pNetwork || spSession->user() != pNetwork->user())) {
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
            NoChannel* pChan = pNetwork->findChannel(sChan);
            if (!pChan) {
                WebSock.PrintErrorPage("No such channel");
                return true;
            }

            return ChanPage(WebSock, Tmpl, pNetwork, pChan);
        } else if (sPageName == "addchan") {
            NoNetwork* pNetwork = SafeGetNetworkFromParam(WebSock);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || !pNetwork || spSession->user() != pNetwork->user())) {
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
            if (!spSession->isAdmin() && (!spSession->user() || !pNetwork || spSession->user() != pNetwork->user())) {
                return false;
            }

            if (pNetwork) {
                return removeChannel(WebSock, pNetwork);
            }

            WebSock.PrintErrorPage("No such username or network");
            return true;
        } else if (sPageName == "deluser") {
            if (!spSession->isAdmin()) {
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

                Tmpl.setFile("del_user.tmpl");
                Tmpl["Username"] = sUser;
                return true;
            }

            // The "Are you sure?" page has been submitted with "Yes",
            // so we actually delete the user now:

            NoString sUser = WebSock.GetParam("user");
            NoUser* pUser = NoApp::Get().FindUser(sUser);

            if (pUser && pUser == spSession->user()) {
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
                    pUser = spSession->user();
                } // else: the "no such user" message will be printed.
            }

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || spSession->user() != pUser)) {
                return false;
            }

            if (pUser) {
                return UserPage(WebSock, Tmpl, pUser);
            }

            WebSock.PrintErrorPage("No such username");
            return true;
        } else if (sPageName == "listusers" && spSession->isAdmin()) {
            return ListUsersPage(WebSock, Tmpl);
        } else if (sPageName == "traffic" && spSession->isAdmin()) {
            return TrafficPage(WebSock, Tmpl);
        } else if (sPageName == "index") {
            return true;
        } else if (sPageName == "add_listener") {
            // Admin Check
            if (!spSession->isAdmin()) {
                return false;
            }

            return AddListener(WebSock, Tmpl);
        } else if (sPageName == "del_listener") {
            // Admin Check
            if (!spSession->isAdmin()) {
                return false;
            }

            return DelListener(WebSock, Tmpl);
        }

        return false;
    }

    bool ChanPage(NoWebSocket& WebSock, NoTemplate& Tmpl, NoNetwork* pNetwork, NoChannel* pChan = nullptr)
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.GetSession();
        Tmpl.setFile("add_edit_chan.tmpl");
        NoUser* pUser = pNetwork->user();

        if (!pUser) {
            WebSock.PrintErrorPage("That user doesn't exist");
            return true;
        }

        if (!WebSock.GetParam("submitted").toUInt()) {
            Tmpl["User"] = pUser->userName();
            Tmpl["Network"] = pNetwork->name();

            if (pChan) {
                Tmpl["Action"] = "editchan";
                Tmpl["Edit"] = "true";
                Tmpl["Title"] = "Edit Channel" + NoString(" [" + pChan->name() + "]") + " of Network [" +
                                pNetwork->name() + "] of User [" + pNetwork->user()->userName() + "]";
                Tmpl["ChanName"] = pChan->name();
                Tmpl["BufferCount"] = NoString(pChan->bufferCount());
                Tmpl["DefModes"] = pChan->defaultModes();
                Tmpl["Key"] = pChan->key();

                if (pChan->inConfig()) {
                    Tmpl["InConfig"] = "true";
                }
            } else {
                Tmpl["Action"] = "addchan";
                Tmpl["Title"] = "Add Channel" + NoString(" for User [" + pUser->userName() + "]");
                Tmpl["BufferCount"] = NoString(pUser->bufferCount());
                Tmpl["DefModes"] = NoString(pUser->defaultChanModes());
                Tmpl["InConfig"] = "true";
            }

            // o1 used to be AutoCycle which was removed

            NoTemplate& o2 = Tmpl.addRow("OptionLoop");
            o2["Name"] = "autoclearchanbuffer";
            o2["DisplayName"] = "Auto Clear Chan Buffer";
            o2["Tooltip"] = "Automatically Clear Channel Buffer After Playback";
            if ((pChan && pChan->autoClearChanBuffer()) || (!pChan && pUser->autoClearChanBuffer())) {
                o2["Checked"] = "true";
            }

            NoTemplate& o3 = Tmpl.addRow("OptionLoop");
            o3["Name"] = "detached";
            o3["DisplayName"] = "Detached";
            if (pChan && pChan->isDetached()) {
                o3["Checked"] = "true";
            }

            NoTemplate& o4 = Tmpl.addRow("OptionLoop");
            o4["Name"] = "disabled";
            o4["DisplayName"] = "Disabled";
            if (pChan && pChan->isDisabled()) {
                o4["Checked"] = "true";
            }

            for (NoModule* pMod : allModules(pNetwork)) {
                NoTemplate& mod = Tmpl.addRow("EmbeddedModuleLoop");
                mod.insert(Tmpl.begin(), Tmpl.end());
                mod["WebadminAction"] = "display";
                if (pMod->OnEmbeddedWebRequest(WebSock, "webadmin/channel", mod)) {
                    mod["Embed"] = WebSock.FindTmpl(pMod, "WebadminChan.tmpl");
                    mod["ModName"] = pMod->GetModName();
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

            if (pNetwork->findChannel(pChan->name())) {
                WebSock.PrintErrorPage("Channel [" + pChan->name() + "] already exists");
                delete pChan;
                return true;
            }

            if (!pNetwork->addChannel(pChan)) {
                WebSock.PrintErrorPage("Could not add channel [" + pChan->name() + "]");
                return true;
            }
        }

        uint uBufferCount = WebSock.GetParam("buffercount").toUInt();
        if (pChan->bufferCount() != uBufferCount) {
            pChan->setBufferCount(uBufferCount, spSession->isAdmin());
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
        TmplMod["User"] = pUser->userName();
        TmplMod["ChanName"] = pChan->name();
        TmplMod["WebadminAction"] = "change";
        for (NoModule* pMod : allModules(pNetwork)) {
            pMod->OnEmbeddedWebRequest(WebSock, "webadmin/channel", TmplMod);
        }

        if (!NoApp::Get().WriteConfig()) {
            WebSock.PrintErrorPage("Channel added/modified, but config was not written");
            return true;
        }

        if (WebSock.HasParam("submit_return")) {
            WebSock.Redirect(GetWebPath() + "editnetwork?user=" + No::escape(pUser->userName(), No::UrlFormat) +
                             "&network=" + No::escape(pNetwork->name(), No::UrlFormat));
        } else {
            WebSock.Redirect(GetWebPath() + "editchan?user=" + No::escape(pUser->userName(), No::UrlFormat) +
                             "&network=" + No::escape(pNetwork->name(), No::UrlFormat) + "&name=" +
                             No::escape(pChan->name(), No::UrlFormat));
        }
        return true;
    }

    bool NetworkPage(NoWebSocket& WebSock, NoTemplate& Tmpl, NoUser* pUser, NoNetwork* pNetwork = nullptr)
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.GetSession();
        Tmpl.setFile("add_edit_network.tmpl");

        if (!WebSock.GetParam("submitted").toUInt()) {
            Tmpl["Username"] = pUser->userName();

            std::set<NoModuleInfo> ssNetworkMods;
            NoApp::Get().GetLoader()->availableModules(ssNetworkMods, No::NetworkModule);
            for (std::set<NoModuleInfo>::iterator it = ssNetworkMods.begin(); it != ssNetworkMods.end(); ++it) {
                const NoModuleInfo& Info = *it;
                NoTemplate& l = Tmpl.addRow("ModuleLoop");

                l["Name"] = Info.name();
                l["Description"] = Info.description();
                l["Wiki"] = Info.wikiPage();
                l["HasArgs"] = NoString(Info.hasArgs());
                l["ArgsHelpText"] = Info.argsHelpText();

                if (pNetwork) {
                    NoModule* pModule = pNetwork->loader()->findModule(Info.name());
                    if (pModule) {
                        l["Checked"] = "true";
                        l["Args"] = pModule->GetArgs();
                    }
                }

                // Check if module is loaded globally
                l["CanBeLoadedGlobally"] = NoString(Info.supportsType(No::GlobalModule));
                l["LoadedGlobally"] = NoString(NoApp::Get().GetLoader()->findModule(Info.name()) != nullptr);

                // Check if module is loaded by user
                l["CanBeLoadedByUser"] = NoString(Info.supportsType(No::UserModule));
                l["LoadedByUser"] = NoString(pUser->loader()->findModule(Info.name()) != nullptr);

                if (!spSession->isAdmin() && pUser->denyLoadMod()) {
                    l["Disabled"] = "true";
                }
            }

            // To change BindHosts be admin or don't have DenysetBindHost
            if (spSession->isAdmin() || !spSession->user()->denysetBindHost()) {
                Tmpl["BindHostEdit"] = "true";
                const NoStringVector& vsBindHosts = NoApp::Get().bindHosts();
                if (vsBindHosts.empty()) {
                    if (pNetwork) {
                        Tmpl["BindHost"] = pNetwork->bindHost();
                    }
                } else {
                    bool bFoundBindHost = false;
                    for (uint b = 0; b < vsBindHosts.size(); b++) {
                        const NoString& sBindHost = vsBindHosts[b];
                        NoTemplate& l = Tmpl.addRow("BindHostLoop");

                        l["BindHost"] = sBindHost;

                        if (pNetwork && pNetwork->bindHost() == sBindHost) {
                            l["Checked"] = "true";
                            bFoundBindHost = true;
                        }
                    }

                    // If our current bindhost is not in the global list...
                    if (pNetwork && !bFoundBindHost && !pNetwork->bindHost().empty()) {
                        NoTemplate& l = Tmpl.addRow("BindHostLoop");

                        l["BindHost"] = pNetwork->bindHost();
                        l["Checked"] = "true";
                    }
                }
            }

            if (pNetwork) {
                Tmpl["Action"] = "editnetwork";
                Tmpl["Edit"] = "true";
                Tmpl["Title"] =
                "Edit Network" + NoString(" [" + pNetwork->name() + "]") + " of User [" + pUser->userName() + "]";
                Tmpl["Name"] = pNetwork->name();

                Tmpl["Nick"] = pNetwork->nick();
                Tmpl["AltNick"] = pNetwork->altNick();
                Tmpl["Ident"] = pNetwork->ident();
                Tmpl["RealName"] = pNetwork->realName();

                Tmpl["QuitMsg"] = pNetwork->quitMsg();

                Tmpl["FloodProtection"] = NoString(NoIrcSocket::IsFloodProtected(pNetwork->floodRate()));
                Tmpl["FloodRate"] = NoString(pNetwork->floodRate());
                Tmpl["FloodBurst"] = NoString(pNetwork->floodBurst());

                Tmpl["JoinDelay"] = NoString(pNetwork->joinDelay());

                Tmpl["IRCConnectEnabled"] = NoString(pNetwork->isEnabled());

                const std::vector<NoServerInfo*>& vServers = pNetwork->servers();
                for (uint a = 0; a < vServers.size(); a++) {
                    NoTemplate& l = Tmpl.addRow("ServerLoop");
                    l["Server"] = vServers[a]->toString();
                }

                const std::vector<NoChannel*>& Channels = pNetwork->channels();
                for (uint c = 0; c < Channels.size(); c++) {
                    NoChannel* pChan = Channels[c];
                    NoTemplate& l = Tmpl.addRow("ChannelLoop");

                    l["Network"] = pNetwork->name();
                    l["Username"] = pUser->userName();
                    l["Name"] = pChan->name();
                    l["Perms"] = pChan->permStr();
                    l["CurModes"] = pChan->modeString();
                    l["DefModes"] = pChan->defaultModes();
                    if (pChan->hasBufferCountSet()) {
                        l["BufferCount"] = NoString(pChan->bufferCount());
                    } else {
                        l["BufferCount"] = NoString(pChan->bufferCount()) + " (default)";
                    }
                    l["Options"] = pChan->options();

                    if (pChan->inConfig()) {
                        l["InConfig"] = "true";
                    }
                }
                for (const NoString& sFP : pNetwork->trustedFingerprints()) {
                    NoTemplate& l = Tmpl.addRow("TrustedFingerprints");
                    l["FP"] = sFP;
                }
            } else {
                if (!spSession->isAdmin() && !pUser->hasSpaceForNewNetwork()) {
                    WebSock.PrintErrorPage("Network number limit reached. Ask an admin to increase the limit for you, "
                                           "or delete unneeded networks from Your Settings.");
                    return true;
                }

                Tmpl["Action"] = "addnetwork";
                Tmpl["Title"] = "Add Network for User [" + pUser->userName() + "]";
                Tmpl["IRCConnectEnabled"] = "true";
                Tmpl["FloodProtection"] = "true";
                Tmpl["FloodRate"] = "1.0";
                Tmpl["FloodBurst"] = "4";
                Tmpl["JoinDelay"] = "0";
            }

            for (NoModule* pMod : allModules(pUser, pNetwork)) {
                NoTemplate& mod = Tmpl.addRow("EmbeddedModuleLoop");
                mod.insert(Tmpl.begin(), Tmpl.end());
                mod["WebadminAction"] = "display";
                if (pMod->OnEmbeddedWebRequest(WebSock, "webadmin/network", mod)) {
                    mod["Embed"] = WebSock.FindTmpl(pMod, "WebadminNetwork.tmpl");
                    mod["ModName"] = pMod->GetModName();
                }
            }

#ifdef HAVE_ICU
            for (const NoString& sEncoding : No::encodings()) {
                NoTemplate& l = Tmpl.addRow("EncodingLoop");
                l["Encoding"] = sEncoding;
            }
            const NoString sEncoding = pNetwork ? pNetwork->encoding() : "^UTF-8";
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
        if (!pNetwork && !spSession->isAdmin() && !pUser->hasSpaceForNewNetwork()) {
            WebSock.PrintErrorPage("Network number limit reached. Ask an admin to increase the limit for you, or "
                                   "delete few old ones from Your Settings");
            return true;
        }
        if (!pNetwork || pNetwork->name() != sName) {
            NoString sNetworkAddError;
            NoNetwork* pOldNetwork = pNetwork;
            pNetwork = pUser->addNetwork(sName, sNetworkAddError);
            if (!pNetwork) {
                WebSock.PrintErrorPage(sNetworkAddError);
                return true;
            }
            if (pOldNetwork) {
                for (NoModule* pModule : pOldNetwork->loader()->modules()) {
                    NoString sPath = pUser->userPath() + "/networks/" + sName + "/moddata/" + pModule->GetModName();
                    NoRegistry registry(pModule);
                    registry.copy(sPath);
                }
                pNetwork->clone(*pOldNetwork, false);
                pUser->deleteNetwork(pOldNetwork->name());
            }
        }

        NoString sArg;

        pNetwork->setNick(WebSock.GetParam("nick"));
        pNetwork->setAltNick(WebSock.GetParam("altnick"));
        pNetwork->setIdent(WebSock.GetParam("ident"));
        pNetwork->setRealName(WebSock.GetParam("realname"));

        pNetwork->setQuitMsg(WebSock.GetParam("quitmsg"));

        pNetwork->setEnabled(WebSock.GetParam("doconnect").toBool());

        sArg = WebSock.GetParam("bindhost");
        // To change BindHosts be admin or don't have DenysetBindHost
        if (spSession->isAdmin() || !spSession->user()->denysetBindHost()) {
            NoString sHost = WebSock.GetParam("bindhost");
            const NoStringVector& vsHosts = NoApp::Get().bindHosts();
            if (!spSession->isAdmin() && !vsHosts.empty()) {
                NoStringVector::const_iterator it;
                bool bFound = false;

                for (it = vsHosts.begin(); it != vsHosts.end(); ++it) {
                    if (sHost.equals(*it)) {
                        bFound = true;
                        break;
                    }
                }

                if (!bFound) {
                    sHost = pNetwork->bindHost();
                }
            }
            pNetwork->setBindHost(sHost);
        }

        if (WebSock.GetParam("floodprotection").toBool()) {
            pNetwork->setFloodRate(WebSock.GetParam("floodrate").toDouble());
            pNetwork->setFloodBurst(WebSock.GetParam("floodburst").toUShort());
        } else {
            pNetwork->setFloodRate(-1);
        }

        pNetwork->setJoinDelay(WebSock.GetParam("joindelay").toUShort());

#ifdef HAVE_ICU
        NoString sEncodingUtf = WebSock.GetParam("encoding_utf");
        if (sEncodingUtf == "legacy") {
            pNetwork->setEncoding("");
        }
        NoString sEncoding = WebSock.GetParam("encoding");
        if (sEncoding.empty()) {
            sEncoding = "UTF-8";
        }
        if (sEncodingUtf == "send") {
            pNetwork->setEncoding("^" + sEncoding);
        } else if (sEncodingUtf == "receive") {
            pNetwork->setEncoding("*" + sEncoding);
        } else if (sEncodingUtf == "simple") {
            pNetwork->setEncoding(sEncoding);
        }
#endif

        pNetwork->delServers();
        NoStringVector vsArgs = WebSock.GetRawParam("servers").split("\n");
        for (uint a = 0; a < vsArgs.size(); a++) {
            pNetwork->addServer(vsArgs[a].trim_n());
        }

        vsArgs = WebSock.GetRawParam("fingerprints").split("\n");
        while (!pNetwork->trustedFingerprints().empty()) {
            pNetwork->removeTrustedFingerprint(*pNetwork->trustedFingerprints().begin());
        }
        for (const NoString& sFP : vsArgs) {
            pNetwork->addTrustedFingerprint(sFP);
        }

        WebSock.GetParamValues("channel", vsArgs);
        for (uint a = 0; a < vsArgs.size(); a++) {
            const NoString& sChan = vsArgs[a];
            NoChannel* pChan = pNetwork->findChannel(sChan.trimRight_n("\r"));
            if (pChan) {
                pChan->setInConfig(WebSock.GetParam("save_" + sChan).toBool());
            }
        }

        std::set<NoString> ssArgs;
        WebSock.GetParamValues("loadmod", ssArgs);
        if (spSession->isAdmin() || !pUser->denyLoadMod()) {
            for (std::set<NoString>::iterator it = ssArgs.begin(); it != ssArgs.end(); ++it) {
                NoString sModRet;
                NoString sModName = (*it).trimRight_n("\r");
                NoString sModLoadError;

                if (!sModName.empty()) {
                    NoString sArgs = WebSock.GetParam("modargs_" + sModName);

                    NoModule* pMod = pNetwork->loader()->findModule(sModName);

                    if (!pMod) {
                        if (!pNetwork->loader()->loadModule(sModName, sArgs, No::NetworkModule, pUser, pNetwork, sModRet)) {
                            sModLoadError = "Unable to load module [" + sModName + "] [" + sModRet + "]";
                        }
                    } else if (pMod->GetArgs() != sArgs) {
                        if (!pNetwork->loader()->reloadModule(sModName, sArgs, pUser, pNetwork, sModRet)) {
                            sModLoadError = "Unable to reload module [" + sModName + "] [" + sModRet + "]";
                        }
                    }

                    if (!sModLoadError.empty()) {
                        NO_DEBUG(sModLoadError);
                        WebSock.GetSession()->addError(sModLoadError);
                    }
                }
            }
        }

        const NoModuleLoader* vCurMods = pNetwork->loader();
        std::set<NoString> ssUnloadMods;

        for (NoModule* pCurMod : vCurMods->modules()) {
            if (ssArgs.find(pCurMod->GetModName()) == ssArgs.end() && pCurMod->GetModName() != GetModName()) {
                ssUnloadMods.insert(pCurMod->GetModName());
            }
        }

        for (std::set<NoString>::iterator it2 = ssUnloadMods.begin(); it2 != ssUnloadMods.end(); ++it2) {
            pNetwork->loader()->unloadModule(*it2);
        }

        NoTemplate TmplMod;
        TmplMod["Username"] = pUser->userName();
        TmplMod["Name"] = pNetwork->name();
        TmplMod["WebadminAction"] = "change";
        for (NoModule* pMod : allModules(pUser, pNetwork)) {
            pMod->OnEmbeddedWebRequest(WebSock, "webadmin/network", TmplMod);
        }

        if (!NoApp::Get().WriteConfig()) {
            WebSock.PrintErrorPage("Network added/modified, but config was not written");
            return true;
        }

        if (WebSock.HasParam("submit_return")) {
            WebSock.Redirect(GetWebPath() + "edituser?user=" + No::escape(pUser->userName(), No::UrlFormat));
        } else {
            WebSock.Redirect(GetWebPath() + "editnetwork?user=" + No::escape(pUser->userName(), No::UrlFormat) +
                             "&network=" + No::escape(pNetwork->name(), No::UrlFormat));
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

            Tmpl.setFile("del_network.tmpl");
            Tmpl["Username"] = pUser->userName();
            Tmpl["Network"] = sNetwork;
            return true;
        }

        pUser->deleteNetwork(sNetwork);

        if (!NoApp::Get().WriteConfig()) {
            WebSock.PrintErrorPage("Network deleted, but config was not written");
            return true;
        }

        WebSock.Redirect(GetWebPath() + "edituser?user=" + No::escape(pUser->userName(), No::UrlFormat));
        return false;
    }

    bool removeChannel(NoWebSocket& WebSock, NoNetwork* pNetwork)
    {
        NoString sChan = WebSock.GetParam("name", false);

        if (sChan.empty()) {
            WebSock.PrintErrorPage("That channel doesn't exist for this user");
            return true;
        }

        pNetwork->removeChannel(sChan);
        pNetwork->putIrc("PART " + sChan);

        if (!NoApp::Get().WriteConfig()) {
            WebSock.PrintErrorPage("Channel deleted, but config was not written");
            return true;
        }

        WebSock.Redirect(GetWebPath() + "editnetwork?user=" + No::escape(pNetwork->user()->userName(), No::UrlFormat) +
                         "&network=" + No::escape(pNetwork->name(), No::UrlFormat));
        return false;
    }

    bool UserPage(NoWebSocket& WebSock, NoTemplate& Tmpl, NoUser* pUser = nullptr)
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.GetSession();
        Tmpl.setFile("add_edit_user.tmpl");

        if (!WebSock.GetParam("submitted").toUInt()) {
            if (pUser) {
                Tmpl["Action"] = "edituser";
                Tmpl["Title"] = "Edit User [" + pUser->userName() + "]";
                Tmpl["Edit"] = "true";
            } else {
                NoString sUsername = WebSock.GetParam("clone", false);
                pUser = NoApp::Get().FindUser(sUsername);

                if (pUser) {
                    Tmpl["Title"] = "Clone User [" + pUser->userName() + "]";
                    Tmpl["Clone"] = "true";
                    Tmpl["CloneUsername"] = pUser->userName();
                }
            }

            Tmpl["ImAdmin"] = NoString(spSession->isAdmin());

            if (pUser) {
                Tmpl["Username"] = pUser->userName();
                Tmpl["Nick"] = pUser->nick();
                Tmpl["AltNick"] = pUser->altNick();
                Tmpl["StatusPrefix"] = pUser->statusPrefix();
                Tmpl["Ident"] = pUser->ident();
                Tmpl["RealName"] = pUser->realName();
                Tmpl["QuitMsg"] = pUser->quitMsg();
                Tmpl["DefaultChanModes"] = pUser->defaultChanModes();
                Tmpl["BufferCount"] = NoString(pUser->bufferCount());
                Tmpl["TimestampFormat"] = pUser->timestampFormat();
                Tmpl["Timezone"] = pUser->timezone();
                Tmpl["JoinTries"] = NoString(pUser->joinTries());
                Tmpl["MaxNetworks"] = NoString(pUser->maxNetworks());
                Tmpl["MaxJoins"] = NoString(pUser->maxJoins());
                Tmpl["MaxQueryBuffers"] = NoString(pUser->maxQueryBuffers());

                const std::set<NoString>& ssAllowedHosts = pUser->allowedHosts();
                for (std::set<NoString>::const_iterator it = ssAllowedHosts.begin(); it != ssAllowedHosts.end(); ++it) {
                    NoTemplate& l = Tmpl.addRow("AllowedHostLoop");
                    l["Host"] = *it;
                }

                const std::vector<NoNetwork*>& vNetworks = pUser->networks();
                for (uint a = 0; a < vNetworks.size(); a++) {
                    NoTemplate& l = Tmpl.addRow("NetworkLoop");
                    l["Name"] = vNetworks[a]->name();
                    l["Username"] = pUser->userName();
                    l["Clients"] = NoString(vNetworks[a]->clients().size());
                    l["IRCNick"] = vNetworks[a]->ircNick().nick();
                    NoServerInfo* pServer = vNetworks[a]->currentServer();
                    if (pServer) {
                        l["Server"] = pServer->host() + ":" + (pServer->isSsl() ? "+" : "") + NoString(pServer->port());
                    }
                }

                const NoStringMap& msCTCPReplies = pUser->ctcpReplies();
                for (NoStringMap::const_iterator it2 = msCTCPReplies.begin(); it2 != msCTCPReplies.end(); ++it2) {
                    NoTemplate& l = Tmpl.addRow("CTCPLoop");
                    l["CTCP"] = it2->first + " " + it2->second;
                }
            } else {
                Tmpl["Action"] = "adduser";
                Tmpl["Title"] = "Add User";
                Tmpl["StatusPrefix"] = "*";
            }

            NoStringSet ssTimezones = No::timezones();
            for (NoStringSet::iterator i = ssTimezones.begin(); i != ssTimezones.end(); ++i) {
                NoTemplate& l = Tmpl.addRow("TZLoop");
                l["TZ"] = *i;
            }

#ifdef HAVE_ICU
            for (const NoString& sEncoding : No::encodings()) {
                NoTemplate& l = Tmpl.addRow("EncodingLoop");
                l["Encoding"] = sEncoding;
            }
            const NoString sEncoding = pUser ? pUser->clientEncoding() : "^UTF-8";
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

            // To change BindHosts be admin or don't have DenysetBindHost
            if (spSession->isAdmin() || !spSession->user()->denysetBindHost()) {
                Tmpl["BindHostEdit"] = "true";
                const NoStringVector& vsBindHosts = NoApp::Get().bindHosts();
                if (vsBindHosts.empty()) {
                    if (pUser) {
                        Tmpl["BindHost"] = pUser->bindHost();
                        Tmpl["DCCBindHost"] = pUser->dccBindHost();
                    }
                } else {
                    bool bFoundBindHost = false;
                    bool bFoundDCCBindHost = false;
                    for (uint b = 0; b < vsBindHosts.size(); b++) {
                        const NoString& sBindHost = vsBindHosts[b];
                        NoTemplate& l = Tmpl.addRow("BindHostLoop");
                        NoTemplate& k = Tmpl.addRow("DCCBindHostLoop");

                        l["BindHost"] = sBindHost;
                        k["BindHost"] = sBindHost;

                        if (pUser && pUser->bindHost() == sBindHost) {
                            l["Checked"] = "true";
                            bFoundBindHost = true;
                        }

                        if (pUser && pUser->dccBindHost() == sBindHost) {
                            k["Checked"] = "true";
                            bFoundDCCBindHost = true;
                        }
                    }

                    // If our current bindhost is not in the global list...
                    if (pUser && !bFoundBindHost && !pUser->bindHost().empty()) {
                        NoTemplate& l = Tmpl.addRow("BindHostLoop");

                        l["BindHost"] = pUser->bindHost();
                        l["Checked"] = "true";
                    }
                    if (pUser && !bFoundDCCBindHost && !pUser->dccBindHost().empty()) {
                        NoTemplate& l = Tmpl.addRow("DCCBindHostLoop");

                        l["BindHost"] = pUser->dccBindHost();
                        l["Checked"] = "true";
                    }
                }
            }

            std::vector<NoString> vDirs;
            WebSock.GetAvailSkins(vDirs);

            for (uint d = 0; d < vDirs.size(); d++) {
                const NoString& SubDir = vDirs[d];
                NoTemplate& l = Tmpl.addRow("SkinLoop");
                l["Name"] = SubDir;

                if (pUser && SubDir == pUser->skinName()) {
                    l["Checked"] = "true";
                }
            }

            std::set<NoModuleInfo> ssUserMods;
            NoApp::Get().GetLoader()->availableModules(ssUserMods);

            for (std::set<NoModuleInfo>::iterator it = ssUserMods.begin(); it != ssUserMods.end(); ++it) {
                const NoModuleInfo& Info = *it;
                NoTemplate& l = Tmpl.addRow("ModuleLoop");

                l["Name"] = Info.name();
                l["Description"] = Info.description();
                l["Wiki"] = Info.wikiPage();
                l["HasArgs"] = NoString(Info.hasArgs());
                l["ArgsHelpText"] = Info.argsHelpText();

                NoModule* pModule = nullptr;
                if (pUser) {
                    pModule = pUser->loader()->findModule(Info.name());
                    // Check if module is loaded by all or some networks
                    const std::vector<NoNetwork*>& userNetworks = pUser->networks();
                    uint networksWithRenderedModuleCount = 0;
                    for (uint networkIndex = 0; networkIndex < userNetworks.size(); ++networkIndex) {
                        const NoNetwork* pCurrentNetwork = userNetworks[networkIndex];
                        const NoModuleLoader* networkModules = pCurrentNetwork->loader();
                        if (networkModules->findModule(Info.name())) {
                            networksWithRenderedModuleCount++;
                        }
                    }
                    l["CanBeLoadedByNetwork"] = NoString(Info.supportsType(No::NetworkModule));
                    l["LoadedByAllNetworks"] = NoString(networksWithRenderedModuleCount == userNetworks.size());
                    l["LoadedBySomeNetworks"] = NoString(networksWithRenderedModuleCount != 0);
                }
                if (pModule) {
                    l["Checked"] = "true";
                    l["Args"] = pModule->GetArgs();
                    if (No::UserModule == GetType() && Info.name() == GetModName()) {
                        l["Disabled"] = "true";
                    }
                }
                l["CanBeLoadedGlobally"] = NoString(Info.supportsType(No::GlobalModule));
                // Check if module is loaded globally
                l["LoadedGlobally"] = NoString(NoApp::Get().GetLoader()->findModule(Info.name()) != nullptr);

                if (!spSession->isAdmin() && pUser && pUser->denyLoadMod()) {
                    l["Disabled"] = "true";
                }
            }

            NoTemplate& o1 = Tmpl.addRow("OptionLoop");
            o1["Name"] = "autoclearchanbuffer";
            o1["DisplayName"] = "Auto Clear Chan Buffer";
            o1["Tooltip"] = "Automatically Clear Channel Buffer After Playback (the default value for new channels)";
            if (!pUser || pUser->autoClearChanBuffer()) {
                o1["Checked"] = "true";
            }

            /* o2 used to be auto cycle which was removed */

            NoTemplate& o4 = Tmpl.addRow("OptionLoop");
            o4["Name"] = "multiclients";
            o4["DisplayName"] = "Multi Clients";
            if (!pUser || pUser->multiClients()) {
                o4["Checked"] = "true";
            }

            NoTemplate& o7 = Tmpl.addRow("OptionLoop");
            o7["Name"] = "appendtimestamp";
            o7["DisplayName"] = "Append Timestamps";
            if (pUser && pUser->timestampAppend()) {
                o7["Checked"] = "true";
            }

            NoTemplate& o8 = Tmpl.addRow("OptionLoop");
            o8["Name"] = "prependtimestamp";
            o8["DisplayName"] = "Prepend Timestamps";
            if (pUser && pUser->timestampPrepend()) {
                o8["Checked"] = "true";
            }

            if (spSession->isAdmin()) {
                NoTemplate& o9 = Tmpl.addRow("OptionLoop");
                o9["Name"] = "denyloadmod";
                o9["DisplayName"] = "Deny LoadMod";
                if (pUser && pUser->denyLoadMod()) {
                    o9["Checked"] = "true";
                }

                NoTemplate& o10 = Tmpl.addRow("OptionLoop");
                o10["Name"] = "isadmin";
                o10["DisplayName"] = "Admin";
                if (pUser && pUser->isAdmin()) {
                    o10["Checked"] = "true";
                }
                if (pUser && pUser == NoApp::Get().FindUser(WebSock.GetUser())) {
                    o10["Disabled"] = "true";
                }

                NoTemplate& o11 = Tmpl.addRow("OptionLoop");
                o11["Name"] = "denysetbindhost";
                o11["DisplayName"] = "Deny setBindHost";
                if (pUser && pUser->denysetBindHost()) {
                    o11["Checked"] = "true";
                }
            }

            NoTemplate& o12 = Tmpl.addRow("OptionLoop");
            o12["Name"] = "autoclearquerybuffer";
            o12["DisplayName"] = "Auto Clear Query Buffer";
            o12["Tooltip"] = "Automatically Clear Query Buffer After Playback";
            if (!pUser || pUser->autoclearQueryBuffer()) {
                o12["Checked"] = "true";
            }

            for (NoModule* pMod : allModules(pUser)) {
                NoTemplate& mod = Tmpl.addRow("EmbeddedModuleLoop");
                mod.insert(Tmpl.begin(), Tmpl.end());
                mod["WebadminAction"] = "display";
                if (pMod->OnEmbeddedWebRequest(WebSock, "webadmin/user", mod)) {
                    mod["Embed"] = WebSock.FindTmpl(pMod, "WebadminUser.tmpl");
                    mod["ModName"] = pMod->GetModName();
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
                pNewUser->cloneNetworks(*pCloneUser);
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
            if (!pUser->clone(*pNewUser, sErr, false)) {
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
        for (NoModule* pMod : allModules(pUser)) {
            pMod->OnEmbeddedWebRequest(WebSock, "webadmin/user", TmplMod);
        }

        if (!NoApp::Get().WriteConfig()) {
            WebSock.PrintErrorPage("User " + sAction + ", but config was not written");
            return true;
        }

        if (spSession->isAdmin() && WebSock.HasParam("submit_return")) {
            WebSock.Redirect(GetWebPath() + "listusers");
        } else {
            WebSock.Redirect(GetWebPath() + "edituser?user=" + pUser->userName());
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
            NoTemplate& l = Tmpl.addRow("UserLoop");
            NoUser& User = *it->second;

            l["Username"] = User.userName();
            l["Clients"] = NoString(User.allClients().size());
            l["Networks"] = NoString(User.networks().size());

            if (&User == spSession->user()) {
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
            std::vector<NoNetwork*> vNetworks = User.networks();

            for (std::vector<NoNetwork*>::const_iterator it2 = vNetworks.begin(); it2 != vNetworks.end(); ++it2) {
                NoNetwork* pNetwork = *it2;
                uiNetworks++;

                if (pNetwork->isIrcConnected()) {
                    uiServers++;
                }

                if (pNetwork->isNetworkAttached()) {
                    uiAttached++;
                }

                uiClients += pNetwork->clients().size();
            }

            uiClients += User.userClients().size();
        }

        Tmpl["TotalNetworks"] = NoString(uiNetworks);
        Tmpl["AttachedNetworks"] = NoString(uiAttached);
        Tmpl["TotalCConnections"] = NoString(uiClients);
        Tmpl["TotalIRCConnections"] = NoString(uiServers);

        NoApp::TrafficStatsPair Users, ZNC, Total;
        NoApp::TrafficStatsMap traffic = NoApp::Get().GetTrafficStats(Users, ZNC, Total);
        NoApp::TrafficStatsMap::const_iterator it;

        for (it = traffic.begin(); it != traffic.end(); ++it) {
            NoTemplate& l = Tmpl.addRow("TrafficLoop");

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
                WebSock.GetSession()->addError("Choose either IPv4 or IPv6 or both.");
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
                WebSock.GetSession()->addError("Choose either IRC or Web or both.");
                return SettingsPage(WebSock, Tmpl);
            }
        }

        NoString sMessage;
        if (NoApp::Get().AddListener(uPort, sHost, sURIPrefix, bSSL, eAddr, eAccept, sMessage)) {
            if (!sMessage.empty()) {
                WebSock.GetSession()->addSuccess(sMessage);
            }
            if (!NoApp::Get().WriteConfig()) {
                WebSock.GetSession()->addError("Port changed, but config was not written");
            }
        } else {
            WebSock.GetSession()->addError(sMessage);
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
                WebSock.GetSession()->addError("Invalid request.");
                return SettingsPage(WebSock, Tmpl);
            }
        }

        NoListener* pListener = NoApp::Get().FindListener(uPort, sHost, eAddr);
        if (pListener) {
            NoApp::Get().DelListener(pListener);
            if (!NoApp::Get().WriteConfig()) {
                WebSock.GetSession()->addError("Port changed, but config was not written");
            }
        } else {
            WebSock.GetSession()->addError("The specified listener was not found.");
        }

        return SettingsPage(WebSock, Tmpl);
    }

    bool SettingsPage(NoWebSocket& WebSock, NoTemplate& Tmpl)
    {
        Tmpl.setFile("settings.tmpl");
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

            const NoStringVector& vsBindHosts = NoApp::Get().bindHosts();
            for (uint a = 0; a < vsBindHosts.size(); a++) {
                NoTemplate& l = Tmpl.addRow("BindHostLoop");
                l["BindHost"] = vsBindHosts[a];
            }

            const NoStringVector& vsMotd = NoApp::Get().GetMotd();
            for (uint b = 0; b < vsMotd.size(); b++) {
                NoTemplate& l = Tmpl.addRow("MOTDLoop");
                l["Line"] = vsMotd[b];
            }

            const std::vector<NoListener*>& vpListeners = NoApp::Get().GetListeners();
            for (uint c = 0; c < vpListeners.size(); c++) {
                NoListener* pListener = vpListeners[c];
                NoTemplate& l = Tmpl.addRow("ListenLoop");

                l["Port"] = NoString(pListener->port());
                l["BindHost"] = pListener->host();

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
                NoTemplate& l = Tmpl.addRow("SkinLoop");
                l["Name"] = SubDir;

                if (SubDir == NoApp::Get().GetSkinName()) {
                    l["Checked"] = "true";
                }
            }

            std::set<NoModuleInfo> ssGlobalMods;
            NoApp::Get().GetLoader()->availableModules(ssGlobalMods, No::GlobalModule);

            for (std::set<NoModuleInfo>::iterator it = ssGlobalMods.begin(); it != ssGlobalMods.end(); ++it) {
                const NoModuleInfo& Info = *it;
                NoTemplate& l = Tmpl.addRow("ModuleLoop");

                NoModule* pModule = NoApp::Get().GetLoader()->findModule(Info.name());
                if (pModule) {
                    l["Checked"] = "true";
                    l["Args"] = pModule->GetArgs();
                    if (No::GlobalModule == GetType() && Info.name() == GetModName()) {
                        l["Disabled"] = "true";
                    }
                }

                l["Name"] = Info.name();
                l["Description"] = Info.description();
                l["Wiki"] = Info.wikiPage();
                l["HasArgs"] = NoString(Info.hasArgs());
                l["ArgsHelpText"] = Info.argsHelpText();

                // Check if the module is loaded by all or some users, and/or by all or some networks
                uint usersWithRenderedModuleCount = 0;
                uint networksWithRenderedModuleCount = 0;
                uint networksCount = 0;
                const std::map<NoString, NoUser*>& allUsers = NoApp::Get().GetUserMap();
                for (std::map<NoString, NoUser*>::const_iterator usersIt = allUsers.begin(); usersIt != allUsers.end(); ++usersIt) {
                    const NoUser& User = *usersIt->second;

                    // Count users which has loaded a render module
                    const NoModuleLoader* userModules = User.loader();
                    if (userModules->findModule(Info.name())) {
                        usersWithRenderedModuleCount++;
                    }
                    // Count networks which has loaded a render module
                    const std::vector<NoNetwork*>& userNetworks = User.networks();
                    networksCount += userNetworks.size();
                    for (uint networkIndex = 0; networkIndex < userNetworks.size(); ++networkIndex) {
                        const NoNetwork* pCurrentNetwork = userNetworks[networkIndex];
                        if (pCurrentNetwork->loader()->findModule(Info.name())) {
                            networksWithRenderedModuleCount++;
                        }
                    }
                }
                l["CanBeLoadedByNetwork"] = NoString(Info.supportsType(No::NetworkModule));
                l["LoadedByAllNetworks"] = NoString(networksWithRenderedModuleCount == networksCount);
                l["LoadedBySomeNetworks"] = NoString(networksWithRenderedModuleCount != 0);

                l["CanBeLoadedByUser"] = NoString(Info.supportsType(No::UserModule));
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

                NoModule* pMod = NoApp::Get().GetLoader()->findModule(sModName);
                if (!pMod) {
                    if (!NoApp::Get().GetLoader()->loadModule(sModName, sArgs, No::GlobalModule, nullptr, nullptr, sModRet)) {
                        sModLoadError = "Unable to load module [" + sModName + "] [" + sModRet + "]";
                    }
                } else if (pMod->GetArgs() != sArgs) {
                    if (!NoApp::Get().GetLoader()->reloadModule(sModName, sArgs, nullptr, nullptr, sModRet)) {
                        sModLoadError = "Unable to reload module [" + sModName + "] [" + sModRet + "]";
                    }
                }

                if (!sModLoadError.empty()) {
                    NO_DEBUG(sModLoadError);
                    WebSock.GetSession()->addError(sModLoadError);
                }
            }
        }

        const NoModuleLoader* vCurMods = NoApp::Get().GetLoader();
        std::set<NoString> ssUnloadMods;

        for (NoModule* pCurMod : vCurMods->modules()) {
            if (ssArgs.find(pCurMod->GetModName()) == ssArgs.end() &&
                (No::GlobalModule != GetType() || pCurMod->GetModName() != GetModName())) {
                ssUnloadMods.insert(pCurMod->GetModName());
            }
        }

        for (std::set<NoString>::iterator it2 = ssUnloadMods.begin(); it2 != ssUnloadMods.end(); ++it2) {
            NoApp::Get().GetLoader()->unloadModule(*it2);
        }

        if (!NoApp::Get().WriteConfig()) {
            WebSock.GetSession()->addError("Settings changed, but config was not written");
        }

        WebSock.Redirect(GetWebPath() + "settings");
        /* we don't want the template to be printed while we redirect */
        return false;
    }
};

template <> void no_moduleInfo<NoWebAdminMod>(NoModuleInfo& Info)
{
    Info.addType(No::UserModule);
    Info.setWikiPage("webadmin");
}

GLOBALMODULEDEFS(NoWebAdminMod, "Web based administration module.")
