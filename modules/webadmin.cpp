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
    std::vector<NoModule*> globalMods = noApp->loader()->modules();
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
        addSubPage(settings);

        std::shared_ptr<NoWebPage> edituser = std::make_shared<NoWebPage>("edituser");
        edituser->setTitle("Your Settings");
        edituser->addParam("user", "");
        addSubPage(edituser);

        std::shared_ptr<NoWebPage> traffic = std::make_shared<NoWebPage>("traffic");
        traffic->setTitle("Traffic Info");
        traffic->setFlags(NoWebPage::Admin);
        addSubPage(traffic);

        std::shared_ptr<NoWebPage> listusers = std::make_shared<NoWebPage>("listusers");
        listusers->setTitle("Manage Users");
        listusers->setFlags(NoWebPage::Admin);
        addSubPage(listusers);
    }

    bool onLoad(const NoString& sArgStr, NoString& sMessage) override
    {
        if (sArgStr.empty() || No::GlobalModule != type())
            return true;

        // We don't accept any arguments, but for backwards
        // compatibility we have to do some magic here.
        sMessage = "Arguments converted to new syntax";

        bool ssl = false;
        bool bIPv6 = false;
        bool bShareIRCPorts = true;
        ushort port = 8080;
        NoString args(sArgStr);
        NoString sPort;
        NoString sListenHost;
        NoString sURIPrefix;

        while (args.left(1) == "-") {
            NoString sOpt = No::token(args, 0);
            args = No::tokens(args, 1);

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
        if (args.empty() && bShareIRCPorts)
            return true;

        if (args.contains(" ")) {
            sListenHost = No::token(args, 0);
            sPort = No::tokens(args, 1);
        } else {
            sPort = args;
        }

        if (sPort.left(1) == "+") {
            sPort.trimLeft("+");
            ssl = true;
        }

        if (!sPort.empty()) {
            port = sPort.toUShort();
        }

        if (!bShareIRCPorts) {
            // Make all existing listeners IRC-only
            const std::vector<NoListener*>& vListeners = noApp->listeners();
            std::vector<NoListener*>::const_iterator it;
            for (it = vListeners.begin(); it != vListeners.end(); ++it) {
                (*it)->setAcceptType(No::AcceptIrc);
            }
        }

        // Now turn that into a listener instance
        NoListener* pListener = new NoListener(sListenHost, port);
        pListener->setUriPrefix(sURIPrefix);
        pListener->setSsl(ssl);
        pListener->setAddressType(!bIPv6 ? No::Ipv4Address : No::Ipv4AndIpv6Address);
        pListener->setAcceptType(No::AcceptHttp);

        if (!pListener->listen()) {
            sMessage = "Failed to add backwards-compatible listener";
            return false;
        }
        noApp->addListener(pListener);

        setArgs("");
        return true;
    }

    NoUser* GetNewUser(NoWebSocket& WebSock, NoUser* user)
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.session();
        NoString sUsername = WebSock.param("newuser");

        if (sUsername.empty()) {
            sUsername = WebSock.param("user");
        }

        if (sUsername.empty()) {
            WebSock.printErrorPage("Invalid Submission [Username is required]");
            return nullptr;
        }

        if (user) {
            /* If we are editing a user we must not change the user name */
            sUsername = user->userName();
        }

        NoString arg = WebSock.param("password");

        if (arg != WebSock.param("password2")) {
            WebSock.printErrorPage("Invalid Submission [Passwords do not match]");
            return nullptr;
        }

        NoUser* pNewUser = new NoUser(sUsername);

        if (!arg.empty()) {
            NoString salt = No::salt();
            NoString sHash = NoUser::saltedHash(arg, salt);
            pNewUser->setPassword(sHash, NoUser::HashDefault, salt);
        }

        NoStringVector vsArgs = WebSock.rawParam("allowedips").split("\n");
        uint a = 0;

        if (vsArgs.size()) {
            for (a = 0; a < vsArgs.size(); a++) {
                pNewUser->addAllowedHost(vsArgs[a].trim_n());
            }
        } else {
            pNewUser->addAllowedHost("*");
        }

        vsArgs = WebSock.rawParam("ctcpreplies").split("\n");
        for (a = 0; a < vsArgs.size(); a++) {
            NoString sReply = vsArgs[a].trimRight_n("\r");
            pNewUser->addCtcpReply(No::token(sReply, 0).trim_n(), No::tokens(sReply, 1).trim_n());
        }

        arg = WebSock.param("nick");
        if (!arg.empty()) {
            pNewUser->setNick(arg);
        }
        arg = WebSock.param("altnick");
        if (!arg.empty()) {
            pNewUser->setAltNick(arg);
        }
        arg = WebSock.param("statusprefix");
        if (!arg.empty()) {
            pNewUser->setStatusPrefix(arg);
        }
        arg = WebSock.param("ident");
        if (!arg.empty()) {
            pNewUser->setIdent(arg);
        }
        arg = WebSock.param("realname");
        if (!arg.empty()) {
            pNewUser->setRealName(arg);
        }
        arg = WebSock.param("quitmsg");
        if (!arg.empty()) {
            pNewUser->setQuitMsg(arg);
        }
        arg = WebSock.param("chanmodes");
        if (!arg.empty()) {
            pNewUser->setDefaultChanModes(arg);
        }
        arg = WebSock.param("timestampformat");
        if (!arg.empty()) {
            pNewUser->setTimestampFormat(arg);
        }

        arg = WebSock.param("bindhost");
        // To change BindHosts be admin or don't have DenysetBindHost
        if (spSession->isAdmin() || !spSession->user()->denysetBindHost()) {
            NoString sArg2 = WebSock.param("dccbindhost");
            if (!arg.empty()) {
                pNewUser->setBindHost(arg);
            }
            if (!sArg2.empty()) {
                pNewUser->setDccBindHost(sArg2);
            }

            const NoStringVector& vsHosts = noApp->bindHosts();
            if (!spSession->isAdmin() && !vsHosts.empty()) {
                NoStringVector::const_iterator it;
                bool bFound = false;
                bool bFoundDCC = false;

                for (it = vsHosts.begin(); it != vsHosts.end(); ++it) {
                    if (arg.equals(*it)) {
                        bFound = true;
                    }
                    if (sArg2.equals(*it)) {
                        bFoundDCC = true;
                    }
                }

                if (!bFound) {
                    pNewUser->setBindHost(user ? user->bindHost() : "");
                }
                if (!bFoundDCC) {
                    pNewUser->setDccBindHost(user ? user->dccBindHost() : "");
                }
            }
        } else if (user) {
            pNewUser->setBindHost(user->bindHost());
            pNewUser->setDccBindHost(user->dccBindHost());
        }

        arg = WebSock.param("bufsize");
        if (!arg.empty())
            pNewUser->setBufferCount(arg.toUInt(), spSession->isAdmin());
        if (!arg.empty()) {
            // First apply the old limit in case the new one is too high
            if (user)
                pNewUser->setBufferCount(user->bufferCount(), true);
            pNewUser->setBufferCount(arg.toUInt(), spSession->isAdmin());
        }

        pNewUser->setSkinName(WebSock.param("skin"));
        pNewUser->setAutoClearChanBuffer(WebSock.param("autoclearchanbuffer").toBool());
        pNewUser->setMultiClients(WebSock.param("multiclients").toBool());
        pNewUser->setTimestampAppend(WebSock.param("appendtimestamp").toBool());
        pNewUser->setTimestampPrepend(WebSock.param("prependtimestamp").toBool());
        pNewUser->setTimezone(WebSock.param("timezone"));
        pNewUser->setJoinTries(WebSock.param("jointries").toUInt());
        pNewUser->setMaxJoins(WebSock.param("maxjoins").toUInt());
        pNewUser->setAutoclearQueryBuffer(WebSock.param("autoclearquerybuffer").toBool());
        pNewUser->setMaxQueryBuffers(WebSock.param("maxquerybuffers").toUInt());

#ifdef HAVE_ICU
        NoString sEncodingUtf = WebSock.param("encoding_utf");
        if (sEncodingUtf == "legacy") {
            pNewUser->setClientEncoding("");
        }
        NoString sEncoding = WebSock.param("encoding");
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
            pNewUser->setDenyLoadMod(WebSock.param("denyloadmod").toBool());
            pNewUser->setDenysetBindHost(WebSock.param("denysetbindhost").toBool());
            arg = WebSock.param("maxnetworks");
            if (!arg.empty())
                pNewUser->setMaxNetworks(arg.toUInt());
        } else if (user) {
            pNewUser->setDenyLoadMod(user->denyLoadMod());
            pNewUser->setDenysetBindHost(user->denysetBindHost());
            pNewUser->setMaxNetworks(user->maxNetworks());
        }

        // If user is not nullptr, we are editing an existing user.
        // Users must not be able to change their own admin flag.
        if (user != noApp->findUser(WebSock.username())) {
            pNewUser->setAdmin(WebSock.param("isadmin").toBool());
        } else if (user) {
            pNewUser->setAdmin(user->isAdmin());
        }

        if (spSession->isAdmin() || (user && !user->denyLoadMod())) {
            WebSock.paramValues("loadmod", vsArgs);

            // disallow unload webadmin from itself
            if (No::UserModule == type() && user == noApp->findUser(WebSock.username())) {
                bool bLoadedWebadmin = false;
                for (a = 0; a < vsArgs.size(); ++a) {
                    NoString sModName = vsArgs[a].trimRight_n("\r");
                    if (sModName == moduleName()) {
                        bLoadedWebadmin = true;
                        break;
                    }
                }
                if (!bLoadedWebadmin) {
                    vsArgs.push_back(moduleName());
                }
            }

            for (a = 0; a < vsArgs.size(); a++) {
                NoString sModRet;
                NoString sModName = vsArgs[a].trimRight_n("\r");
                NoString sModLoadError;

                if (!sModName.empty()) {
                    NoString args = WebSock.param("modargs_" + sModName);

                    try {
                        if (!pNewUser->loader()->loadModule(sModName, args, No::UserModule, pNewUser, nullptr, sModRet)) {
                            sModLoadError = "Unable to load module [" + sModName + "] [" + sModRet + "]";
                        }
                    } catch (...) {
                        sModLoadError = "Unable to load module [" + sModName + "] [" + args + "]";
                    }

                    if (!sModLoadError.empty()) {
                        NO_DEBUG(sModLoadError);
                        spSession->addError(sModLoadError);
                    }
                }
            }
        } else if (user) {
            NoModuleLoader* Modules = user->loader();

            for (NoModule* mod : Modules->modules()) {
                NoString sModName = mod->moduleName();
                NoString args = mod->args();
                NoString sModRet;
                NoString sModLoadError;

                try {
                    if (!pNewUser->loader()->loadModule(sModName, args, No::UserModule, pNewUser, nullptr, sModRet)) {
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
        NoString userName = WebSock.param("user"); // check for POST param
        if (userName.empty() && !WebSock.isPost()) {
            // if no POST param named user has been given and we are not
            // saving this form, fall back to using the GET parameter.
            userName = WebSock.param("user", false);
        }
        return userName;
    }

    NoString SafeGetNetworkParam(NoWebSocket& WebSock)
    {
        NoString sNetwork = WebSock.param("network"); // check for POST param
        if (sNetwork.empty() && !WebSock.isPost()) {
            // if no POST param named user has been given and we are not
            // saving this form, fall back to using the GET parameter.
            sNetwork = WebSock.param("network", false);
        }
        return sNetwork;
    }

    NoUser* SafeGetUserFromParam(NoWebSocket& WebSock)
    {
        return noApp->findUser(SafeGetUserNameParam(WebSock));
    }

    NoNetwork* SafeGetNetworkFromParam(NoWebSocket& WebSock)
    {
        NoUser* user = noApp->findUser(SafeGetUserNameParam(WebSock));
        NoNetwork* network = nullptr;

        if (user) {
            network = user->findNetwork(SafeGetNetworkParam(WebSock));
        }

        return network;
    }

    NoString webMenuTitle() override
    {
        return "webadmin";
    }
    bool onWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.session();

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
            NoUser* user = SafeGetUserFromParam(WebSock);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || spSession->user() != user)) {
                return false;
            }

            if (user) {
                return NetworkPage(WebSock, Tmpl, user);
            }

            WebSock.printErrorPage("No such username");
            return true;
        } else if (sPageName == "editnetwork") {
            NoNetwork* network = SafeGetNetworkFromParam(WebSock);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || !network || spSession->user() != network->user())) {
                return false;
            }

            if (!network) {
                WebSock.printErrorPage("No such username or network");
                return true;
            }

            return NetworkPage(WebSock, Tmpl, network->user(), network);

        } else if (sPageName == "delnetwork") {
            NoString sUser = WebSock.param("user");
            if (sUser.empty() && !WebSock.isPost()) {
                sUser = WebSock.param("user", false);
            }

            NoUser* user = noApp->findUser(sUser);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || spSession->user() != user)) {
                return false;
            }

            return DelNetwork(WebSock, user, Tmpl);
        } else if (sPageName == "editchan") {
            NoNetwork* network = SafeGetNetworkFromParam(WebSock);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || !network || spSession->user() != network->user())) {
                return false;
            }

            if (!network) {
                WebSock.printErrorPage("No such username or network");
                return true;
            }

            NoString sChan = WebSock.param("name");
            if (sChan.empty() && !WebSock.isPost()) {
                sChan = WebSock.param("name", false);
            }
            NoChannel* channel = network->findChannel(sChan);
            if (!channel) {
                WebSock.printErrorPage("No such channel");
                return true;
            }

            return ChanPage(WebSock, Tmpl, network, channel);
        } else if (sPageName == "addchan") {
            NoNetwork* network = SafeGetNetworkFromParam(WebSock);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || !network || spSession->user() != network->user())) {
                return false;
            }

            if (network) {
                return ChanPage(WebSock, Tmpl, network);
            }

            WebSock.printErrorPage("No such username or network");
            return true;
        } else if (sPageName == "delchan") {
            NoNetwork* network = SafeGetNetworkFromParam(WebSock);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || !network || spSession->user() != network->user())) {
                return false;
            }

            if (network) {
                return removeChannel(WebSock, network);
            }

            WebSock.printErrorPage("No such username or network");
            return true;
        } else if (sPageName == "deluser") {
            if (!spSession->isAdmin()) {
                return false;
            }

            if (!WebSock.isPost()) {
                // Show the "Are you sure?" page:

                NoString sUser = WebSock.param("user", false);
                NoUser* user = noApp->findUser(sUser);

                if (!user) {
                    WebSock.printErrorPage("No such username");
                    return true;
                }

                Tmpl.setFile("del_user.tmpl");
                Tmpl["Username"] = sUser;
                return true;
            }

            // The "Are you sure?" page has been submitted with "Yes",
            // so we actually delete the user now:

            NoString sUser = WebSock.param("user");
            NoUser* user = noApp->findUser(sUser);

            if (user && user == spSession->user()) {
                WebSock.printErrorPage("Please don't delete yourself, suicide is not the answer!");
                return true;
            } else if (noApp->deleteUser(sUser)) {
                WebSock.redirect(webPath() + "listusers");
                return true;
            }

            WebSock.printErrorPage("No such username");
            return true;
        } else if (sPageName == "edituser") {
            NoString userName = SafeGetUserNameParam(WebSock);
            NoUser* user = noApp->findUser(userName);

            if (!user) {
                if (userName.empty()) {
                    user = spSession->user();
                } // else: the "no such user" message will be printed.
            }

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || spSession->user() != user)) {
                return false;
            }

            if (user) {
                return UserPage(WebSock, Tmpl, user);
            }

            WebSock.printErrorPage("No such username");
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

    bool ChanPage(NoWebSocket& WebSock, NoTemplate& Tmpl, NoNetwork* network, NoChannel* channel = nullptr)
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.session();
        Tmpl.setFile("add_edit_chan.tmpl");
        NoUser* user = network->user();

        if (!user) {
            WebSock.printErrorPage("That user doesn't exist");
            return true;
        }

        if (!WebSock.param("submitted").toUInt()) {
            Tmpl["User"] = user->userName();
            Tmpl["Network"] = network->name();

            if (channel) {
                Tmpl["Action"] = "editchan";
                Tmpl["Edit"] = "true";
                Tmpl["Title"] = "Edit Channel" + NoString(" [" + channel->name() + "]") + " of Network [" +
                                network->name() + "] of User [" + network->user()->userName() + "]";
                Tmpl["ChanName"] = channel->name();
                Tmpl["BufferCount"] = NoString(channel->bufferCount());
                Tmpl["DefModes"] = channel->defaultModes();
                Tmpl["Key"] = channel->key();

                if (channel->inConfig()) {
                    Tmpl["InConfig"] = "true";
                }
            } else {
                Tmpl["Action"] = "addchan";
                Tmpl["Title"] = "Add Channel" + NoString(" for User [" + user->userName() + "]");
                Tmpl["BufferCount"] = NoString(user->bufferCount());
                Tmpl["DefModes"] = NoString(user->defaultChanModes());
                Tmpl["InConfig"] = "true";
            }

            // o1 used to be AutoCycle which was removed

            NoTemplate& o2 = Tmpl.addRow("OptionLoop");
            o2["Name"] = "autoclearchanbuffer";
            o2["DisplayName"] = "Auto Clear Chan Buffer";
            o2["Tooltip"] = "Automatically Clear Channel Buffer After Playback";
            if ((channel && channel->autoClearChanBuffer()) || (!channel && user->autoClearChanBuffer())) {
                o2["Checked"] = "true";
            }

            NoTemplate& o3 = Tmpl.addRow("OptionLoop");
            o3["Name"] = "detached";
            o3["DisplayName"] = "Detached";
            if (channel && channel->isDetached()) {
                o3["Checked"] = "true";
            }

            NoTemplate& o4 = Tmpl.addRow("OptionLoop");
            o4["Name"] = "disabled";
            o4["DisplayName"] = "Disabled";
            if (channel && channel->isDisabled()) {
                o4["Checked"] = "true";
            }

            for (NoModule* mod : allModules(network)) {
                NoTemplate& modrow = Tmpl.addRow("EmbeddedModuleLoop");
                modrow.insert(Tmpl.begin(), Tmpl.end());
                modrow["WebadminAction"] = "display";
                if (mod->onEmbeddedWebRequest(WebSock, "webadmin/channel", modrow)) {
                    modrow["Embed"] = WebSock.findTemplate(mod, "WebadminChan.tmpl");
                    modrow["ModName"] = mod->moduleName();
                }
            }

            return true;
        }

        NoString sChanName = WebSock.param("name").trim_n();

        if (!channel) {
            if (sChanName.empty()) {
                WebSock.printErrorPage("Channel name is a required argument");
                return true;
            }

            // This could change the channel name and e.g. add a "#" prefix
            channel = new NoChannel(sChanName, network, true);

            if (network->findChannel(channel->name())) {
                WebSock.printErrorPage("Channel [" + channel->name() + "] already exists");
                delete channel;
                return true;
            }

            if (!network->addChannel(channel)) {
                WebSock.printErrorPage("Could not add channel [" + channel->name() + "]");
                return true;
            }
        }

        uint uBufferCount = WebSock.param("buffercount").toUInt();
        if (channel->bufferCount() != uBufferCount) {
            channel->setBufferCount(uBufferCount, spSession->isAdmin());
        }
        channel->setDefaultModes(WebSock.param("defmodes"));
        channel->setInConfig(WebSock.param("save").toBool());
        bool bAutoClearChanBuffer = WebSock.param("autoclearchanbuffer").toBool();
        if (channel->autoClearChanBuffer() != bAutoClearChanBuffer) {
            channel->setAutoClearChanBuffer(WebSock.param("autoclearchanbuffer").toBool());
        }
        channel->setKey(WebSock.param("key"));

        bool bDetached = WebSock.param("detached").toBool();
        if (channel->isDetached() != bDetached) {
            if (bDetached) {
                channel->detachUser();
            } else {
                channel->attachUser();
            }
        }

        bool bDisabled = WebSock.param("disabled").toBool();
        if (bDisabled)
            channel->disable();
        else
            channel->enable();

        NoTemplate TmplMod;
        TmplMod["User"] = user->userName();
        TmplMod["ChanName"] = channel->name();
        TmplMod["WebadminAction"] = "change";
        for (NoModule* mod : allModules(network)) {
            mod->onEmbeddedWebRequest(WebSock, "webadmin/channel", TmplMod);
        }

        if (!noApp->writeConfig()) {
            WebSock.printErrorPage("Channel added/modified, but config was not written");
            return true;
        }

        if (WebSock.hasParam("submit_return")) {
            WebSock.redirect(webPath() + "editnetwork?user=" + No::escape(user->userName(), No::UrlFormat) +
                             "&network=" + No::escape(network->name(), No::UrlFormat));
        } else {
            WebSock.redirect(webPath() + "editchan?user=" + No::escape(user->userName(), No::UrlFormat) + "&network=" +
                             No::escape(network->name(), No::UrlFormat) + "&name=" + No::escape(channel->name(), No::UrlFormat));
        }
        return true;
    }

    bool NetworkPage(NoWebSocket& WebSock, NoTemplate& Tmpl, NoUser* user, NoNetwork* network = nullptr)
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.session();
        Tmpl.setFile("add_edit_network.tmpl");

        if (!WebSock.param("submitted").toUInt()) {
            Tmpl["Username"] = user->userName();

            std::set<NoModuleInfo> ssNetworkMods;
            noApp->loader()->availableModules(ssNetworkMods, No::NetworkModule);
            for (std::set<NoModuleInfo>::iterator it = ssNetworkMods.begin(); it != ssNetworkMods.end(); ++it) {
                const NoModuleInfo& Info = *it;
                NoTemplate& l = Tmpl.addRow("ModuleLoop");

                l["Name"] = Info.name();
                l["Description"] = Info.description();
                l["Wiki"] = Info.wikiPage();
                l["HasArgs"] = NoString(Info.hasArgs());
                l["ArgsHelpText"] = Info.argsHelpText();

                if (network) {
                    NoModule* pModule = network->loader()->findModule(Info.name());
                    if (pModule) {
                        l["Checked"] = "true";
                        l["Args"] = pModule->args();
                    }
                }

                // Check if module is loaded globally
                l["CanBeLoadedGlobally"] = NoString(Info.supportsType(No::GlobalModule));
                l["LoadedGlobally"] = NoString(noApp->loader()->findModule(Info.name()) != nullptr);

                // Check if module is loaded by user
                l["CanBeLoadedByUser"] = NoString(Info.supportsType(No::UserModule));
                l["LoadedByUser"] = NoString(user->loader()->findModule(Info.name()) != nullptr);

                if (!spSession->isAdmin() && user->denyLoadMod()) {
                    l["Disabled"] = "true";
                }
            }

            // To change BindHosts be admin or don't have DenysetBindHost
            if (spSession->isAdmin() || !spSession->user()->denysetBindHost()) {
                Tmpl["BindHostEdit"] = "true";
                const NoStringVector& vsBindHosts = noApp->bindHosts();
                if (vsBindHosts.empty()) {
                    if (network) {
                        Tmpl["BindHost"] = network->bindHost();
                    }
                } else {
                    bool bFoundBindHost = false;
                    for (uint b = 0; b < vsBindHosts.size(); b++) {
                        const NoString& sBindHost = vsBindHosts[b];
                        NoTemplate& l = Tmpl.addRow("BindHostLoop");

                        l["BindHost"] = sBindHost;

                        if (network && network->bindHost() == sBindHost) {
                            l["Checked"] = "true";
                            bFoundBindHost = true;
                        }
                    }

                    // If our current bindhost is not in the global list...
                    if (network && !bFoundBindHost && !network->bindHost().empty()) {
                        NoTemplate& l = Tmpl.addRow("BindHostLoop");

                        l["BindHost"] = network->bindHost();
                        l["Checked"] = "true";
                    }
                }
            }

            if (network) {
                Tmpl["Action"] = "editnetwork";
                Tmpl["Edit"] = "true";
                Tmpl["Title"] = "Edit Network" + NoString(" [" + network->name() + "]") + " of User [" + user->userName() + "]";
                Tmpl["Name"] = network->name();

                Tmpl["Nick"] = network->nick();
                Tmpl["AltNick"] = network->altNick();
                Tmpl["Ident"] = network->ident();
                Tmpl["RealName"] = network->realName();

                Tmpl["QuitMsg"] = network->quitMsg();

                Tmpl["FloodProtection"] = NoString(NoIrcSocket::isFloodProtected(network->floodRate()));
                Tmpl["FloodRate"] = NoString(network->floodRate());
                Tmpl["FloodBurst"] = NoString(network->floodBurst());

                Tmpl["JoinDelay"] = NoString(network->joinDelay());

                Tmpl["IRCConnectEnabled"] = NoString(network->isEnabled());

                const std::vector<NoServerInfo*>& vServers = network->servers();
                for (uint a = 0; a < vServers.size(); a++) {
                    NoTemplate& l = Tmpl.addRow("ServerLoop");
                    l["Server"] = vServers[a]->toString();
                }

                const std::vector<NoChannel*>& Channels = network->channels();
                for (uint c = 0; c < Channels.size(); c++) {
                    NoChannel* channel = Channels[c];
                    NoTemplate& l = Tmpl.addRow("ChannelLoop");

                    l["Network"] = network->name();
                    l["Username"] = user->userName();
                    l["Name"] = channel->name();
                    l["Perms"] = channel->permStr();
                    l["CurModes"] = channel->modeString();
                    l["DefModes"] = channel->defaultModes();
                    if (channel->hasBufferCountSet()) {
                        l["BufferCount"] = NoString(channel->bufferCount());
                    } else {
                        l["BufferCount"] = NoString(channel->bufferCount()) + " (default)";
                    }
                    l["Options"] = channel->options();

                    if (channel->inConfig()) {
                        l["InConfig"] = "true";
                    }
                }
                for (const NoString& sFP : network->trustedFingerprints()) {
                    NoTemplate& l = Tmpl.addRow("TrustedFingerprints");
                    l["FP"] = sFP;
                }
            } else {
                if (!spSession->isAdmin() && !user->hasSpaceForNewNetwork()) {
                    WebSock.printErrorPage("Network number limit reached. Ask an admin to increase the limit for you, "
                                           "or delete unneeded networks from Your Settings.");
                    return true;
                }

                Tmpl["Action"] = "addnetwork";
                Tmpl["Title"] = "Add Network for User [" + user->userName() + "]";
                Tmpl["IRCConnectEnabled"] = "true";
                Tmpl["FloodProtection"] = "true";
                Tmpl["FloodRate"] = "1.0";
                Tmpl["FloodBurst"] = "4";
                Tmpl["JoinDelay"] = "0";
            }

            for (NoModule* mod : allModules(user, network)) {
                NoTemplate& modrow = Tmpl.addRow("EmbeddedModuleLoop");
                modrow.insert(Tmpl.begin(), Tmpl.end());
                modrow["WebadminAction"] = "display";
                if (mod->onEmbeddedWebRequest(WebSock, "webadmin/network", modrow)) {
                    modrow["Embed"] = WebSock.findTemplate(mod, "WebadminNetwork.tmpl");
                    modrow["ModName"] = mod->moduleName();
                }
            }

#ifdef HAVE_ICU
            for (const NoString& sEncoding : No::encodings()) {
                NoTemplate& l = Tmpl.addRow("EncodingLoop");
                l["Encoding"] = sEncoding;
            }
            const NoString sEncoding = network ? network->encoding() : "^UTF-8";
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

        NoString name = WebSock.param("name").trim_n();
        if (name.empty()) {
            WebSock.printErrorPage("Network name is a required argument");
            return true;
        }
        if (!network && !spSession->isAdmin() && !user->hasSpaceForNewNetwork()) {
            WebSock.printErrorPage("Network number limit reached. Ask an admin to increase the limit for you, or "
                                   "delete few old ones from Your Settings");
            return true;
        }
        if (!network || network->name() != name) {
            NoString sNetworkAddError;
            NoNetwork* pOldNetwork = network;
            network = user->addNetwork(name, sNetworkAddError);
            if (!network) {
                WebSock.printErrorPage(sNetworkAddError);
                return true;
            }
            if (pOldNetwork) {
                for (NoModule* pModule : pOldNetwork->loader()->modules()) {
                    NoString sPath = user->userPath() + "/networks/" + name + "/moddata/" + pModule->moduleName();
                    NoRegistry registry(pModule);
                    registry.copy(sPath);
                }
                network->clone(*pOldNetwork, false);
                user->deleteNetwork(pOldNetwork->name());
            }
        }

        NoString arg;

        network->setNick(WebSock.param("nick"));
        network->setAltNick(WebSock.param("altnick"));
        network->setIdent(WebSock.param("ident"));
        network->setRealName(WebSock.param("realname"));

        network->setQuitMsg(WebSock.param("quitmsg"));

        network->setEnabled(WebSock.param("doconnect").toBool());

        arg = WebSock.param("bindhost");
        // To change BindHosts be admin or don't have DenysetBindHost
        if (spSession->isAdmin() || !spSession->user()->denysetBindHost()) {
            NoString host = WebSock.param("bindhost");
            const NoStringVector& vsHosts = noApp->bindHosts();
            if (!spSession->isAdmin() && !vsHosts.empty()) {
                NoStringVector::const_iterator it;
                bool bFound = false;

                for (it = vsHosts.begin(); it != vsHosts.end(); ++it) {
                    if (host.equals(*it)) {
                        bFound = true;
                        break;
                    }
                }

                if (!bFound) {
                    host = network->bindHost();
                }
            }
            network->setBindHost(host);
        }

        if (WebSock.param("floodprotection").toBool()) {
            network->setFloodRate(WebSock.param("floodrate").toDouble());
            network->setFloodBurst(WebSock.param("floodburst").toUShort());
        } else {
            network->setFloodRate(-1);
        }

        network->setJoinDelay(WebSock.param("joindelay").toUShort());

#ifdef HAVE_ICU
        NoString sEncodingUtf = WebSock.param("encoding_utf");
        if (sEncodingUtf == "legacy") {
            network->setEncoding("");
        }
        NoString sEncoding = WebSock.param("encoding");
        if (sEncoding.empty()) {
            sEncoding = "UTF-8";
        }
        if (sEncodingUtf == "send") {
            network->setEncoding("^" + sEncoding);
        } else if (sEncodingUtf == "receive") {
            network->setEncoding("*" + sEncoding);
        } else if (sEncodingUtf == "simple") {
            network->setEncoding(sEncoding);
        }
#endif

        network->delServers();
        NoStringVector vsArgs = WebSock.rawParam("servers").split("\n");
        for (uint a = 0; a < vsArgs.size(); a++) {
            network->addServer(vsArgs[a].trim_n());
        }

        vsArgs = WebSock.rawParam("fingerprints").split("\n");
        while (!network->trustedFingerprints().empty()) {
            network->removeTrustedFingerprint(*network->trustedFingerprints().begin());
        }
        for (const NoString& sFP : vsArgs) {
            network->addTrustedFingerprint(sFP);
        }

        WebSock.paramValues("channel", vsArgs);
        for (uint a = 0; a < vsArgs.size(); a++) {
            const NoString& sChan = vsArgs[a];
            NoChannel* channel = network->findChannel(sChan.trimRight_n("\r"));
            if (channel) {
                channel->setInConfig(WebSock.param("save_" + sChan).toBool());
            }
        }

        std::set<NoString> ssArgs;
        WebSock.paramValues("loadmod", ssArgs);
        if (spSession->isAdmin() || !user->denyLoadMod()) {
            for (std::set<NoString>::iterator it = ssArgs.begin(); it != ssArgs.end(); ++it) {
                NoString sModRet;
                NoString sModName = (*it).trimRight_n("\r");
                NoString sModLoadError;

                if (!sModName.empty()) {
                    NoString args = WebSock.param("modargs_" + sModName);

                    NoModule* mod = network->loader()->findModule(sModName);

                    if (!mod) {
                        if (!network->loader()->loadModule(sModName, args, No::NetworkModule, user, network, sModRet)) {
                            sModLoadError = "Unable to load module [" + sModName + "] [" + sModRet + "]";
                        }
                    } else if (mod->args() != args) {
                        if (!network->loader()->reloadModule(sModName, args, user, network, sModRet)) {
                            sModLoadError = "Unable to reload module [" + sModName + "] [" + sModRet + "]";
                        }
                    }

                    if (!sModLoadError.empty()) {
                        NO_DEBUG(sModLoadError);
                        WebSock.session()->addError(sModLoadError);
                    }
                }
            }
        }

        const NoModuleLoader* vCurMods = network->loader();
        std::set<NoString> ssUnloadMods;

        for (NoModule* pCurMod : vCurMods->modules()) {
            if (ssArgs.find(pCurMod->moduleName()) == ssArgs.end() && pCurMod->moduleName() != moduleName()) {
                ssUnloadMods.insert(pCurMod->moduleName());
            }
        }

        for (std::set<NoString>::iterator it2 = ssUnloadMods.begin(); it2 != ssUnloadMods.end(); ++it2) {
            network->loader()->unloadModule(*it2);
        }

        NoTemplate TmplMod;
        TmplMod["Username"] = user->userName();
        TmplMod["Name"] = network->name();
        TmplMod["WebadminAction"] = "change";
        for (NoModule* mod : allModules(user, network)) {
            mod->onEmbeddedWebRequest(WebSock, "webadmin/network", TmplMod);
        }

        if (!noApp->writeConfig()) {
            WebSock.printErrorPage("Network added/modified, but config was not written");
            return true;
        }

        if (WebSock.hasParam("submit_return")) {
            WebSock.redirect(webPath() + "edituser?user=" + No::escape(user->userName(), No::UrlFormat));
        } else {
            WebSock.redirect(webPath() + "editnetwork?user=" + No::escape(user->userName(), No::UrlFormat) +
                             "&network=" + No::escape(network->name(), No::UrlFormat));
        }
        return true;
    }

    bool DelNetwork(NoWebSocket& WebSock, NoUser* user, NoTemplate& Tmpl)
    {
        NoString sNetwork = WebSock.param("name");
        if (sNetwork.empty() && !WebSock.isPost()) {
            sNetwork = WebSock.param("name", false);
        }

        if (!user) {
            WebSock.printErrorPage("That user doesn't exist");
            return true;
        }

        if (sNetwork.empty()) {
            WebSock.printErrorPage("That network doesn't exist for this user");
            return true;
        }

        if (!WebSock.isPost()) {
            // Show the "Are you sure?" page:

            Tmpl.setFile("del_network.tmpl");
            Tmpl["Username"] = user->userName();
            Tmpl["Network"] = sNetwork;
            return true;
        }

        user->deleteNetwork(sNetwork);

        if (!noApp->writeConfig()) {
            WebSock.printErrorPage("Network deleted, but config was not written");
            return true;
        }

        WebSock.redirect(webPath() + "edituser?user=" + No::escape(user->userName(), No::UrlFormat));
        return false;
    }

    bool removeChannel(NoWebSocket& WebSock, NoNetwork* network)
    {
        NoString sChan = WebSock.param("name", false);

        if (sChan.empty()) {
            WebSock.printErrorPage("That channel doesn't exist for this user");
            return true;
        }

        network->removeChannel(sChan);
        network->putIrc("PART " + sChan);

        if (!noApp->writeConfig()) {
            WebSock.printErrorPage("Channel deleted, but config was not written");
            return true;
        }

        WebSock.redirect(webPath() + "editnetwork?user=" + No::escape(network->user()->userName(), No::UrlFormat) +
                         "&network=" + No::escape(network->name(), No::UrlFormat));
        return false;
    }

    bool UserPage(NoWebSocket& WebSock, NoTemplate& Tmpl, NoUser* user = nullptr)
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.session();
        Tmpl.setFile("add_edit_user.tmpl");

        if (!WebSock.param("submitted").toUInt()) {
            if (user) {
                Tmpl["Action"] = "edituser";
                Tmpl["Title"] = "Edit User [" + user->userName() + "]";
                Tmpl["Edit"] = "true";
            } else {
                NoString sUsername = WebSock.param("clone", false);
                user = noApp->findUser(sUsername);

                if (user) {
                    Tmpl["Title"] = "Clone User [" + user->userName() + "]";
                    Tmpl["Clone"] = "true";
                    Tmpl["CloneUsername"] = user->userName();
                }
            }

            Tmpl["ImAdmin"] = NoString(spSession->isAdmin());

            if (user) {
                Tmpl["Username"] = user->userName();
                Tmpl["Nick"] = user->nick();
                Tmpl["AltNick"] = user->altNick();
                Tmpl["StatusPrefix"] = user->statusPrefix();
                Tmpl["Ident"] = user->ident();
                Tmpl["RealName"] = user->realName();
                Tmpl["QuitMsg"] = user->quitMsg();
                Tmpl["DefaultChanModes"] = user->defaultChanModes();
                Tmpl["BufferCount"] = NoString(user->bufferCount());
                Tmpl["TimestampFormat"] = user->timestampFormat();
                Tmpl["Timezone"] = user->timezone();
                Tmpl["JoinTries"] = NoString(user->joinTries());
                Tmpl["MaxNetworks"] = NoString(user->maxNetworks());
                Tmpl["MaxJoins"] = NoString(user->maxJoins());
                Tmpl["MaxQueryBuffers"] = NoString(user->maxQueryBuffers());

                const std::set<NoString>& ssAllowedHosts = user->allowedHosts();
                for (std::set<NoString>::const_iterator it = ssAllowedHosts.begin(); it != ssAllowedHosts.end(); ++it) {
                    NoTemplate& l = Tmpl.addRow("AllowedHostLoop");
                    l["Host"] = *it;
                }

                const std::vector<NoNetwork*>& vNetworks = user->networks();
                for (uint a = 0; a < vNetworks.size(); a++) {
                    NoTemplate& l = Tmpl.addRow("NetworkLoop");
                    l["Name"] = vNetworks[a]->name();
                    l["Username"] = user->userName();
                    l["Clients"] = NoString(vNetworks[a]->clients().size());
                    l["IRCNick"] = vNetworks[a]->ircNick().nick();
                    NoServerInfo* server = vNetworks[a]->currentServer();
                    if (server) {
                        l["Server"] = server->host() + ":" + (server->isSsl() ? "+" : "") + NoString(server->port());
                    }
                }

                const NoStringMap& msCTCPReplies = user->ctcpReplies();
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
            const NoString sEncoding = user ? user->clientEncoding() : "^UTF-8";
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
                const NoStringVector& vsBindHosts = noApp->bindHosts();
                if (vsBindHosts.empty()) {
                    if (user) {
                        Tmpl["BindHost"] = user->bindHost();
                        Tmpl["DCCBindHost"] = user->dccBindHost();
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

                        if (user && user->bindHost() == sBindHost) {
                            l["Checked"] = "true";
                            bFoundBindHost = true;
                        }

                        if (user && user->dccBindHost() == sBindHost) {
                            k["Checked"] = "true";
                            bFoundDCCBindHost = true;
                        }
                    }

                    // If our current bindhost is not in the global list...
                    if (user && !bFoundBindHost && !user->bindHost().empty()) {
                        NoTemplate& l = Tmpl.addRow("BindHostLoop");

                        l["BindHost"] = user->bindHost();
                        l["Checked"] = "true";
                    }
                    if (user && !bFoundDCCBindHost && !user->dccBindHost().empty()) {
                        NoTemplate& l = Tmpl.addRow("DCCBindHostLoop");

                        l["BindHost"] = user->dccBindHost();
                        l["Checked"] = "true";
                    }
                }
            }

            std::vector<NoString> vDirs;
            WebSock.availableSkins(vDirs);

            for (uint d = 0; d < vDirs.size(); d++) {
                const NoString& SubDir = vDirs[d];
                NoTemplate& l = Tmpl.addRow("SkinLoop");
                l["Name"] = SubDir;

                if (user && SubDir == user->skinName()) {
                    l["Checked"] = "true";
                }
            }

            std::set<NoModuleInfo> ssUserMods;
            noApp->loader()->availableModules(ssUserMods);

            for (std::set<NoModuleInfo>::iterator it = ssUserMods.begin(); it != ssUserMods.end(); ++it) {
                const NoModuleInfo& Info = *it;
                NoTemplate& l = Tmpl.addRow("ModuleLoop");

                l["Name"] = Info.name();
                l["Description"] = Info.description();
                l["Wiki"] = Info.wikiPage();
                l["HasArgs"] = NoString(Info.hasArgs());
                l["ArgsHelpText"] = Info.argsHelpText();

                NoModule* pModule = nullptr;
                if (user) {
                    pModule = user->loader()->findModule(Info.name());
                    // Check if module is loaded by all or some networks
                    const std::vector<NoNetwork*>& userNetworks = user->networks();
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
                    l["Args"] = pModule->args();
                    if (No::UserModule == type() && Info.name() == moduleName()) {
                        l["Disabled"] = "true";
                    }
                }
                l["CanBeLoadedGlobally"] = NoString(Info.supportsType(No::GlobalModule));
                // Check if module is loaded globally
                l["LoadedGlobally"] = NoString(noApp->loader()->findModule(Info.name()) != nullptr);

                if (!spSession->isAdmin() && user && user->denyLoadMod()) {
                    l["Disabled"] = "true";
                }
            }

            NoTemplate& o1 = Tmpl.addRow("OptionLoop");
            o1["Name"] = "autoclearchanbuffer";
            o1["DisplayName"] = "Auto Clear Chan Buffer";
            o1["Tooltip"] = "Automatically Clear Channel Buffer After Playback (the default value for new channels)";
            if (!user || user->autoClearChanBuffer()) {
                o1["Checked"] = "true";
            }

            /* o2 used to be auto cycle which was removed */

            NoTemplate& o4 = Tmpl.addRow("OptionLoop");
            o4["Name"] = "multiclients";
            o4["DisplayName"] = "Multi Clients";
            if (!user || user->multiClients()) {
                o4["Checked"] = "true";
            }

            NoTemplate& o7 = Tmpl.addRow("OptionLoop");
            o7["Name"] = "appendtimestamp";
            o7["DisplayName"] = "Append Timestamps";
            if (user && user->timestampAppend()) {
                o7["Checked"] = "true";
            }

            NoTemplate& o8 = Tmpl.addRow("OptionLoop");
            o8["Name"] = "prependtimestamp";
            o8["DisplayName"] = "Prepend Timestamps";
            if (user && user->timestampPrepend()) {
                o8["Checked"] = "true";
            }

            if (spSession->isAdmin()) {
                NoTemplate& o9 = Tmpl.addRow("OptionLoop");
                o9["Name"] = "denyloadmod";
                o9["DisplayName"] = "Deny LoadMod";
                if (user && user->denyLoadMod()) {
                    o9["Checked"] = "true";
                }

                NoTemplate& o10 = Tmpl.addRow("OptionLoop");
                o10["Name"] = "isadmin";
                o10["DisplayName"] = "Admin";
                if (user && user->isAdmin()) {
                    o10["Checked"] = "true";
                }
                if (user && user == noApp->findUser(WebSock.username())) {
                    o10["Disabled"] = "true";
                }

                NoTemplate& o11 = Tmpl.addRow("OptionLoop");
                o11["Name"] = "denysetbindhost";
                o11["DisplayName"] = "Deny setBindHost";
                if (user && user->denysetBindHost()) {
                    o11["Checked"] = "true";
                }
            }

            NoTemplate& o12 = Tmpl.addRow("OptionLoop");
            o12["Name"] = "autoclearquerybuffer";
            o12["DisplayName"] = "Auto Clear Query Buffer";
            o12["Tooltip"] = "Automatically Clear Query Buffer After Playback";
            if (!user || user->autoclearQueryBuffer()) {
                o12["Checked"] = "true";
            }

            for (NoModule* mod : allModules(user)) {
                NoTemplate& modrow = Tmpl.addRow("EmbeddedModuleLoop");
                modrow.insert(Tmpl.begin(), Tmpl.end());
                modrow["WebadminAction"] = "display";
                if (mod->onEmbeddedWebRequest(WebSock, "webadmin/user", modrow)) {
                    modrow["Embed"] = WebSock.findTemplate(mod, "WebadminUser.tmpl");
                    modrow["ModName"] = mod->moduleName();
                }
            }

            return true;
        }

        /* If user is nullptr, we are adding a user, else we are editing this one */

        NoString sUsername = WebSock.param("user");
        if (!user && noApp->findUser(sUsername)) {
            WebSock.printErrorPage("Invalid Submission [User " + sUsername + " already exists]");
            return true;
        }

        NoUser* pNewUser = GetNewUser(WebSock, user);
        if (!pNewUser) {
            WebSock.printErrorPage("Invalid user settings");
            return true;
        }

        NoString sErr;
        NoString sAction;

        if (!user) {
            NoString sClone = WebSock.param("clone");
            if (NoUser* pCloneUser = noApp->findUser(sClone)) {
                pNewUser->cloneNetworks(*pCloneUser);
            }

            // Add User Submission
            if (!noApp->addUser(pNewUser, sErr)) {
                delete pNewUser;
                WebSock.printErrorPage("Invalid submission [" + sErr + "]");
                return true;
            }

            user = pNewUser;
            sAction = "added";
        } else {
            // Edit User Submission
            if (!user->clone(*pNewUser, sErr, false)) {
                delete pNewUser;
                WebSock.printErrorPage("Invalid Submission [" + sErr + "]");
                return true;
            }

            delete pNewUser;
            sAction = "edited";
        }

        NoTemplate TmplMod;
        TmplMod["Username"] = sUsername;
        TmplMod["WebadminAction"] = "change";
        for (NoModule* mod : allModules(user)) {
            mod->onEmbeddedWebRequest(WebSock, "webadmin/user", TmplMod);
        }

        if (!noApp->writeConfig()) {
            WebSock.printErrorPage("User " + sAction + ", but config was not written");
            return true;
        }

        if (spSession->isAdmin() && WebSock.hasParam("submit_return")) {
            WebSock.redirect(webPath() + "listusers");
        } else {
            WebSock.redirect(webPath() + "edituser?user=" + user->userName());
        }

        /* we don't want the template to be printed while we redirect */
        return false;
    }

    bool ListUsersPage(NoWebSocket& WebSock, NoTemplate& Tmpl)
    {
        std::shared_ptr<NoWebSession> spSession = WebSock.session();
        const std::map<NoString, NoUser*>& msUsers = noApp->userMap();
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
        Tmpl["Uptime"] = noApp->uptime();

        const std::map<NoString, NoUser*>& msUsers = noApp->userMap();
        Tmpl["TotalUsers"] = NoString(msUsers.size());

        size_t uiNetworks = 0, uiAttached = 0, uiClients = 0, uiServers = 0;

        for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it) {
            NoUser& User = *it->second;
            std::vector<NoNetwork*> vNetworks = User.networks();

            for (std::vector<NoNetwork*>::const_iterator it2 = vNetworks.begin(); it2 != vNetworks.end(); ++it2) {
                NoNetwork* network = *it2;
                uiNetworks++;

                if (network->isIrcConnected()) {
                    uiServers++;
                }

                if (network->isNetworkAttached()) {
                    uiAttached++;
                }

                uiClients += network->clients().size();
            }

            uiClients += User.userClients().size();
        }

        Tmpl["TotalNetworks"] = NoString(uiNetworks);
        Tmpl["AttachedNetworks"] = NoString(uiAttached);
        Tmpl["TotalCConnections"] = NoString(uiClients);
        Tmpl["TotalIRCConnections"] = NoString(uiServers);

        NoApp::TrafficStatsPair Users, ZNC, Total;
        NoApp::TrafficStatsMap traffic = noApp->trafficStats(Users, ZNC, Total);
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
        ushort port = WebSock.param("port").toUShort();
        NoString host = WebSock.param("host");
        NoString sURIPrefix = WebSock.param("uriprefix");
        if (host == "*")
            host = "";
        bool ssl = WebSock.param("ssl").toBool();
        bool bIPv4 = WebSock.param("ipv4").toBool();
        bool bIPv6 = WebSock.param("ipv6").toBool();
        bool bIRC = WebSock.param("irc").toBool();
        bool bWeb = WebSock.param("web").toBool();

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
                WebSock.session()->addError("Choose either IPv4 or IPv6 or both.");
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
                WebSock.session()->addError("Choose either IRC or Web or both.");
                return SettingsPage(WebSock, Tmpl);
            }
        }

        NoString sMessage;
        if (noApp->addListener(port, host, sURIPrefix, ssl, eAddr, eAccept, sMessage)) {
            if (!sMessage.empty()) {
                WebSock.session()->addSuccess(sMessage);
            }
            if (!noApp->writeConfig()) {
                WebSock.session()->addError("Port changed, but config was not written");
            }
        } else {
            WebSock.session()->addError(sMessage);
        }

        return SettingsPage(WebSock, Tmpl);
    }

    bool DelListener(NoWebSocket& WebSock, NoTemplate& Tmpl)
    {
        ushort port = WebSock.param("port").toUShort();
        NoString host = WebSock.param("host");
        bool bIPv4 = WebSock.param("ipv4").toBool();
        bool bIPv6 = WebSock.param("ipv6").toBool();

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
                WebSock.session()->addError("Invalid request.");
                return SettingsPage(WebSock, Tmpl);
            }
        }

        NoListener* pListener = noApp->findListener(port, host, eAddr);
        if (pListener) {
            noApp->removeListener(pListener);
            if (!noApp->writeConfig()) {
                WebSock.session()->addError("Port changed, but config was not written");
            }
        } else {
            WebSock.session()->addError("The specified listener was not found.");
        }

        return SettingsPage(WebSock, Tmpl);
    }

    bool SettingsPage(NoWebSocket& WebSock, NoTemplate& Tmpl)
    {
        Tmpl.setFile("settings.tmpl");
        if (!WebSock.param("submitted").toUInt()) {
            Tmpl["Action"] = "settings";
            Tmpl["Title"] = "Settings";
            Tmpl["StatusPrefix"] = noApp->statusPrefix();
            Tmpl["MaxBufferSize"] = NoString(noApp->maxBufferSize());
            Tmpl["ConnectDelay"] = NoString(noApp->connectDelay());
            Tmpl["ServerThrottle"] = NoString(noApp->serverThrottle());
            Tmpl["AnonIPLimit"] = NoString(noApp->anonIpLimit());
            Tmpl["ProtectWebSessions"] = NoString(noApp->protectWebSessions());
            Tmpl["HideVersion"] = NoString(noApp->hideVersion());

            const NoStringVector& vsBindHosts = noApp->bindHosts();
            for (uint a = 0; a < vsBindHosts.size(); a++) {
                NoTemplate& l = Tmpl.addRow("BindHostLoop");
                l["BindHost"] = vsBindHosts[a];
            }

            const NoStringVector& vsMotd = noApp->motd();
            for (uint b = 0; b < vsMotd.size(); b++) {
                NoTemplate& l = Tmpl.addRow("MOTDLoop");
                l["Line"] = vsMotd[b];
            }

            const std::vector<NoListener*>& vpListeners = noApp->listeners();
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
                l["SuggestDeletion"] = NoString(pListener->port() != WebSock.localPort());

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
            WebSock.availableSkins(vDirs);

            for (uint d = 0; d < vDirs.size(); d++) {
                const NoString& SubDir = vDirs[d];
                NoTemplate& l = Tmpl.addRow("SkinLoop");
                l["Name"] = SubDir;

                if (SubDir == noApp->skinName()) {
                    l["Checked"] = "true";
                }
            }

            std::set<NoModuleInfo> ssGlobalMods;
            noApp->loader()->availableModules(ssGlobalMods, No::GlobalModule);

            for (std::set<NoModuleInfo>::iterator it = ssGlobalMods.begin(); it != ssGlobalMods.end(); ++it) {
                const NoModuleInfo& Info = *it;
                NoTemplate& l = Tmpl.addRow("ModuleLoop");

                NoModule* pModule = noApp->loader()->findModule(Info.name());
                if (pModule) {
                    l["Checked"] = "true";
                    l["Args"] = pModule->args();
                    if (No::GlobalModule == type() && Info.name() == moduleName()) {
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
                const std::map<NoString, NoUser*>& allUsers = noApp->userMap();
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

        NoString arg;
        arg = WebSock.param("statusprefix");
        noApp->setStatusPrefix(arg);
        arg = WebSock.param("maxbufsize");
        noApp->setMaxBufferSize(arg.toUInt());
        arg = WebSock.param("connectdelay");
        noApp->setConnectDelay(arg.toUInt());
        arg = WebSock.param("serverthrottle");
        noApp->setServerThrottle(arg.toUInt());
        arg = WebSock.param("anoniplimit");
        noApp->setAnonIpLimit(arg.toUInt());
        arg = WebSock.param("protectwebsessions");
        noApp->setProtectWebSessions(arg.toBool());
        arg = WebSock.param("hideversion");
        noApp->setHideVersion(arg.toBool());

        NoStringVector vsArgs = WebSock.rawParam("motd").split("\n");
        noApp->clearMotd();

        uint a = 0;
        for (a = 0; a < vsArgs.size(); a++) {
            noApp->addMotd(vsArgs[a].trimRight_n());
        }

        vsArgs = WebSock.rawParam("bindhosts").split("\n");
        noApp->clearBindHosts();

        for (a = 0; a < vsArgs.size(); a++) {
            noApp->addBindHost(vsArgs[a].trim_n());
        }

        noApp->setSkinName(WebSock.param("skin"));

        std::set<NoString> ssArgs;
        WebSock.paramValues("loadmod", ssArgs);

        for (std::set<NoString>::iterator it = ssArgs.begin(); it != ssArgs.end(); ++it) {
            NoString sModRet;
            NoString sModName = (*it).trimRight_n("\r");
            NoString sModLoadError;

            if (!sModName.empty()) {
                NoString args = WebSock.param("modargs_" + sModName);

                NoModule* mod = noApp->loader()->findModule(sModName);
                if (!mod) {
                    if (!noApp->loader()->loadModule(sModName, args, No::GlobalModule, nullptr, nullptr, sModRet)) {
                        sModLoadError = "Unable to load module [" + sModName + "] [" + sModRet + "]";
                    }
                } else if (mod->args() != args) {
                    if (!noApp->loader()->reloadModule(sModName, args, nullptr, nullptr, sModRet)) {
                        sModLoadError = "Unable to reload module [" + sModName + "] [" + sModRet + "]";
                    }
                }

                if (!sModLoadError.empty()) {
                    NO_DEBUG(sModLoadError);
                    WebSock.session()->addError(sModLoadError);
                }
            }
        }

        const NoModuleLoader* vCurMods = noApp->loader();
        std::set<NoString> ssUnloadMods;

        for (NoModule* pCurMod : vCurMods->modules()) {
            if (ssArgs.find(pCurMod->moduleName()) == ssArgs.end() &&
                (No::GlobalModule != type() || pCurMod->moduleName() != moduleName())) {
                ssUnloadMods.insert(pCurMod->moduleName());
            }
        }

        for (std::set<NoString>::iterator it2 = ssUnloadMods.begin(); it2 != ssUnloadMods.end(); ++it2) {
            noApp->loader()->unloadModule(*it2);
        }

        if (!noApp->writeConfig()) {
            WebSock.session()->addError("Settings changed, but config was not written");
        }

        WebSock.redirect(webPath() + "settings");
        /* we don't want the template to be printed while we redirect */
        return false;
    }
};

template <>
void no_moduleInfo<NoWebAdminMod>(NoModuleInfo& Info)
{
    Info.addType(No::UserModule);
    Info.setWikiPage("webadmin");
}

GLOBALMODULEDEFS(NoWebAdminMod, "Web based administration module.")
