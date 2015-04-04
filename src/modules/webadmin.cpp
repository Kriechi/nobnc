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

#include <nobnc/nomodule.h>
#include <nobnc/nomoduleloader.h>
#include <nobnc/nochannel.h>
#include <nobnc/noserverinfo.h>
#include <nobnc/nouser.h>
#include <nobnc/nonetwork.h>
#include <nobnc/noircsocket.h>
#include <nobnc/nodebug.h>
#include <nobnc/noapp.h>
#include <nobnc/nowebsocket.h>
#include <nobnc/nowebsession.h>
#include <nobnc/noescape.h>
#include <nobnc/nolistener.h>
#include <nobnc/noregistry.h>
#include <nobnc/nonick.h>

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
        traffic->setTitle("Traffic info");
        traffic->setFlags(NoWebPage::Admin);
        addSubPage(traffic);

        std::shared_ptr<NoWebPage> listusers = std::make_shared<NoWebPage>("listusers");
        listusers->setTitle("Manage Users");
        listusers->setFlags(NoWebPage::Admin);
        addSubPage(listusers);
    }

    bool onLoad(const NoString& argStr, NoString& message) override
    {
        if (argStr.empty() || No::GlobalModule != type())
            return true;

        // We don't accept any arguments, but for backwards
        // compatibility we have to do some magic here.
        message = "Arguments converted to new syntax";

        bool ssl = false;
        bool bIPv6 = false;
        bool bShareIRCPorts = true;
        ushort port = 8080;
        NoString args(argStr);
        NoString sPort;
        NoString sListenHost;
        NoString uriPrefix;

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
        pListener->setUriPrefix(uriPrefix);
        pListener->setSsl(ssl);
        pListener->setAddressType(!bIPv6 ? No::Ipv4Address : No::Ipv4AndIpv6Address);
        pListener->setAcceptType(No::AcceptHttp);

        if (!pListener->listen()) {
            message = "Failed to add backwards-compatible listener";
            return false;
        }
        noApp->addListener(pListener);

        setArgs("");
        return true;
    }

    NoUser* GetNewUser(NoWebSocket& socket, NoUser* user)
    {
        std::shared_ptr<NoWebSession> spSession = socket.session();
        NoString username = socket.param("newuser");

        if (username.empty()) {
            username = socket.param("user");
        }

        if (username.empty()) {
            socket.printErrorPage("Invalid Submission [Username is required]");
            return nullptr;
        }

        if (user) {
            /* If we are editing a user we must not change the user name */
            username = user->userName();
        }

        NoString arg = socket.param("password");

        if (arg != socket.param("password2")) {
            socket.printErrorPage("Invalid Submission [Passwords do not match]");
            return nullptr;
        }

        NoUser* pNewUser = new NoUser(username);

        if (!arg.empty()) {
            pNewUser->setPassword(arg);
        }

        NoStringVector vsArgs = socket.rawParam("allowedips").split("\n");
        uint a = 0;

        if (vsArgs.size()) {
            for (a = 0; a < vsArgs.size(); a++) {
                pNewUser->addAllowedHost(vsArgs[a].trim_n());
            }
        } else {
            pNewUser->addAllowedHost("*");
        }

        vsArgs = socket.rawParam("ctcpreplies").split("\n");
        for (a = 0; a < vsArgs.size(); a++) {
            NoString reply = vsArgs[a].trimRight_n("\r");
            pNewUser->addCtcpReply(No::token(reply, 0).trim_n(), No::tokens(reply, 1).trim_n());
        }

        arg = socket.param("nick");
        if (!arg.empty()) {
            pNewUser->setNick(arg);
        }
        arg = socket.param("altnick");
        if (!arg.empty()) {
            pNewUser->setAltNick(arg);
        }
        arg = socket.param("statusprefix");
        if (!arg.empty()) {
            pNewUser->setStatusPrefix(arg);
        }
        arg = socket.param("ident");
        if (!arg.empty()) {
            pNewUser->setIdent(arg);
        }
        arg = socket.param("realname");
        if (!arg.empty()) {
            pNewUser->setRealName(arg);
        }
        arg = socket.param("quitmsg");
        if (!arg.empty()) {
            pNewUser->setQuitMessage(arg);
        }
        arg = socket.param("chanmodes");
        if (!arg.empty()) {
            pNewUser->setDefaultChanModes(arg);
        }
        arg = socket.param("timestampformat");
        if (!arg.empty()) {
            pNewUser->setTimestampFormat(arg);
        }

        arg = socket.param("bindhost");
        // To change BindHosts be admin or don't have DenysetBindHost
        if (spSession->isAdmin() || !spSession->user()->denysetBindHost()) {
            NoString arg2 = socket.param("dccbindhost");
            if (!arg.empty()) {
                pNewUser->setBindHost(arg);
            }
            if (!arg2.empty()) {
                pNewUser->setDccBindHost(arg2);
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
                    if (arg2.equals(*it)) {
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

        arg = socket.param("bufsize");
        if (!arg.empty())
            pNewUser->setBufferCount(arg.toUInt(), spSession->isAdmin());
        if (!arg.empty()) {
            // First apply the old limit in case the new one is too high
            if (user)
                pNewUser->setBufferCount(user->bufferCount(), true);
            pNewUser->setBufferCount(arg.toUInt(), spSession->isAdmin());
        }

        pNewUser->setSkinName(socket.param("skin"));
        pNewUser->setAutoClearChanBuffer(socket.param("autoclearchanbuffer").toBool());
        pNewUser->setMultiClients(socket.param("multiclients").toBool());
        pNewUser->setTimestampAppend(socket.param("appendtimestamp").toBool());
        pNewUser->setTimestampPrepend(socket.param("prependtimestamp").toBool());
        pNewUser->setTimezone(socket.param("timezone"));
        pNewUser->setJoinTries(socket.param("jointries").toUInt());
        pNewUser->setMaxJoins(socket.param("maxjoins").toUInt());
        pNewUser->setAutoclearQueryBuffer(socket.param("autoclearquerybuffer").toBool());
        pNewUser->setMaxQueryBuffers(socket.param("maxquerybuffers").toUInt());

#ifdef HAVE_ICU
        NoString sEncodingUtf = socket.param("encoding_utf");
        if (sEncodingUtf == "legacy") {
            pNewUser->setClientEncoding("");
        }
        NoString sEncoding = socket.param("encoding");
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
            pNewUser->setDenyLoadMod(socket.param("denyloadmod").toBool());
            pNewUser->setDenysetBindHost(socket.param("denysetbindhost").toBool());
            arg = socket.param("maxnetworks");
            if (!arg.empty())
                pNewUser->setMaxNetworks(arg.toUInt());
        } else if (user) {
            pNewUser->setDenyLoadMod(user->denyLoadMod());
            pNewUser->setDenysetBindHost(user->denysetBindHost());
            pNewUser->setMaxNetworks(user->maxNetworks());
        }

        // If user is not nullptr, we are editing an existing user.
        // Users must not be able to change their own admin flag.
        if (user != noApp->findUser(socket.username())) {
            pNewUser->setAdmin(socket.param("isadmin").toBool());
        } else if (user) {
            pNewUser->setAdmin(user->isAdmin());
        }

        if (spSession->isAdmin() || (user && !user->denyLoadMod())) {
            socket.paramValues("loadmod", vsArgs);

            // disallow unload webadmin from itself
            if (No::UserModule == type() && user == noApp->findUser(socket.username())) {
                bool bLoadedWebadmin = false;
                for (a = 0; a < vsArgs.size(); ++a) {
                    NoString name = vsArgs[a].trimRight_n("\r");
                    if (name == moduleName()) {
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
                NoString name = vsArgs[a].trimRight_n("\r");
                NoString sModLoadError;

                if (!name.empty()) {
                    NoString args = socket.param("modargs_" + name);

                    try {
                        if (!pNewUser->loader()->loadModule(name, args, No::UserModule, pNewUser, nullptr, sModRet)) {
                            sModLoadError = "Unable to load module [" + name + "] [" + sModRet + "]";
                        }
                    } catch (...) {
                        sModLoadError = "Unable to load module [" + name + "] [" + args + "]";
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
                NoString name = mod->moduleName();
                NoString args = mod->args();
                NoString sModRet;
                NoString sModLoadError;

                try {
                    if (!pNewUser->loader()->loadModule(name, args, No::UserModule, pNewUser, nullptr, sModRet)) {
                        sModLoadError = "Unable to load module [" + name + "] [" + sModRet + "]";
                    }
                } catch (...) {
                    sModLoadError = "Unable to load module [" + name + "]";
                }

                if (!sModLoadError.empty()) {
                    NO_DEBUG(sModLoadError);
                    spSession->addError(sModLoadError);
                }
            }
        }

        return pNewUser;
    }

    NoString SafeGetUserNameParam(NoWebSocket& socket)
    {
        NoString userName = socket.param("user"); // check for POST param
        if (userName.empty() && !socket.isPost()) {
            // if no POST param named user has been given and we are not
            // saving this form, fall back to using the GET parameter.
            userName = socket.param("user", false);
        }
        return userName;
    }

    NoString SafeGetNetworkParam(NoWebSocket& socket)
    {
        NoString sNetwork = socket.param("network"); // check for POST param
        if (sNetwork.empty() && !socket.isPost()) {
            // if no POST param named user has been given and we are not
            // saving this form, fall back to using the GET parameter.
            sNetwork = socket.param("network", false);
        }
        return sNetwork;
    }

    NoUser* SafeGetUserFromParam(NoWebSocket& socket)
    {
        return noApp->findUser(SafeGetUserNameParam(socket));
    }

    NoNetwork* SafeGetNetworkFromParam(NoWebSocket& socket)
    {
        NoUser* user = noApp->findUser(SafeGetUserNameParam(socket));
        NoNetwork* network = nullptr;

        if (user) {
            network = user->findNetwork(SafeGetNetworkParam(socket));
        }

        return network;
    }

    NoString webMenuTitle() override
    {
        return "webadmin";
    }
    bool onWebRequest(NoWebSocket& socket, const NoString& page, NoTemplate& tmpl) override
    {
        std::shared_ptr<NoWebSession> spSession = socket.session();

        if (page == "settings") {
            // Admin Check
            if (!spSession->isAdmin()) {
                return false;
            }

            return SettingsPage(socket, tmpl);
        } else if (page == "adduser") {
            // Admin Check
            if (!spSession->isAdmin()) {
                return false;
            }

            return UserPage(socket, tmpl);
        } else if (page == "addnetwork") {
            NoUser* user = SafeGetUserFromParam(socket);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || spSession->user() != user)) {
                return false;
            }

            if (user) {
                return NetworkPage(socket, tmpl, user);
            }

            socket.printErrorPage("No such username");
            return true;
        } else if (page == "editnetwork") {
            NoNetwork* network = SafeGetNetworkFromParam(socket);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || !network || spSession->user() != network->user())) {
                return false;
            }

            if (!network) {
                socket.printErrorPage("No such username or network");
                return true;
            }

            return NetworkPage(socket, tmpl, network->user(), network);

        } else if (page == "delnetwork") {
            NoString sUser = socket.param("user");
            if (sUser.empty() && !socket.isPost()) {
                sUser = socket.param("user", false);
            }

            NoUser* user = noApp->findUser(sUser);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || spSession->user() != user)) {
                return false;
            }

            return DelNetwork(socket, user, tmpl);
        } else if (page == "editchan") {
            NoNetwork* network = SafeGetNetworkFromParam(socket);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || !network || spSession->user() != network->user())) {
                return false;
            }

            if (!network) {
                socket.printErrorPage("No such username or network");
                return true;
            }

            NoString sChan = socket.param("name");
            if (sChan.empty() && !socket.isPost()) {
                sChan = socket.param("name", false);
            }
            NoChannel* channel = network->findChannel(sChan);
            if (!channel) {
                socket.printErrorPage("No such channel");
                return true;
            }

            return ChanPage(socket, tmpl, network, channel);
        } else if (page == "addchan") {
            NoNetwork* network = SafeGetNetworkFromParam(socket);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || !network || spSession->user() != network->user())) {
                return false;
            }

            if (network) {
                return ChanPage(socket, tmpl, network);
            }

            socket.printErrorPage("No such username or network");
            return true;
        } else if (page == "delchan") {
            NoNetwork* network = SafeGetNetworkFromParam(socket);

            // Admin||Self Check
            if (!spSession->isAdmin() && (!spSession->user() || !network || spSession->user() != network->user())) {
                return false;
            }

            if (network) {
                return removeChannel(socket, network);
            }

            socket.printErrorPage("No such username or network");
            return true;
        } else if (page == "deluser") {
            if (!spSession->isAdmin()) {
                return false;
            }

            if (!socket.isPost()) {
                // Show the "Are you sure?" page:

                NoString sUser = socket.param("user", false);
                NoUser* user = noApp->findUser(sUser);

                if (!user) {
                    socket.printErrorPage("No such username");
                    return true;
                }

                tmpl.setFile("del_user.tmpl");
                tmpl["Username"] = sUser;
                return true;
            }

            // The "Are you sure?" page has been submitted with "Yes",
            // so we actually delete the user now:

            NoString sUser = socket.param("user");
            NoUser* user = noApp->findUser(sUser);

            if (user && user == spSession->user()) {
                socket.printErrorPage("Please don't delete yourself, suicide is not the answer!");
                return true;
            } else if (noApp->deleteUser(sUser)) {
                socket.redirect(webPath() + "listusers");
                return true;
            }

            socket.printErrorPage("No such username");
            return true;
        } else if (page == "edituser") {
            NoString userName = SafeGetUserNameParam(socket);
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
                return UserPage(socket, tmpl, user);
            }

            socket.printErrorPage("No such username");
            return true;
        } else if (page == "listusers" && spSession->isAdmin()) {
            return ListUsersPage(socket, tmpl);
        } else if (page == "traffic" && spSession->isAdmin()) {
            return TrafficPage(socket, tmpl);
        } else if (page == "index") {
            return true;
        } else if (page == "add_listener") {
            // Admin Check
            if (!spSession->isAdmin()) {
                return false;
            }

            return AddListener(socket, tmpl);
        } else if (page == "del_listener") {
            // Admin Check
            if (!spSession->isAdmin()) {
                return false;
            }

            return DelListener(socket, tmpl);
        }

        return false;
    }

    bool ChanPage(NoWebSocket& socket, NoTemplate& tmpl, NoNetwork* network, NoChannel* channel = nullptr)
    {
        std::shared_ptr<NoWebSession> spSession = socket.session();
        tmpl.setFile("add_edit_chan.tmpl");
        NoUser* user = network->user();

        if (!user) {
            socket.printErrorPage("That user doesn't exist");
            return true;
        }

        if (!socket.param("submitted").toUInt()) {
            tmpl["User"] = user->userName();
            tmpl["Network"] = network->name();

            if (channel) {
                tmpl["Action"] = "editchan";
                tmpl["Edit"] = "true";
                tmpl["Title"] = "Edit channel" + NoString(" [" + channel->name() + "]") + " of network [" +
                                network->name() + "] of User [" + network->user()->userName() + "]";
                tmpl["ChanName"] = channel->name();
                tmpl["BufferCount"] = NoString(channel->bufferCount());
                tmpl["DefModes"] = channel->defaultModes();
                tmpl["Key"] = channel->key();

                if (channel->inConfig()) {
                    tmpl["InConfig"] = "true";
                }
            } else {
                tmpl["Action"] = "addchan";
                tmpl["Title"] = "Add channel" + NoString(" for User [" + user->userName() + "]");
                tmpl["BufferCount"] = NoString(user->bufferCount());
                tmpl["DefModes"] = NoString(user->defaultChanModes());
                tmpl["InConfig"] = "true";
            }

            // o1 used to be AutoCycle which was removed

            NoTemplate& o2 = tmpl.addRow("OptionLoop");
            o2["Name"] = "autoclearchanbuffer";
            o2["DisplayName"] = "Auto Clear channel Buffer";
            o2["Tooltip"] = "Automatically Clear channel Buffer After Playback";
            if ((channel && channel->autoClearChanBuffer()) || (!channel && user->autoClearChanBuffer())) {
                o2["Checked"] = "true";
            }

            NoTemplate& o3 = tmpl.addRow("OptionLoop");
            o3["Name"] = "detached";
            o3["DisplayName"] = "Detached";
            if (channel && channel->isDetached()) {
                o3["Checked"] = "true";
            }

            NoTemplate& o4 = tmpl.addRow("OptionLoop");
            o4["Name"] = "disabled";
            o4["DisplayName"] = "Disabled";
            if (channel && channel->isDisabled()) {
                o4["Checked"] = "true";
            }

            for (NoModule* mod : allModules(network)) {
                NoTemplate& modrow = tmpl.addRow("EmbeddedModuleLoop");
                modrow.insert(tmpl.begin(), tmpl.end());
                modrow["WebadminAction"] = "display";
                if (mod->onEmbeddedWebRequest(socket, "webadmin/channel", modrow)) {
                    modrow["Embed"] = socket.findTemplate(mod, "WebadminChan.tmpl");
                    modrow["ModName"] = mod->moduleName();
                }
            }

            return true;
        }

        NoString sChanName = socket.param("name").trim_n();

        if (!channel) {
            if (sChanName.empty()) {
                socket.printErrorPage("channel name is a required argument");
                return true;
            }

            // This could change the channel name and e.g. add a "#" prefix
            channel = new NoChannel(sChanName, network, true);

            if (network->findChannel(channel->name())) {
                socket.printErrorPage("channel [" + channel->name() + "] already exists");
                delete channel;
                return true;
            }

            if (!network->addChannel(channel)) {
                socket.printErrorPage("Could not add channel [" + channel->name() + "]");
                return true;
            }
        }

        uint uBufferCount = socket.param("buffercount").toUInt();
        if (channel->bufferCount() != uBufferCount) {
            channel->setBufferCount(uBufferCount, spSession->isAdmin());
        }
        channel->setDefaultModes(socket.param("defmodes"));
        channel->setInConfig(socket.param("save").toBool());
        bool bAutoClearChanBuffer = socket.param("autoclearchanbuffer").toBool();
        if (channel->autoClearChanBuffer() != bAutoClearChanBuffer) {
            channel->setAutoClearChanBuffer(socket.param("autoclearchanbuffer").toBool());
        }
        channel->setKey(socket.param("key"));

        bool bDetached = socket.param("detached").toBool();
        if (channel->isDetached() != bDetached) {
            if (bDetached) {
                channel->detachUser();
            } else {
                channel->attachUser();
            }
        }

        bool bDisabled = socket.param("disabled").toBool();
        if (bDisabled)
            channel->disable();
        else
            channel->enable();

        NoTemplate TmplMod;
        TmplMod["User"] = user->userName();
        TmplMod["ChanName"] = channel->name();
        TmplMod["WebadminAction"] = "change";
        for (NoModule* mod : allModules(network)) {
            mod->onEmbeddedWebRequest(socket, "webadmin/channel", TmplMod);
        }

        if (!noApp->writeConfig()) {
            socket.printErrorPage("channel added/modified, but config was not written");
            return true;
        }

        if (socket.hasParam("submit_return")) {
            socket.redirect(webPath() + "editnetwork?user=" + No::escape(user->userName(), No::UrlFormat) +
                             "&network=" + No::escape(network->name(), No::UrlFormat));
        } else {
            socket.redirect(webPath() + "editchan?user=" + No::escape(user->userName(), No::UrlFormat) + "&network=" +
                             No::escape(network->name(), No::UrlFormat) + "&name=" + No::escape(channel->name(), No::UrlFormat));
        }
        return true;
    }

    bool NetworkPage(NoWebSocket& socket, NoTemplate& tmpl, NoUser* user, NoNetwork* network = nullptr)
    {
        std::shared_ptr<NoWebSession> spSession = socket.session();
        tmpl.setFile("add_edit_network.tmpl");

        if (!socket.param("submitted").toUInt()) {
            tmpl["Username"] = user->userName();

            std::set<NoModuleInfo> ssNetworkMods = noApp->loader()->availableModules(No::NetworkModule);
            for (std::set<NoModuleInfo>::iterator it = ssNetworkMods.begin(); it != ssNetworkMods.end(); ++it) {
                const NoModuleInfo& info = *it;
                NoTemplate& l = tmpl.addRow("ModuleLoop");

                l["Name"] = info.name();
                l["Description"] = info.description();
                l["Wiki"] = info.wikiPage();
                l["HasArgs"] = NoString(info.hasArgs());
                l["ArgsHelpText"] = info.argsHelpText();

                if (network) {
                    NoModule* module = network->loader()->findModule(info.name());
                    if (module) {
                        l["Checked"] = "true";
                        l["Args"] = module->args();
                    }
                }

                // Check if module is loaded globally
                l["CanBeLoadedGlobally"] = NoString(info.supportsType(No::GlobalModule));
                l["LoadedGlobally"] = NoString(noApp->loader()->findModule(info.name()) != nullptr);

                // Check if module is loaded by user
                l["CanBeLoadedByUser"] = NoString(info.supportsType(No::UserModule));
                l["LoadedByUser"] = NoString(user->loader()->findModule(info.name()) != nullptr);

                if (!spSession->isAdmin() && user->denyLoadMod()) {
                    l["Disabled"] = "true";
                }
            }

            // To change BindHosts be admin or don't have DenysetBindHost
            if (spSession->isAdmin() || !spSession->user()->denysetBindHost()) {
                tmpl["BindHostEdit"] = "true";
                const NoStringVector& vsBindHosts = noApp->bindHosts();
                if (vsBindHosts.empty()) {
                    if (network) {
                        tmpl["BindHost"] = network->bindHost();
                    }
                } else {
                    bool bFoundBindHost = false;
                    for (uint b = 0; b < vsBindHosts.size(); b++) {
                        const NoString& bindHost = vsBindHosts[b];
                        NoTemplate& l = tmpl.addRow("BindHostLoop");

                        l["BindHost"] = bindHost;

                        if (network && network->bindHost() == bindHost) {
                            l["Checked"] = "true";
                            bFoundBindHost = true;
                        }
                    }

                    // If our current bindhost is not in the global list...
                    if (network && !bFoundBindHost && !network->bindHost().empty()) {
                        NoTemplate& l = tmpl.addRow("BindHostLoop");

                        l["BindHost"] = network->bindHost();
                        l["Checked"] = "true";
                    }
                }
            }

            if (network) {
                tmpl["Action"] = "editnetwork";
                tmpl["Edit"] = "true";
                tmpl["Title"] = "Edit network" + NoString(" [" + network->name() + "]") + " of User [" + user->userName() + "]";
                tmpl["Name"] = network->name();

                tmpl["Nick"] = network->nick();
                tmpl["AltNick"] = network->altNick();
                tmpl["Ident"] = network->ident();
                tmpl["RealName"] = network->realName();

                tmpl["QuitMsg"] = network->quitMessage();

                tmpl["FloodProtection"] = NoString(NoIrcSocket::isFloodProtected(network->floodRate()));
                tmpl["FloodRate"] = NoString(network->floodRate());
                tmpl["FloodBurst"] = NoString(network->floodBurst());

                tmpl["JoinDelay"] = NoString(network->joinDelay());

                tmpl["IRCConnectEnabled"] = NoString(network->isEnabled());

                const std::vector<NoServerInfo*>& vServers = network->servers();
                for (uint a = 0; a < vServers.size(); a++) {
                    NoTemplate& l = tmpl.addRow("ServerLoop");
                    l["Server"] = vServers[a]->toString();
                }

                const std::vector<NoChannel*>& Channels = network->channels();
                for (uint c = 0; c < Channels.size(); c++) {
                    NoChannel* channel = Channels[c];
                    NoTemplate& l = tmpl.addRow("ChannelLoop");

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
                for (const NoString& fingerprint : network->trustedFingerprints()) {
                    NoTemplate& l = tmpl.addRow("TrustedFingerprints");
                    l["FP"] = fingerprint;
                }
            } else {
                if (!spSession->isAdmin() && !user->hasSpaceForNewNetwork()) {
                    socket.printErrorPage("Network number limit reached. Ask an admin to increase the limit for you, "
                                           "or delete unneeded networks from Your Settings.");
                    return true;
                }

                tmpl["Action"] = "addnetwork";
                tmpl["Title"] = "Add network for User [" + user->userName() + "]";
                tmpl["IRCConnectEnabled"] = "true";
                tmpl["FloodProtection"] = "true";
                tmpl["FloodRate"] = "1.0";
                tmpl["FloodBurst"] = "4";
                tmpl["JoinDelay"] = "0";
            }

            for (NoModule* mod : allModules(user, network)) {
                NoTemplate& modrow = tmpl.addRow("EmbeddedModuleLoop");
                modrow.insert(tmpl.begin(), tmpl.end());
                modrow["WebadminAction"] = "display";
                if (mod->onEmbeddedWebRequest(socket, "webadmin/network", modrow)) {
                    modrow["Embed"] = socket.findTemplate(mod, "WebadminNetwork.tmpl");
                    modrow["ModName"] = mod->moduleName();
                }
            }

#ifdef HAVE_ICU
            for (const NoString& sEncoding : No::encodings()) {
                NoTemplate& l = tmpl.addRow("EncodingLoop");
                l["Encoding"] = sEncoding;
            }
            const NoString sEncoding = network ? network->encoding() : "^UTF-8";
            if (sEncoding.empty()) {
                tmpl["EncodingUtf"] = "legacy";
            } else if (sEncoding[0] == '*') {
                tmpl["EncodingUtf"] = "receive";
                tmpl["Encoding"] = sEncoding.substr(1);
            } else if (sEncoding[0] == '^') {
                tmpl["EncodingUtf"] = "send";
                tmpl["Encoding"] = sEncoding.substr(1);
            } else {
                tmpl["EncodingUtf"] = "simple";
                tmpl["Encoding"] = sEncoding;
            }
#else
            tmpl["EncodingDisabled"] = "true";
            tmpl["EncodingUtf"] = "legacy";
#endif

            return true;
        }

        NoString name = socket.param("name").trim_n();
        if (name.empty()) {
            socket.printErrorPage("Network name is a required argument");
            return true;
        }
        if (!network && !spSession->isAdmin() && !user->hasSpaceForNewNetwork()) {
            socket.printErrorPage("Network number limit reached. Ask an admin to increase the limit for you, or "
                                   "delete few old ones from Your Settings");
            return true;
        }
        if (!network || network->name() != name) {
            NoString sNetworkAddError;
            NoNetwork* pOldNetwork = network;
            network = user->addNetwork(name, sNetworkAddError);
            if (!network) {
                socket.printErrorPage(sNetworkAddError);
                return true;
            }
            if (pOldNetwork) {
                for (NoModule* module : pOldNetwork->loader()->modules()) {
                    NoString path = user->userPath() + "/networks/" + name + "/moddata/" + module->moduleName();
                    NoRegistry registry(module);
                    registry.copy(path);
                }
                network->clone(*pOldNetwork, false);
                user->deleteNetwork(pOldNetwork->name());
            }
        }

        NoString arg;

        network->setNick(socket.param("nick"));
        network->setAltNick(socket.param("altnick"));
        network->setIdent(socket.param("ident"));
        network->setRealName(socket.param("realname"));

        network->setQuitMessage(socket.param("quitmsg"));

        network->setEnabled(socket.param("doconnect").toBool());

        arg = socket.param("bindhost");
        // To change BindHosts be admin or don't have DenysetBindHost
        if (spSession->isAdmin() || !spSession->user()->denysetBindHost()) {
            NoString host = socket.param("bindhost");
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

        if (socket.param("floodprotection").toBool()) {
            network->setFloodRate(socket.param("floodrate").toDouble());
            network->setFloodBurst(socket.param("floodburst").toUShort());
        } else {
            network->setFloodRate(-1);
        }

        network->setJoinDelay(socket.param("joindelay").toUShort());

#ifdef HAVE_ICU
        NoString sEncodingUtf = socket.param("encoding_utf");
        if (sEncodingUtf == "legacy") {
            network->setEncoding("");
        }
        NoString sEncoding = socket.param("encoding");
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
        NoStringVector vsArgs = socket.rawParam("servers").split("\n");
        for (uint a = 0; a < vsArgs.size(); a++) {
            network->addServer(vsArgs[a].trim_n());
        }

        vsArgs = socket.rawParam("fingerprints").split("\n");
        while (!network->trustedFingerprints().empty()) {
            network->removeTrustedFingerprint(*network->trustedFingerprints().begin());
        }
        for (const NoString& fingerprint : vsArgs) {
            network->addTrustedFingerprint(fingerprint);
        }

        socket.paramValues("channel", vsArgs);
        for (uint a = 0; a < vsArgs.size(); a++) {
            const NoString& sChan = vsArgs[a];
            NoChannel* channel = network->findChannel(sChan.trimRight_n("\r"));
            if (channel) {
                channel->setInConfig(socket.param("save_" + sChan).toBool());
            }
        }

        std::set<NoString> ssArgs;
        socket.paramValues("loadmod", ssArgs);
        if (spSession->isAdmin() || !user->denyLoadMod()) {
            for (std::set<NoString>::iterator it = ssArgs.begin(); it != ssArgs.end(); ++it) {
                NoString sModRet;
                NoString name = (*it).trimRight_n("\r");
                NoString sModLoadError;

                if (!name.empty()) {
                    NoString args = socket.param("modargs_" + name);

                    NoModule* mod = network->loader()->findModule(name);

                    if (!mod) {
                        if (!network->loader()->loadModule(name, args, No::NetworkModule, user, network, sModRet)) {
                            sModLoadError = "Unable to load module [" + name + "] [" + sModRet + "]";
                        }
                    } else if (mod->args() != args) {
                        if (!network->loader()->reloadModule(name, args, user, network, sModRet)) {
                            sModLoadError = "Unable to reload module [" + name + "] [" + sModRet + "]";
                        }
                    }

                    if (!sModLoadError.empty()) {
                        NO_DEBUG(sModLoadError);
                        socket.session()->addError(sModLoadError);
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
            mod->onEmbeddedWebRequest(socket, "webadmin/network", TmplMod);
        }

        if (!noApp->writeConfig()) {
            socket.printErrorPage("Network added/modified, but config was not written");
            return true;
        }

        if (socket.hasParam("submit_return")) {
            socket.redirect(webPath() + "edituser?user=" + No::escape(user->userName(), No::UrlFormat));
        } else {
            socket.redirect(webPath() + "editnetwork?user=" + No::escape(user->userName(), No::UrlFormat) +
                             "&network=" + No::escape(network->name(), No::UrlFormat));
        }
        return true;
    }

    bool DelNetwork(NoWebSocket& socket, NoUser* user, NoTemplate& tmpl)
    {
        NoString sNetwork = socket.param("name");
        if (sNetwork.empty() && !socket.isPost()) {
            sNetwork = socket.param("name", false);
        }

        if (!user) {
            socket.printErrorPage("That user doesn't exist");
            return true;
        }

        if (sNetwork.empty()) {
            socket.printErrorPage("That network doesn't exist for this user");
            return true;
        }

        if (!socket.isPost()) {
            // Show the "Are you sure?" page:

            tmpl.setFile("del_network.tmpl");
            tmpl["Username"] = user->userName();
            tmpl["Network"] = sNetwork;
            return true;
        }

        user->deleteNetwork(sNetwork);

        if (!noApp->writeConfig()) {
            socket.printErrorPage("Network deleted, but config was not written");
            return true;
        }

        socket.redirect(webPath() + "edituser?user=" + No::escape(user->userName(), No::UrlFormat));
        return false;
    }

    bool removeChannel(NoWebSocket& socket, NoNetwork* network)
    {
        NoString sChan = socket.param("name", false);

        if (sChan.empty()) {
            socket.printErrorPage("That channel doesn't exist for this user");
            return true;
        }

        network->removeChannel(sChan);
        network->putIrc("PART " + sChan);

        if (!noApp->writeConfig()) {
            socket.printErrorPage("channel deleted, but config was not written");
            return true;
        }

        socket.redirect(webPath() + "editnetwork?user=" + No::escape(network->user()->userName(), No::UrlFormat) +
                         "&network=" + No::escape(network->name(), No::UrlFormat));
        return false;
    }

    bool UserPage(NoWebSocket& socket, NoTemplate& tmpl, NoUser* user = nullptr)
    {
        std::shared_ptr<NoWebSession> spSession = socket.session();
        tmpl.setFile("add_edit_user.tmpl");

        if (!socket.param("submitted").toUInt()) {
            if (user) {
                tmpl["Action"] = "edituser";
                tmpl["Title"] = "Edit User [" + user->userName() + "]";
                tmpl["Edit"] = "true";
            } else {
                NoString username = socket.param("clone", false);
                user = noApp->findUser(username);

                if (user) {
                    tmpl["Title"] = "Clone User [" + user->userName() + "]";
                    tmpl["Clone"] = "true";
                    tmpl["CloneUsername"] = user->userName();
                }
            }

            tmpl["ImAdmin"] = NoString(spSession->isAdmin());

            if (user) {
                tmpl["Username"] = user->userName();
                tmpl["Nick"] = user->nick();
                tmpl["AltNick"] = user->altNick();
                tmpl["StatusPrefix"] = user->statusPrefix();
                tmpl["Ident"] = user->ident();
                tmpl["RealName"] = user->realName();
                tmpl["QuitMsg"] = user->quitMessage();
                tmpl["DefaultChanModes"] = user->defaultChanModes();
                tmpl["BufferCount"] = NoString(user->bufferCount());
                tmpl["TimestampFormat"] = user->timestampFormat();
                tmpl["Timezone"] = user->timezone();
                tmpl["JoinTries"] = NoString(user->joinTries());
                tmpl["MaxNetworks"] = NoString(user->maxNetworks());
                tmpl["MaxJoins"] = NoString(user->maxJoins());
                tmpl["MaxQueryBuffers"] = NoString(user->maxQueryBuffers());

                const std::set<NoString>& ssAllowedHosts = user->allowedHosts();
                for (std::set<NoString>::const_iterator it = ssAllowedHosts.begin(); it != ssAllowedHosts.end(); ++it) {
                    NoTemplate& l = tmpl.addRow("AllowedHostLoop");
                    l["Host"] = *it;
                }

                const std::vector<NoNetwork*>& vNetworks = user->networks();
                for (uint a = 0; a < vNetworks.size(); a++) {
                    NoTemplate& l = tmpl.addRow("NetworkLoop");
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
                    NoTemplate& l = tmpl.addRow("CTCPLoop");
                    l["CTCP"] = it2->first + " " + it2->second;
                }
            } else {
                tmpl["Action"] = "adduser";
                tmpl["Title"] = "Add User";
                tmpl["StatusPrefix"] = "*";
            }

            NoStringSet ssTimezones = No::timezones();
            for (NoStringSet::iterator i = ssTimezones.begin(); i != ssTimezones.end(); ++i) {
                NoTemplate& l = tmpl.addRow("TZLoop");
                l["TZ"] = *i;
            }

#ifdef HAVE_ICU
            for (const NoString& sEncoding : No::encodings()) {
                NoTemplate& l = tmpl.addRow("EncodingLoop");
                l["Encoding"] = sEncoding;
            }
            const NoString sEncoding = user ? user->clientEncoding() : "^UTF-8";
            if (sEncoding.empty()) {
                tmpl["EncodingUtf"] = "legacy";
            } else if (sEncoding[0] == '*') {
                tmpl["EncodingUtf"] = "receive";
                tmpl["Encoding"] = sEncoding.substr(1);
            } else if (sEncoding[0] == '^') {
                tmpl["EncodingUtf"] = "send";
                tmpl["Encoding"] = sEncoding.substr(1);
            } else {
                tmpl["EncodingUtf"] = "simple";
                tmpl["Encoding"] = sEncoding;
            }
#else
            tmpl["EncodingDisabled"] = "true";
            tmpl["EncodingUtf"] = "legacy";
#endif

            // To change BindHosts be admin or don't have DenysetBindHost
            if (spSession->isAdmin() || !spSession->user()->denysetBindHost()) {
                tmpl["BindHostEdit"] = "true";
                const NoStringVector& vsBindHosts = noApp->bindHosts();
                if (vsBindHosts.empty()) {
                    if (user) {
                        tmpl["BindHost"] = user->bindHost();
                        tmpl["DCCBindHost"] = user->dccBindHost();
                    }
                } else {
                    bool bFoundBindHost = false;
                    bool bFoundDCCBindHost = false;
                    for (uint b = 0; b < vsBindHosts.size(); b++) {
                        const NoString& bindHost = vsBindHosts[b];
                        NoTemplate& l = tmpl.addRow("BindHostLoop");
                        NoTemplate& k = tmpl.addRow("DCCBindHostLoop");

                        l["BindHost"] = bindHost;
                        k["BindHost"] = bindHost;

                        if (user && user->bindHost() == bindHost) {
                            l["Checked"] = "true";
                            bFoundBindHost = true;
                        }

                        if (user && user->dccBindHost() == bindHost) {
                            k["Checked"] = "true";
                            bFoundDCCBindHost = true;
                        }
                    }

                    // If our current bindhost is not in the global list...
                    if (user && !bFoundBindHost && !user->bindHost().empty()) {
                        NoTemplate& l = tmpl.addRow("BindHostLoop");

                        l["BindHost"] = user->bindHost();
                        l["Checked"] = "true";
                    }
                    if (user && !bFoundDCCBindHost && !user->dccBindHost().empty()) {
                        NoTemplate& l = tmpl.addRow("DCCBindHostLoop");

                        l["BindHost"] = user->dccBindHost();
                        l["Checked"] = "true";
                    }
                }
            }

            std::vector<NoString> vDirs;
            socket.availableSkins(vDirs);

            for (uint d = 0; d < vDirs.size(); d++) {
                const NoString& SubDir = vDirs[d];
                NoTemplate& l = tmpl.addRow("SkinLoop");
                l["Name"] = SubDir;

                if (user && SubDir == user->skinName()) {
                    l["Checked"] = "true";
                }
            }

            std::set<NoModuleInfo> ssUserMods = noApp->loader()->availableModules(No::UserModule);

            for (std::set<NoModuleInfo>::iterator it = ssUserMods.begin(); it != ssUserMods.end(); ++it) {
                const NoModuleInfo& info = *it;
                NoTemplate& l = tmpl.addRow("ModuleLoop");

                l["Name"] = info.name();
                l["Description"] = info.description();
                l["Wiki"] = info.wikiPage();
                l["HasArgs"] = NoString(info.hasArgs());
                l["ArgsHelpText"] = info.argsHelpText();

                NoModule* module = nullptr;
                if (user) {
                    module = user->loader()->findModule(info.name());
                    // Check if module is loaded by all or some networks
                    const std::vector<NoNetwork*>& userNetworks = user->networks();
                    uint networksWithRenderedModuleCount = 0;
                    for (uint networkIndex = 0; networkIndex < userNetworks.size(); ++networkIndex) {
                        const NoNetwork* pCurrentNetwork = userNetworks[networkIndex];
                        const NoModuleLoader* networkModules = pCurrentNetwork->loader();
                        if (networkModules->findModule(info.name())) {
                            networksWithRenderedModuleCount++;
                        }
                    }
                    l["CanBeLoadedByNetwork"] = NoString(info.supportsType(No::NetworkModule));
                    l["LoadedByAllNetworks"] = NoString(networksWithRenderedModuleCount == userNetworks.size());
                    l["LoadedBySomeNetworks"] = NoString(networksWithRenderedModuleCount != 0);
                }
                if (module) {
                    l["Checked"] = "true";
                    l["Args"] = module->args();
                    if (No::UserModule == type() && info.name() == moduleName()) {
                        l["Disabled"] = "true";
                    }
                }
                l["CanBeLoadedGlobally"] = NoString(info.supportsType(No::GlobalModule));
                // Check if module is loaded globally
                l["LoadedGlobally"] = NoString(noApp->loader()->findModule(info.name()) != nullptr);

                if (!spSession->isAdmin() && user && user->denyLoadMod()) {
                    l["Disabled"] = "true";
                }
            }

            NoTemplate& o1 = tmpl.addRow("OptionLoop");
            o1["Name"] = "autoclearchanbuffer";
            o1["DisplayName"] = "Auto Clear channel Buffer";
            o1["Tooltip"] = "Automatically Clear channel Buffer After Playback (the default value for new channels)";
            if (!user || user->autoClearChanBuffer()) {
                o1["Checked"] = "true";
            }

            /* o2 used to be auto cycle which was removed */

            NoTemplate& o4 = tmpl.addRow("OptionLoop");
            o4["Name"] = "multiclients";
            o4["DisplayName"] = "Multi Clients";
            if (!user || user->multiClients()) {
                o4["Checked"] = "true";
            }

            NoTemplate& o7 = tmpl.addRow("OptionLoop");
            o7["Name"] = "appendtimestamp";
            o7["DisplayName"] = "Append Timestamps";
            if (user && user->timestampAppend()) {
                o7["Checked"] = "true";
            }

            NoTemplate& o8 = tmpl.addRow("OptionLoop");
            o8["Name"] = "prependtimestamp";
            o8["DisplayName"] = "Prepend Timestamps";
            if (user && user->timestampPrepend()) {
                o8["Checked"] = "true";
            }

            if (spSession->isAdmin()) {
                NoTemplate& o9 = tmpl.addRow("OptionLoop");
                o9["Name"] = "denyloadmod";
                o9["DisplayName"] = "Deny LoadMod";
                if (user && user->denyLoadMod()) {
                    o9["Checked"] = "true";
                }

                NoTemplate& o10 = tmpl.addRow("OptionLoop");
                o10["Name"] = "isadmin";
                o10["DisplayName"] = "Admin";
                if (user && user->isAdmin()) {
                    o10["Checked"] = "true";
                }
                if (user && user == noApp->findUser(socket.username())) {
                    o10["Disabled"] = "true";
                }

                NoTemplate& o11 = tmpl.addRow("OptionLoop");
                o11["Name"] = "denysetbindhost";
                o11["DisplayName"] = "Deny setBindHost";
                if (user && user->denysetBindHost()) {
                    o11["Checked"] = "true";
                }
            }

            NoTemplate& o12 = tmpl.addRow("OptionLoop");
            o12["Name"] = "autoclearquerybuffer";
            o12["DisplayName"] = "Auto Clear Query Buffer";
            o12["Tooltip"] = "Automatically Clear Query Buffer After Playback";
            if (!user || user->autoclearQueryBuffer()) {
                o12["Checked"] = "true";
            }

            for (NoModule* mod : allModules(user)) {
                NoTemplate& modrow = tmpl.addRow("EmbeddedModuleLoop");
                modrow.insert(tmpl.begin(), tmpl.end());
                modrow["WebadminAction"] = "display";
                if (mod->onEmbeddedWebRequest(socket, "webadmin/user", modrow)) {
                    modrow["Embed"] = socket.findTemplate(mod, "WebadminUser.tmpl");
                    modrow["ModName"] = mod->moduleName();
                }
            }

            return true;
        }

        /* If user is nullptr, we are adding a user, else we are editing this one */

        NoString username = socket.param("user");
        if (!user && noApp->findUser(username)) {
            socket.printErrorPage("Invalid Submission [User " + username + " already exists]");
            return true;
        }

        NoUser* pNewUser = GetNewUser(socket, user);
        if (!pNewUser) {
            socket.printErrorPage("Invalid user settings");
            return true;
        }

        NoString sErr;
        NoString action;

        if (!user) {
            NoString sClone = socket.param("clone");
            if (NoUser* pCloneUser = noApp->findUser(sClone)) {
                pNewUser->cloneNetworks(pCloneUser);
            }

            // Add User Submission
            if (!noApp->addUser(pNewUser, sErr)) {
                delete pNewUser;
                socket.printErrorPage("Invalid submission [" + sErr + "]");
                return true;
            }

            user = pNewUser;
            action = "added";
        } else {
            // Edit User Submission
            if (!user->clone(pNewUser, sErr, false)) {
                delete pNewUser;
                socket.printErrorPage("Invalid Submission [" + sErr + "]");
                return true;
            }

            delete pNewUser;
            action = "edited";
        }

        NoTemplate TmplMod;
        TmplMod["Username"] = username;
        TmplMod["WebadminAction"] = "change";
        for (NoModule* mod : allModules(user)) {
            mod->onEmbeddedWebRequest(socket, "webadmin/user", TmplMod);
        }

        if (!noApp->writeConfig()) {
            socket.printErrorPage("User " + action + ", but config was not written");
            return true;
        }

        if (spSession->isAdmin() && socket.hasParam("submit_return")) {
            socket.redirect(webPath() + "listusers");
        } else {
            socket.redirect(webPath() + "edituser?user=" + user->userName());
        }

        /* we don't want the template to be printed while we redirect */
        return false;
    }

    bool ListUsersPage(NoWebSocket& socket, NoTemplate& tmpl)
    {
        std::shared_ptr<NoWebSession> spSession = socket.session();
        const std::map<NoString, NoUser*>& msUsers = noApp->userMap();
        tmpl["Title"] = "Manage Users";
        tmpl["Action"] = "listusers";

        uint a = 0;

        for (std::map<NoString, NoUser*>::const_iterator it = msUsers.begin(); it != msUsers.end(); ++it, a++) {
            NoTemplate& l = tmpl.addRow("UserLoop");
            NoUser* user = it->second;

            l["Username"] = user->userName();
            l["Clients"] = NoString(user->allClients().size());
            l["Networks"] = NoString(user->networks().size());

            if (user == spSession->user()) {
                l["IsSelf"] = "true";
            }
        }

        return true;
    }

    bool TrafficPage(NoWebSocket& socket, NoTemplate& tmpl)
    {
        tmpl["Title"] = "Traffic info";
        tmpl["Uptime"] = noApp->uptime();

        const std::map<NoString, NoUser*>& msUsers = noApp->userMap();
        tmpl["TotalUsers"] = NoString(msUsers.size());

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

        tmpl["TotalNetworks"] = NoString(uiNetworks);
        tmpl["AttachedNetworks"] = NoString(uiAttached);
        tmpl["TotalCConnections"] = NoString(uiClients);
        tmpl["TotalIRCConnections"] = NoString(uiServers);

        NoApp::TrafficStatsPair Users, ZNC, Total;
        NoApp::TrafficStatsMap traffic = noApp->trafficStats(Users, ZNC, Total);
        NoApp::TrafficStatsMap::const_iterator it;

        for (it = traffic.begin(); it != traffic.end(); ++it) {
            NoTemplate& l = tmpl.addRow("TrafficLoop");

            l["Username"] = it->first;
            l["In"] = No::toByteStr(it->second.first);
            l["Out"] = No::toByteStr(it->second.second);
            l["Total"] = No::toByteStr(it->second.first + it->second.second);
        }

        tmpl["UserIn"] = No::toByteStr(Users.first);
        tmpl["UserOut"] = No::toByteStr(Users.second);
        tmpl["UserTotal"] = No::toByteStr(Users.first + Users.second);

        tmpl["ZNCIn"] = No::toByteStr(ZNC.first);
        tmpl["ZNCOut"] = No::toByteStr(ZNC.second);
        tmpl["ZNCTotal"] = No::toByteStr(ZNC.first + ZNC.second);

        tmpl["AllIn"] = No::toByteStr(Total.first);
        tmpl["AllOut"] = No::toByteStr(Total.second);
        tmpl["AllTotal"] = No::toByteStr(Total.first + Total.second);

        return true;
    }

    bool AddListener(NoWebSocket& socket, NoTemplate& tmpl)
    {
        ushort port = socket.param("port").toUShort();
        NoString host = socket.param("host");
        NoString uriPrefix = socket.param("uriprefix");
        if (host == "*")
            host = "";
        bool ssl = socket.param("ssl").toBool();
        bool bIPv4 = socket.param("ipv4").toBool();
        bool bIPv6 = socket.param("ipv6").toBool();
        bool bIRC = socket.param("irc").toBool();
        bool bWeb = socket.param("web").toBool();

        No::AddressType addressType = No::Ipv4AndIpv6Address;
        if (bIPv4) {
            if (bIPv6) {
                addressType = No::Ipv4AndIpv6Address;
            } else {
                addressType = No::Ipv4Address;
            }
        } else {
            if (bIPv6) {
                addressType = No::Ipv6Address;
            } else {
                socket.session()->addError("Choose either IPv4 or IPv6 or both.");
                return SettingsPage(socket, tmpl);
            }
        }

        No::AcceptType acceptType;
        if (bIRC) {
            if (bWeb) {
                acceptType = No::AcceptAll;
            } else {
                acceptType = No::AcceptIrc;
            }
        } else {
            if (bWeb) {
                acceptType = No::AcceptHttp;
            } else {
                socket.session()->addError("Choose either IRC or Web or both.");
                return SettingsPage(socket, tmpl);
            }
        }

        NoString message;
        if (noApp->addListener(port, host, uriPrefix, ssl, addressType, acceptType, message)) {
            if (!message.empty()) {
                socket.session()->addSuccess(message);
            }
            if (!noApp->writeConfig()) {
                socket.session()->addError("Port changed, but config was not written");
            }
        } else {
            socket.session()->addError(message);
        }

        return SettingsPage(socket, tmpl);
    }

    bool DelListener(NoWebSocket& socket, NoTemplate& tmpl)
    {
        ushort port = socket.param("port").toUShort();
        NoString host = socket.param("host");
        bool bIPv4 = socket.param("ipv4").toBool();
        bool bIPv6 = socket.param("ipv6").toBool();

        No::AddressType addressType = No::Ipv4AndIpv6Address;
        if (bIPv4) {
            if (bIPv6) {
                addressType = No::Ipv4AndIpv6Address;
            } else {
                addressType = No::Ipv4Address;
            }
        } else {
            if (bIPv6) {
                addressType = No::Ipv6Address;
            } else {
                socket.session()->addError("Invalid request.");
                return SettingsPage(socket, tmpl);
            }
        }

        NoListener* pListener = noApp->findListener(port, host, addressType);
        if (pListener) {
            noApp->removeListener(pListener);
            if (!noApp->writeConfig()) {
                socket.session()->addError("Port changed, but config was not written");
            }
        } else {
            socket.session()->addError("The specified listener was not found.");
        }

        return SettingsPage(socket, tmpl);
    }

    bool SettingsPage(NoWebSocket& socket, NoTemplate& tmpl)
    {
        tmpl.setFile("settings.tmpl");
        if (!socket.param("submitted").toUInt()) {
            tmpl["Action"] = "settings";
            tmpl["Title"] = "Settings";
            tmpl["StatusPrefix"] = noApp->statusPrefix();
            tmpl["MaxBufferSize"] = NoString(noApp->maxBufferSize());
            tmpl["ConnectDelay"] = NoString(noApp->connectDelay());
            tmpl["ServerThrottle"] = NoString(noApp->serverThrottle());
            tmpl["AnonIPLimit"] = NoString(noApp->anonIpLimit());
            tmpl["ProtectWebSessions"] = NoString(noApp->protectWebSessions());
            tmpl["HideVersion"] = NoString(noApp->hideVersion());

            const NoStringVector& vsBindHosts = noApp->bindHosts();
            for (uint a = 0; a < vsBindHosts.size(); a++) {
                NoTemplate& l = tmpl.addRow("BindHostLoop");
                l["BindHost"] = vsBindHosts[a];
            }

            const NoStringVector& vsMotd = noApp->motd();
            for (uint b = 0; b < vsMotd.size(); b++) {
                NoTemplate& l = tmpl.addRow("MOTDLoop");
                l["Line"] = vsMotd[b];
            }

            const std::vector<NoListener*>& vpListeners = noApp->listeners();
            for (uint c = 0; c < vpListeners.size(); c++) {
                NoListener* pListener = vpListeners[c];
                NoTemplate& l = tmpl.addRow("ListenLoop");

                l["Port"] = NoString(pListener->port());
                l["BindHost"] = pListener->host();

                l["IsWeb"] = NoString(pListener->acceptType() != No::AcceptIrc);
                l["IsIRC"] = NoString(pListener->acceptType() != No::AcceptHttp);

                l["URIPrefix"] = pListener->uriPrefix() + "/";

                // simple protection for user from shooting his own foot
                // TODO check also for hosts/families
                // such check is only here, user still can forge HTTP request to delete web port
                l["SuggestDeletion"] = NoString(pListener->port() != socket.localPort());

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
            socket.availableSkins(vDirs);

            for (uint d = 0; d < vDirs.size(); d++) {
                const NoString& SubDir = vDirs[d];
                NoTemplate& l = tmpl.addRow("SkinLoop");
                l["Name"] = SubDir;

                if (SubDir == noApp->skinName()) {
                    l["Checked"] = "true";
                }
            }

            std::set<NoModuleInfo> ssGlobalMods = noApp->loader()->availableModules(No::GlobalModule);

            for (std::set<NoModuleInfo>::iterator it = ssGlobalMods.begin(); it != ssGlobalMods.end(); ++it) {
                const NoModuleInfo& info = *it;
                NoTemplate& l = tmpl.addRow("ModuleLoop");

                NoModule* module = noApp->loader()->findModule(info.name());
                if (module) {
                    l["Checked"] = "true";
                    l["Args"] = module->args();
                    if (No::GlobalModule == type() && info.name() == moduleName()) {
                        l["Disabled"] = "true";
                    }
                }

                l["Name"] = info.name();
                l["Description"] = info.description();
                l["Wiki"] = info.wikiPage();
                l["HasArgs"] = NoString(info.hasArgs());
                l["ArgsHelpText"] = info.argsHelpText();

                // Check if the module is loaded by all or some users, and/or by all or some networks
                uint usersWithRenderedModuleCount = 0;
                uint networksWithRenderedModuleCount = 0;
                uint networksCount = 0;
                const std::map<NoString, NoUser*>& allUsers = noApp->userMap();
                for (std::map<NoString, NoUser*>::const_iterator usersIt = allUsers.begin(); usersIt != allUsers.end(); ++usersIt) {
                    const NoUser& User = *usersIt->second;

                    // Count users which has loaded a render module
                    const NoModuleLoader* userModules = User.loader();
                    if (userModules->findModule(info.name())) {
                        usersWithRenderedModuleCount++;
                    }
                    // Count networks which has loaded a render module
                    const std::vector<NoNetwork*>& userNetworks = User.networks();
                    networksCount += userNetworks.size();
                    for (uint networkIndex = 0; networkIndex < userNetworks.size(); ++networkIndex) {
                        const NoNetwork* pCurrentNetwork = userNetworks[networkIndex];
                        if (pCurrentNetwork->loader()->findModule(info.name())) {
                            networksWithRenderedModuleCount++;
                        }
                    }
                }
                l["CanBeLoadedByNetwork"] = NoString(info.supportsType(No::NetworkModule));
                l["LoadedByAllNetworks"] = NoString(networksWithRenderedModuleCount == networksCount);
                l["LoadedBySomeNetworks"] = NoString(networksWithRenderedModuleCount != 0);

                l["CanBeLoadedByUser"] = NoString(info.supportsType(No::UserModule));
                l["LoadedByAllUsers"] = NoString(usersWithRenderedModuleCount == allUsers.size());
                l["LoadedBySomeUsers"] = NoString(usersWithRenderedModuleCount != 0);
            }

            return true;
        }

        NoString arg;
        arg = socket.param("statusprefix");
        noApp->setStatusPrefix(arg);
        arg = socket.param("maxbufsize");
        noApp->setMaxBufferSize(arg.toUInt());
        arg = socket.param("connectdelay");
        noApp->setConnectDelay(arg.toUInt());
        arg = socket.param("serverthrottle");
        noApp->setServerThrottle(arg.toUInt());
        arg = socket.param("anoniplimit");
        noApp->setAnonIpLimit(arg.toUInt());
        arg = socket.param("protectwebsessions");
        noApp->setProtectWebSessions(arg.toBool());
        arg = socket.param("hideversion");
        noApp->setHideVersion(arg.toBool());

        NoStringVector vsArgs = socket.rawParam("motd").split("\n");
        noApp->clearMotd();

        uint a = 0;
        for (a = 0; a < vsArgs.size(); a++) {
            noApp->addMotd(vsArgs[a].trimRight_n());
        }

        vsArgs = socket.rawParam("bindhosts").split("\n");
        noApp->clearBindHosts();

        for (a = 0; a < vsArgs.size(); a++) {
            noApp->addBindHost(vsArgs[a].trim_n());
        }

        noApp->setSkinName(socket.param("skin"));

        std::set<NoString> ssArgs;
        socket.paramValues("loadmod", ssArgs);

        for (std::set<NoString>::iterator it = ssArgs.begin(); it != ssArgs.end(); ++it) {
            NoString sModRet;
            NoString name = (*it).trimRight_n("\r");
            NoString sModLoadError;

            if (!name.empty()) {
                NoString args = socket.param("modargs_" + name);

                NoModule* mod = noApp->loader()->findModule(name);
                if (!mod) {
                    if (!noApp->loader()->loadModule(name, args, No::GlobalModule, nullptr, nullptr, sModRet)) {
                        sModLoadError = "Unable to load module [" + name + "] [" + sModRet + "]";
                    }
                } else if (mod->args() != args) {
                    if (!noApp->loader()->reloadModule(name, args, nullptr, nullptr, sModRet)) {
                        sModLoadError = "Unable to reload module [" + name + "] [" + sModRet + "]";
                    }
                }

                if (!sModLoadError.empty()) {
                    NO_DEBUG(sModLoadError);
                    socket.session()->addError(sModLoadError);
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
            socket.session()->addError("Settings changed, but config was not written");
        }

        socket.redirect(webPath() + "settings");
        /* we don't want the template to be printed while we redirect */
        return false;
    }
};

template <>
void no_moduleInfo<NoWebAdminMod>(NoModuleInfo& info)
{
    info.addType(No::UserModule);
    info.setWikiPage("webadmin");
}

GLOBALMODULEDEFS(NoWebAdminMod, "Web based administration module.")
