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

#ifndef NOMODULE_H
#define NOMODULE_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
#include <nobnc/nomoduleinfo.h>
#include <nobnc/nomodulecommand.h>

#include <sys/time.h>
#include <memory>

class NoUser;
class NoNick;
class NoTimer;
class NoSocket;
class NoClient;
class NoChannel;
class NoNetwork;
class NoWebPage;
class NoHostMask;
class NoTemplate;
class NoWebSocket;
class NoIrcSocket;
class NoModuleJob;
class NoModuleSocket;
class NoAuthenticator;
class NoSocketManager;
class NoModulePrivate;

#ifdef REQUIRESSL
#ifndef HAVE_LIBSSL
#error -
#error -
#error This module only works when ZNC is compiled with OpenSSL support
#error -
#error -
#endif
#endif

#if HAVE_VISIBILITY
#define MODULE_EXPORT __attribute__((__visibility__("default")))
#else
#define MODULE_EXPORT
#endif

#define MODCOMMONDEFS(CLASS, DESCRIPTION, TYPE)                          \
    extern "C" {                                                         \
    MODULE_EXPORT bool no_moduleInfo(double version, NoModuleInfo& info) \
    {                                                                    \
        if (version != NO_VERSION)                                       \
            return false;                                                \
        info.setDescription(DESCRIPTION);                                \
        info.setDefaultType(TYPE);                                       \
        info.addType(TYPE);                                              \
        info.setLoader(no_loadModule<CLASS>);                            \
        no_moduleInfo<CLASS>(info);                                      \
        return true;                                                     \
    }                                                                    \
    }

/** Instead of writing a constructor, you should call this macro. It accepts all
 *  the necessary arguments and passes them on to NoModule's constructor. You
 *  should assume that there are no arguments to the constructor.
 *
 *  Usage:
 *  \code
 *  class MyModule : public NoModule {
 *      MODCONSTRUCTOR(MyModule) {
 *          // Your own constructor's code here
 *      }
 *  }
 *  \endcode
 *
 *  @param CLASS The name of your module's class.
 */
#define MODCONSTRUCTOR(CLASS)                                                                                                                \
    CLASS(NoModuleHandle pDLL, NoUser* user, NoNetwork* network, const NoString& name, const NoString& path, No::ModuleType type) \
        : NoModule(pDLL, user, network, name, path, type)

/** This works exactly like MODULEDEFS, but for user modules. */
#define USERMODULEDEFS(CLASS, DESCRIPTION) MODCOMMONDEFS(CLASS, DESCRIPTION, No::UserModule)

/** This works exactly like MODULEDEFS, but for global modules. */
#define GLOBALMODULEDEFS(CLASS, DESCRIPTION) MODCOMMONDEFS(CLASS, DESCRIPTION, No::GlobalModule)

/** This works exactly like MODULEDEFS, but for network modules. */
#define NETWORKMODULEDEFS(CLASS, DESCRIPTION) MODCOMMONDEFS(CLASS, DESCRIPTION, No::NetworkModule)

/** At the end of your source file, you must call this macro in global context.
 *  It defines some static functions which ZNC needs to load this module.
 *  By default the module will be a network module.
 *  @param CLASS The name of your module's class.
 *  @param DESCRIPTION A short description of your module.
 */
#define MODULEDEFS(CLASS, DESCRIPTION) NETWORKMODULEDEFS(CLASS, DESCRIPTION)

/** The base class for your own ZNC modules.
 *
 *  If you want to write a module for ZNC, you will have to implement a class
 *  which inherits from this class. You should override some of the "On*"
 *  functions in this class. These function will then be called by ZNC when the
 *  associated event happens.
 *
 *  If such a module hook is called with a non-const reference to e.g. a
 *  NoString, then it is free to modify that argument to influence ZNC's
 *  behavior.
 *
 *  @see MODCONSTRUCTOR and MODULEDEFS
 */
class NO_EXPORT NoModule
{
public:
    NoModule(NoModuleHandle pDLL, NoUser* user, NoNetwork* network, const NoString& name, const NoString& dataDir, No::ModuleType type);
    virtual ~NoModule();

    No::ModuleType type() const;

    NoUser* user() const;
    NoNetwork* network() const;
    NoClient* client() const;
    NoSocketManager* manager() const;

    NoString description() const;
    NoString modulePath() const;

    NoString args() const;
    void setArgs(const NoString& args);

    /** This enum is just used for return from module hooks. Based on this
     *  return, ZNC then decides what to do with the event which caused the
     *  module hook.
     */
    enum ModRet {
        /** ZNC will continue event processing normally. This is what
         *  you should return normally.
         */
        CONTINUE = 1,
        /** This is the same as both NoModule::HALTMODS and
         * NoModule::HALTCORE together.
         */
        HALT = 2,
        /** Stop sending this even to other modules which were not
         *  called yet. Internally, the event is handled normally.
         */
        HALTMODS = 3,
        /** Continue calling other modules. When done, ignore the event
         *  in the ZNC core. (For most module hooks this means that a
         *  given event won't be forwarded to the connected users)
         */
        HALTCORE = 4
    };

    /** This function throws NoModule::UNLOAD which causes this module to be unloaded.
     */
    void unload();

    /** This module hook is called when a module is loaded
     *  @param args The arguments for the modules.
     *  @param message A message that may be displayed to the user after
     *                  loading the module. Useful for returning error messages.
     *  @return true if the module loaded successfully, else false.
     */
    virtual bool onLoad(const NoString& args, NoString& message);
    /** This module hook is called during ZNC startup. Only modules loaded
     *  from znc.conf get this call.
     *  @return false to abort ZNC startup.
     */
    virtual bool onBoot();

    /** Modules which can only be used with an active user session have to return true here.
     *  @return false for modules that can do stuff for non-logged in web users as well.
     */
    virtual bool webRequiresLogin();
    /** Return true if this module should only be usable for admins on the web.
     *  @return false if normal users can use this module's web pages as well.
     */
    virtual bool webRequiresAdmin();
    /** Return the title of the module's section in the web interface's side bar.
     *  @return The Title.
     */
    virtual NoString webMenuTitle();
    virtual NoString webPath();
    virtual NoString webFilesPath();
    /** For WebMods: Called before the list of registered SubPages will be checked.
     *  Important: If you return true, you need to take care of calling socket.Close!
     *  This allows for stuff like returning non-templated data, long-polling and other fun.
     *  @param socket The active request.
     *  @param page The name of the page that has been requested.
     *  @return true if you handled the page request or false if the name is to be checked
     *          against the list of registered SubPages and their permission settings.
     */
    virtual bool onWebPreRequest(NoWebSocket* socket, const NoString& page);
    /** If OnWebPreRequest returned false, and the RequiresAdmin/IsAdmin check has been passed,
     *  this method will be called with the page name. It will also be called for pages that
     *  have NOT been specifically registered with AddSubPage.
     *  @param socket The active request.
     *  @param page The name of the page that has been requested.
     *  @param tmpl The active template. You can add variables, loops and stuff to it.
     *  @return You MUST return true if you want the template to be evaluated and sent to the browser.
     *          Return false if you called Redirect() or PrintErrorPage(). If you didn't, a 404 page will be sent.
     */
    virtual bool onWebRequest(NoWebSocket* socket, const NoString& page, NoTemplate& tmpl);
    /** Registers a sub page for the sidebar.
     *  @param page The SubPage instance.
     */
    virtual void addSubPage(std::shared_ptr<NoWebPage> page);
    /** Using this hook, module can embed web stuff directly to different places.
     *  This method is called whenever embededded modules I/O happens.
     *  Name of used .tmpl file (if any) is up to caller.
     *  @param socket Socket for web connection, don't do bad things with it.
     *  @param page Describes the place where web stuff is embedded to.
     *  @param tmpl Template. Depending on context, you can do various stuff with it.
     *  @return If you don't need to embed web stuff to the specified place, just return false.
     *          Exact meaning of return value is up to caller, and depends on context.
     */
    virtual bool onEmbeddedWebRequest(NoWebSocket* socket, const NoString& page, NoTemplate& tmpl);

    /** Called just before znc.conf is rehashed */
    virtual void onPreRehash();
    /** This module hook is called after a <em>successful</em> rehash. */
    virtual void onPostRehash();
    /** This module hook is called when a user gets disconnected from IRC. */
    virtual void onIrcDisconnected();
    /** This module hook is called after a successful login to IRC. */
    virtual void onIrcConnected();
    /** This module hook is called just before ZNC tries to establish a
     *  connection to an IRC server.
     *  @param socket The socket that will be used for the connection.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onIrcConnecting(NoIrcSocket* socket);
    /** This module hook is called when a NoIrcSock fails to connect or
     *  a module returned HALTCORE from onIrcConnecting.
     *  @param socket The socket that failed to connect.
     */
    virtual void onIrcConnectionError(NoIrcSocket* socket);
    /** This module hook is called before loging in to the IRC server. The
     *  low-level connection is established at this point, but SSL
     *  handshakes didn't necessarily finish yet.
     *  @param pass The server password that will be used.
     *  @param nick The nick that will be used.
     *  @param ident The protocol identity that will be used. This is not
     *                the ident string that is transfered via e.g. oidentd!
     *  @param realName The real name that will be used.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onIrcRegistration(NoString& pass, NoString& nick, NoString& ident, NoString& realName);
    /** This module hook is called when a message is broadcasted to all users.
     *  @param message The message that is broadcasted.
     *  @return see NoModule::ModRet
     */
    virtual ModRet onBroadcast(NoString& message);

    /** This module hook is called when a user mode on a channel changes.
     *  @param opNick The nick who sent the mode change, or nullptr if set by server.
     *  @param nick The nick whose channel mode changes.
     *  @param channel The channel on which the user mode is changed.
     *  @param mode The mode character that is changed, e.g. '@' for op.
     *  @param added True if the mode is added, else false.
     *  @param noChange true if this mode change doesn't change anything
     *                   because the nick already had this permission.
     *  @see NoIrcSock::GetModeType() for converting mode into a mode (e.g.
     *       'o' for op).
     */
    virtual void onChannelPermission(const NoNick* opNick, const NoNick& nick, NoChannel* channel, uchar mode, bool added, bool noChange);
    /** Called when a nick is opped on a channel */
    virtual void onOp(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange);
    /** Called when a nick is deopped on a channel */
    virtual void onDeop(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange);
    /** Called when a nick is voiced on a channel */
    virtual void onVoice(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange);
    /** Called when a nick is devoiced on a channel */
    virtual void onDevoice(const NoNick* opNick, const NoNick& nick, NoChannel* channel, bool noChange);
    /** Called on an individual channel mode change.
     *  @param opNick The nick who changes the channel mode, or nullptr if set by server.
     *  @param channel The channel whose mode is changed.
     *  @param mode The mode character that is changed.
     *  @param arg The argument to the mode character, if any.
     *  @param added True if this mode is added ("+"), else false.
     *  @param noChange True if this mode was already effective before.
     */
    virtual void onMode(const NoNick* opNick, NoChannel* channel, char mode, const NoString& arg, bool added, bool noChange);
    /** Called on any channel mode change. This is called before the more
     *  detailed mode hooks like e.g. onOp() and onMode().
     *  @param opNick The nick who changes the channel mode, or nullptr if set by server.
     *  @param channel The channel whose mode is changed.
     *  @param modes The raw mode change, e.g. "+s-io".
     *  @param args All arguments to the mode change from modes.
     */
    virtual void onRawMode(const NoNick* opNick, NoChannel* channel, const NoString& modes, const NoString& args);

    /** Called on any raw IRC line received from the <em>IRC server</em>.
     *  @param line The line read from the server.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onRaw(NoString& line);

    /** Called when a command to *status is sent.
     *  @param command The command sent.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onStatusCommand(NoString& command);
    /** Called when a command to your module is sent, e.g. query to *modname.
     *  @param command The command that was sent.
     */
    virtual void onModCommand(const NoString& command);
    /** This is similar to onModCommand(), but it is only called if
     * handleCommand didn't find any that wants to handle this. This is only
     * called if handleCommand() is called, which practically means that
     * this is only called if you don't overload onModCommand().
     *  @param command The command that was sent.
     */
    virtual void onUnknownModCommand(const NoString& command);
    /** Called when a your module nick was sent a notice.
     *  @param message The message which was sent.
     */
    virtual void onModNotice(const NoString& message);
    /** Called when your module nick was sent a CTCP message. onModCommand()
     *  won't be called for this message.
     *  @param message The message which was sent.
     */
    virtual void onModCTCP(const NoString& message);

    /** Called when a nick quit from IRC.
     *  @param nick The nick which quit.
     *  @param message The quit message.
     */
    virtual void onQuit(const NoHostMask& nick, const NoString& message);
    /** Called when a nickname change occurs. If we are changing our nick,
     *  newNick will equal m_pIRCSock->GetNick().
     *  @param nick The nick which changed its nickname
     *  @param newNick The new nickname.
     */
    virtual void onNick(const NoHostMask& nick, const NoString& newNick);
    /** Called when a nick is kicked from a channel.
     *  @param opNick The nick which generated the kick.
     *  @param sKickedNick The nick which was kicked.
     *  @param channel The channel on which this kick occurs.
     *  @param message The kick message.
     */
    virtual void onKick(const NoNick& opNick, const NoString& sKickedNick, NoChannel* channel, const NoString& message);
    /** This module hook is called just before ZNC tries to join an IRC channel.
     *  @param channel The channel which is about to get joined.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onJoining(NoChannel* channel);
    /** Called when a nick joins a channel.
     *  @param nick The nick who joined.
     *  @param channel The channel which was joined.
     */
    virtual void onJoin(const NoNick& nick, NoChannel* channel);
    /** Called when a nick parts a channel.
     *  @param nick The nick who parted.
     *  @param channel The channel which was parted.
     *  @param message The part message.
     */
    virtual void onPart(const NoNick& nick, NoChannel* channel, const NoString& message);
    /** Called when user is invited into a channel
     *  @param nick The nick who invited you.
     *  @param sChan The channel the user got invited into
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onInvite(const NoHostMask& nick, const NoString& sChan);

    /** Called before a channel buffer is played back to a client.
     *  @param channel The channel which will be played back.
     *  @param client The client the buffer will be played back to.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onChannelBufferStarting(NoChannel* channel, NoClient* client);
    /** Called after a channel buffer was played back to a client.
     *  @param channel The channel which was played back.
     *  @param client The client the buffer was played back to.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onChannelBufferEnding(NoChannel* channel, NoClient* client);
    /** Called when for each line during a channel's buffer play back.
     *  @param channel The channel this playback is from.
     *  @param client The client the buffer is played back to.
     *  @param line The current line of buffer playback. This is a raw IRC
     *               traffic line!
     *  @param tv The timestamp of the message.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onChannelBufferPlayLine(NoChannel* channel, NoClient* client, NoString& line, const timeval& tv);
    /** Called when a line from the query buffer is played back.
     *  @param client The client this line will go to.
     *  @param line The raw IRC traffic line from the buffer.
     *  @param tv The timestamp of the message.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onPrivateBufferPlayLine(NoClient* client, NoString& line, const timeval& tv);

    /** Called when a client successfully logged in to ZNC. */
    virtual void onClientLogin();
    /** Called when a client disconnected from ZNC. */
    virtual void onClientDisconnect();
    /** This module hook is called when a client sends a raw traffic line to ZNC.
     *  @param line The raw traffic line sent.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onUserRaw(NoString& line);
    /** This module hook is called when a client sends a CTCP reply.
     *  @param target The target for the CTCP reply. Could be a channel
     *                 name or a nick name.
     *  @param message The CTCP reply message.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onUserCtcpReply(NoString& target, NoString& message);
    /** This module hook is called when a client sends a CTCP request.
     *  @param target The target for the CTCP request. Could be a channel
     *                 name or a nick name.
     *  @param message The CTCP request message.
     *  @return See NoModule::ModRet.
     *  @note This is not called for CTCP ACTION messages, use
     *        NoModule::onUserAction() instead.
     */
    virtual ModRet onUserCtcp(NoString& target, NoString& message);
    /** Called when a client sends a CTCP ACTION request ("/me").
     *  @param target The target for the CTCP ACTION. Could be a channel
     *                 name or a nick name.
     *  @param message The action message.
     *  @return See NoModule::ModRet.
     *  @note NoModule::onUserCtcp() will not be called for this message.
     */
    virtual ModRet onUserAction(NoString& target, NoString& message);
    /** This module hook is called when a user sends a normal IRC message.
     *  @param target The target of the message. Could be a channel name or
     *                 a nick name.
     *  @param message The message which was sent.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onUserMessage(NoString& target, NoString& message);
    /** This module hook is called when a user sends a notice message.
     *  @param target The target of the message. Could be a channel name or
     *                 a nick name.
     *  @param message The message which was sent.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onUserNotice(NoString& target, NoString& message);
    /** This hooks is called when a user sends a JOIN message.
     *  @param channel The channel name the join is for.
     *  @param key The key for the channel.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onUserJoin(NoString& channel, NoString& key);
    /** This hooks is called when a user sends a PART message.
     *  @param channel The channel name the part is for.
     *  @param message The part message the client sent.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onUserPart(NoString& channel, NoString& message);
    /** This module hook is called when a user wants to change a channel topic.
     *  @param channel The channel.
     *  @param topic The new topic which the user sent.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onUserTopic(NoString& channel, NoString& topic);
    /** This hook is called when a user requests a channel's topic.
     *  @param channel The channel for which the request is.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onUserTopicRequest(NoString& channel);
    /** This module hook is called when a user requests to quit from network.
     *  @param message The quit message the client sent.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onUserQuit(NoString& message);

    /** Called when we receive a CTCP reply <em>from IRC</em>.
     *  @param nick The nick the CTCP reply is from.
     *  @param message The CTCP reply message.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onCtcpReply(NoHostMask& nick, NoString& message);
    /** Called when we receive a private CTCP request <em>from IRC</em>.
     *  @param nick The nick the CTCP request is from.
     *  @param message The CTCP request message.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onPrivateCtcp(NoHostMask& nick, NoString& message);
    /** Called when we receive a channel CTCP request <em>from IRC</em>.
     *  @param nick The nick the CTCP request is from.
     *  @param channel The channel to which the request was sent.
     *  @param message The CTCP request message.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onChannelCtcp(NoNick& nick, NoChannel* channel, NoString& message);
    /** Called when we receive a private CTCP ACTION ("/me" in query) <em>from IRC</em>.
     *  This is called after NoModule::onPrivateCtcp().
     *  @param nick The nick the action came from.
     *  @param message The action message
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onPrivateAction(NoHostMask& nick, NoString& message);
    /** Called when we receive a channel CTCP ACTION ("/me" in a channel) <em>from IRC</em>.
     *  This is called after NoModule::onChannelCtcp().
     *  @param nick The nick the action came from.
     *  @param channel The channel the action was sent to.
     *  @param message The action message
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onChannelAction(NoNick& nick, NoChannel* channel, NoString& message);
    /** Called when we receive a private message <em>from IRC</em>.
     *  @param nick The nick which sent the message.
     *  @param message The message.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onPrivateMessage(NoHostMask& nick, NoString& message);
    /** Called when we receive a channel message <em>from IRC</em>.
     *  @param nick The nick which sent the message.
     *  @param channel The channel to which the message was sent.
     *  @param message The message.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onChannelMessage(NoNick& nick, NoChannel* channel, NoString& message);
    /** Called when we receive a private notice.
     *  @param nick The nick which sent the notice.
     *  @param message The notice message.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onPrivateNotice(NoHostMask& nick, NoString& message);
    /** Called when we receive a channel notice.
     *  @param nick The nick which sent the notice.
     *  @param channel The channel to which the notice was sent.
     *  @param message The notice message.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onChannelNotice(NoNick& nick, NoChannel* channel, NoString& message);
    /** Called when we receive a channel topic change <em>from IRC</em>.
     *  @param nick The nick which changed the topic.
     *  @param channel The channel whose topic was changed.
     *  @param topic The new topic.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onTopic(NoNick& nick, NoChannel* channel, NoString& topic);

    /** Called for every CAP received via CAP LS from server.
     *  @param cap capability supported by server.
     *  @return true if your module supports this CAP and
     *          needs to turn it on with CAP REQ.
     */
    virtual bool onServerCapAvailable(const NoString& cap);
    /** Called for every CAP accepted or rejected by server
     *  (with CAP ACK or CAP NAK after our CAP REQ).
     *  @param cap capability accepted/rejected by server.
     *  @param success true if capability was accepted, false if rejected.
     */
    virtual void onServerCapResult(const NoString& cap, bool success);

    /** This module hook is called just before ZNC tries to join a channel
     *  by itself because it's in the config but wasn't joined yet.
     *  @param channel The channel which will be joined.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onTimerAutoJoin(NoChannel* channel);

    /** This module hook is called when a network is being added.
     *  @param network The new IRC network.
     *  @param error A message that may be displayed to the user if
     *                  the module stops adding the network.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onAddNetwork(NoNetwork* network, NoString& error);
    /** This module hook is called when a network is deleted.
     *  @param network The IRC network which is going to be deleted.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onDeleteNetwork(NoNetwork* network);

    /** Called when ZNC sends a raw traffic line to a client.
     *  @param line The raw traffic line sent.
     *  @param client The client this line is sent to.
     *  @warning Calling putUser() from within this hook leads to infinite recursion.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onSendToClient(NoString& line, NoClient* client);
    /** Called when ZNC sends a raw traffic line to the IRC server.
     *  @param line The raw traffic line sent.
     *  @warning Calling putIrc() from within this hook leads to infinite recursion.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onSendToIrc(NoString& line);

    NoModuleHandle GetDLL();
    static double GetCoreVersion();

    /** This function sends a given raw IRC line to the IRC server, if we
     *  are connected to one. Else this line is discarded.
     *  @param line The line which should be sent.
     *  @return true if the line was queued for sending.
     */
    virtual bool putIrc(const NoString& line);
    /** This function sends a given raw IRC line to a client.
     *  If we are in a module hook which is called for a specific client,
     *  only that client will get the line, else all connected clients will
     *  receive this line.
     *  @param line The line which should be sent.
     *  @return true if the line was sent to at least one client.
     */
    virtual bool putUser(const NoString& line);
    /** This function generates a query from *status. If we are in a module
     *  hook for a specific client, only that client gets this message, else
     *  all connected clients will receive it.
     *  @param line The message which should be sent from *status.
     *  @return true if the line was sent to at least one client.
     */
    virtual bool putStatus(const NoString& line);
    /** This function sends a query from your module nick. If we are in a
     *  module hook for a specific client, only that client gets this
     *  message, else all connected clients will receive it.
     *  @param line The message which should be sent.
     *  @return true if the line was sent to at least one client.
     */
    virtual bool putModule(const NoString& line);
    /** This function calls NoModule::putModule(const NoString&, const
     *  NoString&, const NoString&) for each line in the table.
     *  @param table The table which should be send.
     *  @return The number of lines sent.
     */
    virtual uint putModule(const NoTable& table);
    /** Send a notice from your module nick. If we are in a module hook for
     *  a specific client, only that client gets this notice, else all
     *  clients will receive it.
     *  @param line The line which should be sent.
     *  @return true if the line was sent to at least one client.
     */
    virtual bool putModuleNotice(const NoString& line);

    /** @returns The name of the module. */
    NoString moduleName() const;

    /** @returns The nick of the module. This is just the module name
     *           prefixed by the status prefix.
     */
    NoString moduleNick() const;

    /** Get the module's data dir.
     *  Modules can be accompanied by static data, e.g. skins for webadmin.
     *  These function will return the path to that data.
     */
    NoString moduleDataDir() const;

    NoTimer* findTimer(const NoString& label) const;
    NoModuleSocket* findSocket(const NoString& name) const;

#ifdef HAVE_PTHREAD
    void addJob(NoModuleJob* pJob);
    void cancelJob(NoModuleJob* pJob);
    bool cancelJob(const NoString& sJobName);
    void cancelJobs(const std::set<NoModuleJob*>& sJobs);
    bool unlinkJob(NoModuleJob* pJob);
#endif

    /// Register the "Help" command.
    void addHelpCommand();
    /// @return True if the command was successfully added.
    bool addCommand(const NoModuleCommand& command);
    /// @return True if the command was successfully added.
    bool addCommand(const NoString& cmd, NoModuleCommand::ModCmdFunc func, const NoString& args = "", const NoString& desc = "");
    /// @return True if the command was successfully added.
    bool addCommand(const NoString& cmd, const NoString& args, const NoString& desc, std::function<void(const NoString& line)> func);
    /// @return True if the command was successfully removed.
    bool removeCommand(const NoString& cmd);
    /// @return The NoModuleCommand instance or nullptr if none was found.
    const NoModuleCommand* findCommand(const NoString& cmd) const;
    /** This function tries to dispatch the given command via the correct
     * instance of NoModuleCommand. Before this can be called, commands have to
     * be added via addCommand(). If no matching commands are found then
     * OnUnknownModCommand will be called.
     * @param line The command line to handle.
     * @return True if something was done, else false.
     */
    bool handleCommand(const NoString& line);
    /** Send a description of all registered commands via putModule().
     * @param line The help command that is being asked for.
     */
    void handleHelpCommand(const NoString& line = "");

    NoString savePath() const;
    NoString expandString(const NoString& str) const;
    NoString& expandString(const NoString& str, NoString& ret) const;

    /** This module hook is called when a user is being added.
     * @param User The user which will be added.
     * @param error A message that may be displayed to the user if
     *                  the module stops adding the user.
     * @return See NoModule::ModRet.
     */
    virtual ModRet onAddUser(NoUser* user, NoString& error);
    /** This module hook is called when a user is deleted.
     *  @param User The user which will be deleted.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onDeleteUser(NoUser* user);
    /** This module hook is called when there is an incoming connection on
     *  any of ZNC's listening sockets.
     *  @param socket The incoming client socket.
     *  @param host The IP the client is connecting from.
     *  @param port The port the client is connecting from.
     */
    virtual void onClientConnect(NoSocket* socket, const NoString& host, ushort port);
    /** This module hook is called when a client tries to login. If your
     *  module wants to handle the login attempt, it must return
     *  NoModule::ModRet::HALT;
     *  @param Auth The necessary authentication info for this login attempt.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onLoginAttempt(std::shared_ptr<NoAuthenticator> Auth);
    /** Called after a client login was rejected.
     *  @param username The username that tried to log in.
     *  @param sRemoteIP The IP address from which the client tried to login.
     */
    virtual void onFailedLogin(const NoString& username, const NoString& sRemoteIP);
    /** This function behaves like NoModule::onUserRaw(), but is also called
     *  before the client successfully logged in to ZNC. You should always
     *  prefer to use NoModule::onUserRaw() if possible.
     *  @param client The client which send this line.
     *  @param line The raw traffic line which the client sent.
     */
    virtual ModRet onUnknownUserRaw(NoClient* client, NoString& line);

    /** Called when a client told us CAP LS. Use caps.insert("cap-name")
     *  for announcing capabilities which your module supports.
     *  @param client The client which requested the list.
     *  @param caps set of caps which will be sent to client.
     */
    virtual void onClientCapLs(NoClient* client, NoStringSet& caps);
    /** Called only to check if your module supports turning on/off named capability.
     *  @param client The client which wants to enable/disable a capability.
     *  @param cap name of capability.
     *  @param state On or off, depending on which case is interesting for client.
     *  @return true if your module supports this capability in the specified state.
     */
    virtual bool isClientCapSupported(NoClient* client, const NoString& cap, bool state);
    /** Called when we actually need to turn a capability on or off for a client.
     *  @param client The client which requested the capability.
     *  @param cap name of wanted capability.
     *  @param state On or off, depending on which case client needs.
     */
    virtual void onClientCapRequest(NoClient* client, const NoString& cap, bool state);

    /** Called when a module is going to be loaded.
     *  @param name name of the module.
     *  @param type wanted type of the module (user/global).
     *  @param args arguments of the module.
     *  @param[out] success the module was loaded successfully
     *                       as result of this module hook?
     *  @param[out] message text about loading of the module.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onModuleLoading(const NoString& name, const NoString& args, No::ModuleType type, bool& success, NoString& message);
    /** Called when a module is going to be unloaded.
     *  @param module the module.
     *  @param[out] success the module was unloaded successfully
     *                       as result of this module hook?
     *  @param[out] message text about unloading of the module.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onModuleUnloading(NoModule* module, bool& success, NoString& message);
    /** Called when info about a module is needed.
     *  @param[out] info put result here, if your module knows it.
     *  @param module name of the module.
     *  @param success this module provided info about the module.
     *  @param message text describing possible issues.
     *  @return See NoModule::ModRet.
     */
    virtual ModRet onGetModuleInfo(NoModuleInfo& info, const NoString& name, bool& success, NoString& message);
    /** Called when list of available mods is requested.
     *  @param modules put new modules here.
     *  @param bGlobal true if global modules are needed.
     */
    virtual void onGetAvailableModules(std::set<NoModuleInfo>& modules, No::ModuleType type);

private:
    NoModule(const NoModule&) = delete;
    NoModule& operator=(const NoModule&) = delete;
    std::unique_ptr<NoModulePrivate> d;
    friend class NoModulePrivate;
};

#endif // NOMODULE_H
