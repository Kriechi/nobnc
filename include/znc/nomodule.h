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

#ifndef NOMODULE_H
#define NOMODULE_H

#include <znc/noconfig.h>
#include <znc/nowebmodules.h>
#include <znc/noutils.h>
#include <znc/nothreads.h>
#include <znc/notimer.h>
#include <znc/main.h>
#include <functional>
#include <set>
#include <queue>
#include <sys/time.h>

class NoAuthBase;
class NoChannel;
class NoNetwork;
class NoClient;
class NoWebSock;
class NoTemplate;
class NoIrcSock;
class NoModule;
class NoModInfo;

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

#define MODCOMMONDEFS(CLASS, DESCRIPTION, TYPE)                         \
    extern "C" {                                                        \
    MODULE_EXPORT bool ZNNoModInfo(double dCoreVersion, NoModInfo& Info); \
    bool ZNNoModInfo(double dCoreVersion, NoModInfo& Info)                \
    {                                                                   \
        if (dCoreVersion != NO_VERSION) return false;                      \
        Info.SetDescription(DESCRIPTION);                               \
        Info.SetDefaultType(TYPE);                                      \
        Info.AddType(TYPE);                                             \
        Info.SetLoader(TModLoad<CLASS>);                                \
        TModInfo<CLASS>(Info);                                          \
        return true;                                                    \
    }                                                                   \
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
#define MODCONSTRUCTOR(CLASS)                                                                                                                 \
    CLASS(ModHandle pDLL, NoUser* pUser, NoNetwork* pNetwork, const NoString& sModName, const NoString& sModPath, NoModInfo::EModuleType eType) \
        : NoModule(pDLL, pUser, pNetwork, sModName, sModPath, eType)

/** This works exactly like MODULEDEFS, but for user modules. */
#define USERMODULEDEFS(CLASS, DESCRIPTION) MODCOMMONDEFS(CLASS, DESCRIPTION, NoModInfo::UserModule)

/** This works exactly like MODULEDEFS, but for global modules. */
#define GLOBALMODULEDEFS(CLASS, DESCRIPTION) MODCOMMONDEFS(CLASS, DESCRIPTION, NoModInfo::GlobalModule)

/** This works exactly like MODULEDEFS, but for network modules. */
#define NETWORKMODULEDEFS(CLASS, DESCRIPTION) MODCOMMONDEFS(CLASS, DESCRIPTION, NoModInfo::NetworkModule)

/** At the end of your source file, you must call this macro in global context.
 *  It defines some static functions which ZNC needs to load this module.
 *  By default the module will be a network module.
 *  @param CLASS The name of your module's class.
 *  @param DESCRIPTION A short description of your module.
 */
#define MODULEDEFS(CLASS, DESCRIPTION) NETWORKMODULEDEFS(CLASS, DESCRIPTION)

class NoApp;
class NoUser;
class NoNick;
class NoChannel;
class NoModule;
class NoSocketManager;

#ifdef HAVE_PTHREAD
/// A NoJob version which can be safely used in modules. The job will be
/// cancelled when the module is unloaded.
class NoModuleJob : public NoJob
{
public:
    NoModuleJob(NoModule* pModule, const NoString& sName, const NoString& sDesc)
        : NoJob(), m_pModule(pModule), m_sName(sName), m_sDescription(sDesc)
    {
    }
    virtual ~NoModuleJob();

    NoModuleJob(const NoModuleJob&) = delete;
    NoModuleJob& operator=(const NoModuleJob&) = delete;

    NoModule* GetModule() const { return m_pModule; }
    const NoString& GetName() const { return m_sName; }
    const NoString& GetDescription() const { return m_sDescription; }

private:
    NoModule* m_pModule;
    const NoString m_sName;
    const NoString m_sDescription;
};
#endif

typedef void* ModHandle;

class NoModInfo
{
public:
    typedef enum { GlobalModule, UserModule, NetworkModule } EModuleType;

    typedef NoModule* (*ModLoader)(ModHandle p, NoUser* pUser, NoNetwork* pNetwork, const NoString& sModName, const NoString& sModPath, EModuleType eType);

    NoModInfo() : NoModInfo("", "", NetworkModule) {}
    NoModInfo(const NoString& sName, const NoString& sPath, EModuleType eType)
        : m_seType(), m_eDefaultType(eType), m_sName(sName), m_sPath(sPath), m_sDescription(""), m_sWikiPage(""),
          m_sArgsHelpText(""), m_bHasArgs(false), m_fLoader(nullptr)
    {
    }
    ~NoModInfo() {}

    bool operator<(const NoModInfo& Info) const { return (GetName() < Info.GetName()); }

    bool SupportsType(EModuleType eType) const { return m_seType.find(eType) != m_seType.end(); }

    void AddType(EModuleType eType) { m_seType.insert(eType); }

    static NoString ModuleTypeToString(EModuleType eType)
    {
        switch (eType) {
        case GlobalModule:
            return "Global";
        case UserModule:
            return "User";
        case NetworkModule:
            return "Network";
        default:
            return "UNKNOWN";
        }
    }

    const NoString& GetName() const { return m_sName; }
    const NoString& GetPath() const { return m_sPath; }
    const NoString& GetDescription() const { return m_sDescription; }
    const NoString& GetWikiPage() const { return m_sWikiPage; }
    const NoString& GetArgsHelpText() const { return m_sArgsHelpText; }
    bool GetHasArgs() const { return m_bHasArgs; }
    ModLoader GetLoader() const { return m_fLoader; }
    EModuleType GetDefaultType() const { return m_eDefaultType; }

    void SetName(const NoString& s) { m_sName = s; }
    void SetPath(const NoString& s) { m_sPath = s; }
    void SetDescription(const NoString& s) { m_sDescription = s; }
    void SetWikiPage(const NoString& s) { m_sWikiPage = s; }
    void SetArgsHelpText(const NoString& s) { m_sArgsHelpText = s; }
    void SetHasArgs(bool b = false) { m_bHasArgs = b; }
    void SetLoader(ModLoader fLoader) { m_fLoader = fLoader; }
    void SetDefaultType(EModuleType eType) { m_eDefaultType = eType; }

private:
    std::set<EModuleType> m_seType;
    EModuleType m_eDefaultType;
    NoString m_sName;
    NoString m_sPath;
    NoString m_sDescription;
    NoString m_sWikiPage;
    NoString m_sArgsHelpText;
    bool m_bHasArgs;
    ModLoader m_fLoader;
};

template <class M> void TModInfo(NoModInfo& Info) {}

template <class M>
NoModule*
TModLoad(ModHandle p, NoUser* pUser, NoNetwork* pNetwork, const NoString& sModName, const NoString& sModPath, NoModInfo::EModuleType eType)
{
    return new M(p, pUser, pNetwork, sModName, sModPath, eType);
}

/** A helper class for handling commands in modules. */
class NoModCommand
{
public:
    /// Type for the callback function that handles the actual command.
    typedef void (NoModule::*ModCmdFunc)(const NoString& sLine);
    typedef std::function<void(const NoString& sLine)> CmdFunc;

    /// Default constructor, needed so that this can be saved in a std::map.
    NoModCommand();

    /** Construct a new NoModCommand.
     * @param sCmd The name of the command.
     * @param func The command's callback function.
     * @param sArgs Help text describing the arguments to this command.
     * @param sDesc Help text describing what this command does.
     */
    NoModCommand(const NoString& sCmd, NoModule* pMod, ModCmdFunc func, const NoString& sArgs, const NoString& sDesc);
    NoModCommand(const NoString& sCmd, CmdFunc func, const NoString& sArgs, const NoString& sDesc);

    /** Copy constructor, needed so that this can be saved in a std::map.
     * @param other Object to copy from.
     */
    NoModCommand(const NoModCommand& other);

    /** Assignment operator, needed so that this can be saved in a std::map.
     * @param other Object to copy from.
     */
    NoModCommand& operator=(const NoModCommand& other);

    /** Initialize a NoTable so that it can be used with AddHelp().
     * @param Table The instance of NoTable to initialize.
     */
    static void InitHelp(NoTable& Table);

    /** Add this command to the NoTable instance.
     * @param Table Instance of NoTable to which this should be added.
     * @warning The Table should be initialized via InitHelp().
     */
    void AddHelp(NoTable& Table) const;

    const NoString& GetCommand() const { return m_sCmd; }
    CmdFunc GetFunction() const { return m_pFunc; }
    const NoString& GetArgs() const { return m_sArgs; }
    const NoString& GetDescription() const { return m_sDesc; }

    void Call(const NoString& sLine) const { m_pFunc(sLine); }

private:
    NoString m_sCmd;
    CmdFunc m_pFunc;
    NoString m_sArgs;
    NoString m_sDesc;
};

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
class NoModule
{
public:
    NoModule(ModHandle pDLL,
            NoUser* pUser,
            NoNetwork* pNetwork,
            const NoString& sModName,
            const NoString& sDataDir,
            NoModInfo::EModuleType eType = NoModInfo::NetworkModule); // TODO: remove default value in ZNC 2.x
    virtual ~NoModule();

    NoModule(const NoModule&) = delete;
    NoModule& operator=(const NoModule&) = delete;

    /** This enum is just used for return from module hooks. Based on this
     *  return, ZNC then decides what to do with the event which caused the
     *  module hook.
     */
    typedef enum {
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
    } EModRet;

    typedef enum {
        /** Your module can throw this enum at any given time. When this
         * is thrown, the module will be unloaded.
         */
        UNLOAD
    } EModException;

    void SetUser(NoUser* pUser);
    void SetNetwork(NoNetwork* pNetwork);
    void SetClient(NoClient* pClient);

    /** This function throws NoModule::UNLOAD which causes this module to be unloaded.
     */
    void Unload() { throw UNLOAD; }

    /** This module hook is called when a module is loaded
     *  @param sArgsi The arguments for the modules.
     *  @param sMessage A message that may be displayed to the user after
     *                  loading the module. Useful for returning error messages.
     *  @return true if the module loaded successfully, else false.
     */
    virtual bool OnLoad(const NoString& sArgsi, NoString& sMessage);
    /** This module hook is called during ZNC startup. Only modules loaded
     *  from znc.conf get this call.
     *  @return false to abort ZNC startup.
     */
    virtual bool OnBoot();


    /** Modules which can only be used with an active user session have to return true here.
     *  @return false for modules that can do stuff for non-logged in web users as well.
     */
    virtual bool WebRequiresLogin() { return true; }
    /** Return true if this module should only be usable for admins on the web.
     *  @return false if normal users can use this module's web pages as well.
     */
    virtual bool WebRequiresAdmin() { return false; }
    /** Return the title of the module's section in the web interface's side bar.
     *  @return The Title.
     */
    virtual NoString GetWebMenuTitle() { return ""; }
    virtual NoString GetWebPath();
    virtual NoString GetWebFilesPath();
    /** For WebMods: Called before the list of registered SubPages will be checked.
     *  Important: If you return true, you need to take care of calling WebSock.Close!
     *  This allows for stuff like returning non-templated data, long-polling and other fun.
     *  @param WebSock The active request.
     *  @param sPageName The name of the page that has been requested.
     *  @return true if you handled the page request or false if the name is to be checked
     *          against the list of registered SubPages and their permission settings.
     */
    virtual bool OnWebPreRequest(NoWebSock& WebSock, const NoString& sPageName);
    /** If OnWebPreRequest returned false, and the RequiresAdmin/IsAdmin check has been passed,
     *  this method will be called with the page name. It will also be called for pages that
     *  have NOT been specifically registered with AddSubPage.
     *  @param WebSock The active request.
     *  @param sPageName The name of the page that has been requested.
     *  @param Tmpl The active template. You can add variables, loops and stuff to it.
     *  @return You MUST return true if you want the template to be evaluated and sent to the browser.
     *          Return false if you called Redirect() or PrintErrorPage(). If you didn't, a 404 page will be sent.
     */
    virtual bool OnWebRequest(NoWebSock& WebSock, const NoString& sPageName, NoTemplate& Tmpl);
    /** Registers a sub page for the sidebar.
     *  @param spSubPage The SubPage instance.
     */
    virtual void AddSubPage(TWebSubPage spSubPage) { m_vSubPages.push_back(spSubPage); }
    /** Removes all registered (AddSubPage'd) SubPages.
     */
    virtual void ClearSubPages() { m_vSubPages.clear(); }
    /** Returns a list of all registered SubPages. Don't mess with it too much.
     *  @return The List.
     */
    virtual VWebSubPages& GetSubPages() { return m_vSubPages; }
    /** Using this hook, module can embed web stuff directly to different places.
     *  This method is called whenever embededded modules I/O happens.
     *  Name of used .tmpl file (if any) is up to caller.
     *  @param WebSock Socket for web connection, don't do bad things with it.
     *  @param sPageName Describes the place where web stuff is embedded to.
     *  @param Tmpl Template. Depending on context, you can do various stuff with it.
     *  @return If you don't need to embed web stuff to the specified place, just return false.
     *          Exact meaning of return value is up to caller, and depends on context.
     */
    virtual bool OnEmbeddedWebRequest(NoWebSock& WebSock, const NoString& sPageName, NoTemplate& Tmpl);


    /** Called just before znc.conf is rehashed */
    virtual void OnPreRehash();
    /** This module hook is called after a <em>successful</em> rehash. */
    virtual void OnPostRehash();
    /** This module hook is called when a user gets disconnected from IRC. */
    virtual void OnIRCDisconnected();
    /** This module hook is called after a successful login to IRC. */
    virtual void OnIRCConnected();
    /** This module hook is called just before ZNC tries to establish a
     *  connection to an IRC server.
     *  @param pIRCSock The socket that will be used for the connection.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnIRCConnecting(NoIrcSock* pIRCSock);
    /** This module hook is called when a NoIrcSock fails to connect or
     *  a module returned HALTCORE from OnIRCConnecting.
     *  @param pIRCSock The socket that failed to connect.
     */
    virtual void OnIRCConnectionError(NoIrcSock* pIRCSock);
    /** This module hook is called before loging in to the IRC server. The
     *  low-level connection is established at this point, but SSL
     *  handshakes didn't necessarily finish yet.
     *  @param sPass The server password that will be used.
     *  @param sNick The nick that will be used.
     *  @param sIdent The protocol identity that will be used. This is not
     *                the ident string that is transfered via e.g. oidentd!
     *  @param sRealName The real name that will be used.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnIRCRegistration(NoString& sPass, NoString& sNick, NoString& sIdent, NoString& sRealName);
    /** This module hook is called when a message is broadcasted to all users.
     *  @param sMessage The message that is broadcasted.
     *  @return see NoModule::EModRet
     */
    virtual EModRet OnBroadcast(NoString& sMessage);

    /** This module hook is called when a user mode on a channel changes.
     *  @param pOpNick The nick who sent the mode change, or nullptr if set by server.
     *  @param Nick The nick whose channel mode changes.
     *  @param Channel The channel on which the user mode is changed.
     *  @param uMode The mode character that is changed, e.g. '@' for op.
     *  @param bAdded True if the mode is added, else false.
     *  @param bNoChange true if this mode change doesn't change anything
     *                   because the nick already had this permission.
     *  @see NoIrcSock::GetModeType() for converting uMode into a mode (e.g.
     *       'o' for op).
     */
    virtual void
    OnChanPermission2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, unsigned char uMode, bool bAdded, bool bNoChange);
    virtual void OnChanPermission(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, unsigned char uMode, bool bAdded, bool bNoChange);
    /** Called when a nick is opped on a channel */
    virtual void OnOp2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    virtual void OnOp(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    /** Called when a nick is deopped on a channel */
    virtual void OnDeop2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    virtual void OnDeop(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    /** Called when a nick is voiced on a channel */
    virtual void OnVoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    virtual void OnVoice(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    /** Called when a nick is devoiced on a channel */
    virtual void OnDevoice2(const NoNick* pOpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    virtual void OnDevoice(const NoNick& OpNick, const NoNick& Nick, NoChannel& Channel, bool bNoChange);
    /** Called on an individual channel mode change.
     *  @param pOpNick The nick who changes the channel mode, or nullptr if set by server.
     *  @param Channel The channel whose mode is changed.
     *  @param uMode The mode character that is changed.
     *  @param sArg The argument to the mode character, if any.
     *  @param bAdded True if this mode is added ("+"), else false.
     *  @param bNoChange True if this mode was already effective before.
     */
    virtual void OnMode2(const NoNick* pOpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange);
    virtual void OnMode(const NoNick& OpNick, NoChannel& Channel, char uMode, const NoString& sArg, bool bAdded, bool bNoChange);
    /** Called on any channel mode change. This is called before the more
     *  detailed mode hooks like e.g. OnOp() and OnMode().
     *  @param pOpNick The nick who changes the channel mode, or nullptr if set by server.
     *  @param Channel The channel whose mode is changed.
     *  @param sModes The raw mode change, e.g. "+s-io".
     *  @param sArgs All arguments to the mode change from sModes.
     */
    virtual void OnRawMode2(const NoNick* pOpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs);
    virtual void OnRawMode(const NoNick& OpNick, NoChannel& Channel, const NoString& sModes, const NoString& sArgs);

    /** Called on any raw IRC line received from the <em>IRC server</em>.
     *  @param sLine The line read from the server.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnRaw(NoString& sLine);

    /** Called when a command to *status is sent.
     *  @param sCommand The command sent.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnStatusCommand(NoString& sCommand);
    /** Called when a command to your module is sent, e.g. query to *modname.
     *  @param sCommand The command that was sent.
     */
    virtual void OnModCommand(const NoString& sCommand);
    /** This is similar to OnModCommand(), but it is only called if
     * HandleCommand didn't find any that wants to handle this. This is only
     * called if HandleCommand() is called, which practically means that
     * this is only called if you don't overload OnModCommand().
     *  @param sCommand The command that was sent.
     */
    virtual void OnUnknownModCommand(const NoString& sCommand);
    /** Called when a your module nick was sent a notice.
     *  @param sMessage The message which was sent.
     */
    virtual void OnModNotice(const NoString& sMessage);
    /** Called when your module nick was sent a CTCP message. OnModCommand()
     *  won't be called for this message.
     *  @param sMessage The message which was sent.
     */
    virtual void OnModCTCP(const NoString& sMessage);

    /** Called when a nick quit from IRC.
     *  @param Nick The nick which quit.
     *  @param sMessage The quit message.
     *  @param vChans List of channels which you and nick share.
     */
    virtual void OnQuit(const NoNick& Nick, const NoString& sMessage, const std::vector<NoChannel*>& vChans);
    /** Called when a nickname change occurs. If we are changing our nick,
     *  sNewNick will equal m_pIRCSock->GetNick().
     *  @param Nick The nick which changed its nickname
     *  @param sNewNick The new nickname.
     *  @param vChans Channels which we and nick share.
     */
    virtual void OnNick(const NoNick& Nick, const NoString& sNewNick, const std::vector<NoChannel*>& vChans);
    /** Called when a nick is kicked from a channel.
     *  @param OpNick The nick which generated the kick.
     *  @param sKickedNick The nick which was kicked.
     *  @param Channel The channel on which this kick occurs.
     *  @param sMessage The kick message.
     */
    virtual void OnKick(const NoNick& OpNick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage);
    /** This module hook is called just before ZNC tries to join an IRC channel.
     *  @param Chan The channel which is about to get joined.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnJoining(NoChannel& Channel);
    /** Called when a nick joins a channel.
     *  @param Nick The nick who joined.
     *  @param Channel The channel which was joined.
     */
    virtual void OnJoin(const NoNick& Nick, NoChannel& Channel);
    /** Called when a nick parts a channel.
     *  @param Nick The nick who parted.
     *  @param Channel The channel which was parted.
     *  @param sMessage The part message.
     */
    virtual void OnPart(const NoNick& Nick, NoChannel& Channel, const NoString& sMessage);
    /** Called when user is invited into a channel
     *  @param Nick The nick who invited you.
     *  @param sChan The channel the user got invited into
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnInvite(const NoNick& Nick, const NoString& sChan);

    /** Called before a channel buffer is played back to a client.
     *  @param Chan The channel which will be played back.
     *  @param Client The client the buffer will be played back to.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnChanBufferStarting(NoChannel& Chan, NoClient& Client);
    /** Called after a channel buffer was played back to a client.
     *  @param Chan The channel which was played back.
     *  @param Client The client the buffer was played back to.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnChanBufferEnding(NoChannel& Chan, NoClient& Client);
    /** Called when for each line during a channel's buffer play back.
     *  @param Chan The channel this playback is from.
     *  @param Client The client the buffer is played back to.
     *  @param sLine The current line of buffer playback. This is a raw IRC
     *               traffic line!
     *  @param tv The timestamp of the message.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnChanBufferPlayLine2(NoChannel& Chan, NoClient& Client, NoString& sLine, const timeval& tv);
    virtual EModRet OnChanBufferPlayLine(NoChannel& Chan, NoClient& Client, NoString& sLine);
    /** Called when a line from the query buffer is played back.
     *  @param Client The client this line will go to.
     *  @param sLine The raw IRC traffic line from the buffer.
     *  @param tv The timestamp of the message.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnPrivBufferPlayLine2(NoClient& Client, NoString& sLine, const timeval& tv);
    virtual EModRet OnPrivBufferPlayLine(NoClient& Client, NoString& sLine);

    /** Called when a client successfully logged in to ZNC. */
    virtual void OnClientLogin();
    /** Called when a client disconnected from ZNC. */
    virtual void OnClientDisconnect();
    /** This module hook is called when a client sends a raw traffic line to ZNC.
     *  @param sLine The raw traffic line sent.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnUserRaw(NoString& sLine);
    /** This module hook is called when a client sends a CTCP reply.
     *  @param sTarget The target for the CTCP reply. Could be a channel
     *                 name or a nick name.
     *  @param sMessage The CTCP reply message.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnUserCTCPReply(NoString& sTarget, NoString& sMessage);
    /** This module hook is called when a client sends a CTCP request.
     *  @param sTarget The target for the CTCP request. Could be a channel
     *                 name or a nick name.
     *  @param sMessage The CTCP request message.
     *  @return See NoModule::EModRet.
     *  @note This is not called for CTCP ACTION messages, use
     *        NoModule::OnUserAction() instead.
     */
    virtual EModRet OnUserCTCP(NoString& sTarget, NoString& sMessage);
    /** Called when a client sends a CTCP ACTION request ("/me").
     *  @param sTarget The target for the CTCP ACTION. Could be a channel
     *                 name or a nick name.
     *  @param sMessage The action message.
     *  @return See NoModule::EModRet.
     *  @note NoModule::OnUserCTCP() will not be called for this message.
     */
    virtual EModRet OnUserAction(NoString& sTarget, NoString& sMessage);
    /** This module hook is called when a user sends a normal IRC message.
     *  @param sTarget The target of the message. Could be a channel name or
     *                 a nick name.
     *  @param sMessage The message which was sent.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnUserMsg(NoString& sTarget, NoString& sMessage);
    /** This module hook is called when a user sends a notice message.
     *  @param sTarget The target of the message. Could be a channel name or
     *                 a nick name.
     *  @param sMessage The message which was sent.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnUserNotice(NoString& sTarget, NoString& sMessage);
    /** This hooks is called when a user sends a JOIN message.
     *  @param sChannel The channel name the join is for.
     *  @param sKey The key for the channel.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnUserJoin(NoString& sChannel, NoString& sKey);
    /** This hooks is called when a user sends a PART message.
     *  @param sChannel The channel name the part is for.
     *  @param sMessage The part message the client sent.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnUserPart(NoString& sChannel, NoString& sMessage);
    /** This module hook is called when a user wants to change a channel topic.
     *  @param sChannel The channel.
     *  @param sTopic The new topic which the user sent.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnUserTopic(NoString& sChannel, NoString& sTopic);
    /** This hook is called when a user requests a channel's topic.
     *  @param sChannel The channel for which the request is.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnUserTopicRequest(NoString& sChannel);
    /** This module hook is called when a user requests to quit from network.
     *  @param sMessage The quit message the client sent.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnUserQuit(NoString& sMessage);

    /** Called when we receive a CTCP reply <em>from IRC</em>.
     *  @param Nick The nick the CTCP reply is from.
     *  @param sMessage The CTCP reply message.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnCTCPReply(NoNick& Nick, NoString& sMessage);
    /** Called when we receive a private CTCP request <em>from IRC</em>.
     *  @param Nick The nick the CTCP request is from.
     *  @param sMessage The CTCP request message.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnPrivCTCP(NoNick& Nick, NoString& sMessage);
    /** Called when we receive a channel CTCP request <em>from IRC</em>.
     *  @param Nick The nick the CTCP request is from.
     *  @param Channel The channel to which the request was sent.
     *  @param sMessage The CTCP request message.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnChanCTCP(NoNick& Nick, NoChannel& Channel, NoString& sMessage);
    /** Called when we receive a private CTCP ACTION ("/me" in query) <em>from IRC</em>.
     *  This is called after NoModule::OnPrivCTCP().
     *  @param Nick The nick the action came from.
     *  @param sMessage The action message
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnPrivAction(NoNick& Nick, NoString& sMessage);
    /** Called when we receive a channel CTCP ACTION ("/me" in a channel) <em>from IRC</em>.
     *  This is called after NoModule::OnChanCTCP().
     *  @param Nick The nick the action came from.
     *  @param Channel The channel the action was sent to.
     *  @param sMessage The action message
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnChanAction(NoNick& Nick, NoChannel& Channel, NoString& sMessage);
    /** Called when we receive a private message <em>from IRC</em>.
     *  @param Nick The nick which sent the message.
     *  @param sMessage The message.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnPrivMsg(NoNick& Nick, NoString& sMessage);
    /** Called when we receive a channel message <em>from IRC</em>.
     *  @param Nick The nick which sent the message.
     *  @param Channel The channel to which the message was sent.
     *  @param sMessage The message.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage);
    /** Called when we receive a private notice.
     *  @param Nick The nick which sent the notice.
     *  @param sMessage The notice message.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnPrivNotice(NoNick& Nick, NoString& sMessage);
    /** Called when we receive a channel notice.
     *  @param Nick The nick which sent the notice.
     *  @param Channel The channel to which the notice was sent.
     *  @param sMessage The notice message.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnChanNotice(NoNick& Nick, NoChannel& Channel, NoString& sMessage);
    /** Called when we receive a channel topic change <em>from IRC</em>.
     *  @param Nick The nick which changed the topic.
     *  @param Channel The channel whose topic was changed.
     *  @param sTopic The new topic.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnTopic(NoNick& Nick, NoChannel& Channel, NoString& sTopic);

    /** Called for every CAP received via CAP LS from server.
     *  @param sCap capability supported by server.
     *  @return true if your module supports this CAP and
     *          needs to turn it on with CAP REQ.
     */
    virtual bool OnServerCapAvailable(const NoString& sCap);
    /** Called for every CAP accepted or rejected by server
     *  (with CAP ACK or CAP NAK after our CAP REQ).
     *  @param sCap capability accepted/rejected by server.
     *  @param bSuccess true if capability was accepted, false if rejected.
     */
    virtual void OnServerCapResult(const NoString& sCap, bool bSuccess);

    /** This module hook is called just before ZNC tries to join a channel
     *  by itself because it's in the config but wasn't joined yet.
     *  @param Channel The channel which will be joined.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnTimerAutoJoin(NoChannel& Channel);

    /** This module hook is called when a network is being added.
     *  @param Network The new IRC network.
     *  @param sErrorRet A message that may be displayed to the user if
     *                  the module stops adding the network.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnAddNetwork(NoNetwork& Network, NoString& sErrorRet);
    /** This module hook is called when a network is deleted.
     *  @param Network The IRC network which is going to be deleted.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnDeleteNetwork(NoNetwork& Network);

    /** Called when ZNC sends a raw traffic line to a client.
     *  @param sLine The raw traffic line sent.
     *  @param Client The client this line is sent to.
     *  @warning Calling PutUser() from within this hook leads to infinite recursion.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnSendToClient(NoString& sLine, NoClient& Client);
    /** Called when ZNC sends a raw traffic line to the IRC server.
     *  @param sLine The raw traffic line sent.
     *  @warning Calling PutIRC() from within this hook leads to infinite recursion.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnSendToIRC(NoString& sLine);

    ModHandle GetDLL() { return m_pDLL; }
    static double GetCoreVersion() { return NO_VERSION; }

    /** This function sends a given raw IRC line to the IRC server, if we
     *  are connected to one. Else this line is discarded.
     *  @param sLine The line which should be sent.
     *  @return true if the line was queued for sending.
     */
    virtual bool PutIRC(const NoString& sLine);
    /** This function sends a given raw IRC line to a client.
     *  If we are in a module hook which is called for a specific client,
     *  only that client will get the line, else all connected clients will
     *  receive this line.
     *  @param sLine The line which should be sent.
     *  @return true if the line was sent to at least one client.
     */
    virtual bool PutUser(const NoString& sLine);
    /** This function generates a query from *status. If we are in a module
     *  hook for a specific client, only that client gets this message, else
     *  all connected clients will receive it.
     *  @param sLine The message which should be sent from *status.
     *  @return true if the line was sent to at least one client.
     */
    virtual bool PutStatus(const NoString& sLine);
    /** This function sends a query from your module nick. If we are in a
     *  module hook for a specific client, only that client gets this
     *  message, else all connected clients will receive it.
     *  @param sLine The message which should be sent.
     *  @return true if the line was sent to at least one client.
     */
    virtual bool PutModule(const NoString& sLine);
    /** This function calls NoModule::PutModule(const NoString&, const
     *  NoString&, const NoString&) for each line in the table.
     *  @param table The table which should be send.
     *  @return The number of lines sent.
     */
    virtual unsigned int PutModule(const NoTable& table);
    /** Send a notice from your module nick. If we are in a module hook for
     *  a specific client, only that client gets this notice, else all
     *  clients will receive it.
     *  @param sLine The line which should be sent.
     *  @return true if the line was sent to at least one client.
     */
    virtual bool PutModNotice(const NoString& sLine);

    /** @returns The name of the module. */
    const NoString& GetModName() const { return m_sModName; }

    /** @returns The nick of the module. This is just the module name
     *           prefixed by the status prefix.
     */
    NoString GetModNick() const;

    /** Get the module's data dir.
     *  Modules can be accompanied by static data, e.g. skins for webadmin.
     *  These function will return the path to that data.
     */
    const NoString& GetModDataDir() const { return m_sDataDir; }

    bool AddTimer(NoTimer* pTimer);
    bool AddTimer(FPTimer_t pFBCallback, const NoString& sLabel, u_int uInterval, u_int uCycles = 0, const NoString& sDescription = "");
    bool RemTimer(NoTimer* pTimer);
    bool RemTimer(const NoString& sLabel);
    bool UnlinkTimer(NoTimer* pTimer);
    NoTimer* FindTimer(const NoString& sLabel);
    std::set<NoTimer*>::const_iterator BeginTimers() const { return m_sTimers.begin(); }
    std::set<NoTimer*>::const_iterator EndTimers() const { return m_sTimers.end(); }
    virtual void ListTimers();

    bool AddSocket(NoSocket* pSocket);
    bool RemSocket(NoSocket* pSocket);
    bool RemSocket(const NoString& sSockName);
    bool UnlinkSocket(NoSocket* pSocket);
    NoSocket* FindSocket(const NoString& sSockName);
    std::set<NoSocket*>::const_iterator BeginSockets() const { return m_sSockets.begin(); }
    std::set<NoSocket*>::const_iterator EndSockets() const { return m_sSockets.end(); }
    virtual void ListSockets();

#ifdef HAVE_PTHREAD
    void AddJob(NoModuleJob* pJob);
    void CancelJob(NoModuleJob* pJob);
    bool CancelJob(const NoString& sJobName);
    void CancelJobs(const std::set<NoModuleJob*>& sJobs);
    bool UnlinkJob(NoModuleJob* pJob);
#endif

    /// Register the "Help" command.
    void AddHelpCommand();
    /// @return True if the command was successfully added.
    bool AddCommand(const NoModCommand& Command);
    /// @return True if the command was successfully added.
    bool AddCommand(const NoString& sCmd, NoModCommand::ModCmdFunc func, const NoString& sArgs = "", const NoString& sDesc = "");
    /// @return True if the command was successfully added.
    bool AddCommand(const NoString& sCmd, const NoString& sArgs, const NoString& sDesc, std::function<void(const NoString& sLine)> func);
    /// @return True if the command was successfully removed.
    bool RemCommand(const NoString& sCmd);
    /// @return The NoModCommand instance or nullptr if none was found.
    const NoModCommand* FindCommand(const NoString& sCmd) const;
    /** This function tries to dispatch the given command via the correct
     * instance of NoModCommand. Before this can be called, commands have to
     * be added via AddCommand(). If no matching commands are found then
     * OnUnknownModCommand will be called.
     * @param sLine The command line to handle.
     * @return True if something was done, else false.
     */
    bool HandleCommand(const NoString& sLine);
    /** Send a description of all registered commands via PutModule().
     * @param sLine The help command that is being asked for.
     */
    void HandleHelpCommand(const NoString& sLine = "");

    bool LoadRegistry();
    bool SaveRegistry() const;
    bool MoveRegistry(const NoString& sPath);
    bool SetNV(const NoString& sName, const NoString& sValue, bool bWriteToDisk = true);
    NoString GetNV(const NoString& sName) const;
    bool DelNV(const NoString& sName, bool bWriteToDisk = true);
    NoStringMap::iterator FindNV(const NoString& sName) { return m_mssRegistry.find(sName); }
    NoStringMap::iterator EndNV() { return m_mssRegistry.end(); }
    NoStringMap::iterator BeginNV() { return m_mssRegistry.begin(); }
    void DelNV(NoStringMap::iterator it) { m_mssRegistry.erase(it); }
    bool ClearNV(bool bWriteToDisk = true);

    const NoString& GetSavePath() const;
    NoString ExpandString(const NoString& sStr) const;
    NoString& ExpandString(const NoString& sStr, NoString& sRet) const;

    void SetType(NoModInfo::EModuleType eType) { m_eType = eType; }
    void SetDescription(const NoString& s) { m_sDescription = s; }
    void SetModPath(const NoString& s) { m_sModPath = s; }
    void SetArgs(const NoString& s) { m_sArgs = s; }

    NoModInfo::EModuleType GetType() const { return m_eType; }
    const NoString& GetDescription() const { return m_sDescription; }
    const NoString& GetArgs() const { return m_sArgs; }
    const NoString& GetModPath() const { return m_sModPath; }

    /** @returns For user modules this returns the user for which this
     *           module was loaded. For global modules this returns nullptr,
     *           except when we are in a user-specific module hook in which
     *           case this is the user pointer.
     */
    NoUser* GetUser() const { return m_pUser; }
    /** @returns nullptr except when we are in a client-specific module hook in
     *           which case this is the client for which the hook is called.
     */
    NoNetwork* GetNetwork() const { return m_pNetwork; }
    NoClient* GetClient() const { return m_pClient; }
    NoSocketManager* GetManager() const { return m_pManager; }

    /** This module hook is called when a user is being added.
     * @param User The user which will be added.
     * @param sErrorRet A message that may be displayed to the user if
     *                  the module stops adding the user.
     * @return See NoModule::EModRet.
     */
    virtual EModRet OnAddUser(NoUser& User, NoString& sErrorRet);
    /** This module hook is called when a user is deleted.
     *  @param User The user which will be deleted.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnDeleteUser(NoUser& User);
    /** This module hook is called when there is an incoming connection on
     *  any of ZNC's listening sockets.
     *  @param pSock The incoming client socket.
     *  @param sHost The IP the client is connecting from.
     *  @param uPort The port the client is connecting from.
     */
    virtual void OnClientConnect(NoBaseSocket* pSock, const NoString& sHost, unsigned short uPort);
    /** This module hook is called when a client tries to login. If your
     *  module wants to handle the login attempt, it must return
     *  NoModule::EModRet::HALT;
     *  @param Auth The necessary authentication info for this login attempt.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnLoginAttempt(std::shared_ptr<NoAuthBase> Auth);
    /** Called after a client login was rejected.
     *  @param sUsername The username that tried to log in.
     *  @param sRemoteIP The IP address from which the client tried to login.
     */
    virtual void OnFailedLogin(const NoString& sUsername, const NoString& sRemoteIP);
    /** This function behaves like NoModule::OnUserRaw(), but is also called
     *  before the client successfully logged in to ZNC. You should always
     *  prefer to use NoModule::OnUserRaw() if possible.
     *  @param pClient The client which send this line.
     *  @param sLine The raw traffic line which the client sent.
     */
    virtual EModRet OnUnknownUserRaw(NoClient* pClient, NoString& sLine);

    /** Called when a client told us CAP LS. Use ssCaps.insert("cap-name")
     *  for announcing capabilities which your module supports.
     *  @param pClient The client which requested the list.
     *  @param ssCaps set of caps which will be sent to client.
     */
    virtual void OnClientCapLs(NoClient* pClient, NoStringSet& ssCaps);
    /** Called only to check if your module supports turning on/off named capability.
     *  @param pClient The client which wants to enable/disable a capability.
     *  @param sCap name of capability.
     *  @param bState On or off, depending on which case is interesting for client.
     *  @return true if your module supports this capability in the specified state.
     */
    virtual bool IsClientCapSupported(NoClient* pClient, const NoString& sCap, bool bState);
    /** Called when we actually need to turn a capability on or off for a client.
     *  @param pClient The client which requested the capability.
     *  @param sCap name of wanted capability.
     *  @param bState On or off, depending on which case client needs.
     */
    virtual void OnClientCapRequest(NoClient* pClient, const NoString& sCap, bool bState);

    /** Called when a module is going to be loaded.
     *  @param sModName name of the module.
     *  @param eType wanted type of the module (user/global).
     *  @param sArgs arguments of the module.
     *  @param[out] bSuccess the module was loaded successfully
     *                       as result of this module hook?
     *  @param[out] sRetMsg text about loading of the module.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet
    OnModuleLoading(const NoString& sModName, const NoString& sArgs, NoModInfo::EModuleType eType, bool& bSuccess, NoString& sRetMsg);
    /** Called when a module is going to be unloaded.
     *  @param pModule the module.
     *  @param[out] bSuccess the module was unloaded successfully
     *                       as result of this module hook?
     *  @param[out] sRetMsg text about unloading of the module.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnModuleUnloading(NoModule* pModule, bool& bSuccess, NoString& sRetMsg);
    /** Called when info about a module is needed.
     *  @param[out] ModInfo put result here, if your module knows it.
     *  @param sModule name of the module.
     *  @param bSuccess this module provided info about the module.
     *  @param sRetMsg text describing possible issues.
     *  @return See NoModule::EModRet.
     */
    virtual EModRet OnGetModInfo(NoModInfo& ModInfo, const NoString& sModule, bool& bSuccess, NoString& sRetMsg);
    /** Called when list of available mods is requested.
     *  @param ssMods put new modules here.
     *  @param bGlobal true if global modules are needed.
     */
    virtual void OnGetAvailableMods(std::set<NoModInfo>& ssMods, NoModInfo::EModuleType eType);

private:
    NoModInfo::EModuleType m_eType;
    NoString m_sDescription;
    std::set<NoTimer*> m_sTimers;
    std::set<NoSocket*> m_sSockets;
#ifdef HAVE_PTHREAD
    std::set<NoModuleJob*> m_sJobs;
#endif
    ModHandle m_pDLL;
    NoSocketManager* m_pManager;
    NoUser* m_pUser;
    NoNetwork* m_pNetwork;
    NoClient* m_pClient;
    NoString m_sModName;
    NoString m_sDataDir;
    NoString m_sSavePath;
    NoString m_sArgs;
    NoString m_sModPath;

private:
    NoStringMap m_mssRegistry; //!< way to save name/value pairs. Note there is no encryption involved in this
    VWebSubPages m_vSubPages;
    std::map<NoString, NoModCommand> m_mCommands;
};

#endif // NOMODULE_H
