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
#include <nobnc/nonetwork.h>
#include <nobnc/noircsocket.h>
#include <nobnc/noclient.h>
#include <nobnc/noregistry.h>
#include <nobnc/notimer.h>
#include <nobnc/noutils.h>

struct reply
{
    const char* szReply;
    bool bLastResponse;
};

// TODO this list is far from complete, no errors are handled
static const struct
{
    const char* szRequest;
    struct reply vReplies[19];
} vRouteReplies[] = { { "WHO",
                        { { "402", true }, /* rfc1459 ERR_NOSUCHSERVER */
                          { "352", false }, /* rfc1459 RPL_WHOREPLY */
                          { "315", true }, /* rfc1459 RPL_ENDOFWHO */
                          { "354", false }, // e.g. Quaknet uses this for WHO #chan %n
                          { "403", true }, // No such chan
                          { nullptr, true } } },
                      { "LIST",
                        { { "402", true }, /* rfc1459 ERR_NOSUCHSERVER */
                          { "321", false }, /* rfc1459 RPL_LISTSTART */
                          { "322", false }, /* rfc1459 RPL_LIST */
                          { "323", true }, /* rfc1459 RPL_LISTEND */
                          { nullptr, true } } },
                      { "NAMES",
                        {
                          { "353", false }, /* rfc1459 RPL_NAMREPLY */
                          { "366", true }, /* rfc1459 RPL_ENDOFNAMES */
                          // No such nick/channel
                          { "401", true },
                          { nullptr, true },
                        } },
                      { "LUSERS",
                        { { "251", false }, /* rfc1459 RPL_LUSERCLIENT */
                          { "252", false }, /* rfc1459 RPL_LUSEROP */
                          { "253", false }, /* rfc1459 RPL_LUSERUNKNOWN */
                          { "254", false }, /* rfc1459 RPL_LUSERCHANNELS */
                          { "255", false }, /* rfc1459 RPL_LUSERME */
                          { "265", false },
                          { "266", true },
                          // We don't handle 250 here since some IRCds don't sent it
                          //{"250", true},
                          { nullptr, true } } },
                      { "WHOIS",
                        { { "311", false }, /* rfc1459 RPL_WHOISUSER */
                          { "312", false }, /* rfc1459 RPL_WHOISSERVER */
                          { "313", false }, /* rfc1459 RPL_WHOISOPERATOR */
                          { "317", false }, /* rfc1459 RPL_WHOISIDLE */
                          { "319", false }, /* rfc1459 RPL_WHOISCHANNELS */
                          { "301", false }, /* rfc1459 RPL_AWAY */
                          { "276", false }, /* oftc-hybrid RPL_WHOISCERTFP */
                          { "330", false }, /* ratbox RPL_WHOISLOGGEDIN
                                               aka ircu RPL_WHOISACCOUNT */
                          { "338", false }, /* RPL_WHOISACTUALLY -- "actually using host" */
                          { "378", false }, /* RPL_WHOISHOST -- real address of vhosts */
                          { "671", false }, /* RPL_WHOISSECURE */
                          { "307", false }, /* RPL_WHOISREGNICK */
                          { "379", false }, /* RPL_WHOISMODES */
                          { "760", false }, /* ircv3.2 RPL_WHOISKEYVALUE */
                          { "318", true }, /* rfc1459 RPL_ENDOFWHOIS */
                          { "401", true }, /* rfc1459 ERR_NOSUCHNICK */
                          { "402", true }, /* rfc1459 ERR_NOSUCHSERVER */
                          { "431", true }, /* rfc1459 ERR_NONICKNAMEGIVEN */
                          { nullptr, true } } },
                      { "PING",
                        { { "PONG", true },
                          { "402", true }, /* rfc1459 ERR_NOSUCHSERVER */
                          { "409", true }, /* rfc1459 ERR_NOORIGIN */
                          { nullptr, true } } },
                      { "USERHOST",
                        { { "302", true },
                          { "461", true }, /* rfc1459 ERR_NEEDMOREPARAMS */
                          { nullptr, true } } },
                      { "TIME",
                        { { "391", true }, /* rfc1459 RPL_TIME */
                          { "402", true }, /* rfc1459 ERR_NOSUCHSERVER */
                          { nullptr, true } } },
                      { "WHOWAS",
                        { { "406", false }, /* rfc1459 ERR_WASNOSUCHNICK */
                          { "312", false }, /* rfc1459 RPL_WHOISSERVER */
                          { "314", false }, /* rfc1459 RPL_WHOWASUSER */
                          { "369", true }, /* rfc1459 RPL_ENDOFWHOWAS */
                          { "431", true }, /* rfc1459 ERR_NONICKNAMEGIVEN */
                          { nullptr, true } } },
                      { "ISON",
                        { { "303", true }, /* rfc1459 RPL_ISON */
                          { "461", true }, /* rfc1459 ERR_NEEDMOREPARAMS */
                          { nullptr, true } } },
                      { "LINKS",
                        { { "364", false }, /* rfc1459 RPL_LINKS */
                          { "365", true }, /* rfc1459 RPL_ENDOFLINKS */
                          { "402", true }, /* rfc1459 ERR_NOSUCHSERVER */
                          { nullptr, true } } },
                      { "MAP",
                        { { "006", false },
                          // inspircd
                          { "270", false },
                          // SilverLeo wants this two added
                          { "015", false },
                          { "017", true },
                          { "007", true },
                          { "481", true }, /* rfc1459 ERR_NOPRIVILEGES */
                          { nullptr, true } } },
                      { "TRACE",
                        { { "200", false }, /* rfc1459 RPL_TRACELINK */
                          { "201", false }, /* rfc1459 RPL_TRACECONNECTING */
                          { "202", false }, /* rfc1459 RPL_TRACEHANDSHAKE */
                          { "203", false }, /* rfc1459 RPL_TRACEUNKNOWN */
                          { "204", false }, /* rfc1459 RPL_TRACEOPERATOR */
                          { "205", false }, /* rfc1459 RPL_TRACEUSER */
                          { "206", false }, /* rfc1459 RPL_TRACESERVER */
                          { "208", false }, /* rfc1459 RPL_TRACENEWTYPE */
                          { "261", false }, /* rfc1459 RPL_TRACELOG */
                          { "262", true },
                          { "402", true }, /* rfc1459 ERR_NOSUCHSERVER */
                          { nullptr, true } } },
                      { "USERS",
                        {
                          { "265", false },
                          { "266", true },
                          { "392", false }, /* rfc1459 RPL_USERSSTART */
                          { "393", false }, /* rfc1459 RPL_USERS */
                          { "394", true }, /* rfc1459 RPL_ENDOFUSERS */
                          { "395", false }, /* rfc1459 RPL_NOUSERS */
                          { "402", true }, /* rfc1459 ERR_NOSUCHSERVER */
                          { "424", true }, /* rfc1459 ERR_FILEERROR */
                          { "446", true }, /* rfc1459 ERR_USERSDISABLED */
                          { nullptr, true },
                        } },
                      { "METADATA",
                        {
                          { "761", false }, /* ircv3.2 RPL_KEYVALUE */
                          { "762", true }, /* ircv3.2 RPL_METADATAEND */
                          { "765", true }, /* ircv3.2 ERR_TARGETINVALID */
                          { "766", true }, /* ircv3.2 ERR_NOMATCHINGKEYS */
                          { "767", true }, /* ircv3.2 ERR_KEYINVALID */
                          { "768", true }, /* ircv3.2 ERR_KEYNOTSET */
                          { "769", true }, /* ircv3.2 ERR_KEYNOPERMISSION */
                          { nullptr, true },
                        } },
                      // This is just a list of all possible /mode replies stuffed together.
                      // Since there should never be more than one of these going on, this
                      // should work fine and makes the code simpler.
                      { "MODE",
                        { // "You're not a channel operator"
                          { "482", true },
                          // MODE I
                          { "346", false },
                          { "347", true },
                          // MODE b
                          { "367", false },
                          { "368", true },
                          // MODE e
                          { "348", false },
                          { "349", true },
                          { "467", true }, /* rfc1459 ERR_KEYSET */
                          { "472", true }, /* rfc1459 ERR_UNKNOWNMODE */
                          { "501", true }, /* rfc1459 ERR_UMODEUNKNOWNFLAG */
                          { "502", true }, /* rfc1459 ERR_USERSDONTMATCH */
                          { nullptr, true },
                        } },
                      // END (last item!)
                      { nullptr, { { nullptr, true } } } };

class NoRouteTimeout : public NoTimer
{
public:
    NoRouteTimeout(NoModule* module) : NoTimer(module)
    {
        setName("RouteTimeout");
        setDescription("Recover from missing / wrong server replies");
    }

protected:
    void run() override;
};

struct queued_req
{
    NoString line;
    const struct reply* reply;
};

typedef std::map<NoClient*, std::vector<struct queued_req>> requestQueue;

class NoRouteRepliesMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoRouteRepliesMod)
    {
        m_pDoing = nullptr;
        m_pReplies = nullptr;

        addHelpCommand();
        addCommand("Silent", static_cast<NoModule::CommandFunction>(&NoRouteRepliesMod::SilentCommand), "[yes|no]");
    }

    virtual ~NoRouteRepliesMod()
    {
        requestQueue::iterator it;

        while (!m_vsPending.empty()) {
            it = m_vsPending.begin();

            while (!it->second.empty()) {
                putIrc(it->second[0].line);
                it->second.erase(it->second.begin());
            }

            m_vsPending.erase(it);
        }
    }

    void onIrcConnected() override
    {
        m_pDoing = nullptr;
        m_pReplies = nullptr;
        m_vsPending.clear();

        // No way we get a reply, so stop the timer (If it's running)
        delete findTimer("RouteTimeout");
    }

    void onIrcDisconnected() override
    {
        onIrcConnected(); // Let's keep it in one place
    }

    void onClientDisconnect() override
    {
        requestQueue::iterator it;

        if (client() == m_pDoing) {
            // The replies which aren't received yet will be
            // broadcasted to everyone, but at least nothing breaks
            delete findTimer("RouteTimeout");
            m_pDoing = nullptr;
            m_pReplies = nullptr;
        }

        it = m_vsPending.find(client());

        if (it != m_vsPending.end())
            m_vsPending.erase(it);

        SendRequest();
    }

    Return onRaw(NoString& line) override
    {
        NoString cmd = No::token(line, 1).toUpper();
        size_t i = 0;

        if (!m_pReplies)
            return Continue;

        // Is this a "not enough arguments" error?
        if (cmd == "461") {
            // :server 461 nick WHO :Not enough parameters
            NoString sOrigCmd = No::token(line, 3);

            if (No::token(m_sLastRequest, 0).equals(sOrigCmd)) {
                // This is the reply to the last request
                if (RouteReply(line, true))
                    return HaltCore;
                return Continue;
            }
        }

        while (m_pReplies[i].szReply != nullptr) {
            if (m_pReplies[i].szReply == cmd) {
                if (RouteReply(line, m_pReplies[i].bLastResponse, cmd == "353"))
                    return HaltCore;
                return Continue;
            }
            i++;
        }

        // TODO HaltCore is wrong, it should not be passed to
        // the clients, but the core itself should still handle it!

        return Continue;
    }

    Return onUserRaw(NoString& line) override
    {
        NoString cmd = No::token(line, 0).toUpper();

        if (!network()->ircSocket())
            return Continue;

        if (cmd.equals("MODE")) {
            // Check if this is a mode request that needs to be handled

            // If there are arguments to a mode change,
            // we must not route it.
            if (!No::tokens(line, 3).empty())
                return Continue;

            // Grab the mode change parameter
            NoString sMode = No::token(line, 2);

            // If this is a channel mode request, znc core replies to it
            if (sMode.empty())
                return Continue;

            // Check if this is a mode change or a specific
            // mode request (the later needs to be routed).
            sMode.trimPrefix("+");
            if (sMode.length() != 1)
                return Continue;

            // Now just check if it's one of the supported modes
            switch (sMode[0]) {
            case 'I':
            case 'b':
            case 'e':
                break;
            default:
                return Continue;
            }

            // Ok, this looks like we should route it.
            // Fall through to the next loop
        }

        for (size_t i = 0; vRouteReplies[i].szRequest != nullptr; i++) {
            if (vRouteReplies[i].szRequest == cmd) {
                struct queued_req req = { line, vRouteReplies[i].vReplies };
                m_vsPending[client()].push_back(req);
                SendRequest();

                return HaltCore;
            }
        }

        return Continue;
    }

    void Timeout()
    {
        // The timer will be deleted after this by the event loop

        NoRegistry registry(this);
        if (!registry.value("silent_timeouts").toBool()) {
            putModule("This module hit a timeout which is possibly a bug.");
            putModule("To disable this message, do \"/msg " + prefix() + " silent yes\"");
            putModule("Last request: " + m_sLastRequest);
            putModule("Expected replies: ");

            for (size_t i = 0; m_pReplies[i].szReply != nullptr; i++) {
                if (m_pReplies[i].bLastResponse)
                    putModule(m_pReplies[i].szReply + NoString(" (last)"));
                else
                    putModule(m_pReplies[i].szReply);
            }
        }

        m_pDoing = nullptr;
        m_pReplies = nullptr;
        SendRequest();
    }

private:
    bool RouteReply(const NoString& line, bool bFinished = false, bool bIsRaw353 = false)
    {
        if (!m_pDoing)
            return false;

        // 353 needs special treatment due to NAMESX and UHNAMES
        if (bIsRaw353)
            network()->ircSocket()->forwardRaw353(line, m_pDoing);
        else
            m_pDoing->putClient(line);

        if (bFinished) {
            // Stop the timeout
            delete findTimer("RouteTimeout");

            m_pDoing = nullptr;
            m_pReplies = nullptr;
            SendRequest();
        }

        return true;
    }

    void SendRequest()
    {
        requestQueue::iterator it;

        if (m_pDoing || m_pReplies)
            return;

        if (m_vsPending.empty())
            return;

        it = m_vsPending.begin();

        if (it->second.empty()) {
            m_vsPending.erase(it);
            SendRequest();
            return;
        }

        // When we are called from the timer, we need to remove it.
        // We can't delete it (segfault on return), thus we
        // just stop it. The main loop will delete it.
        delete findTimer("RouteTimeout");

        NoRouteTimeout* timer = new NoRouteTimeout(this);
        timer->setSingleShot(true);
        timer->start(60);

        m_pDoing = it->first;
        m_pReplies = it->second[0].reply;
        m_sLastRequest = it->second[0].line;
        putIrc(it->second[0].line);
        it->second.erase(it->second.begin());
    }

    void SilentCommand(const NoString& line)
    {
        const NoString value = No::token(line, 1);

        NoRegistry registry(this);
        if (!value.empty()) {
            registry.setValue("silent_timeouts", value);
        }

        NoString prefix = registry.value("silent_timeouts").toBool() ? "dis" : "en";
        putModule("Timeout messages are " + prefix + "abled.");
    }

    NoClient* m_pDoing;
    const struct reply* m_pReplies;
    requestQueue m_vsPending;
    // This field is only used for display purpose.
    NoString m_sLastRequest;
};

void NoRouteTimeout::run()
{
    static_cast<NoRouteRepliesMod*>(module())->Timeout();
}

template <>
void no_moduleInfo<NoRouteRepliesMod>(NoModuleInfo& info)
{
    info.setWikiPage("route_replies");
}

NETWORKMODULEDEFS(NoRouteRepliesMod, "Send replies (e.g. to /who) to the right client only")
