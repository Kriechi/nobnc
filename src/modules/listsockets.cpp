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
#include <nobnc/nouser.h>
#include <nobnc/noapp.h>
#include <nobnc/nosocket.h>
#include <nobnc/notemplate.h>
#include <nobnc/notable.h>

#include <queue>

class NoSocketSorter
{
public:
    NoSocketSorter(NoSocket* p)
    {
        m_pSock = p;
    }
    bool operator<(const NoSocketSorter& other) const
    {
        // The 'biggest' item is displayed first.
        // return false: this is first
        // return true: other is first

        // Listeners go to the top
        if (m_pSock->isListener() != other.m_pSock->isListener()) {
            if (m_pSock->isListener())
                return false;
            if (other.m_pSock->isListener())
                return true;
        }
        const NoString& sMyName = m_pSock->name();
        const NoString& sMyName2 = No::tokens(sMyName, 1, "::");
        bool bMyEmpty = sMyName2.empty();
        const NoString& sHisName = other.GetSock()->name();
        const NoString& sHisName2 = No::tokens(sHisName, 1, "::");
        bool bHisEmpty = sHisName2.empty();

        // Then sort by first token after "::"
        if (bMyEmpty && !bHisEmpty)
            return false;
        if (bHisEmpty && !bMyEmpty)
            return true;

        if (!bMyEmpty && !bHisEmpty) {
            int c = sMyName2.compare(sHisName2, No::CaseSensitive);
            if (c < 0)
                return false;
            if (c > 0)
                return true;
        }
        // and finally sort by the whole socket name
        return sMyName.compare(sHisName, No::CaseSensitive) > 0;
    }
    NoSocket* GetSock() const
    {
        return m_pSock;
    }

private:
    NoSocket* m_pSock;
};

class NoListSockets : public NoModule
{
public:
    MODCONSTRUCTOR(NoListSockets)
    {
        addHelpCommand();
        addCommand("List",
                   static_cast<NoModule::CommandFunction>(&NoListSockets::OnListCommand),
                   "[-n]",
                   "Show the list of active sockets. Pass -n to show IP addresses");
    }

    bool onLoad(const NoString& args, NoString& message) override
    {
#ifndef MOD_LISTSOCKETS_ALLOW_EVERYONE
        if (!user()->isAdmin()) {
            message = "You must be admin to use this module";
            return false;
        }
#endif

        return true;
    }

    std::priority_queue<NoSocketSorter> GetSockets()
    {
        NoSocketManager* m = noApp->manager();
        std::priority_queue<NoSocketSorter> ret;

        for (NoSocket* socket : m->sockets())
            ret.push(socket);

        return ret;
    }

    bool webRequiresAdmin() override
    {
        return true;
    }
    NoString webMenuTitle() override
    {
        return "List sockets";
    }

    bool onWebRequest(NoWebSocket* socket, const NoString& page, NoTemplate& tmpl) override
    {
        if (page == "index") {
            if (noApp->manager()->sockets().empty()) {
                return false;
            }

            std::priority_queue<NoSocketSorter> socks = GetSockets();

            while (!socks.empty()) {
                NoSocket* pSocket = socks.top().GetSock();
                socks.pop();

                NoTemplate& Row = tmpl.addRow("SocketsLoop");
                Row["Name"] = pSocket->name();
                Row["Created"] = GetCreatedTime(pSocket);
                Row["State"] = GetSocketState(pSocket);
                Row["SSL"] = pSocket->isSsl() ? "Yes" : "No";
                Row["Local"] = GetLocalHost(pSocket, true);
                Row["Remote"] = GetRemoteHost(pSocket, true);
                Row["In"] = No::toByteStr(pSocket->bytesRead());
                Row["Out"] = No::toByteStr(pSocket->bytesWritten());
            }

            return true;
        }

        return false;
    }

    void OnListCommand(const NoString& line)
    {
        NoString arg = No::tokens(line, 1);

        bool bShowHosts = true;
        if (arg.equals("-n")) {
            bShowHosts = false;
        }
        ShowSocks(bShowHosts);
    }

    NoString GetSocketState(NoSocket* pSocket)
    {
        if (pSocket->isListener())
            return "Listener";
        if (pSocket->isInbound())
            return "Inbound";
        if (pSocket->isOutbound()) {
            if (pSocket->isConnected())
                return "Outbound";
            else
                return "Connecting";
        }

        return "UNKNOWN";
    }

    NoString GetCreatedTime(NoSocket* pSocket)
    {
        ulonglong iStartTime = pSocket->startTime();
        time_t iTime = iStartTime / 1000;
        return No::formatTime(iTime, "%Y-%m-%d %H:%M:%S", user()->timezone());
    }

    NoString GetLocalHost(NoSocket* pSocket, bool bShowHosts)
    {
        NoString bindHost;

        if (bShowHosts) {
            bindHost = pSocket->bindHost();
        }

        if (bindHost.empty()) {
            bindHost = pSocket->localAddress();
        }

        return bindHost + " " + NoString(pSocket->localPort());
    }

    NoString GetRemoteHost(NoSocket* pSocket, bool bShowHosts)
    {
        NoString host;
        u_short port;

        if (!bShowHosts) {
            host = pSocket->remoteAddress();
        }

        // While connecting, there might be no ip available
        if (host.empty()) {
            host = pSocket->host();
        }

        // While connecting, GetRemotePort() would return 0
        if (pSocket->isOutbound()) {
            port = pSocket->port();
        } else {
            port = pSocket->remotePort();
        }

        if (port != 0) {
            return host + " " + NoString(port);
        }

        return host;
    }

    void ShowSocks(bool bShowHosts)
    {
        if (noApp->manager()->sockets().empty()) {
            putStatus("You have no open sockets.");
            return;
        }

        std::priority_queue<NoSocketSorter> socks = GetSockets();

        NoTable Table;
        Table.addColumn("Name");
        Table.addColumn("Created");
        Table.addColumn("State");
#ifdef HAVE_LIBSSL
        Table.addColumn("SSL");
#endif
        Table.addColumn("Local");
        Table.addColumn("Remote");
        Table.addColumn("In");
        Table.addColumn("Out");

        while (!socks.empty()) {
            NoSocket* pSocket = socks.top().GetSock();
            socks.pop();

            Table.addRow();
            Table.setValue("Name", pSocket->name());
            Table.setValue("Created", GetCreatedTime(pSocket));
            Table.setValue("State", GetSocketState(pSocket));

#ifdef HAVE_LIBSSL
            Table.setValue("SSL", pSocket->isSsl() ? "Yes" : "No");
#endif

            Table.setValue("Local", GetLocalHost(pSocket, bShowHosts));
            Table.setValue("Remote", GetRemoteHost(pSocket, bShowHosts));
            Table.setValue("In", No::toByteStr(pSocket->bytesRead()));
            Table.setValue("Out", No::toByteStr(pSocket->bytesWritten()));
        }

        putModule(Table);
        return;
    }
};

template <>
void no_moduleInfo<NoListSockets>(NoModuleInfo& info)
{
    info.setWikiPage("listsockets");
}

USERMODULEDEFS(NoListSockets, "List active sockets")
