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
#include <no/nouser.h>
#include <no/noapp.h>
#include <no/nosocket.h>
#include <no/notemplate.h>

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
                   static_cast<NoModuleCommand::ModCmdFunc>(&NoListSockets::OnListCommand),
                   "[-n]",
                   "Show the list of active sockets. Pass -n to show IP addresses");
    }

    bool onLoad(const NoString& sArgs, NoString& sMessage) override
    {
#ifndef MOD_LISTSOCKETS_ALLOW_EVERYONE
        if (!user()->isAdmin()) {
            sMessage = "You must be admin to use this module";
            return false;
        }
#endif

        return true;
    }

    std::priority_queue<NoSocketSorter> GetSockets()
    {
        NoSocketManager& m = NoApp::instance().manager();
        std::priority_queue<NoSocketSorter> ret;

        for (NoSocket* pSock : m.sockets())
            ret.push(pSock);

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

    bool onWebRequest(NoWebSocket& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "index") {
            if (NoApp::instance().manager().sockets().empty()) {
                return false;
            }

            std::priority_queue<NoSocketSorter> socks = GetSockets();

            while (!socks.empty()) {
                NoSocket* pSocket = socks.top().GetSock();
                socks.pop();

                NoTemplate& Row = Tmpl.addRow("SocketsLoop");
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

    void OnListCommand(const NoString& sLine)
    {
        NoString sArg = No::tokens(sLine, 1);

        bool bShowHosts = true;
        if (sArg.equals("-n")) {
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
        NoString sBindHost;

        if (bShowHosts) {
            sBindHost = pSocket->bindHost();
        }

        if (sBindHost.empty()) {
            sBindHost = pSocket->localAddress();
        }

        return sBindHost + " " + NoString(pSocket->localPort());
    }

    NoString GetRemoteHost(NoSocket* pSocket, bool bShowHosts)
    {
        NoString sHost;
        u_short uPort;

        if (!bShowHosts) {
            sHost = pSocket->remoteAddress();
        }

        // While connecting, there might be no ip available
        if (sHost.empty()) {
            sHost = pSocket->host();
        }

        // While connecting, GetRemotePort() would return 0
        if (pSocket->isOutbound()) {
            uPort = pSocket->port();
        } else {
            uPort = pSocket->remotePort();
        }

        if (uPort != 0) {
            return sHost + " " + NoString(uPort);
        }

        return sHost;
    }

    void ShowSocks(bool bShowHosts)
    {
        if (NoApp::instance().manager().sockets().empty()) {
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
void no_moduleInfo<NoListSockets>(NoModuleInfo& Info)
{
    Info.setWikiPage("listsockets");
}

USERMODULEDEFS(NoListSockets, "List active sockets")
