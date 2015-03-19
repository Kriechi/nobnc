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

#include <no/nouser.h>
#include <no/noapp.h>
#include <no/nosocket.h>

class NoSocketSorter
{
public:
    NoSocketSorter(NoBaseSocket* p) { m_pSock = p; }
    bool operator<(const NoSocketSorter& other) const
    {
        // The 'biggest' item is displayed first.
        // return false: this is first
        // return true: other is first

        // Listeners go to the top
        if (m_pSock->IsListener() != other.m_pSock->IsListener()) {
            if (m_pSock->IsListener()) return false;
            if (other.m_pSock->IsListener()) return true;
        }
        const NoString& sMyName = m_pSock->GetSockName();
        const NoString& sMyName2 = sMyName.Token(1, true, "::");
        bool bMyEmpty = sMyName2.empty();
        const NoString& sHisName = other.GetSock()->GetSockName();
        const NoString& sHisName2 = sHisName.Token(1, true, "::");
        bool bHisEmpty = sHisName2.empty();

        // Then sort by first token after "::"
        if (bMyEmpty && !bHisEmpty) return false;
        if (bHisEmpty && !bMyEmpty) return true;

        if (!bMyEmpty && !bHisEmpty) {
            int c = sMyName2.Compare(sHisName2, No::CaseSensitive);
            if (c < 0) return false;
            if (c > 0) return true;
        }
        // and finally sort by the whole socket name
        return sMyName.Compare(sHisName, No::CaseSensitive) > 0;
    }
    NoBaseSocket* GetSock() const { return m_pSock; }

private:
    NoBaseSocket* m_pSock;
};

class NoListSockets : public NoModule
{
public:
    MODCONSTRUCTOR(NoListSockets)
    {
        AddHelpCommand();
        AddCommand("List",
                   static_cast<NoModCommand::ModCmdFunc>(&NoListSockets::OnListCommand),
                   "[-n]",
                   "Show the list of active sockets. Pass -n to show IP addresses");
    }

    bool OnLoad(const NoString& sArgs, NoString& sMessage) override
    {
#ifndef MOD_LISTSOCKETS_ALLOW_EVERYONE
        if (!GetUser()->IsAdmin()) {
            sMessage = "You must be admin to use this module";
            return false;
        }
#endif

        return true;
    }

    std::priority_queue<NoSocketSorter> GetSockets()
    {
        NoSocketManager& m = NoApp::Get().GetManager();
        std::priority_queue<NoSocketSorter> ret;

        for (NoBaseSocket* pSock : m.GetSockets()) {
            // These sockets went through SwapSockByAddr. That means
            // another socket took over the connection from this
            // socket. So ignore this to avoid listing the
            // connection twice.
            if (pSock->GetCloseType() == NoBaseSocket::CLT_DEREFERENCE) continue;
            ret.push(pSock);
        }

        return ret;
    }

    bool WebRequiresAdmin() override { return true; }
    NoString GetWebMenuTitle() override { return "List sockets"; }

    bool OnWebRequest(NoWebSock& WebSock, const NoString& sPageName, NoTemplate& Tmpl) override
    {
        if (sPageName == "index") {
            if (NoApp::Get().GetManager().GetSockets().empty()) {
                return false;
            }

            std::priority_queue<NoSocketSorter> socks = GetSockets();

            while (!socks.empty()) {
                NoBaseSocket* pSocket = socks.top().GetSock();
                socks.pop();

                NoTemplate& Row = Tmpl.AddRow("SocketsLoop");
                Row["Name"] = pSocket->GetSockName();
                Row["Created"] = GetCreatedTime(pSocket);
                Row["State"] = GetSocketState(pSocket);
                Row["SSL"] = pSocket->GetSSL() ? "Yes" : "No";
                Row["Local"] = GetLocalHost(pSocket, true);
                Row["Remote"] = GetRemoteHost(pSocket, true);
                Row["In"] = NoUtils::ToByteStr(pSocket->GetBytesRead());
                Row["Out"] = NoUtils::ToByteStr(pSocket->GetBytesWritten());
            }

            return true;
        }

        return false;
    }

    void OnListCommand(const NoString& sLine)
    {
        NoString sArg = sLine.Token(1, true);

        bool bShowHosts = true;
        if (sArg.Equals("-n")) {
            bShowHosts = false;
        }
        ShowSocks(bShowHosts);
    }

    NoString GetSocketState(NoBaseSocket* pSocket)
    {
        if (pSocket->IsListener())
            return "Listener";
        if (pSocket->IsInbound())
            return "Inbound";
        if (pSocket->IsOutbound()) {
            if (pSocket->IsConnected())
                return "Outbound";
            else
                return "Connecting";
        }

        return "UNKNOWN";
    }

    NoString GetCreatedTime(NoBaseSocket* pSocket)
    {
        ulonglong iStartTime = pSocket->GetStartTime();
        time_t iTime = iStartTime / 1000;
        return NoUtils::FormatTime(iTime, "%Y-%m-%d %H:%M:%S", GetUser()->GetTimezone());
    }

    NoString GetLocalHost(NoBaseSocket* pSocket, bool bShowHosts)
    {
        NoString sBindHost;

        if (bShowHosts) {
            sBindHost = pSocket->GetBindHost();
        }

        if (sBindHost.empty()) {
            sBindHost = pSocket->GetLocalIP();
        }

        return sBindHost + " " + NoString(pSocket->GetLocalPort());
    }

    NoString GetRemoteHost(NoBaseSocket* pSocket, bool bShowHosts)
    {
        NoString sHost;
        u_short uPort;

        if (!bShowHosts) {
            sHost = pSocket->GetRemoteIP();
        }

        // While connecting, there might be no ip available
        if (sHost.empty()) {
            sHost = pSocket->GetHostName();
        }

        // While connecting, GetRemotePort() would return 0
        if (pSocket->IsOutbound()) {
            uPort = pSocket->GetPort();
        } else {
            uPort = pSocket->GetRemotePort();
        }

        if (uPort != 0) {
            return sHost + " " + NoString(uPort);
        }

        return sHost;
    }

    void ShowSocks(bool bShowHosts)
    {
        if (NoApp::Get().GetManager().GetSockets().empty()) {
            PutStatus("You have no open sockets.");
            return;
        }

        std::priority_queue<NoSocketSorter> socks = GetSockets();

        NoTable Table;
        Table.AddColumn("Name");
        Table.AddColumn("Created");
        Table.AddColumn("State");
#ifdef HAVE_LIBSSL
        Table.AddColumn("SSL");
#endif
        Table.AddColumn("Local");
        Table.AddColumn("Remote");
        Table.AddColumn("In");
        Table.AddColumn("Out");

        while (!socks.empty()) {
            NoBaseSocket* pSocket = socks.top().GetSock();
            socks.pop();

            Table.AddRow();
            Table.SetCell("Name", pSocket->GetSockName());
            Table.SetCell("Created", GetCreatedTime(pSocket));
            Table.SetCell("State", GetSocketState(pSocket));

#ifdef HAVE_LIBSSL
            Table.SetCell("SSL", pSocket->GetSSL() ? "Yes" : "No");
#endif

            Table.SetCell("Local", GetLocalHost(pSocket, bShowHosts));
            Table.SetCell("Remote", GetRemoteHost(pSocket, bShowHosts));
            Table.SetCell("In", NoUtils::ToByteStr(pSocket->GetBytesRead()));
            Table.SetCell("Out", NoUtils::ToByteStr(pSocket->GetBytesWritten()));
        }

        PutModule(Table);
        return;
    }

    virtual ~NoListSockets() {}
};

template <> void TModInfo<NoListSockets>(NoModInfo& Info) { Info.SetWikiPage("listsockets"); }

USERMODULEDEFS(NoListSockets, "List active sockets")
