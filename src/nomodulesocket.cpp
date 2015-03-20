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

#include "nomodulesocket.h"
#include "nomodule.h"
#include "nonetwork.h"
#include "nouser.h"
#include "noapp.h"
#include "nodebug.h"

NoModuleSocket::NoModuleSocket(NoModule* pModule) : NoSocket(), m_pModule(pModule)
{
    if (m_pModule) m_pModule->AddSocket(this);
    EnableReadLine();
    SetMaxBufferThreshold(10240);
}

NoModuleSocket::NoModuleSocket(NoModule* pModule, const NoString& sHostname, ushort uPort, int iTimeout)
    : NoSocket(sHostname, uPort, iTimeout), m_pModule(pModule)
{
    if (m_pModule) m_pModule->AddSocket(this);
    EnableReadLine();
    SetMaxBufferThreshold(10240);
}

NoModuleSocket::~NoModuleSocket()
{
    NoUser* pUser = nullptr;

    // NoWebSock could cause us to have a nullptr pointer here
    if (m_pModule) {
        pUser = m_pModule->GetUser();
        m_pModule->UnlinkSocket(this);
    }

    if (pUser && m_pModule && (m_pModule->GetType() != NoModInfo::GlobalModule)) {
        pUser->AddBytesWritten(GetBytesWritten());
        pUser->AddBytesRead(GetBytesRead());
    } else {
        NoApp::Get().AddBytesWritten(GetBytesWritten());
        NoApp::Get().AddBytesRead(GetBytesRead());
    }
}

void NoModuleSocket::ReachedMaxBufferImpl()
{
    NO_DEBUG(GetSockName() << " == ReachedMaxBuffer()");
    if (m_pModule) m_pModule->PutModule("Some socket reached its max buffer limit and was closed!");
    Close();
}

void NoModuleSocket::SockErrorImpl(int iErrno, const NoString& sDescription)
{
    NO_DEBUG(GetSockName() << " == SockError(" << sDescription << ", " << strerror(iErrno) << ")");
    if (iErrno == EMFILE) {
        // We have too many open fds, this can cause a busy loop.
        Close();
    }
}

bool NoModuleSocket::ConnectionFromImpl(const NoString& sHost, ushort uPort)
{
    return NoApp::Get().AllowConnectionFrom(sHost);
}

bool NoModuleSocket::Connect(const NoString& sHostname, ushort uPort, bool bSSL, uint uTimeout)
{
    if (!m_pModule) {
        NO_DEBUG("ERROR: NoSocket::Connect called on instance without m_pModule handle!");
        return false;
    }

    NoUser* pUser = m_pModule->GetUser();
    NoString sSockName = "MOD::C::" + m_pModule->GetModName();
    NoString sBindHost;

    if (pUser) {
        sSockName += "::" + pUser->GetUserName();
        sBindHost = pUser->GetBindHost();
        NoNetwork* pNetwork = m_pModule->GetNetwork();
        if (pNetwork) {
            sSockName += "::" + pNetwork->GetName();
            sBindHost = pNetwork->GetBindHost();
        }
    }

    // Don't overwrite the socket name if one is already set
    if (!GetSockName().empty()) {
        sSockName = GetSockName();
    }

    m_pModule->GetManager()->Connect(sHostname, uPort, sSockName, uTimeout, bSSL, sBindHost, this);
    return true;
}

bool NoModuleSocket::Listen(ushort uPort, bool bSSL, uint uTimeout)
{
    if (!m_pModule) {
        NO_DEBUG("ERROR: NoSocket::Listen called on instance without m_pModule handle!");
        return false;
    }

    NoUser* pUser = m_pModule->GetUser();
    NoString sSockName = "MOD::L::" + m_pModule->GetModName();

    if (pUser) {
        sSockName += "::" + pUser->GetUserName();
    }
    // Don't overwrite the socket name if one is already set
    if (!GetSockName().empty()) {
        sSockName = GetSockName();
    }

    return m_pModule->GetManager()->ListenAll(uPort, sSockName, bSSL, SOMAXCONN, this);
}

NoModule* NoModuleSocket::GetModule() const { return m_pModule; }
