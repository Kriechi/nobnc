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

#include "nomodulesocket.h"
#include "nomodule.h"
#include "nomodule_p.h"
#include "nonetwork.h"
#include "nouser.h"
#include "noapp.h"
#include "nodebug.h"

NoModuleSocket::NoModuleSocket(NoModule* pModule) : NoSocket(), m_module(pModule)
{
    if (pModule)
        NoModulePrivate::get(pModule)->addSocket(this);
    enableReadLine();
    setMaxBufferThreshold(10240);
}

NoModuleSocket::NoModuleSocket(NoModule* pModule, const NoString& sHostname, ushort port)
    : NoSocket(sHostname, port), m_module(pModule)
{
    if (pModule)
        NoModulePrivate::get(pModule)->addSocket(this);
    enableReadLine();
    setMaxBufferThreshold(10240);
}

NoModuleSocket::~NoModuleSocket()
{
    NoUser* user = nullptr;

    // NoWebSocket could cause us to have a nullptr pointer here
    if (m_module) {
        user = m_module->user();
        NoModulePrivate::get(m_module)->removeSocket(this);
        m_module->manager()->removeSocket(this);
    }

    if (user && m_module && m_module->type() != No::GlobalModule) {
        user->addBytesWritten(bytesWritten());
        user->addBytesRead(bytesRead());
    } else {
        noApp->addBytesWritten(bytesWritten());
        noApp->addBytesRead(bytesRead());
    }
}

void NoModuleSocket::onReachedMaxBuffer()
{
    NO_DEBUG(name() << " == ReachedMaxBuffer()");
    if (m_module)
        m_module->putModule("Some socket reached its max buffer limit and was closed!");
    close();
}

void NoModuleSocket::onSocketError(int iErrno, const NoString& sDescription)
{
    NO_DEBUG(name() << " == SockError(" << sDescription << ", " << strerror(iErrno) << ")");
    if (iErrno == EMFILE) {
        // We have too many open fds, this can cause a busy loop.
        close();
    }
}

bool NoModuleSocket::onConnectionFrom(const NoString& host, ushort port)
{
    return noApp->allowConnectionFrom(host);
}

bool NoModuleSocket::connect(const NoString& sHostname, ushort port, bool ssl, uint uTimeout)
{
    if (!m_module) {
        NO_DEBUG("ERROR: NoSocket::Connect called on instance without m_pModule handle!");
        return false;
    }

    NoUser* user = m_module->user();
    NoString sSockName = "MOD::C::" + m_module->moduleName();
    NoString sBindHost;

    if (user) {
        sSockName += "::" + user->userName();
        sBindHost = user->bindHost();
        NoNetwork* network = m_module->network();
        if (network) {
            sSockName += "::" + network->name();
            sBindHost = network->bindHost();
        }
    }

    // Don't overwrite the socket name if one is already set
    if (!name().empty()) {
        sSockName = name();
    }

    m_module->manager()->connect(sHostname, port, sSockName, uTimeout, ssl, sBindHost, this);
    return true;
}

bool NoModuleSocket::listen(ushort port, bool ssl, uint uTimeout)
{
    if (!m_module) {
        NO_DEBUG("ERROR: NoSocket::Listen called on instance without m_pModule handle!");
        return false;
    }

    NoUser* user = m_module->user();
    NoString sSockName = "MOD::L::" + m_module->moduleName();

    if (user) {
        sSockName += "::" + user->userName();
    }
    // Don't overwrite the socket name if one is already set
    if (!name().empty()) {
        sSockName = name();
    }

    return m_module->manager()->listenAll(port, sSockName, ssl, SOMAXCONN, this);
}

NoModule* NoModuleSocket::module() const
{
    return m_module;
}
