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
#include "nosocketinfo.h"
#include "nomodule.h"
#include "nomodule_p.h"
#include "nonetwork.h"
#include "nouser_p.h"
#include "noapp_p.h"
#include "nodebug.h"

NoModuleSocket::NoModuleSocket(NoModule* module) : NoSocket(), m_module(module)
{
    if (module)
        NoModulePrivate::get(module)->sockets.insert(this);
    enableReadLine();
    setMaxBufferThreshold(10240);
}

NoModuleSocket::NoModuleSocket(NoModule* module, const NoString& hostname, ushort port)
    : NoSocket(hostname, port), m_module(module)
{
    if (module)
        NoModulePrivate::get(module)->sockets.insert(this);
    enableReadLine();
    setMaxBufferThreshold(10240);
}

NoModuleSocket::~NoModuleSocket()
{
    NoUser* user = nullptr;

    // NoWebSocket could cause us to have a nullptr pointer here
    if (m_module) {
        user = m_module->user();
        NoModulePrivate::get(m_module)->sockets.erase(this);
        noApp->manager()->removeSocket(this);
    }

    NoSocketInfo info(this);
    if (user && m_module && m_module->type() != No::GlobalModule) {
        NoUserPrivate::get(user)->addBytesWritten(info.bytesWritten());
        NoUserPrivate::get(user)->addBytesRead(info.bytesRead());
    } else {
        NoAppPrivate::get(noApp)->addBytesWritten(info.bytesWritten());
        NoAppPrivate::get(noApp)->addBytesRead(info.bytesRead());
    }
}

void NoModuleSocket::onReachedMaxBuffer()
{
    NO_DEBUG(name() << " == ReachedMaxBuffer()");
    if (m_module)
        m_module->putModule("Some socket reached its max buffer limit and was closed!");
    close();
}

void NoModuleSocket::onSocketError(int iErrno, const NoString& description)
{
    NO_DEBUG(name() << " == SockError(" << description << ", " << strerror(iErrno) << ")");
    if (iErrno == EMFILE) {
        // We have too many open fds, this can cause a busy loop.
        close();
    }
}

bool NoModuleSocket::onConnectionFrom(const NoString& host, ushort port)
{
    return noApp->allowConnectionFrom(host);
}

bool NoModuleSocket::connect(const NoString& hostname, ushort port, bool ssl)
{
    if (!m_module) {
        NO_DEBUG("ERROR: NoSocket::Connect called on instance without m_pModule handle!");
        return false;
    }

    NoUser* user = m_module->user();
    NoString name = "MOD::C::" + m_module->name();
    NoString bindHost;

    if (user) {
        name += "::" + user->userName();
        bindHost = user->bindHost();
        NoNetwork* network = m_module->network();
        if (network) {
            name += "::" + network->name();
            bindHost = network->bindHost();
        }
    }

    // Don't overwrite the socket name if one is already set
    if (!NoSocket::name().empty()) {
        name = NoSocket::name();
    }

    noApp->manager()->connect(hostname, port, name, ssl, bindHost, this);
    return true;
}

bool NoModuleSocket::listen(ushort port, bool ssl)
{
    if (!m_module) {
        NO_DEBUG("ERROR: NoSocket::Listen called on instance without m_pModule handle!");
        return false;
    }

    NoUser* user = m_module->user();
    NoString name = "MOD::L::" + m_module->name();

    if (user) {
        name += "::" + user->userName();
    }
    // Don't overwrite the socket name if one is already set
    if (!NoSocket::name().empty()) {
        name = NoSocket::name();
    }

    return noApp->manager()->listenHost(port, name, "", ssl, this);
}

NoModule* NoModuleSocket::module() const
{
    return m_module;
}
