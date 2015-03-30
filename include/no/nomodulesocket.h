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

#ifndef NOMODULESOCKET_H
#define NOMODULESOCKET_H

#include <no/noglobal.h>
#include <no/nosocket.h>

/**
 * @class NoSocket
 * @brief Base Csock implementation to be used by modules
 *
 * By all means, this class should be used as a base for sockets originating from modules. It handles removing instances
 *of itself
 * from the module as it unloads, and simplifies use in general.
 * - EnableReadLine is default to true in this class
 * - MaxBuffer for readline is set to 10240, in the event this is reached the socket is closed (@see ReachedMaxBuffer)
 */
class NO_EXPORT NoModuleSocket : public NoSocket
{
public:
    /**
     * @brief ctor
     * @param pModule the module this sock instance is associated to
     */
    NoModuleSocket(NoModule* pModule);
    /**
     * @brief ctor
     * @param pModule the module this sock instance is associated to
     * @param sHostname the hostname being connected to
     * @param uPort the port being connected to
     */
    NoModuleSocket(NoModule* pModule, const NoString& sHostname, ushort uPort);
    virtual ~NoModuleSocket();

    NoModuleSocket(const NoModuleSocket&) = delete;
    NoModuleSocket& operator=(const NoModuleSocket&) = delete;

    using NoSocket::connect;
    using NoSocket::listen;

    //! This defaults to closing the socket, feel free to override
    void onReachedMaxBuffer() override;
    void onSocketError(int iErrno, const NoString& sDescription) override;

    //! This limits the global connections from this IP to defeat DoS attacks, feel free to override. The ACL used is
    // provided by the main interface @see NoApp::AllowConnectionFrom
    bool onConnectionFrom(const NoString& sHost, ushort uPort) override;

    //! Ease of use Connect, assigns to the manager and is subsequently tracked
    bool connect(const NoString& sHostname, ushort uPort, bool bSSL = false, uint uTimeout = 60);
    //! Ease of use Listen, assigned to the manager and is subsequently tracked
    bool listen(ushort uPort, bool bSSL, uint uTimeout = 0);

    NoModule* module() const;

private:
    NoModule* m_module; //!< pointer to the module that this sock instance belongs to
};

#endif // NOMODULESOCKET_H
