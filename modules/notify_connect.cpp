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
#include <no/noapp.h>
#include <no/nouser.h>
#include <no/noclient.h>
#include <no/nosocket.h>

class NoNotifyConnectMod : public NoModule
{
public:
    MODCONSTRUCTOR(NoNotifyConnectMod)
    {
    }

    void onClientLogin() override
    {
        SendAdmins(user()->userName() + " attached (from " + client()->socket()->remoteAddress() + ")");
    }

    void onClientDisconnect() override
    {
        SendAdmins(user()->userName() + " detached (from " + client()->socket()->remoteAddress() + ")");
    }

private:
    void SendAdmins(const NoString& msg)
    {
        noApp->broadcast(msg, true, nullptr, client());
    }
};

template <>
void no_moduleInfo<NoNotifyConnectMod>(NoModuleInfo& Info)
{
    Info.setWikiPage("notify_connect");
}

GLOBALMODULEDEFS(NoNotifyConnectMod, "Notifies all admin users when a client connects or disconnects.")
