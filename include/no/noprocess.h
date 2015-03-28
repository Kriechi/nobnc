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

#ifndef NOPROCESS_H
#define NOPROCESS_H

#include <no/noglobal.h>
#include <no/nosocket.h>
#include <memory>

class NoProcessPrivate;

//! @author imaginos@imaginos.net
class NO_EXPORT NoProcess : public NoSocket
{
public:
    NoProcess();
    ~NoProcess();

    int processId() const;
    NoString command() const;

    bool execute(const NoString& command);
    void kill();

private:
    NoProcess(const NoProcess&) = delete;
    NoProcess& operator=(const NoProcess&) = delete;

    std::unique_ptr<NoProcessPrivate> d;
};

#endif // NOPROCESS_H
