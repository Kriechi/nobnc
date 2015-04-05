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

#ifndef NOMODULECOMMAND_H
#define NOMODULECOMMAND_H

#include <nobnc/noglobal.h>
#include <nobnc/nostring.h>
#include <nobnc/nomoduleinfo.h>
#include <memory>

class NoModuleCommandPrivate;

class NO_EXPORT NoModuleCommand
{
public:
    typedef void (NoModule::*Function)(const NoString& line);

    NoModuleCommand(const NoString& cmd = "", Function func = nullptr);
    NoModuleCommand(const NoModuleCommand& other);
    NoModuleCommand& operator=(const NoModuleCommand& other);
    ~NoModuleCommand();

    NoString command() const;
    Function function() const;

    NoString args() const;
    void setArgs(const NoString& args);

    NoString description() const;
    void setDescription(const NoString& description);

private:
    friend class NoModuleCommandPrivate;
    std::shared_ptr<NoModuleCommandPrivate> d;
};

#endif // NOMODULECOMMAND_H
