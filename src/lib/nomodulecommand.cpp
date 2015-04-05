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

#include "nomodulecommand.h"

class NoModuleCommandPrivate
{
public:
    NoString command;
    NoString args;
    NoString description;
    NoModuleCommand::Function function;
};

NoModuleCommand::NoModuleCommand(const NoString& command, Function function) : d(new NoModuleCommandPrivate)
{
    d->command = command;
    d->function = function;
}

NoModuleCommand::NoModuleCommand(const NoModuleCommand& other) : d(new NoModuleCommandPrivate)
{
    d->command = other.command();
    d->function = other.function();
    d->args = other.args();
    d->description = other.description();
}

NoModuleCommand& NoModuleCommand::operator=(const NoModuleCommand& other)
{
    if (this != &other) {
        d->command = other.command();
        d->function = other.function();
        d->args = other.args();
        d->description = other.description();
    }
    return *this;
}

NoModuleCommand::~NoModuleCommand()
{
}

NoString NoModuleCommand::command() const
{
    return d->command;
}

NoModuleCommand::Function NoModuleCommand::function() const
{
    return d->function;
}

NoString NoModuleCommand::args() const
{
    return d->args;
}

void NoModuleCommand::setArgs(const NoString& args)
{
    d->args = args;
}

NoString NoModuleCommand::description() const
{
    return d->description;
}

void NoModuleCommand::setDescription(const NoString& description)
{
    d->description = description;
}
