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
#include "notable.h"

NoModuleCommand::NoModuleCommand() : m_cmd(), m_func(nullptr), m_args(), m_desc()
{
}

NoModuleCommand::NoModuleCommand(const NoString& cmd, NoModule* mod, ModCmdFunc func, const NoString& args, const NoString& desc)
    : m_cmd(cmd), m_func(func), m_args(args), m_desc(desc)
{
}

NoModuleCommand::NoModuleCommand(const NoModuleCommand& other)
    : m_cmd(other.m_cmd), m_func(other.m_func), m_args(other.m_args), m_desc(other.m_desc)
{
}

NoModuleCommand& NoModuleCommand::operator=(const NoModuleCommand& other)
{
    m_cmd = other.m_cmd;
    m_func = other.m_func;
    m_args = other.m_args;
    m_desc = other.m_desc;
    return *this;
}

void NoModuleCommand::initHelp(NoTable& Table)
{
    Table.addColumn("Command");
    Table.addColumn("Arguments");
    Table.addColumn("Description");
}

void NoModuleCommand::addHelp(NoTable& Table) const
{
    Table.addRow();
    Table.setValue("Command", command());
    Table.setValue("Arguments", args());
    Table.setValue("Description", description());
}

void NoModuleCommand::call(NoModule* module, const NoString& line) const
{
    (module->*m_func)(line);
}

NoString NoModuleCommand::description() const
{
    return m_desc;
}

NoString NoModuleCommand::args() const
{
    return m_args;
}

NoModuleCommand::ModCmdFunc NoModuleCommand::function() const
{
    return m_func;
}

NoString NoModuleCommand::command() const
{
    return m_cmd;
}
