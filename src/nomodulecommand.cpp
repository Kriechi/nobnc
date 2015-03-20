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

#include "nomodulecommand.h"
#include "notable.h"

NoModuleCommand::NoModuleCommand() : m_sCmd(), m_pFunc(nullptr), m_sArgs(), m_sDesc() {}

NoModuleCommand::NoModuleCommand(const NoString& sCmd, NoModule* pMod, ModCmdFunc func, const NoString& sArgs, const NoString& sDesc)
    : m_sCmd(sCmd), m_pFunc([pMod, func](const NoString& sLine) { (pMod->*func)(sLine); }), m_sArgs(sArgs), m_sDesc(sDesc)
{
}

NoModuleCommand::NoModuleCommand(const NoString& sCmd, CmdFunc func, const NoString& sArgs, const NoString& sDesc)
    : m_sCmd(sCmd), m_pFunc(std::move(func)), m_sArgs(sArgs), m_sDesc(sDesc)
{
}

NoModuleCommand::NoModuleCommand(const NoModuleCommand& other)
    : m_sCmd(other.m_sCmd), m_pFunc(other.m_pFunc), m_sArgs(other.m_sArgs), m_sDesc(other.m_sDesc)
{
}

NoModuleCommand& NoModuleCommand::operator=(const NoModuleCommand& other)
{
    m_sCmd = other.m_sCmd;
    m_pFunc = other.m_pFunc;
    m_sArgs = other.m_sArgs;
    m_sDesc = other.m_sDesc;
    return *this;
}

void NoModuleCommand::InitHelp(NoTable& Table)
{
    Table.AddColumn("Command");
    Table.AddColumn("Arguments");
    Table.AddColumn("Description");
}

void NoModuleCommand::AddHelp(NoTable& Table) const
{
    Table.AddRow();
    Table.SetCell("Command", GetCommand());
    Table.SetCell("Arguments", GetArgs());
    Table.SetCell("Description", GetDescription());
}

void NoModuleCommand::Call(const NoString& sLine) const { m_pFunc(sLine); }

const NoString& NoModuleCommand::GetDescription() const { return m_sDesc; }

const NoString& NoModuleCommand::GetArgs() const { return m_sArgs; }

NoModuleCommand::CmdFunc NoModuleCommand::GetFunction() const { return m_pFunc; }

const NoString& NoModuleCommand::GetCommand() const { return m_sCmd; }
