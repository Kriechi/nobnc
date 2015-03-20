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

#ifndef NOMODULECOMMAND_H
#define NOMODULECOMMAND_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <no/nomoduleinfo.h>
#include <functional>

class NoTable;

/** A helper class for handling commands in modules. */
class NO_EXPORT NoModuleCommand
{
public:
    /// Type for the callback function that handles the actual command.
    typedef void (NoModule::*ModCmdFunc)(const NoString& sLine);
    typedef std::function<void(const NoString& sLine)> CmdFunc;

    /// Default constructor, needed so that this can be saved in a std::map.
    NoModuleCommand();

    /** Construct a new NoModuleCommand.
     * @param sCmd The name of the command.
     * @param func The command's callback function.
     * @param sArgs Help text describing the arguments to this command.
     * @param sDesc Help text describing what this command does.
     */
    NoModuleCommand(const NoString& sCmd, NoModule* pMod, ModCmdFunc func, const NoString& sArgs, const NoString& sDesc);
    NoModuleCommand(const NoString& sCmd, CmdFunc func, const NoString& sArgs, const NoString& sDesc);

    /** Copy constructor, needed so that this can be saved in a std::map.
     * @param other Object to copy from.
     */
    NoModuleCommand(const NoModuleCommand& other);

    /** Assignment operator, needed so that this can be saved in a std::map.
     * @param other Object to copy from.
     */
    NoModuleCommand& operator=(const NoModuleCommand& other);

    /** Initialize a NoTable so that it can be used with AddHelp().
     * @param Table The instance of NoTable to initialize.
     */
    static void InitHelp(NoTable& Table);

    /** Add this command to the NoTable instance.
     * @param Table Instance of NoTable to which this should be added.
     * @warning The Table should be initialized via InitHelp().
     */
    void AddHelp(NoTable& Table) const;

    const NoString& GetCommand() const;
    CmdFunc GetFunction() const;
    const NoString& GetArgs() const;
    const NoString& GetDescription() const;

    void Call(const NoString& sLine) const;

private:
    NoString m_sCmd;
    CmdFunc m_pFunc;
    NoString m_sArgs;
    NoString m_sDesc;
};

#endif // NOMODULECOMMAND_H
