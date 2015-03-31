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
    typedef void (NoModule::*ModCmdFunc)(const NoString& line);
    typedef std::function<void(const NoString& line)> CmdFunc;

    /// Default constructor, needed so that this can be saved in a std::map.
    NoModuleCommand();

    /** Construct a new NoModuleCommand.
     * @param cmd The name of the command.
     * @param func The command's callback function.
     * @param args Help text describing the arguments to this command.
     * @param desc Help text describing what this command does.
     */
    NoModuleCommand(const NoString& cmd, NoModule* mod, ModCmdFunc func, const NoString& args, const NoString& desc);
    NoModuleCommand(const NoString& cmd, CmdFunc func, const NoString& args, const NoString& desc);

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
    static void initHelp(NoTable& Table);

    /** Add this command to the NoTable instance.
     * @param Table Instance of NoTable to which this should be added.
     * @warning The Table should be initialized via InitHelp().
     */
    void addHelp(NoTable& Table) const;

    NoString command() const;
    CmdFunc function() const;
    NoString args() const;
    NoString description() const;

    void call(const NoString& line) const;

private:
    NoString m_cmd;
    CmdFunc m_func;
    NoString m_args;
    NoString m_desc;
};

#endif // NOMODULECOMMAND_H
