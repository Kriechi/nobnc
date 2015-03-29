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

#ifndef NODEBUG_H
#define NODEBUG_H

#include <no/noglobal.h>
#include <no/nostring.h>
#include <sstream>

/** Output a debug info if debugging is enabled.
 *  If ZNC was compiled with <code>--enable-debug</code> or was started with
 *  <code>--debug</code>, the given argument will be sent to stdout.
 *
 *  You can use all the features of C++ streams:
 *  @code
 *  NO_DEBUG("I had " << errors << " errors");
 *  @endcode
 *
 *  @param f The expression you want to display.
 */
#define NO_DEBUG(f)                 \
    do {                         \
        if (NoDebug::isEnabled()) {   \
            NoDebugStream sDebug; \
            sDebug << f;         \
        }                        \
    } while (0)

class NO_EXPORT NoDebug
{
public:
    static bool isEnabled() { return enabled; }
    static void setEnabled(bool b) { enabled = b; }

    static bool isFormatted() { return formatted; }
    static void setFormatted(bool b) { formatted = b; }

private:
    static bool enabled;
    static bool formatted;
};

class NO_EXPORT NoDebugStream : public std::ostringstream
{
public:
    ~NoDebugStream();
};

#endif // NODEBUG_H
