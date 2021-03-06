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

#ifndef NODEFINES_H
#define NODEFINES_H

#include <nobnc/noglobal.h>
#include <nobnc/nodebug.h>
#include <nobnc/nostring.h>

// The only reason this header exists is Csocket

#define CS_STRING NoString
#define _NO_CSOCKET_NS

#ifndef NDEBUG
#define __DEBUG__
#endif

#define CS_DEBUG(f) NO_DEBUG(__FILE__ << ":" << __LINE__ << " " << f)
#define PERROR(f) NO_DEBUG(__FILE__ << ":" << __LINE__ << " " << f << ": " << strerror(GetSockError()))

#endif // NODEFINES_H
