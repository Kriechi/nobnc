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

#ifndef NOMESSAGE_P_H
#define NOMESSAGE_P_H

#include "nomessage.h"

class NoMessagePrivate
{
public:
    static NoMessagePrivate* get(const NoMessage& msg) { return msg.d.get(); }

    void updateTime();

    NoString format;
    NoString text;
    timeval ts;
};

#endif // NOMESSAGE_P_H
