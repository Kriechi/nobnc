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

#include "pidfile.h"
#include <nobnc/nofile.h>
#include <nobnc/noutils.h>

PidFile::PidFile(const NoString& filePath) : m_filePath(filePath)
{
}

PidFile::~PidFile()
{
    if (!m_filePath.empty()) {
        NoFile file(m_filePath);
        No::printAction("Deleting pid file [" + file.GetLongName() + "]");
        file.Delete();
    }
}

bool PidFile::write(int pid)
{
    if (!m_filePath.empty()) {
        NoFile file(m_filePath);
        if (file.Open(O_WRONLY | O_TRUNC | O_CREAT)) {
            No::printAction("Writing pid file [" + file.GetLongName() + "]");
            file.Write(NoString(pid) + "\n");
            file.Close();
            return true;
        }
    }
    return false;
}

void PidFile::reset()
{
    m_filePath = "";
}
