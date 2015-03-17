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

#include "noexecsock.h"
#include <sys/wait.h>
#include <unistd.h>

NoExecSock::NoExecSock() : NoBaseSocket(0), m_iPid(-1)
{
}

NoExecSock::~NoExecSock()
{
    close2(m_iPid, GetRSock(), GetWSock());
    SetRSock(-1);
    SetWSock(-1);
}

int NoExecSock::Execute(const NoString& sExec)
{
    int iReadFD, iWriteFD;
    m_iPid = popen2(iReadFD, iWriteFD, sExec);
    if (m_iPid != -1) {
        ConnectFD(iReadFD, iWriteFD, "0.0.0.0:0");
    }
    return (m_iPid);
}
void NoExecSock::Kill(int iSignal)
{
    kill(m_iPid, iSignal);
    Close();
}

int NoExecSock::popen2(int& iReadFD, int& iWriteFD, const NoString& sCommand)
{
    int rpipes[2] = { -1, -1 };
    int wpipes[2] = { -1, -1 };
    iReadFD = -1;
    iWriteFD = -1;

    if (pipe(rpipes) < 0) return -1;

    if (pipe(wpipes) < 0) {
        close(rpipes[0]);
        close(rpipes[1]);
        return -1;
    }

    int iPid = fork();

    if (iPid == -1) {
        close(rpipes[0]);
        close(rpipes[1]);
        close(wpipes[0]);
        close(wpipes[1]);
        return -1;
    }

    if (iPid == 0) {
        close(wpipes[1]);
        close(rpipes[0]);
        dup2(wpipes[0], 0);
        dup2(rpipes[1], 1);
        dup2(rpipes[1], 2);
        close(wpipes[0]);
        close(rpipes[1]);
        const char* pArgv[] = { "sh", "-c", sCommand.c_str(), nullptr };
        execvp("sh", (char* const*)pArgv);
        // if execvp returns, there was an error
        perror("execvp");
        exit(1);
    }

    close(wpipes[0]);
    close(rpipes[1]);

    iWriteFD = wpipes[1];
    iReadFD = rpipes[0];

    return iPid;
}

void NoExecSock::close2(int iPid, int iReadFD, int iWriteFD)
{
    close(iReadFD);
    close(iWriteFD);
    time_t iNow = time(nullptr);
    while (waitpid(iPid, nullptr, WNOHANG) == 0) {
        if ((time(nullptr) - iNow) > 5) break; // giveup
        usleep(100);
    }
    return;
}
