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

#include "noprocess.h"
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

static int no_popen(int& rfd, int& wfd, const NoString& command);
static void no_close(int pid, int rfd, int wfd);

class NoProcessPrivate
{
public:
    int pid = -1;
    NoString command;
};

NoProcess::NoProcess() : NoSocket(0), d(new NoProcessPrivate)
{
}

NoProcess::~NoProcess()
{
    no_close(d->pid, GetRSock(), GetWSock());
    SetRSock(-1);
    SetWSock(-1);
}

int NoProcess::processId() const
{
    return d->pid;
}

NoString NoProcess::command() const
{
    return d->command;
}

bool NoProcess::execute(const NoString& command)
{
    int rfd, wfd;
    d->command = command;
    d->pid = no_popen(rfd, wfd, command);
    if (d->pid != -1)
        ConnectFD(rfd, wfd, "0.0.0.0:0");
    return d->pid != -1;
}

void NoProcess::kill()
{
    ::kill(d->pid, SIGKILL);
    d->command = "";
    d->pid = -1;
    Close();
}

int no_popen(int& rfd, int& wfd, const NoString& command)
{
    int rpipes[2] = { -1, -1 };
    int wpipes[2] = { -1, -1 };
    rfd = -1;
    wfd = -1;

    if (pipe(rpipes) < 0)
        return -1;

    if (pipe(wpipes) < 0) {
        close(rpipes[0]);
        close(rpipes[1]);
        return -1;
    }

    int pid = fork();

    if (pid == -1) {
        close(rpipes[0]);
        close(rpipes[1]);
        close(wpipes[0]);
        close(wpipes[1]);
        return -1;
    }

    if (pid == 0) {
        close(wpipes[1]);
        close(rpipes[0]);
        dup2(wpipes[0], 0);
        dup2(rpipes[1], 1);
        dup2(rpipes[1], 2);
        close(wpipes[0]);
        close(rpipes[1]);
        const char* pArgv[] = { "sh", "-c", command.c_str(), nullptr };
        execvp("sh", (char* const*)pArgv);
        // if execvp returns, there was an error
        perror("execvp");
        exit(1);
    }

    close(wpipes[0]);
    close(rpipes[1]);

    wfd = wpipes[1];
    rfd = rpipes[0];

    return pid;
}

void no_close(int pid, int rfd, int wfd)
{
    close(rfd);
    close(wfd);
    time_t now = time(nullptr);
    while (waitpid(pid, nullptr, WNOHANG) == 0) {
        if (time(nullptr) - now > 5)
            break; // giveup
        usleep(100);
    }
    return;
}
