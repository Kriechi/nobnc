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
#include <nobnc/noapp.h>
#include <nobnc/noexception_p.h>
#include <nobnc/nodebug.h>
#include <nobnc/nodir.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <iostream>

#if defined(HAVE_LIBSSL) && defined(HAVE_PTHREAD)
#include <nobnc/nomutex_p.h>
#include <openssl/crypto.h>
#include <memory>

static std::vector<std::unique_ptr<NoMutex>> lock_cs;

static void locking_callback(int mode, int type, const char* file, int line)
{
    if (mode & CRYPTO_LOCK) {
        lock_cs[type]->lock();
    } else {
        lock_cs[type]->unlock();
    }
}

static ulong thread_id_callback()
{
    return (ulong)pthread_self();
}

static CRYPTO_dynlock_value* dyn_create_callback(const char* file, int line)
{
    return (CRYPTO_dynlock_value*)new NoMutex;
}

static void dyn_lock_callback(int mode, CRYPTO_dynlock_value* dlock, const char* file, int line)
{
    NoMutex* mtx = (NoMutex*)dlock;

    if (mode & CRYPTO_LOCK) {
        mtx->lock();
    } else {
        mtx->unlock();
    }
}

static void dyn_destroy_callback(CRYPTO_dynlock_value* dlock, const char* file, int line)
{
    NoMutex* mtx = (NoMutex*)dlock;

    delete mtx;
}

static void thread_setup()
{
    lock_cs.resize(CRYPTO_num_locks());

    for (std::unique_ptr<NoMutex>& mtx : lock_cs)
        mtx = std::unique_ptr<NoMutex>(new NoMutex());

    CRYPTO_set_id_callback(&thread_id_callback);
    CRYPTO_set_locking_callback(&locking_callback);

    CRYPTO_set_dynlock_create_callback(&dyn_create_callback);
    CRYPTO_set_dynlock_lock_callback(&dyn_lock_callback);
    CRYPTO_set_dynlock_destroy_callback(&dyn_destroy_callback);
}

#else
#define thread_setup()
#endif

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
#define no_argument 0
#define required_argument 1
#define optional_argument 2

struct option
{
    const char* a;
    int opt;
    int* flag;
    int val;
};

static inline int getopt_long(int argc, char* const argv[], const char* optstring, const struct option*, int*)
{
    return getopt(argc, argv, optstring);
}
#endif

static const struct option g_LongOpts[] = { { "help", no_argument, nullptr, 'h' },
                                            { "version", no_argument, nullptr, 'v' },
                                            { "debug", no_argument, nullptr, 'D' },
                                            { "foreground", no_argument, nullptr, 'f' },
                                            { "no-color", no_argument, nullptr, 'n' },
                                            { "allow-root", no_argument, nullptr, 'r' },
                                            { "makeconf", no_argument, nullptr, 'c' },
                                            { "makepass", no_argument, nullptr, 's' },
                                            { "makepem", no_argument, nullptr, 'p' },
                                            { "datadir", required_argument, nullptr, 'd' },
                                            { nullptr, 0, nullptr, 0 } };

static void GenerateHelp(const char* appname)
{
    No::printMessage("USAGE: " + NoString(appname) + " [options]");
    No::printMessage("Options are:");
    No::printMessage("\t-h, --help         List available command line options (this page)");
    No::printMessage("\t-v, --version      Output version information and exit");
    No::printMessage("\t-f, --foreground   Don't fork into the background");
    No::printMessage("\t-D, --debug        Output debugging information (Implies -f)");
    No::printMessage("\t-n, --no-color     Don't use escape sequences in the output");
    No::printMessage("\t-r, --allow-root   Don't complain if NoBNC is run as root");
    No::printMessage("\t-c, --makeconf     Interactively create a new config");
    No::printMessage("\t-s, --makepass     Generates a password for use in config");
#ifdef HAVE_LIBSSL
    No::printMessage("\t-p, --makepem      Generates a pemfile for use with SSL");
#endif // HAVE_LIBSSL
    No::printMessage("\t-d, --datadir      Set a different NoBNC repository (default is ~/.nobnc)");
}

extern void no_cleanup();

static void die(int sig)
{
    signal(SIGPIPE, SIG_DFL);

    No::printMessage("Exiting on SIG [" + NoString(sig) + "]");

    no_cleanup();

    exit(sig);
}

static void signalHandler(int sig)
{
    switch (sig) {
    case SIGHUP:
        No::printMessage("Caught SIGHUP");
        noApp->setConfigState(NoApp::ConfigNeedRehash);
        break;
    case SIGUSR1:
        No::printMessage("Caught SIGUSR1");
        noApp->setConfigState(NoApp::ConfigNeedVerboseWrite);
        break;
    default:
        No::printMessage("WTF? Signal handler called for a signal it doesn't know?");
    }
}

static bool isRoot()
{
    // User root? If one of these were root, we could switch the others to root, too
    return (geteuid() == 0 || getuid() == 0);
}

static void seedPRNG()
{
    struct timeval tv;
    uint seed;

    // Try to find a seed which can't be as easily guessed as only time()

    if (gettimeofday(&tv, nullptr) == 0) {
        seed = (uint)tv.tv_sec;

        // This is in [0:1e6], which means that roughly 20 bits are
        // actually used, let's try to shuffle the high bits.
        seed ^= uint32_t((tv.tv_usec << 10) | tv.tv_usec);
    } else
        seed = (uint)time(nullptr);

    seed ^= rand();
    seed ^= getpid();

    srand(seed);
}

int main(int argc, char** argv)
{
    NoString config;
    NoString dataDir = "";

    thread_setup();

    seedPRNG();
    NoDebug::setFormatted(isatty(1));

    int iArg, iOptIndex = -1;
    bool bMakeConf = false;
    bool bMakePass = false;
    bool allowRoot = false;
    bool bForeground = false;
#ifdef HAVE_LIBSSL
    bool bMakePem = false;
#endif
    NoApp app;

    while ((iArg = getopt_long(argc, argv, "hvnrcspd:Df", g_LongOpts, &iOptIndex)) != -1) {
        switch (iArg) {
        case 'h':
            GenerateHelp(argv[0]);
            return 0;
        case 'v':
            std::cout << NoApp::tag() << std::endl;
            std::cout << NoApp::compileOptionsString() << std::endl;
            return 0;
        case 'n':
            NoDebug::setFormatted(false);
            break;
        case 'r':
            allowRoot = true;
            break;
        case 'c':
            bMakeConf = true;
            break;
        case 's':
            bMakePass = true;
            break;
        case 'p':
#ifdef HAVE_LIBSSL
            bMakePem = true;
            break;
#else
            No::PrintError("NoBNC is compiled without SSL support.");
            return 1;
#endif // HAVE_LIBSSL
        case 'd':
            dataDir = NoString(optarg);
            break;
        case 'f':
            bForeground = true;
            break;
        case 'D':
            bForeground = true;
            NoDebug::setEnabled(true);
            break;
        case '?':
        default:
            GenerateHelp(argv[0]);
            return 1;
        }
    }

    if (optind < argc) {
        No::printError("Specifying a config file as an argument isn't supported anymore.");
        No::printError("Use --datadir instead.");
        return 1;
    }

    app.initDirs((argc ? argv[0] : ""), dataDir);

#ifdef HAVE_LIBSSL
    if (bMakePem) {
        app.writePemFile();
        return 0;
    }
#endif // HAVE_LIBSSL

    if (bMakePass) {
        NoString salt;
        No::printMessage("Type your new password.");
        NoString sHash = No::getSaltedHashPass(salt);
        No::printMessage("Kill NoBNC process, if it's running.");
        No::printMessage("Then replace password in the <User> section of your config with this:");
        // Not PrintMessage(), to remove [**] from the beginning, to ease copypasting
        std::cout << "<Pass password>" << std::endl;
        std::cout << "\tHash = " << sHash << std::endl;
        std::cout << "\tSalt = " << salt << std::endl;
        std::cout << "</Pass>" << std::endl;
        No::printMessage("After that start NoBNC again, and you should be able to login with the new password.");
        return 0;
    }

    {
        No::printAction("Checking for list of available modules");
        std::set<NoModuleInfo> ssGlobalMods = app.loader()->availableModules(No::GlobalModule);
        std::set<NoModuleInfo> ssUserMods = app.loader()->availableModules(No::UserModule);
        std::set<NoModuleInfo> ssNetworkMods = app.loader()->availableModules(No::NetworkModule);
        if (ssGlobalMods.empty() && ssUserMods.empty() && ssNetworkMods.empty()) {
            No::printStatus(false, "");
            No::printError("No modules found. Perhaps you didn't install NoBNC properly?");
            No::printError("Read http://wiki.znc.in/Installation for instructions.");
            if (!No::getBoolInput("Do you really want to run NoBNC without any modules?", false)) {
                return 1;
            }
        }
        No::printStatus(true, "");
    }

    if (isRoot()) {
        No::printError("You are running NoBNC as root! Don't do that! There are not many valid");
        No::printError("reasons for this and it can, in theory, cause great damage!");
        if (!allowRoot) {
            return 1;
        }
        No::printError("You have been warned.");
        No::printError("Hit CTRL+C now if you don't want to run NoBNC as root.");
        No::printError("NoBNC will start in 30 seconds.");
        sleep(30);
    }

    if (bMakeConf) {
        if (!app.writeNewConfig(config)) {
            return 0;
        }
        /* Fall through to normal bootup */
    }

    NoString configError;
    if (!app.parseConfig(config, configError)) {
        No::printError("Unrecoverable config error.");
        return 1;
    }

    if (!app.onBoot()) {
        No::printError("Exiting due to module boot errors.");
        return 1;
    }

    // TODO: NoDir(app.appPath()).filePath("nobnc.pid")
    PidFile pidFile("");

    if (bForeground) {
        int pid = getpid();
        No::printMessage("Staying open for debugging [pid: " + NoString(pid) + "]");

        pidFile.write(pid);
        No::printMessage(NoApp::tag());
    } else {
        No::printAction("Forking into the background");

        int pid = fork();

        if (pid == -1) {
            No::printStatus(false, strerror(errno));
            return 1;
        }

        if (pid > 0) {
            // We are the parent. We are done and will go to bed.
            No::printStatus(true, "[pid: " + NoString(pid) + "]");

            pidFile.write(pid);
            No::printMessage(NoApp::tag());
            pidFile.reset();
            return 0;
        }

        /* fcntl() locks don't necessarily propagate to forked()
         *   children.  Reacquire the lock here.  Use the blocking
         *   call to avoid race condition with parent exiting.
         */
        if (!app.waitForChildLock()) {
            No::printError("Child was unable to obtain lock on config file.");
            return 1;
        }

        // Redirect std in/out/err to /dev/null
        close(0);
        open("/dev/null", O_RDONLY);
        close(1);
        open("/dev/null", O_WRONLY);
        close(2);
        open("/dev/null", O_WRONLY);

        NoDebug::setFormatted(false);

        // We are the child. There is no way we can be a process group
        // leader, thus setsid() must succeed.
        setsid();
        // Now we are in our own process group and session (no
        // controlling terminal). We are independent!
    }

    struct sigaction sa;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, (struct sigaction*)nullptr);

    sa.sa_handler = signalHandler;
    sigaction(SIGHUP, &sa, (struct sigaction*)nullptr);
    sigaction(SIGUSR1, &sa, (struct sigaction*)nullptr);

    // Once this signal is caught, the signal handler is reset
    // to SIG_DFL. This avoids endless loop with signals.
    sa.sa_flags = SA_RESETHAND;
    sa.sa_handler = die;
    sigaction(SIGINT, &sa, (struct sigaction*)nullptr);
    sigaction(SIGQUIT, &sa, (struct sigaction*)nullptr);
    sigaction(SIGTERM, &sa, (struct sigaction*)nullptr);

    int iRet = 0;

    try {
        iRet = app.exec();
    } catch (const NoException& e) {
        switch (e.type()) {
        case NoException::Shutdown:
            iRet = 0;
            break;
        case NoException::Restart: {
            // strdup() because GCC is stupid
            char* args[] = { strdup(argv[0]), strdup("--datadir"), strdup(app.appPath().c_str()), nullptr,
                             nullptr,         nullptr,             nullptr };
            int pos = 3;
            if (NoDebug::isEnabled())
                args[pos++] = strdup("--debug");
            else if (bForeground)
                args[pos++] = strdup("--foreground");
            if (!NoDebug::isFormatted())
                args[pos++] = strdup("--no-color");
            if (allowRoot)
                args[pos++] = strdup("--allow-root");
            // The above code adds 3 entries to args tops
            // which means the array should be big enough

            execvp(args[0], args);
            No::printError("Unable to restart NoBNC [" + NoString(strerror(errno)) + "]");
        } /* Fall through */
        default:
            iRet = 1;
        }
    }

    return iRet;
}
