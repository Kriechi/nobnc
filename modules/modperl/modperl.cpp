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

#include <znc/nochannel.h>
#include <znc/nofile.h>
#include <znc/nostring.h>
#include <znc/noircsock.h>
#include <znc/nomodules.h>
#include <znc/nonick.h>
#include <znc/nouser.h>
#include <znc/noznc.h>

#include "module.h"
#include "swigperlrun.h"
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#if defined(__APPLE__) && defined(__MACH__)
#include <crt_externs.h> // for _NSGetEnviron
#endif

#include "pstring.h"

using std::set;
using std::vector;

// Allows perl to load .so files when needed by .pm
// For example, it needs to load ZNC.so
extern "C" {
void boot_DynaLoader(pTHX_ CV* cv);
static void xs_init(pTHX) { newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, __FILE__); }
}

class CModPerl : public NoModule
{
    PerlInterpreter* m_pPerl;

public:
    MODCONSTRUCTOR(CModPerl) { m_pPerl = nullptr; }

#define PSTART   \
    dSP;         \
    I32 ax;      \
    int ret = 0; \
    ENTER;       \
    SAVETMPS;    \
    PUSHMARK(SP)
#define PCALL(name)                        \
    PUTBACK;                               \
    ret = call_pv(name, G_EVAL | G_ARRAY); \
    SPAGAIN;                               \
    SP -= ret;                             \
    ax = (SP - PL_stack_base) + 1
#define PEND  \
    ax += 0;  \
    PUTBACK;  \
    FREETMPS; \
    LEAVE
#define PUSH_STR(s) XPUSHs(PString(s).GetSV())
#define PUSH_PTR(type, p) XPUSHs(SWIG_NewInstanceObj(const_cast<type>(p), SWIG_TypeQuery(#type), SWIG_SHADOW))

    bool OnLoad(const NoString& sArgsi, NoString& sMessage) override
    {
        NoString sModPath, sTmp;
        if (!NoModules::FindModPath("modperl/startup.pl", sModPath, sTmp)) {
            sMessage = "startup.pl not found.";
            return false;
        }
        sTmp = NoDir::ChangeDir(sModPath, "..");
        int argc = 6;
        char* pArgv[] = { "",                              "-T",                                "-w",   "-I",
                          const_cast<char*>(sTmp.c_str()), const_cast<char*>(sModPath.c_str()), nullptr };
        char** argv = pArgv;
        char*** const pEnviron =
#if defined(__APPLE__) && defined(__MACH__)
        _NSGetEnviron();
#else
        &environ;
#endif
        PERL_SYS_INIT3(&argc, &argv, pEnviron);
        m_pPerl = perl_alloc();
        perl_construct(m_pPerl);
        if (perl_parse(m_pPerl, xs_init, argc, argv, *pEnviron)) {
            sMessage = "Can't initialize perl. ";
            if (SvTRUE(ERRSV)) {
                sMessage += PString(ERRSV);
            }
            perl_free(m_pPerl);
            PERL_SYS_TERM();
            m_pPerl = nullptr;
            DEBUG(__PRETTY_FUNCTION__ << " can't init perl");
            return false;
        }
        PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
        PSTART;
        PCALL("ZNC::Core::Init");
        PEND;
        return true;
    }

    virtual EModRet
    OnModuleLoading(const NoString& sModName, const NoString& sArgs, NoModInfo::EModuleType eType, bool& bSuccess, NoString& sRetMsg) override
    {
        EModRet result = HALT;
        PSTART;
        PUSH_STR(sModName);
        PUSH_STR(sArgs);
        mXPUSHi(eType);
        PUSH_PTR(NoUser*, GetUser());
        PUSH_PTR(NoNetwork*, GetNetwork());
        PCALL("ZNC::Core::LoadModule");

        if (SvTRUE(ERRSV)) {
            sRetMsg = PString(ERRSV);
            bSuccess = false;
            result = HALT;
            DEBUG("Perl ZNC::Core::LoadModule died: " << sRetMsg);
        } else if (ret < 1 || 2 < ret) {
            sRetMsg = "Error: Perl ZNC::Core::LoadModule returned " + NoString(ret) + " values.";
            bSuccess = false;
            result = HALT;
        } else {
            ELoadPerlMod eLPM = static_cast<ELoadPerlMod>(SvUV(ST(0)));
            if (Perl_NotFound == eLPM) {
                result = CONTINUE; // Not a Perl module
            } else {
                sRetMsg = PString(ST(1));
                result = HALT;
                bSuccess = eLPM == Perl_Loaded;
            }
        }

        PEND;
        return result;
    }

    EModRet OnModuleUnloading(NoModule* pModule, bool& bSuccess, NoString& sRetMsg) override
    {
        CPerlModule* pMod = AsPerlModule(pModule);
        if (pMod) {
            EModRet result = HALT;
            NoString sModName = pMod->GetModName();
            PSTART;
            XPUSHs(pMod->GetPerlObj());
            PCALL("ZNC::Core::UnloadModule");
            if (SvTRUE(ERRSV)) {
                bSuccess = false;
                sRetMsg = PString(ERRSV);
            } else if (ret < 1 || 2 < ret) {
                sRetMsg = "Error: Perl ZNC::Core::UnloadModule returned " + NoString(ret) + " values.";
                bSuccess = false;
                result = HALT;
            } else {
                int bUnloaded = SvUV(ST(0));
                if (bUnloaded) {
                    bSuccess = true;
                    sRetMsg = "Module [" + sModName + "] unloaded";
                    result = HALT;
                } else {
                    result =
                    CONTINUE; // module wasn't loaded by modperl. Perhaps a module-provider written in perl did that.
                }
            }
            PEND;
            DEBUG(__PRETTY_FUNCTION__ << " " << sRetMsg);
            return result;
        }
        return CONTINUE;
    }

    virtual EModRet OnGetModInfo(NoModInfo& ModInfo, const NoString& sModule, bool& bSuccess, NoString& sRetMsg) override
    {
        PSTART;
        PUSH_STR(sModule);
        PUSH_PTR(NoModInfo*, &ModInfo);
        PCALL("ZNC::Core::GetModInfo");
        EModRet result = CONTINUE;
        if (SvTRUE(ERRSV)) {
            bSuccess = false;
            sRetMsg = PString(ERRSV);
            DEBUG("Perl ZNC::Core::GetModInfo died: " << sRetMsg);
        } else if (0 < ret) {
            switch (static_cast<ELoadPerlMod>(SvUV(ST(0)))) {
            case Perl_NotFound:
                result = CONTINUE;
                break;
            case Perl_Loaded:
                result = HALT;
                if (1 == ret) {
                    bSuccess = true;
                } else {
                    bSuccess = false;
                    sRetMsg = "Something weird happened";
                }
                break;
            case Perl_LoadError:
                result = HALT;
                bSuccess = false;
                if (2 == ret) {
                    sRetMsg = PString(ST(1));
                } else {
                    sRetMsg = "Something weird happened";
                }
            }
        } else {
            result = HALT;
            bSuccess = false;
            sRetMsg = "Something weird happened";
        }
        PEND;
        return result;
    }

    void OnGetAvailableMods(set<NoModInfo>& ssMods, NoModInfo::EModuleType eType) override
    {

        unsigned int a = 0;
        NoDir Dir;

        NoModules::ModDirList dirs = NoModules::GetModDirs();

        while (!dirs.empty()) {
            Dir.FillByWildcard(dirs.front().first, "*.pm");
            dirs.pop();

            for (a = 0; a < Dir.size(); a++) {
                NoFile& File = *Dir[a];
                NoString sName = File.GetShortName();
                NoString sPath = File.GetLongName();
                NoModInfo ModInfo;
                sName.RightChomp(3);
                PSTART;
                PUSH_STR(sPath);
                PUSH_STR(sName);
                PUSH_PTR(NoModInfo*, &ModInfo);
                PCALL("ZNC::Core::ModInfoByPath");
                if (SvTRUE(ERRSV)) {
                    DEBUG(__PRETTY_FUNCTION__ << ": " << sPath << ": " << PString(ERRSV));
                } else if (ModInfo.SupportsType(eType)) {
                    ssMods.insert(ModInfo);
                }
                PEND;
            }
        }
    }

    virtual ~CModPerl()
    {
        if (m_pPerl) {
            PSTART;
            PCALL("ZNC::Core::UnloadAll");
            PEND;
            perl_destruct(m_pPerl);
            perl_free(m_pPerl);
            PERL_SYS_TERM();
        }
    }
};

#include "functions.cpp"

VWebSubPages& CPerlModule::GetSubPages()
{
    VWebSubPages* result = _GetSubPages();
    if (!result) {
        return NoModule::GetSubPages();
    }
    return *result;
}

void CPerlTimer::RunJob()
{
    CPerlModule* pMod = AsPerlModule(GetModule());
    if (pMod) {
        PSTART;
        XPUSHs(GetPerlObj());
        PCALL("ZNC::Core::CallTimer");
        PEND;
    }
}

CPerlTimer::~CPerlTimer()
{
    CPerlModule* pMod = AsPerlModule(GetModule());
    if (pMod) {
        PSTART;
        XPUSHs(sv_2mortal(m_perlObj));
        PCALL("ZNC::Core::RemoveTimer");
        PEND;
    }
}

#define SOCKSTART \
    PSTART;       \
    XPUSHs(GetPerlObj())
#define SOCKCBCHECK(OnSuccess)                                  \
    PCALL("ZNC::Core::CallSocket");                             \
    if (SvTRUE(ERRSV)) {                                        \
        Close();                                                \
        DEBUG("Perl socket hook died with: " + PString(ERRSV)); \
    } else {                                                    \
        OnSuccess;                                              \
    }                                                           \
    PEND
#define CBSOCK(Func)                                   \
    void CPerlSocket::Func()                           \
    {                                                  \
        CPerlModule* pMod = AsPerlModule(GetModule()); \
        if (pMod) {                                    \
            SOCKSTART;                                 \
            PUSH_STR("On" #Func);                      \
            SOCKCBCHECK();                             \
        }                                              \
    }
CBSOCK(Connected);
CBSOCK(Disconnected);
CBSOCK(Timeout);
CBSOCK(ConnectionRefused);

void CPerlSocket::ReadData(const char* data, size_t len)
{
    CPerlModule* pMod = AsPerlModule(GetModule());
    if (pMod) {
        SOCKSTART;
        PUSH_STR("OnReadData");
        XPUSHs(sv_2mortal(newSVpvn(data, len)));
        mXPUSHi(len);
        SOCKCBCHECK();
    }
}
void CPerlSocket::ReadLine(const NoString& sLine)
{
    CPerlModule* pMod = AsPerlModule(GetModule());
    if (pMod) {
        SOCKSTART;
        PUSH_STR("OnReadLine");
        PUSH_STR(sLine);
        SOCKCBCHECK();
    }
}
Csock* CPerlSocket::GetSockObj(const NoString& sHost, unsigned short uPort)
{
    CPerlModule* pMod = AsPerlModule(GetModule());
    Csock* result = nullptr;
    if (pMod) {
        SOCKSTART;
        PUSH_STR("_Accepted");
        PUSH_STR(sHost);
        mXPUSHi(uPort);
        SOCKCBCHECK(result = SvToPtr<CPerlSocket>("CPerlSocket*")(ST(0)););
    }
    return result;
}

CPerlSocket::~CPerlSocket()
{
    CPerlModule* pMod = AsPerlModule(GetModule());
    if (pMod) {
        PSTART;
        XPUSHs(sv_2mortal(m_perlObj));
        PCALL("ZNC::Core::RemoveSocket");
        PEND;
    }
}

template <> void TModInfo<CModPerl>(NoModInfo& Info) { Info.SetWikiPage("modperl"); }

GLOBALMODULEDEFS(CModPerl, "Loads perl scripts as ZNC modules")
