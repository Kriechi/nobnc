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
#include <znc/noircsock.h>
#include <znc/noserver.h>
#include <znc/nouser.h>
#include <znc/nonetwork.h>

#include <tcl.h>

using std::vector;
using std::map;

#define STDVAR (ClientData cd, Tcl_Interp * irp, int argc, const char* argv[])

#define BADARGS(nl, nh, example)                                                                    \
    do {                                                                                            \
        if ((argc < (nl)) || (argc > (nh))) {                                                       \
            Tcl_AppendResult(irp, "wrong # args: should be \"", argv[0], (example), "\"", nullptr); \
            return TCL_ERROR;                                                                       \
        }                                                                                           \
    } while (0)

class CModTcl;

class CModTclTimer : public NoTimer
{
public:
    CModTclTimer(NoModule* pModule, unsigned int uInterval, unsigned int uCycles, const NoString& sLabel, const NoString& sDescription)
        : NoTimer(pModule, uInterval, uCycles, sLabel, sDescription), m_pParent(nullptr)
    {
    }
    virtual ~CModTclTimer() {}

protected:
    void RunJob() override;
    CModTcl* m_pParent;
};

class CModTclStartTimer : public NoTimer
{
public:
    CModTclStartTimer(NoModule* pModule, unsigned int uInterval, unsigned int uCycles, const NoString& sLabel, const NoString& sDescription)
        : NoTimer(pModule, uInterval, uCycles, sLabel, sDescription), m_pParent(nullptr)
    {
    }
    virtual ~CModTclStartTimer() {}

protected:
    void RunJob() override;
    CModTcl* m_pParent;
};


class CModTcl : public NoModule
{
public:
    MODCONSTRUCTOR(CModTcl) { interp = nullptr; }

    virtual ~CModTcl()
    {
        if (interp) {
            Tcl_DeleteInterp(interp);
        }
    }

    bool OnLoad(const NoString& sArgs, NoString& sErrorMsg) override
    {
#ifndef MOD_MODTCL_ALLOW_EVERYONE
        if (!GetUser()->IsAdmin()) {
            sErrorMsg = "You must be admin to use the modtcl module";
            return false;
        }
#endif

        AddTimer(new CModTclStartTimer(this, 1, 1, "ModTclStarter", "Timer for modtcl to load the interpreter."));
        return true;
    }

    void Start()
    {
        NoString sMyArgs = GetArgs();

        interp = Tcl_CreateInterp();
        Tcl_Init(interp);
        Tcl_CreateCommand(interp, "Binds::ProcessPubm", tcl_Bind, this, nullptr);
        Tcl_CreateCommand(interp, "Binds::ProcessMsgm", tcl_Bind, this, nullptr);
        Tcl_CreateCommand(interp, "Binds::ProcessTime", tcl_Bind, this, nullptr);
        Tcl_CreateCommand(interp, "Binds::ProcessEvnt", tcl_Bind, this, nullptr);
        Tcl_CreateCommand(interp, "Binds::ProcessNick", tcl_Bind, this, nullptr);
        Tcl_CreateCommand(interp, "Binds::ProcessKick", tcl_Bind, this, nullptr);
        Tcl_CreateCommand(interp, "PutIRC", tcl_PutIRC, this, nullptr);
        Tcl_CreateCommand(interp, "PutModule", tcl_PutModule, this, nullptr);
        Tcl_CreateCommand(interp, "PutStatus", tcl_PutStatus, this, nullptr);
        Tcl_CreateCommand(interp, "PutStatusNotice", tcl_PutStatusNotice, this, nullptr);
        Tcl_CreateCommand(interp, "PutUser", tcl_PutUser, this, nullptr);

        Tcl_CreateCommand(interp, "GetCurNick", tcl_GetCurNick, this, nullptr);
        Tcl_CreateCommand(interp, "GetUsername", tcl_GetUsername, this, nullptr);
        Tcl_CreateCommand(interp, "GetRealName", tcl_GetRealName, this, nullptr);
        Tcl_CreateCommand(interp, "GetVHost", tcl_GetBindHost, this, nullptr);
        Tcl_CreateCommand(interp, "GetBindHost", tcl_GetBindHost, this, nullptr);
        Tcl_CreateCommand(interp, "GetChans", tcl_GetChans, this, nullptr);
        Tcl_CreateCommand(interp, "GetChannelUsers", tcl_GetChannelUsers, this, nullptr);
        Tcl_CreateCommand(interp, "GetChannelModes", tcl_GetChannelModes, this, nullptr);
        Tcl_CreateCommand(interp, "GetServer", tcl_GetServer, this, nullptr);
        Tcl_CreateCommand(interp, "GetServerOnline", tcl_GetServerOnline, this, nullptr);
        Tcl_CreateCommand(interp, "GetModules", tcl_GetModules, this, nullptr);
        Tcl_CreateCommand(interp, "GetClientCount", tcl_GetClientCount, this, nullptr);

        Tcl_CreateCommand(interp, "exit", tcl_exit, this, nullptr);

        if (!sMyArgs.empty()) {
            i = Tcl_EvalFile(interp, sMyArgs.c_str());
            if (i != TCL_OK) {
                PutModule(Tcl_GetStringResult(interp));
            }
        }

        AddTimer(new CModTclTimer(this,
                                  1,
                                  0,
                                  "ModTclUpdate",
                                  "Timer for modtcl to process pending events and idle "
                                  "callbacks."));
    }

    void OnModCommand(const NoString& sCommand) override
    {
        NoString sResult;
        NoStringVector vsResult;
        NoString sCmd = sCommand;

        if (sCmd.Token(0).CaseCmp(".tcl") == 0) sCmd = sCmd.Token(1, true);

        if (sCmd.Left(1).CaseCmp(".") == 0) sCmd = "Binds::ProcessDcc - - {" + sCmd + "}";

        Tcl_Eval(interp, sCmd.c_str());

        sResult = NoString(Tcl_GetStringResult(interp));
        if (!sResult.empty()) {
            sResult.Split("\n", vsResult);
            unsigned int a = 0;
            for (a = 0; a < vsResult.size(); a++) PutModule(vsResult[a].TrimRight_n());
        }
    }

    void TclUpdate()
    {
        while (Tcl_DoOneEvent(TCL_DONT_WAIT)) {
        }
        i = Tcl_Eval(interp, "Binds::ProcessTime");
        if (i != TCL_OK) {
            PutModule(Tcl_GetStringResult(interp));
        }
    }

    NoString TclEscape(NoString sLine)
    {
        sLine.Replace("\\", "\\\\");
        sLine.Replace("{", "\\{");
        sLine.Replace("}", "\\}");
        return sLine;
    }

    void OnPreRehash() override
    {
        if (interp) Tcl_Eval(interp, "Binds::ProcessEvnt prerehash");
    }

    void OnPostRehash() override
    {
        if (interp) {
            Tcl_Eval(interp, "rehash");
            Tcl_Eval(interp, "Binds::ProcessEvnt rehash");
        }
    }

    void OnIRCConnected() override
    {
        if (interp) Tcl_Eval(interp, "Binds::ProcessEvnt init-server");
    }

    void OnIRCDisconnected() override
    {
        if (interp) Tcl_Eval(interp, "Binds::ProcessEvnt disconnect-server");
    }

    EModRet OnChanMsg(NoNick& Nick, NoChannel& Channel, NoString& sMessage) override
    {
        NoString sMes = TclEscape(sMessage);
        NoString sNick = TclEscape(NoString(Nick.GetNick()));
        NoString sHost = TclEscape(NoString(Nick.GetIdent() + "@" + Nick.GetHost()));
        NoString sChannel = TclEscape(NoString(Channel.GetName()));

        NoString sCommand = "Binds::ProcessPubm {" + sNick + "} {" + sHost + "} - {" + sChannel + "} {" + sMes + "}";
        i = Tcl_Eval(interp, sCommand.c_str());
        if (i != TCL_OK) {
            PutModule(Tcl_GetStringResult(interp));
        }
        return CONTINUE;
    }

    EModRet OnPrivMsg(NoNick& Nick, NoString& sMessage) override
    {
        NoString sMes = TclEscape(sMessage);
        NoString sNick = TclEscape(NoString(Nick.GetNick()));
        NoString sHost = TclEscape(NoString(Nick.GetIdent() + "@" + Nick.GetHost()));

        NoString sCommand = "Binds::ProcessMsgm {" + sNick + "} {" + sHost + "} - {" + sMes + "}";
        i = Tcl_Eval(interp, sCommand.c_str());
        if (i != TCL_OK) {
            PutModule(Tcl_GetStringResult(interp));
        }
        return CONTINUE;
    }

    void OnNick(const NoNick& OldNick, const NoString& sNewNick, const vector<NoChannel*>& vChans) override
    {
        NoString sOldNick = TclEscape(NoString(OldNick.GetNick()));
        NoString sNewNickTmp = TclEscape(sNewNick);
        NoString sHost = TclEscape(NoString(OldNick.GetIdent() + "@" + OldNick.GetHost()));

        NoString sCommand;
        // Nick change is triggered for each common chan so that binds can be chan specific
        unsigned int nLength = vChans.size();
        for (unsigned int n = 0; n < nLength; n++) {
            sCommand =
            "Binds::ProcessNick {" + sOldNick + "} {" + sHost + "} - {" + vChans[n]->GetName() + "} {" + sNewNickTmp + "}";
            i = Tcl_Eval(interp, sCommand.c_str());
            if (i != TCL_OK) {
                PutModule(Tcl_GetStringResult(interp));
            }
        }
    }

    void OnKick(const NoNick& OpNick, const NoString& sKickedNick, NoChannel& Channel, const NoString& sMessage) override
    {
        NoString sOpNick = TclEscape(NoString(OpNick.GetNick()));
        NoString sNick = TclEscape(sKickedNick);
        NoString sOpHost = TclEscape(NoString(OpNick.GetIdent() + "@" + OpNick.GetHost()));

        NoString sCommand = "Binds::ProcessKick {" + sOpNick + "} {" + sOpHost + "} - {" + Channel.GetName() + "} {" +
                           sNick + "} {" + sMessage + "}";
        i = Tcl_Eval(interp, sCommand.c_str());
        if (i != TCL_OK) {
            PutModule(Tcl_GetStringResult(interp));
        }
    }


private:
    Tcl_Interp* interp;
    int i;

    static NoString argvit(const char* argv[], unsigned int end, unsigned int begin, NoString delim)
    {
        NoString sRet;
        unsigned int i;
        if (begin < end) sRet = NoString(argv[begin]);

        for (i = begin + 1; i < end; i++) {
            sRet = sRet + delim + NoString(argv[i]);
        }

        return sRet;
    }

    // Placeholder for binds incase binds.tcl isn't used
    static int tcl_Bind STDVAR { return TCL_OK; }

    static int tcl_GetCurNick STDVAR
    {
        CModTcl* mod = static_cast<CModTcl*>(cd);
        Tcl_SetResult(irp, (char*)mod->GetNetwork()->GetCurNick().c_str(), TCL_VOLATILE);
        return TCL_OK;
    }

    static int tcl_GetUsername STDVAR
    {
        CModTcl* mod = static_cast<CModTcl*>(cd);
        Tcl_SetResult(irp, (char*)mod->GetUser()->GetUserName().c_str(), TCL_VOLATILE);
        return TCL_OK;
    }

    static int tcl_GetRealName STDVAR
    {
        CModTcl* mod = static_cast<CModTcl*>(cd);
        Tcl_SetResult(irp, (char*)mod->GetUser()->GetRealName().c_str(), TCL_VOLATILE);
        return TCL_OK;
    }

    static int tcl_GetBindHost STDVAR
    {
        CModTcl* mod = static_cast<CModTcl*>(cd);
        Tcl_SetResult(irp, (char*)mod->GetUser()->GetBindHost().c_str(), TCL_VOLATILE);
        return TCL_OK;
    }

    static int tcl_GetChans STDVAR
    {
        char* p;
        const char* l[1];
        CModTcl* mod = static_cast<CModTcl*>(cd);

        BADARGS(1, 1, "");

        const vector<NoChannel*>& Channels = mod->GetNetwork()->GetChans();
        for (unsigned int c = 0; c < Channels.size(); c++) {
            NoChannel* pChan = Channels[c];
            l[0] = pChan->GetName().c_str();
            p = Tcl_Merge(1, l);
            Tcl_AppendElement(irp, p);
            Tcl_Free((char*)p);
        }

        return TCL_OK;
    }

    static int tcl_GetChannelUsers STDVAR
    {
        char* p;
        const char* l[4];
        CModTcl* mod = static_cast<CModTcl*>(cd);

        BADARGS(2, 999, " channel");

        NoString sChannel = argvit(argv, argc, 1, " ");
        NoChannel* pChannel = mod->GetNetwork()->FindChan(sChannel);

        if (!pChannel) {
            NoString sMsg = "invalid channel: " + sChannel;
            Tcl_SetResult(irp, (char*)sMsg.c_str(), TCL_VOLATILE);
            return TCL_ERROR;
        }

        const map<NoString, NoNick>& msNicks = pChannel->GetNicks();
        for (map<NoString, NoNick>::const_iterator it = msNicks.begin(); it != msNicks.end(); ++it) {
            const NoNick& Nick = it->second;
            l[0] = (Nick.GetNick()).c_str();
            l[1] = (Nick.GetIdent()).c_str();
            l[2] = (Nick.GetHost()).c_str();
            l[3] = (Nick.GetPermStr()).c_str();
            p = Tcl_Merge(4, l);
            Tcl_AppendElement(irp, p);
            Tcl_Free((char*)p);
        }

        return TCL_OK;
    }

    static int tcl_GetChannelModes STDVAR
    {
        CModTcl* mod = static_cast<CModTcl*>(cd);

        BADARGS(2, 999, " channel");

        NoString sChannel = argvit(argv, argc, 1, " ");
        NoChannel* pChannel = mod->GetNetwork()->FindChan(sChannel);
        NoString sMsg;

        if (!pChannel) {
            sMsg = "invalid channel: " + sChannel;
            Tcl_SetResult(irp, (char*)sMsg.c_str(), TCL_VOLATILE);
            return TCL_ERROR;
        }

        sMsg = pChannel->GetModeString();
        Tcl_SetResult(irp, (char*)sMsg.c_str(), TCL_VOLATILE);
        return TCL_OK;
    }

    static int tcl_GetServer STDVAR
    {
        CModTcl* mod = static_cast<CModTcl*>(cd);
        NoServer* pServer = mod->GetNetwork()->GetCurrentServer();
        NoString sMsg;
        if (pServer) sMsg = pServer->GetName() + ":" + NoString(pServer->GetPort());
        Tcl_SetResult(irp, (char*)sMsg.c_str(), TCL_VOLATILE);
        return TCL_OK;
    }

    static int tcl_GetServerOnline STDVAR
    {
        CModTcl* mod = static_cast<CModTcl*>(cd);
        NoIrcSock* pIRCSock = mod->GetNetwork()->GetIRCSock();
        NoString sMsg = "0";
        if (pIRCSock) sMsg = NoString(pIRCSock->GetStartTime());
        Tcl_SetResult(irp, (char*)sMsg.c_str(), TCL_VOLATILE);
        return TCL_OK;
    }

    static int tcl_GetModules STDVAR
    {
        char* p;
        const char* l[3];
        CModTcl* mod = static_cast<CModTcl*>(cd);

        BADARGS(1, 1, "");

        NoModules& GModules = CZNC::Get().GetModules();
        NoModules& Modules = mod->GetUser()->GetModules();

        for (unsigned int b = 0; b < GModules.size(); b++) {
            l[0] = GModules[b]->GetModName().c_str();
            l[1] = GModules[b]->GetArgs().c_str();
            l[2] = "1"; // IsGlobal
            p = Tcl_Merge(3, l);
            Tcl_AppendElement(irp, p);
            Tcl_Free((char*)p);
        }
        for (unsigned int b = 0; b < Modules.size(); b++) {
            l[0] = Modules[b]->GetModName().c_str();
            l[1] = Modules[b]->GetArgs().c_str();
            l[2] = "0"; // IsGlobal
            p = Tcl_Merge(3, l);
            Tcl_AppendElement(irp, p);
            Tcl_Free((char*)p);
        }

        return TCL_OK;
    }

    static int tcl_GetClientCount STDVAR
    {
        CModTcl* mod = static_cast<CModTcl*>(cd);
        Tcl_SetResult(irp, (char*)NoString(mod->GetNetwork()->GetClients().size()).c_str(), TCL_VOLATILE);
        return TCL_OK;
    }

    static int tcl_PutIRC STDVAR
    {
        NoString sMsg;
        CModTcl* mod = static_cast<CModTcl*>(cd);

        BADARGS(2, 999, " string");
        sMsg = argvit(argv, argc, 1, " ");
        mod->GetNetwork()->PutIRC(sMsg);
        return TCL_OK;
    }

    static int tcl_PutModule STDVAR
    {
        NoString sMsg;
        NoStringVector vsMsg;
        CModTcl* mod = static_cast<CModTcl*>(cd);

        BADARGS(2, 999, " string");
        sMsg = argvit(argv, argc, 1, " ");
        // mod->PutModule(sMsg);
        sMsg.Split("\n", vsMsg);
        unsigned int a = 0;
        for (a = 0; a < vsMsg.size(); a++) mod->PutModule(vsMsg[a].TrimRight_n());
        return TCL_OK;
    }

    static int tcl_PutStatus STDVAR
    {
        NoString sMsg;
        CModTcl* mod = static_cast<CModTcl*>(cd);

        BADARGS(2, 999, " string");
        sMsg = argvit(argv, argc, 1, " ");
        mod->PutStatus(sMsg);
        return TCL_OK;
    }

    static int tcl_PutStatusNotice STDVAR
    {
        NoString sMsg;
        CModTcl* mod = static_cast<CModTcl*>(cd);

        BADARGS(2, 999, " string");
        sMsg = argvit(argv, argc, 1, " ");
        mod->GetUser()->PutStatusNotice(sMsg);
        return TCL_OK;
    }

    static int tcl_PutUser STDVAR
    {
        NoString sMsg;
        CModTcl* mod = static_cast<CModTcl*>(cd);

        BADARGS(2, 999, " string");
        sMsg = argvit(argv, argc, 1, " ");
        mod->GetUser()->PutUser(sMsg);
        return TCL_OK;
    }

    static int tcl_exit STDVAR
    {
        NoString sMsg;
        CModTcl* mod = static_cast<CModTcl*>(cd);

        BADARGS(1, 2, " ?reason?");

        if (!mod->GetUser()->IsAdmin()) {
            sMsg = "You need to be administrator to shutdown the bnc.";
            Tcl_SetResult(irp, (char*)sMsg.c_str(), TCL_VOLATILE);
            return TCL_ERROR;
        }
        if (argc > 1) {
            sMsg = argvit(argv, argc, 1, " ");
            CZNC::Get().Broadcast(sMsg);
            usleep(100000); // Sleep for 10ms to attempt to allow the previous Broadcast() to go through to all users
        }

        throw NoException(NoException::EX_Shutdown);

        return TCL_OK;
    }
};

void CModTclTimer::RunJob()
{
    CModTcl* p = (CModTcl*)GetModule();
    if (p) p->TclUpdate();
}

void CModTclStartTimer::RunJob()
{
    CModTcl* p = (CModTcl*)GetModule();
    if (p) p->Start();
}

template <> void TModInfo<CModTcl>(NoModInfo& Info)
{
    Info.SetWikiPage("modtcl");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("Absolute path to modtcl.tcl file");
}

NETWORKMODULEDEFS(CModTcl, "Loads Tcl scripts as ZNC modules")
