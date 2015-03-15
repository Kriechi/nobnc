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

%module znc_core

%{
#include <utility>
#include "../include/znc/noutils.h"
#include "../include/znc/nothreads.h"
#include "../include/znc/nosettings.h"
#include "../include/znc/nosocket.h"
#include "../include/znc/nomodules.h"
#include "../include/znc/nonick.h"
#include "../include/znc/nochannel.h"
#include "../include/znc/nouser.h"
#include "../include/znc/nonetwork.h"
#include "../include/znc/noclient.h"
#include "../include/znc/noircsock.h"
#include "../include/znc/nolistener.h"
#include "../include/znc/nohttpsock.h"
#include "../include/znc/notemplate.h"
#include "../include/znc/nowebmodules.h"
#include "../include/znc/noznc.h"
#include "../include/znc/noserver.h"
#include "../include/znc/nostring.h"
#include "../include/znc/nofileutils.h"
#include "../include/znc/nodebug.h"
#include "../include/znc/noexecsock.h"
#include "../include/znc/nobuffer.h"
#include "../include/znc/nomessage.h"
#include "module.h"

#include "ret.h"

#define stat struct stat
using std::allocator;
%}

%apply long { off_t };
%apply long { uint16_t };
%apply long { uint32_t };
%apply long { uint64_t };

// Just makes generated python code slightly more beautiful.
%feature("python:defaultargs");
// Probably can be removed when swig is fixed to not produce bad code for some cases
%feature("python:defaultargs", "0") CDir::MakeDir; // 0700 doesn't work in python3
%feature("python:defaultargs", "0") CUtils::GetNumInput; // SyntaxError: non-default argument follows default argument
%feature("python:defaultargs", "0") CModules::GetAvailableMods; // NameError: name 'UserModule' is not defined
%feature("python:defaultargs", "0") CModules::GetDefaultMods; // NameError: name 'UserModule' is not defined

%begin %{
#include "znc/noconfig.h"
%}

%include <pyabc.i>
%include <typemaps.i>
%include <stl.i>
%include <std_list.i>
%include <std_set.i>
%include <std_deque.i>
%include <std_shared_ptr.i>

%shared_ptr(CAuthBase);
%shared_ptr(CWebSession);
%shared_ptr(CClientAuth);

%include "cstring.i"
%template(_stringlist) std::list<CString>;

%typemap(out) CModules::ModDirList %{
	$result = PyList_New($1.size());
	if ($result) {
		for (size_t i = 0; !$1.empty(); $1.pop(), ++i) {
			PyList_SetItem($result, i, Py_BuildValue("ss", $1.front().first.c_str(), $1.front().second.c_str()));
		}
	}
%}

%template(VIRCNetworks) std::vector<CNetwork*>;
%template(VChannels) std::vector<CChannel*>;
%template(MNicks) std::map<CString, CNick>;
%template(SModInfo) std::set<CModInfo>;
%template(SCString) std::set<CString>;
typedef std::set<CString> SCString;
%template(VCString) std::vector<CString>;
typedef std::vector<CString> VCString;
%template(PyMCString) std::map<CString, CString>;
%template(PyMStringVString) std::map<CString, VCString>;
class MCString : public std::map<CString, CString> {};
%template(PyModulesVector) std::vector<CModule*>;
%template(VListeners) std::vector<CListener*>;
%template(BufLines) std::deque<CMessage>;
%template(VVString) std::vector<VCString>;

%typemap(in) CString& {
	String* p;
	int res = SWIG_IsOK(SWIG_ConvertPtr($input, (void**)&p, SWIG_TypeQuery("String*"), 0));
	if (SWIG_IsOK(res)) {
		$1 = &p->s;
	} else {
		SWIG_exception_fail(SWIG_ArgError(res), "need znc.String object as argument $argnum $1_name");
	}
}

%typemap(out) CString&, CString* {
	if ($1) {
		$result = CPyRetString::wrap(*$1);
	} else {
		$result = Py_None;
		Py_INCREF(Py_None);
	}
}

%typemap(typecheck) CString&, CString* {
    String* p;
    $1 = SWIG_IsOK(SWIG_ConvertPtr($input, (void**)&p, SWIG_TypeQuery("String*"), 0));
}

/*TODO %typemap(in) bool& to be able to call from python functions which get bool& */

%typemap(out) bool&, bool* {
	if ($1) {
		$result = CPyRetBool::wrap(*$1);
	} else {
		$result = Py_None;
		Py_INCREF(Py_None);
	}
}

#define u_short unsigned short
#define u_int unsigned int
#include "../include/znc/noconfig.h"
#include "../include/znc/nostring.h"
%include "../include/znc/defines.h"
%include "../include/znc/noutils.h"
%include "../include/znc/nothreads.h"
%include "../include/znc/nosettings.h"
%include "../include/znc/Csocket.h"
%template(ZNCSocketManager) TSocketManager<CZNCSock>;
%include "../include/znc/nosocket.h"
%include "../include/znc/nofileutils.h"
%include "../include/znc/nomodules.h"
%include "../include/znc/nonick.h"
%include "../include/znc/nochan.h"
%include "../include/znc/nouser.h"
%include "../include/znc/nonetwork.h"
%include "../include/znc/noclient.h"
%include "../include/znc/noircsock.h"
%include "../include/znc/nolistener.h"
%include "../include/znc/nohttpsock.h"
%include "../include/znc/notemplate.h"
%include "../include/znc/nowebmodules.h"
%include "../include/znc/noznc.h"
%include "../include/znc/noserver.h"
%include "../include/znc/nodebug.h"
%include "../include/znc/noexecsock.h"
%include "../include/znc/nobuffer.h"
%include "../include/znc/nomessage.h"

%include "module.h"

/* Really it's CString& inside, but SWIG shouldn't know that :) */
class CPyRetString {
	CPyRetString();
public:
	CString s;
};

%extend CPyRetString {
	CString __str__() {
		return $self->s;
	}
};

%extend String {
	CString __str__() {
		return $self->s;
	}
};

class CPyRetBool {
	CPyRetBool();
	public:
	bool b;
};

%extend CPyRetBool {
	bool __bool__() {
		return $self->b;
	}
}

%extend Csock {
    PyObject* WriteBytes(PyObject* data) {
        if (!PyBytes_Check(data)) {
            PyErr_SetString(PyExc_TypeError, "socket.WriteBytes needs bytes as argument");
            return nullptr;
        }
        char* buffer;
        Py_ssize_t length;
        if (-1 == PyBytes_AsStringAndSize(data, &buffer, &length)) {
            return nullptr;
        }
        if ($self->Write(buffer, length)) {
            Py_RETURN_TRUE;
        } else {
            Py_RETURN_FALSE;
        }
    }
}

%extend CModule {
	CString __str__() {
		return $self->GetModName();
	}
	MCString_iter BeginNV_() {
		return MCString_iter($self->BeginNV());
	}
	bool ExistsNV(const CString& sName) {
		return $self->EndNV() != $self->FindNV(sName);
	}
}

%extend CModules {
	bool removeModule(CModule* p) {
		for (CModules::iterator i = $self->begin(); $self->end() != i; ++i) {
			if (*i == p) {
				$self->erase(i);
				return true;
			}
		}
		return false;
	}
}

%extend CUser {
	CString __str__() {
		return $self->GetUserName();
	}
	CString __repr__() {
		return "<CUser " + $self->GetUserName() + ">";
	}
	std::vector<CNetwork*> GetNetworks_() {
		return $self->GetNetworks();
	}
};

%extend CNetwork {
	CString __str__() {
		return $self->GetName();
	}
	CString __repr__() {
		return "<CNetwork " + $self->GetName() + ">";
	}
	std::vector<CChannel*> GetChans_() {
		return $self->GetChans();
	}
}

%extend CChannel {
	CString __str__() {
		return $self->GetName();
	}
	CString __repr__() {
		return "<CChannel " + $self->GetName() + ">";
	}
	std::map<CString, CNick> GetNicks_() {
		return $self->GetNicks();
	}
};

%extend CNick {
	CString __str__() {
		return $self->GetNick();
	}
	CString __repr__() {
		return "<CNick " + $self->GetHostMask() + ">";
	}
};

%extend CZNC {
    PyObject* GetUserMap_() {
        PyObject* result = PyDict_New();
        auto user_type = SWIG_TypeQuery("CUser*");
        for (const auto& p : $self->GetUserMap()) {
            PyObject* user = SWIG_NewInstanceObj(p.second, user_type, 0);
            PyDict_SetItemString(result, p.first.c_str(), user);
            Py_CLEAR(user);
        }
        return result;
    }
};

/* To allow module-loaders to be written on python.
 * They can call CreatePyModule() to create CModule* object, but one of arguments to CreatePyModule() is "CModule* pModPython"
 * Pointer to modpython is already accessible to python modules as self.GetModPython(), but it's just a pointer to something, not to CModule*.
 * So make it known that CModPython is really a CModule.
 */
class CModPython : public CModule {
private:
	CModPython();
	CModPython(const CModPython&);
	~CModPython();
};

/* Web */

%template(StrPair) std::pair<CString, CString>;
%template(VPair) std::vector<std::pair<CString, CString> >;
typedef std::vector<std::pair<CString, CString> > VPair;
%template(VWebSubPages) std::vector<TWebSubPage>;

%inline %{
	void VPair_Add2Str_(VPair* self, const CString& a, const CString& b) {
		self->push_back(std::make_pair(a, b));
	}
%}

%extend CTemplate {
	void set(const CString& key, const CString& value) {
		DEBUG("WARNING: modpython's CTemplate.set is deprecated and will be removed. Use normal dict's operations like Tmpl['foo'] = 'bar'");
		(*$self)[key] = value;
	}
}

%inline %{
	TWebSubPage CreateWebSubPage_(const CString& sName, const CString& sTitle, const VPair& vParams, unsigned int uFlags) {
		return std::make_shared<CWebSubPage>(sName, sTitle, vParams, uFlags);
	}
%}

/* vim: set filetype=cpp: */
