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
#include "../include/znc/nofile.h"
#include "../include/znc/nodir.h"
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
%feature("python:defaultargs", "0") NoDir::MakeDir; // 0700 doesn't work in python3
%feature("python:defaultargs", "0") NoUtils::GetNumInput; // SyntaxError: non-default argument follows default argument
%feature("python:defaultargs", "0") NoModules::GetAvailableMods; // NameError: name 'UserModule' is not defined
%feature("python:defaultargs", "0") NoModules::GetDefaultMods; // NameError: name 'UserModule' is not defined

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

%shared_ptr(NoAuthBase);
%shared_ptr(NoWebSession);
%shared_ptr(NoClientAuth);

%include "cstring.i"
%template(_stringlist) std::list<NoString>;

%typemap(out) NoModules::ModDirList %{
	$result = PyList_New($1.size());
	if ($result) {
		for (size_t i = 0; !$1.empty(); $1.pop(), ++i) {
			PyList_SetItem($result, i, Py_BuildValue("ss", $1.front().first.c_str(), $1.front().second.c_str()));
		}
	}
%}

%template(VIRNoNetworks) std::vector<NoNetwork*>;
%template(VChannels) std::vector<NoChannel*>;
%template(MNicks) std::map<NoString, NoNick>;
%template(SModInfo) std::set<NoModInfo>;
%template(NoStringSet) std::set<NoString>;
typedef std::set<NoString> NoStringSet;
%template(NoStringVector) std::vector<NoString>;
typedef std::vector<NoString> NoStringVector;
%template(PyNoStringMap) std::map<NoString, NoString>;
%template(PyMStringVString) std::map<NoString, NoStringVector>;
class NoStringMap : public std::map<NoString, NoString> {};
%template(PyModulesVector) std::vector<NoModule*>;
%template(VListeners) std::vector<NoListener*>;
%template(BufLines) std::deque<NoMessage>;
%template(VVString) std::vector<NoStringVector>;

%typemap(in) NoString& {
	String* p;
	int res = SWIG_IsOK(SWIG_ConvertPtr($input, (void**)&p, SWIG_TypeQuery("String*"), 0));
	if (SWIG_IsOK(res)) {
		$1 = &p->s;
	} else {
		SWIG_exception_fail(SWIG_ArgError(res), "need znc.String object as argument $argnum $1_name");
	}
}

%typemap(out) NoString&, NoString* {
	if ($1) {
		$result = CPyRetString::wrap(*$1);
	} else {
		$result = Py_None;
		Py_INCREF(Py_None);
	}
}

%typemap(typecheck) NoString&, NoString* {
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
%template(ZNNoSocketManager) TSocketManager<NoBaseSocket>;
%include "../include/znc/nosocket.h"
%include "../include/znc/nofile.h"
%include "../include/znc/nodir.h"
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

/* Really it's NoString& inside, but SWIG shouldn't know that :) */
class CPyRetString {
	CPyRetString();
public:
	NoString s;
};

%extend CPyRetString {
	NoString __str__() {
		return $self->s;
	}
};

%extend String {
	NoString __str__() {
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

%extend NoModule {
	NoString __str__() {
		return $self->GetModName();
	}
	NoStringMap_iter BeginNV_() {
		return NoStringMap_iter($self->BeginNV());
	}
	bool ExistsNV(const NoString& sName) {
		return $self->EndNV() != $self->FindNV(sName);
	}
}

%extend NoModules {
	bool removeModule(NoModule* p) {
		for (NoModules::iterator i = $self->begin(); $self->end() != i; ++i) {
			if (*i == p) {
				$self->erase(i);
				return true;
			}
		}
		return false;
	}
}

%extend NoUser {
	NoString __str__() {
		return $self->GetUserName();
	}
	NoString __repr__() {
		return "<NoUser " + $self->GetUserName() + ">";
	}
	std::vector<NoNetwork*> GetNetworks_() {
		return $self->GetNetworks();
	}
};

%extend NoNetwork {
	NoString __str__() {
		return $self->GetName();
	}
	NoString __repr__() {
		return "<NoNetwork " + $self->GetName() + ">";
	}
	std::vector<NoChannel*> GetChans_() {
		return $self->GetChans();
	}
}

%extend NoChannel {
	NoString __str__() {
		return $self->GetName();
	}
	NoString __repr__() {
		return "<NoChannel " + $self->GetName() + ">";
	}
	std::map<NoString, NoNick> GetNicks_() {
		return $self->GetNicks();
	}
};

%extend NoNick {
	NoString __str__() {
		return $self->GetNick();
	}
	NoString __repr__() {
		return "<NoNick " + $self->GetHostMask() + ">";
	}
};

%extend CZNC {
    PyObject* GetUserMap_() {
        PyObject* result = PyDict_New();
        auto user_type = SWIG_TypeQuery("NoUser*");
        for (const auto& p : $self->GetUserMap()) {
            PyObject* user = SWIG_NewInstanceObj(p.second, user_type, 0);
            PyDict_SetItemString(result, p.first.c_str(), user);
            Py_CLEAR(user);
        }
        return result;
    }
};

/* To allow module-loaders to be written on python.
 * They can call CreatePyModule() to create NoModule* object, but one of arguments to CreatePyModule() is "NoModule* pModPython"
 * Pointer to modpython is already accessible to python modules as self.GetModPython(), but it's just a pointer to something, not to NoModule*.
 * So make it known that CModPython is really a NoModule.
 */
class CModPython : public NoModule {
private:
	CModPython();
	CModPython(const CModPython&);
	~CModPython();
};

/* Web */

%template(StrPair) std::pair<NoString, NoString>;
%template(NoStringPairVector) std::vector<std::pair<NoString, NoString> >;
typedef std::vector<std::pair<NoString, NoString> > NoStringPairVector;
%template(VWebSubPages) std::vector<TWebSubPage>;

%inline %{
	void NoStringPairVector_Add2Str_(NoStringPairVector* self, const NoString& a, const NoString& b) {
		self->push_back(std::make_pair(a, b));
	}
%}

%extend NoTemplate {
	void set(const NoString& key, const NoString& value) {
		DEBUG("WARNING: modpython's NoTemplate.set is deprecated and will be removed. Use normal dict's operations like Tmpl['foo'] = 'bar'");
		(*$self)[key] = value;
	}
}

%inline %{
	TWebSubPage CreateWebSubPage_(const NoString& sName, const NoString& sTitle, const NoStringPairVector& vParams, unsigned int uFlags) {
		return std::make_shared<NoWebSubPage>(sName, sTitle, vParams, uFlags);
	}
%}

/* vim: set filetype=cpp: */
