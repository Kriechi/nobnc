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

%module ZNC %{
#ifdef Copy
# undef Copy
#endif
#ifdef Pause
# undef Pause
#endif
#ifdef seed
# undef seed
#endif
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
#define stat struct stat
%}

%apply long { off_t };
%apply long { uint16_t };
%apply long { uint32_t };
%apply long { uint64_t };

%begin %{
#include "znc/noconfig.h"
%}

%include <typemaps.i>
%include <stl.i>
%include <std_list.i>
%include <std_deque.i>

namespace std {
	template<class K> class set {
		public:
		set();
		set(const set<K>&);
	};
}
%include "NoString.i"
%template(_stringlist) std::list<NoString>;
%typemap(out) std::list<NoString> {
	std::list<NoString>::const_iterator i;
	unsigned int j;
	int len = $1.size();
	SV **svs = new SV*[len];
	for (i=$1.begin(), j=0; i!=$1.end(); i++, j++) {
		svs[j] = sv_newmortal();
		SwigSvFromString(svs[j], *i);
	}
	AV *myav = av_make(len, svs);
	delete[] svs;
	$result = newRV_noinc((SV*) myav);
	sv_2mortal($result);
	argvi++;
}

%template(VIRNoNetworks) std::vector<NoNetwork*>;
%template(VChannels) std::vector<NoChannel*>;
%template(NoStringVector) std::vector<NoString>;
typedef std::vector<NoString> NoStringVector;
/*%template(MNicks) std::map<NoString, NoNick>;*/
/*%template(SModInfo) std::set<NoModInfo>;
%template(NoStringSet) std::set<NoString>;
typedef std::set<NoString> NoStringSet;*/
%template(PerlNoStringMap) std::map<NoString, NoString>;
class NoStringMap : public std::map<NoString, NoString> {};
/*%template(PerlModulesVector) std::vector<NoModule*>;*/
%template(VListeners) std::vector<NoListener*>;
%template(BufLines) std::deque<NoMessage>;
%template(VVString) std::vector<NoStringVector>;

%typemap(out) std::map<NoString, NoNick> {
	HV* myhv = newHV();
	for (std::map<NoString, NoNick>::const_iterator i = $1.begin(); i != $1.end(); ++i) {
		SV* val = SWIG_NewInstanceObj(const_cast<NoNick*>(&i->second), SWIG_TypeQuery("NoNick*"), SWIG_SHADOW);
		SvREFCNT_inc(val);// it was created mortal
		hv_store(myhv, i->first.c_str(), i->first.length(), val, 0);
	}
	$result = newRV_noinc((SV*)myhv);
	sv_2mortal($result);
	argvi++;
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
%include "../include/znc/nochannel.h"
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

%inline %{
	class String : public NoString {
		public:
			String() {}
			String(const NoString& s)	: NoString(s) {}
			String(double d, int prec=2): NoString(d, prec) {}
			String(float f, int prec=2) : NoString(f, prec) {}
			String(int i)			   : NoString(i) {}
			String(unsigned int i)	  : NoString(i) {}
			String(long int i)		  : NoString(i) {}
			String(unsigned long int i) : NoString(i) {}
			String(char c)			  : NoString(c) {}
			String(unsigned char c)	 : NoString(c) {}
			String(short int i)		 : NoString(i) {}
			String(unsigned short int i): NoString(i) {}
			String(bool b)			  : NoString(b) {}
			NoString GetPerlStr() {
				return *this;
			}
	};
%}

%extend NoModule {
	std::list<NoString> _GetNVKeys() {
		std::list<NoString> res;
		for (NoStringMap::iterator i = $self->BeginNV(); i != $self->EndNV(); ++i) {
			res.push_back(i->first);
		}
		return res;
	}
	bool ExistsNV(const NoString& sName) {
		return $self->EndNV() != $self->FindNV(sName);
	}
}

%perlcode %{
	package ZNC::NoModule;
	sub GetNVKeys {
		my $result = _GetNVKeys(@_);
		return @$result;
	}
%}

%extend NoModules {
	void push_back(NoModule* p) {
		$self->push_back(p);
	}
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
	std::vector<NoNetwork*> GetNetworks_() {
		return $self->GetNetworks();
	}
}

%extend NoNetwork {
	std::vector<NoChannel*> GetChans_() {
		return $self->GetChans();
	}
}

%extend NoChannel {
	std::map<NoString, NoNick> GetNicks_() {
		return $self->GetNicks();
	}
}

/* Web */

%template(StrPair) std::pair<NoString, NoString>;
%template(NoStringPairVector) std::vector<std::pair<NoString, NoString> >;
typedef std::vector<std::pair<NoString, NoString> > NoStringPairVector;
%template(VWebSubPages) std::vector<TWebSubPage>;

%inline %{
	void _NoStringPairVector_Add2Str(NoStringPairVector* self, const NoString& a, const NoString& b) {
		self->push_back(std::make_pair(a, b));
	}
%}

%extend NoTemplate {
	void set(const NoString& key, const NoString& value) {
		(*$self)[key] = value;
	}
}

%inline %{
	TWebSubPage _CreateWebSubPage(const NoString& sName, const NoString& sTitle, const NoStringPairVector& vParams, unsigned int uFlags) {
		return std::make_shared<NoWebSubPage>(sName, sTitle, vParams, uFlags);
	}
%}

%perlcode %{
	package ZNC;
	sub CreateWebSubPage {
		my ($name, %arg) = @_;
		my $params = $arg{params}//{};
		my $vpair = ZNC::NoStringPairVector->new;
		while (my ($key, $val) = each %$params) {
			ZNC::_NoStringPairVector_Add2Str($vpair, $key, $val);
		}
		my $flags = 0;
		$flags |= $ZNC::NoWebSubPage::F_ADMIN if $arg{admin}//0;
		return _CreateWebSubPage($name, $arg{title}//'', $vpair, $flags);
	}
%}

%inline %{
	void _CleanupStash(const NoString& sModname) {
		hv_clear(gv_stashpv(sModname.c_str(), 0));
	}
%}

%perlcode %{
	package ZNC;
	*CONTINUE = *ZNC::NoModule::CONTINUE;
	*HALT = *ZNC::NoModule::HALT;
	*HALTMODS = *ZNC::NoModule::HALTMODS;
	*HALTCORE = *ZNC::NoModule::HALTCORE;
	*UNLOAD = *ZNC::NoModule::UNLOAD;

	package ZNC::NoNetwork;
	*GetChans = *GetChans_;

	package ZNC::NoUser;
	*GetNetworks = *GetNetworks_;

	package ZNC::NoChannel;
	sub _GetNicks_ {
		my $result = GetNicks_(@_);
		return %$result;
	}
	*GetNicks = *_GetNicks_;
%}

/* vim: set filetype=cpp: */
