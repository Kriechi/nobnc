/*
   SWIG-generated sources are used here.
*/

//
// String
//

%{
#include <string>
%}

%feature("naturalvar") NoString;
class NoString {
public:
typedef size_t size_type;
};

/*@SWIG:/usr/share/swig1.3/typemaps/std_strings.swg,74,%typemaps_std_string@*/

/*@SWIG:/usr/share/swig1.3/typemaps/std_strings.swg,4,%std_string_asptr@*/
%fragment("SWIG_" "AsPtr" "_" {NoString},"header",fragment="SWIG_AsCharPtrAndSize") {
SWIGINTERN int
SWIG_AsPtr_std_string (PyObject * obj, NoString **val)
{
  char* buf = 0 ; size_t size = 0; int alloc = SWIG_OLDOBJ;
  if (SWIG_IsOK((SWIG_AsCharPtrAndSize(obj, &buf, &size, &alloc)))) {
    if (buf) {
      if (val) *val = new NoString(buf, size - 1);
      if (alloc == SWIG_NEWOBJ) free((char*)buf);
      return SWIG_NEWOBJ;
    } else {
      if (val) *val = 0;
      return SWIG_OLDOBJ;
    }
  } else {
    static int init = 0;
    static swig_type_info* descriptor = 0;
    if (!init) {
      descriptor = SWIG_TypeQuery("NoString" " *");
      init = 1;
    }
    if (descriptor) {
      NoString *vptr;
      int res = SWIG_ConvertPtr(obj, (void**)&vptr, descriptor, 0);
      if (SWIG_IsOK(res) && val) *val = vptr;
      return res;
    }
  }
  return SWIG_ERROR;
}
}
/*@SWIG@*/
/*@SWIG:/usr/share/swig1.3/typemaps/std_strings.swg,52,%std_string_asval@*/
%fragment("SWIG_" "AsVal" "_" {NoString},"header", fragment="SWIG_" "AsPtr" "_" {NoString}) {
SWIGINTERN int
SWIG_AsVal_std_string (PyObject * obj, NoString *val)
{
  NoString* v = (NoString *) 0;
  int res = SWIG_AsPtr_std_string (obj, &v);
  if (!SWIG_IsOK(res)) return res;
  if (v) {
    if (val) *val = *v;
    if (SWIG_IsNewObj(res)) {
      free((char*)v);
      res = SWIG_DelNewMask(res);
    }
    return res;
  }
  return SWIG_ERROR;
}
}
/*@SWIG@*/
/*@SWIG:/usr/share/swig1.3/typemaps/std_strings.swg,38,%std_string_from@*/
%fragment("SWIG_" "From" "_" {NoString},"header",fragment="SWIG_FromCharPtrAndSize",fragment="StdTraits") {
SWIGINTERNINLINE PyObject *
SWIG_From_std_string  (const NoString& s)
{
  if (s.size()) {
    return SWIG_FromCharPtrAndSize(s.data(), s.size());
  } else {
    return SWIG_FromCharPtrAndSize(s.c_str(), 0);
  }
}
}
/*@SWIG@*/

%fragment("StdTraitsNoString","header",fragment="SWIG_From_NoString") {
    namespace swig {
       template<> struct traits_from<NoString> {
           static PyObject *from(const NoString& s) {
               return SWIG_From_std_string(s);
           }
       };
    }
}


/*@SWIG:/usr/share/swig1.3/typemaps/ptrtypes.swg,204,%typemaps_asptrfromn@*/
/*@SWIG:/usr/share/swig1.3/typemaps/ptrtypes.swg,193,%typemaps_asptrfrom@*/
  /*@SWIG:/usr/share/swig1.3/typemaps/ptrtypes.swg,163,%typemaps_asptr@*/
  %fragment("SWIG_" "AsVal" "_" {NoString},"header",fragment="SWIG_" "AsPtr" "_" {NoString}) {
    SWIGINTERNINLINE int
    SWIG_AsVal_std_string (PyObject * obj, NoString *val)
    {
      NoString *v = (NoString *)0;
      int res = SWIG_AsPtr_std_string (obj, &v);
      if (!SWIG_IsOK(res)) return res;
      if (v) {
	if (val) *val = *v;
	if (SWIG_IsNewObj(res)) {
	  free((char*)v);
	  res = SWIG_DelNewMask(res);
	}
	return res;
      }
      return SWIG_ERROR;
    }
  }
  /*@SWIG:/usr/share/swig1.3/typemaps/ptrtypes.swg,31,%ptr_in_typemap@*/
  %typemap(in,fragment="SWIG_" "AsPtr" "_" {NoString},fragment="StdTraitsNoString") NoString {
    NoString *ptr = (NoString *)0;
    int res = SWIG_AsPtr_std_string($input, &ptr);
    if (!SWIG_IsOK(res) || !ptr) {
      SWIG_exception_fail(SWIG_ArgError((ptr ? res : SWIG_TypeError)), "in method '" "$symname" "', argument " "$argnum"" of type '" "$type""'");
    }
    $1 = *ptr;
    if (SWIG_IsNewObj(res)) free((char*)ptr);
  }
  %typemap(freearg) NoString "";
  %typemap(in,fragment="SWIG_" "AsPtr" "_" {NoString}) const NoString & (int res = SWIG_OLDOBJ) {
    NoString *ptr = (NoString *)0;
    res = SWIG_AsPtr_std_string($input, &ptr);
    if (!SWIG_IsOK(res)) { SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$type""'"); }
    if (!ptr) { SWIG_exception_fail(SWIG_ValueError, "invalid null reference " "in method '" "$symname" "', argument " "$argnum"" of type '" "$type""'"); }
    $1 = ptr;
  }
  %typemap(freearg,noblock=1) const NoString &  {
    if (SWIG_IsNewObj(res$argnum)) free((char*)$1);
  }
/*@SWIG@*/;
  /*@SWIG:/usr/share/swig1.3/typemaps/ptrtypes.swg,56,%ptr_varin_typemap@*/
  %typemap(varin,fragment="SWIG_" "AsPtr" "_" {NoString}) NoString {
    NoString *ptr = (NoString *)0;
    int res = SWIG_AsPtr_std_string($input, &ptr);
    if (!SWIG_IsOK(res) || !ptr) {
      SWIG_exception_fail(SWIG_ArgError((ptr ? res : SWIG_TypeError)), "in variable '""$name""' of type '""$type""'");
    }
    $1 = *ptr;
    if (SWIG_IsNewObj(res)) free((char*)ptr);
  }
/*@SWIG@*/;
  /*@SWIG:/usr/share/swig1.3/typemaps/ptrtypes.swg,71,%ptr_directorout_typemap@*/
  %typemap(directorargout,noblock=1,fragment="SWIG_" "AsPtr" "_" {NoString}) NoString *DIRECTOROUT ($*ltype temp) {
    NoString *swig_optr = 0;
    int swig_ores = $input ? SWIG_AsPtr_std_string($input, &swig_optr) : 0;
    if (!SWIG_IsOK(swig_ores) || !swig_optr) {
      Swig::DirectorTypeMismatchException::raise(SWIG_ErrorType(SWIG_ArgError((swig_optr ? swig_ores : SWIG_TypeError))), "in output value of type '""$type""'");
    }
    temp = *swig_optr;
    $result = &temp;
    if (SWIG_IsNewObj(swig_ores)) free((char*)swig_optr);
  }

  %typemap(directorout,noblock=1,fragment="SWIG_" "AsPtr" "_" {NoString}) NoString {
    NoString *swig_optr = 0;
    int swig_ores = SWIG_AsPtr_std_string($input, &swig_optr);
    if (!SWIG_IsOK(swig_ores) || !swig_optr) {
      Swig::DirectorTypeMismatchException::raise(SWIG_ErrorType(SWIG_ArgError((swig_optr ? swig_ores : SWIG_TypeError))), "in output value of type '""$type""'");
    }
    $result = *swig_optr;
    if (SWIG_IsNewObj(swig_ores)) free((char*)swig_optr);
  }

  %typemap(directorout,noblock=1,fragment="SWIG_" "AsPtr" "_" {NoString},warning= "473:Returning a pointer or reference in a director method is not recommended." ) NoString* {
    NoString *swig_optr = 0;
    int swig_ores = SWIG_AsPtr_std_string($input, &swig_optr);
    if (!SWIG_IsOK(swig_ores)) {
      Swig::DirectorTypeMismatchException::raise(SWIG_ErrorType(SWIG_ArgError(swig_ores)), "in output value of type '""$type""'");
    }
    $result = swig_optr;
    if (SWIG_IsNewObj(swig_ores)) {
      swig_acquire_ownership(swig_optr);
    }
  }
  %typemap(directorfree,noblock=1) NoString*
  {
    if (director)  {
      director->swig_release_ownership(SWIG_as_voidptr($input));
    }
  }

  %typemap(directorout,noblock=1,fragment="SWIG_" "AsPtr" "_" {NoString},warning= "473:Returning a pointer or reference in a director method is not recommended." ) NoString& {
    NoString *swig_optr = 0;
    int swig_ores = SWIG_AsPtr_std_string($input, &swig_optr);
    if (!SWIG_IsOK(swig_ores)) {
      Swig::DirectorTypeMismatchException::raise(SWIG_ErrorType(SWIG_ArgError(swig_ores)), "in output value of type '""$type""'");
    } else {
      if (!swig_optr) {
	Swig::DirectorTypeMismatchException::raise(SWIG_ErrorType(SWIG_ValueError), "invalid null reference " "in output value of type '""$type""'");
      }
    }
    $result = swig_optr;
    if (SWIG_IsNewObj(swig_ores)) {
      swig_acquire_ownership(swig_optr);
    }
  }
  %typemap(directorfree,noblock=1) NoString&
  {
    if (director) {
      director->swig_release_ownership(SWIG_as_voidptr($input));
    }
  }


  %typemap(directorout,fragment="SWIG_" "AsPtr" "_" {NoString}) NoString &DIRECTOROUT = NoString

/*@SWIG@*/;
  /*@SWIG:/usr/share/swig1.3/typemaps/ptrtypes.swg,146,%ptr_typecheck_typemap@*/
%typemap(typecheck,noblock=1,precedence=135,fragment="SWIG_" "AsPtr" "_" {NoString}) NoString * {
  int res = SWIG_AsPtr_std_string($input, (NoString**)(0));
  $1 = SWIG_CheckState(res);
}

%typemap(typecheck,noblock=1,precedence=135,fragment="SWIG_" "AsPtr" "_" {NoString}) NoString, const NoString& {
  int res = SWIG_AsPtr_std_string($input, (NoString**)(0));
  $1 = SWIG_CheckState(res);
}
/*@SWIG@*/;
  /*@SWIG:/usr/share/swig1.3/typemaps/inoutlist.swg,254,%ptr_input_typemap@*/
  /*@SWIG:/usr/share/swig1.3/typemaps/inoutlist.swg,117,%_ptr_input_typemap@*/
  %typemap(in,noblock=1,fragment="SWIG_" "AsPtr" "_" {NoString}) NoString *INPUT(int res = 0) {
    res = SWIG_AsPtr_std_string($input, &$1);
    if (!SWIG_IsOK(res)) {
      SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$type""'");
    }
    res = SWIG_AddTmpMask(res);
  }
  %typemap(in,noblock=1,fragment="SWIG_" "AsPtr" "_" {NoString}) NoString &INPUT(int res = 0) {
    res = SWIG_AsPtr_std_string($input, &$1);
    if (!SWIG_IsOK(res)) {
      SWIG_exception_fail(SWIG_ArgError(res), "in method '" "$symname" "', argument " "$argnum"" of type '" "$type""'");
    }
    if (!$1) {
      SWIG_exception_fail(SWIG_ValueError, "invalid null reference " "in method '" "$symname" "', argument " "$argnum"" of type '" "$type""'");
    }
    res = SWIG_AddTmpMask(res);
  }
  %typemap(freearg,noblock=1,match="in") NoString *INPUT, NoString &INPUT {
    if (SWIG_IsNewObj(res$argnum)) free((char*)$1);
  }
  %typemap(typecheck,noblock=1,precedence=135,fragment="SWIG_" "AsPtr" "_" {NoString}) NoString *INPUT, NoString &INPUT {
    int res = SWIG_AsPtr_std_string($input, (NoString**)0);
    $1 = SWIG_CheckState(res);
  }
/*@SWIG@*/
/*@SWIG@*/;
/*@SWIG@*/
  /*@SWIG:/usr/share/swig1.3/typemaps/valtypes.swg,184,%typemaps_from@*/
  /*@SWIG:/usr/share/swig1.3/typemaps/valtypes.swg,55,%value_out_typemap@*/
  %typemap(out,noblock=1,fragment="SWIG_" "From" "_" {NoString}) NoString, const NoString {
    $result = SWIG_From_std_string((NoString)($1));
  }
  %typemap(out,noblock=1,fragment="SWIG_" "From" "_" {NoString}) const NoString& {
    $result = SWIG_From_std_string((NoString)(*$1));
  }
/*@SWIG@*/;
  /*@SWIG:/usr/share/swig1.3/typemaps/valtypes.swg,79,%value_varout_typemap@*/
  %typemap(varout,noblock=1,fragment="SWIG_" "From" "_" {NoString}) NoString, const NoString&  {
    $result = SWIG_From_std_string((NoString)($1));
  }
/*@SWIG@*/;
  /*@SWIG:/usr/share/swig1.3/typemaps/valtypes.swg,87,%value_constcode_typemap@*/
  %typemap(constcode,noblock=1,fragment="SWIG_" "From" "_" {NoString}) NoString {
    SWIG_Python_SetConstant(d, "$symname",SWIG_From_std_string((NoString)($value)));
  }
/*@SWIG@*/;
  /*@SWIG:/usr/share/swig1.3/typemaps/valtypes.swg,98,%value_directorin_typemap@*/
  %typemap(directorin,noblock=1,fragment="SWIG_" "From" "_" {NoString}) NoString *DIRECTORIN {
    $input = SWIG_From_std_string((NoString)(*$1_name));
  }
  %typemap(directorin,noblock=1,fragment="SWIG_" "From" "_" {NoString}) NoString, const NoString& {
    $input = SWIG_From_std_string((NoString)($1_name));
  }
/*@SWIG@*/;
  /*@SWIG:/usr/share/swig1.3/typemaps/valtypes.swg,154,%value_throws_typemap@*/
  %typemap(throws,noblock=1,fragment="SWIG_" "From" "_" {NoString}) NoString {
    SWIG_Python_Raise(SWIG_From_std_string((NoString)($1)), "$type", 0); SWIG_fail;
  }
/*@SWIG@*/;
  /*@SWIG:/usr/share/swig1.3/typemaps/inoutlist.swg,258,%value_output_typemap@*/
  /*@SWIG:/usr/share/swig1.3/typemaps/inoutlist.swg,175,%_value_output_typemap@*/
 %typemap(in,numinputs=0,noblock=1)
   NoString *OUTPUT ($*1_ltype temp, int res = SWIG_TMPOBJ),
   NoString &OUTPUT ($*1_ltype temp, int res = SWIG_TMPOBJ) {
   $1 = &temp;
 }
 %typemap(argout,noblock=1,fragment="SWIG_" "From" "_" {NoString}) NoString *OUTPUT, NoString &OUTPUT {
   if (SWIG_IsTmpObj(res$argnum)) {
     $result = SWIG_Python_AppendOutput($result, SWIG_From_std_string((*$1)));
   } else {
     int new_flags = SWIG_IsNewObj(res$argnum) ? (SWIG_POINTER_OWN |  0 ) :  0 ;
     $result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj((void*)($1), $1_descriptor, new_flags));
   }
 }
/*@SWIG@*/
/*@SWIG@*/;
/*@SWIG@*/;
  /*@SWIG:/usr/share/swig1.3/typemaps/inoutlist.swg,258,%value_output_typemap@*/
  /*@SWIG:/usr/share/swig1.3/typemaps/inoutlist.swg,175,%_value_output_typemap@*/
 %typemap(in,numinputs=0,noblock=1)
   NoString *OUTPUT ($*1_ltype temp, int res = SWIG_TMPOBJ),
   NoString &OUTPUT ($*1_ltype temp, int res = SWIG_TMPOBJ) {
   $1 = &temp;
 }
 %typemap(argout,noblock=1,fragment="SWIG_" "From" "_" {NoString}) NoString *OUTPUT, NoString &OUTPUT {
   if (SWIG_IsTmpObj(res$argnum)) {
     $result = SWIG_Python_AppendOutput($result, SWIG_From_std_string((*$1)));
   } else {
     int new_flags = SWIG_IsNewObj(res$argnum) ? (SWIG_POINTER_OWN |  0 ) :  0 ;
     $result = SWIG_Python_AppendOutput($result, SWIG_NewPointerObj((void*)($1), $1_descriptor, new_flags));
   }
 }
/*@SWIG@*/
/*@SWIG@*/;
  /*@SWIG:/usr/share/swig1.3/typemaps/inoutlist.swg,240,%_ptr_inout_typemap@*/
 /*@SWIG:/usr/share/swig1.3/typemaps/inoutlist.swg,230,%_value_inout_typemap@*/
 %typemap(in) NoString *INOUT = NoString *INPUT;
 %typemap(in) NoString &INOUT = NoString &INPUT;
 %typemap(typecheck) NoString *INOUT = NoString *INPUT;
 %typemap(typecheck) NoString &INOUT = NoString &INPUT;
 %typemap(argout) NoString *INOUT = NoString *OUTPUT;
 %typemap(argout) NoString &INOUT = NoString &OUTPUT;
/*@SWIG@*/
 %typemap(typecheck) NoString *INOUT = NoString *INPUT;
 %typemap(typecheck) NoString &INOUT = NoString &INPUT;
 %typemap(freearg) NoString *INOUT = NoString *INPUT;
 %typemap(freearg) NoString &INOUT = NoString &INPUT;
/*@SWIG@*/;
/*@SWIG@*/;
/*@SWIG@*/;

/*@SWIG@*/;


