# Defines DEFINE_EXPORT and DEFINE_IMPORT
#
# Based on GenerateExportHeader.cmake
#=============================================================================
# Copyright 2011 Stephen Kelly <steveire@gmail.com>
#
# Distributed under the OSI-approved BSD License (the "License");
# see accompanying file Copyright.txt for details.
#
# This software is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the License for more information.
#=============================================================================

include(CheckCXXCompilerFlag)

macro(_check_cxx_compiler_attribute _ATTRIBUTE _RESULT)
  check_cxx_source_compiles("${_ATTRIBUTE} int somefunc() { return 0; }
    int main() { return somefunc();}" ${_RESULT}
  )
endmacro()

macro(_test_compiler_hidden_visibility)

  if(CMAKE_COMPILER_IS_GNUCXX AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "4.2")
    set(GCC_TOO_OLD TRUE)
  elseif(CMAKE_COMPILER_IS_GNUC AND CMAKE_C_COMPILER_VERSION VERSION_LESS "4.2")
    set(GCC_TOO_OLD TRUE)
  elseif(CMAKE_CXX_COMPILER_ID MATCHES Intel AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "12.0")
    set(_INTEL_TOO_OLD TRUE)
  endif()

  # Exclude XL here because it misinterprets -fvisibility=hidden even though
  # the check_cxx_compiler_flag passes
  # http://www.cdash.org/CDash/testDetails.php?test=109109951&build=1419259
  if(NOT GCC_TOO_OLD
      AND NOT _INTEL_TOO_OLD
      AND NOT WIN32
      AND NOT CYGWIN
      AND NOT "${CMAKE_CXX_COMPILER_ID}" MATCHES XL
      AND NOT "${CMAKE_CXX_COMPILER_ID}" MATCHES PGI
      AND NOT "${CMAKE_CXX_COMPILER_ID}" MATCHES Watcom)
    check_cxx_compiler_flag(-fvisibility=hidden COMPILER_HAS_HIDDEN_VISIBILITY)
    check_cxx_compiler_flag(-fvisibility-inlines-hidden COMPILER_HAS_HIDDEN_INLINE_VISIBILITY)
    option(USE_COMPILER_HIDDEN_VISIBILITY
      "Use HIDDEN visibility support if available." ON)
    mark_as_advanced(USE_COMPILER_HIDDEN_VISIBILITY)
  endif()
endmacro()

macro(_DO_SET_MACRO_VALUES)
  set(DEFINE_EXPORT)
  set(DEFINE_IMPORT)

  if(WIN32 OR CYGWIN)
    set(DEFINE_EXPORT "__declspec(dllexport)")
    set(DEFINE_IMPORT "__declspec(dllimport)")
  elseif(COMPILER_HAS_HIDDEN_VISIBILITY AND USE_COMPILER_HIDDEN_VISIBILITY)
    set(DEFINE_EXPORT "__attribute__((visibility(\"default\")))")
    set(DEFINE_IMPORT "__attribute__((visibility(\"default\")))")
  endif()
endmacro()

_test_compiler_hidden_visibility()
_do_set_macro_values()
