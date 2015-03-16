include(CheckCXXCompilerFlag)
include(CheckCSourceCompiles)
include(CheckFileOffsetBits)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckIncludeFiles)
include(DefineVisibility)

include_directories("${PROJECT_SOURCE_DIR}/include")
include_directories("${PROJECT_BINARY_DIR}/include")

list(APPEND NO_DEFINITIONS "-D_MODDIR_=\"${NO_MODDIR}\"")
list(APPEND NO_DEFINITIONS "-D_DATADIR_=\"${NO_DATADIR}\"")

add_definitions(${NO_DEFINITIONS})

check_cxx_compiler_flag("-std=c++11" COMPILER_SUPPORTS_CXX11)
if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
    check_cxx_compiler_flag("-std=c++0x" COMPILER_SUPPORTS_CXX0X)
    if(COMPILER_SUPPORTS_CXX0X)
        check_cxx_source_compiles("struct Base { virtual void f() {} };
                                   struct Child : public Base { virtual void f() override {} };
                                   int main() {}" COMPILER_SUPPORTS_CXX0X)
    endif()
    if(COMPILER_SUPPORTS_CXX0X)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
    else()
        message(FATAL_ERROR "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
    endif()
endif()

check_file_offset_bits()

check_function_exists(getopt_long HAVE_GETOPT_LONG)
check_function_exists(getphassphrase HAVE_GETPHASSPHRASE)
check_function_exists(lstat HAVE_LSTAT)

check_library_exists(gnugetopt getopt_long "" HAVE_LIBGNUGETOPT)

if(HAVE_PTHREAD)
    check_symbol_exists(PTHREAD_CREATE_JOINABLE pthread.h HAVE_PTHREAD_CREATE_JOINABLE)
    if(NOT HAVE_PTHREAD_CREATE_JOINABLE)
        check_symbol_exists(PTHREAD_CREATE_DETACHED pthread.h HAVE_PTHREAD_CREATE_DETACHED)
        if(HAVE_PTHREAD_CREATE_DETACHED)
            set(PTHREAD_CREATE_JOINABLE "PTHREAD_CREATE_DETACHED")
        endif()
    endif()
    check_symbol_exists(PTHREAD_PRIO_INHERIT pthread.h HAVE_PTHREAD_PRIO_INHERIT)
    check_c_source_compiles("#include <sys/types.h>
                            #include <sys/socket.h>
                            #include <netdb.h>
                            int main() { int x = AI_ADDRCONFIG; (void) x; }" HAVE_THREADED_DNS)
endif()

if(CYGWIN)
    # We don't want to use -std=gnu++11 instead of -std=c++11, but among other things,
    # -std=c++11 defines __STRICT_ANSI__ which makes cygwin not to compile: undefined references to
    # strerror_r, fdopen and strcasecmp etc. (their declarations in system headers are between ifdef)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -U__STRICT_ANSI__")
elseif(CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -W -Wno-unused-parameter -Woverloaded-virtual -Wshadow")
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        # These enable some debug options in g++'s STL, e.g. invalid use of iterators
        # But they cause crashes on cygwin while loading modules
        set(_GLIBCXX_DEBUG ON)
        set(_GLIBCXX_DEBUG_PEDANTIC ON)
    endif()
endif()

if(NOT DEFINED CMAKE_MACOSX_RPATH)
    set(CMAKE_MACOSX_RPATH ON)
endif()
SET(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib)

macro(process_definitions _DEFINITIONS _OUTPUT)
    foreach(_def ${_DEFINITIONS})
        if(${_def} MATCHES "^-.*")
            list(APPEND _defs ${_def})
        else()
            list(APPEND _defs "-D${_def}")
        endif()
    endforeach()
    if(_defs)
        list(REMOVE_DUPLICATES _defs)
        string(REPLACE ";" " " ${_OUTPUT} "${_defs}")
    endif()
endmacro()

macro(process_includedirs _INCLUDEDIRS _OUTPUT)
    foreach(_dir ${_INCLUDEDIRS})
        if(${_dir} MATCHES "^-.*")
            list(APPEND _dirs ${_dir})
        else()
            list(APPEND _dirs "-I${_dir}")
        endif()
    endforeach()
    if(_dirs)
        list(REMOVE_DUPLICATES _dirs)
        string(REPLACE ";" " " ${_OUTPUT} "${_dirs}")
    endif()
endmacro()

macro(process_link_libraries _LIBRARIES _OUTPUT)
    foreach(_lib ${_LIBRARIES})
        if(${_lib} MATCHES "^-.*")
            list(APPEND _ldflags ${_lib})
        else()
            get_filename_component(_dir ${_lib} PATH)
            if(_dir)
                list(APPEND _ldflags "-L${_dir}")
            endif()
            get_filename_component(_name ${_lib} NAME_WE)
            string(REGEX REPLACE "^lib" "" _name ${_name})
            if(_name)
                list(APPEND _ldflags "-l${_name}")
            endif()
        endif()
    endforeach()
    if(_ldflags)
        list(REMOVE_DUPLICATES _ldflags)
        string(REPLACE ";" " " ${_OUTPUT} "${_ldflags}")
    endif()
endmacro()
