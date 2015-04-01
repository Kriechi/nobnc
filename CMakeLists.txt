cmake_minimum_required(VERSION 2.8.4)
project(NoBNC)

set(NO_VERSION_MAJOR 1)
set(NO_VERSION_MINOR 7)
set(NO_VERSION_PATCH -1)
set(NO_VERSION_STR "1.7.x")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

include(DefineFeatures)
include(DefineDirectories)
include(DefineBuildFlags)
include(DefineVersion)

### SUB MODULES

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/src/3rdparty/Csocket/Csocket.h")
    message(FATAL_ERROR "Run 'git submodule update --init' (src/3rdparty/Csocket missing).")
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/src/3rdparty/sha2/sha2.h")
    message(FATAL_ERROR "Run 'git submodule update --init' (src/3rdparty/sha2 missing).")
endif()

### SOURCES

list(APPEND NO_HEADERS include/nobnc/noapp.h
                       include/nobnc/noapp_p.h
                       include/nobnc/noauthenticator.h
                       include/nobnc/nobuffer.h
                       include/nobnc/nocachemap.h
                       include/nobnc/nochannel.h
                       include/nobnc/noclient.h
                       include/nobnc/noconditionvariable.h
                       include/nobnc/nodebug.h
                       include/nobnc/nodir.h
                       include/nobnc/noescape.h
                       include/nobnc/noexception.h
                       include/nobnc/nofile.h
                       include/nobnc/nohttpsocket.h
                       include/nobnc/noircsocket.h
                       include/nobnc/nojob.h
                       include/nobnc/nolistener.h
                       include/nobnc/nonamespace.h
                       include/nobnc/nomessage.h
                       include/nobnc/nomessage_p.h
                       include/nobnc/nomodule.h
                       include/nobnc/nomodule_p.h
                       include/nobnc/nomodulecall.h
                       include/nobnc/nomodulecommand.h
                       include/nobnc/nomoduleinfo.h
                       include/nobnc/nomodulejob.h
                       include/nobnc/nomoduleloader.h
                       include/nobnc/nomodulesocket.h
                       include/nobnc/nomutex.h
                       include/nobnc/nomutexlocker.h
                       include/nobnc/nonetwork.h
                       include/nobnc/nonick.h
                       include/nobnc/noprocess.h
                       include/nobnc/noquery.h
                       include/nobnc/noregistry.h
                       include/nobnc/noserverinfo.h
                       include/nobnc/nosettings.h
                       include/nobnc/nosocket.h
                       include/nobnc/nosocketmanager.h
                       include/nobnc/nosslverifyhost.h
                       include/nobnc/nostring.h
                       include/nobnc/notable.h
                       include/nobnc/notemplate.h
                       include/nobnc/nothread.h
                       include/nobnc/nothread_p.h
                       include/nobnc/notimer.h
                       include/nobnc/nouser.h
                       include/nobnc/noutils.h
                       include/nobnc/nowebpage.h
                       include/nobnc/nowebsession.h
                       include/nobnc/nowebsocket.h
                       src/3rdparty/defines.h
                       src/3rdparty/md5/md5.h
                       src/3rdparty/sha2/sha2.h
                       src/3rdparty/Csocket/Csocket.h
                       ${PROJECT_BINARY_DIR}/include/nobnc/noglobal.h
)

list(APPEND NO_SOURCES src/noapp.cpp
                       src/noauthenticator.cpp
                       src/nobuffer.cpp
                       src/nochannel.cpp
                       src/noclient.cpp
                       src/noclientcommand.cpp
                       src/nodebug.cpp
                       src/nodir.cpp
                       src/noescape.cpp
                       src/noexception.cpp
                       src/nofile.cpp
                       src/nohttpsocket.cpp
                       src/noircsocket.cpp
                       src/nolistener.cpp
                       src/nomessage.cpp
                       src/nomodule.cpp
                       src/nomodulecommand.cpp
                       src/nomoduleinfo.cpp
                       src/nomodulejob.cpp
                       src/nomoduleloader.cpp
                       src/nomodulesocket.cpp
                       src/nonetwork.cpp
                       src/nonick.cpp
                       src/noprocess.cpp
                       src/noquery.cpp
                       src/noregistry.cpp
                       src/noserverinfo.cpp
                       src/nosettings.cpp
                       src/nosocket.cpp
                       src/nosocketmanager.cpp
                       src/nosslverifyhost.cpp
                       src/nostring.cpp
                       src/notable.cpp
                       src/notemplate.cpp
                       src/nothread.cpp
                       src/notimer.cpp
                       src/nouser.cpp
                       src/noutils.cpp
                       src/nowebpage.cpp
                       src/nowebsession.cpp
                       src/3rdparty/md5/md5.cpp
                       src/3rdparty/sha2/sha2.c
                       src/3rdparty/Csocket/Csocket.cc
                       ${PROJECT_BINARY_DIR}/src/noglobal.cpp
)

### TARGETS

add_library(libno SHARED ${NO_SOURCES} ${NO_HEADERS})
include_directories(${NO_INCLUDEDIRS} src/3rdparty)
include_directories(${PROJECT_SOURCE_DIR}/include/nobnc) ### TODO: cleanup
include_directories(${PROJECT_BINARY_DIR}/include/nobnc) ### TODO: cleanup
target_link_libraries(libno ${NO_LIBRARIES})
set_target_properties(libno PROPERTIES OUTPUT_NAME no DEFINE_SYMBOL EXPORT_NO)
add_dependencies(libno version)

list(APPEND NO_LIBRARIES libno)

add_executable(nobnc src/main.cpp)
target_link_libraries(nobnc ${NO_LIBRARIES})

add_subdirectory(modules)
add_subdirectory(share)
add_subdirectory(tests)

### INSTALLS

if(NOT DEVELOPER)
    install(TARGETS nobnc RUNTIME DESTINATION ${INSTALL_BINDIR})
    install(TARGETS libno LIBRARY DESTINATION ${INSTALL_LIBDIR}
                          RUNTIME DESTINATION ${INSTALL_BINDIR}
                          ARCHIVE DESTINATION ${INSTALL_LIBDIR})
    install(DIRECTORY include/nobnc DESTINATION ${INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN *.h)
endif()

### GENERATED FILES

configure_file("${PROJECT_SOURCE_DIR}/include/nobnc/noglobal.h.in"
               "${PROJECT_BINARY_DIR}/include/nobnc/noglobal.h")
configure_file("${PROJECT_SOURCE_DIR}/include/nobnc/noconfig.h.in"
               "${PROJECT_BINARY_DIR}/include/nobnc/noconfig.h")
configure_file("${PROJECT_SOURCE_DIR}/src/noglobal.cpp.in"
               "${PROJECT_BINARY_DIR}/src/noglobal.cpp")

if(NOT DEVELOPER)
    install(FILES "${PROJECT_BINARY_DIR}/include/nobnc/noconfig.h"
            DESTINATION ${INSTALL_INCLUDEDIR}/no)
    install(FILES "${PROJECT_BINARY_DIR}/include/nobnc/noglobal.h"
            DESTINATION ${INSTALL_INCLUDEDIR}/no)
endif()

process_definitions("${NO_DEFINITIONS}" NO_DEFINITION_FLAGS)
process_includedirs("${NO_INCLUDEDIRS}" NO_INCLUDE_FLAGS)
process_link_libraries("${NO_LIBRARIES}" NO_LIBRARY_FLAGS)

if(NOT DEVELOPER)
    set(NO_INCLUDE_FLAGS "-I${INSTALL_INCLUDEDIR} ${NO_INCLUDE_FLAGS}")
    set(NO_LIBRARY_FLAGS "-L${INSTALL_LIBDIR} ${NO_LIBRARY_FLAGS}")
else()
    set(NO_INCLUDE_FLAGS "-I${PROJECT_SOURCE_DIR}/include -I${PROJECT_BINARY_DIR}/include ${NO_INCLUDE_FLAGS}")
    set(NO_LIBRARY_FLAGS "-L${PROJECT_BINARY_DIR} ${NO_LIBRARY_FLAGS}")
endif()

set(NO_CXXFLAGS "${CMAKE_SHARED_MODULE_CXX_FLAGS} ${CMAKE_CXX_FLAGS} ${NO_DEFINITION_FLAGS} ${NO_INCLUDE_FLAGS}")
set(NO_LDFLAGS "${CMAKE_SHARED_MODULE_CREATE_CXX_FLAGS} ${NO_LIBRARY_FLAGS}")

configure_file("${PROJECT_SOURCE_DIR}/nobnc-buildmod.in"
               "${PROJECT_BINARY_DIR}/nobnc-buildmod" @ONLY)

configure_file("${PROJECT_SOURCE_DIR}/nobnc.pc.in"
               "${PROJECT_BINARY_DIR}/nobnc.pc" @ONLY)

if(NOT DEVELOPER)
    install(FILES "${PROJECT_BINARY_DIR}/nobnc.pc" DESTINATION ${INSTALL_LIBDIR}/pkgconfig)
    install(PROGRAMS "${PROJECT_BINARY_DIR}/nobnc-buildmod" DESTINATION ${INSTALL_BINDIR})
endif()

### PACKAGE

if(NOT DEVELOPER)
    if(NOT CPACK_SOURCE_PACKAGE_FILE_NAME)
        set(CPACK_SOURCE_PACKAGE_FILE_NAME "nobnc-${NO_VERSION}")
    endif()
    if(NOT CPACK_OUTPUT_FILE_PREFIX)
        set(CPACK_OUTPUT_FILE_PREFIX ${PROJECT_BINARY_DIR})
    endif()
    set(CPACK_PACKAGE_NAME nobnc)
    set(CPACK_PACKAGE_VENDOR "http://nobnc.github.io")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "NoBNC - a Nordic IRC bouncer")
    set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/README.md")
    set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
    set(CPACK_PACKAGE_VERSION_MAJOR ${NO_VERSION_MAJOR})
    set(CPACK_PACKAGE_VERSION_MINOR ${NO_VERSION_MINOR})
    set(CPACK_PACKAGE_VERSION_PATCH ${NO_VERSION_PATCH})
    set(CPACK_PACKAGE_VERSION ${NO_VERSION})
    set(CPACK_GENERATOR TGZ)
    set(CPACK_SOURCE_GENERATOR TGZ)
    set(CPACK_STRIP_FILES "nobnc")
    set(CPACK_PACKAGE_EXECUTABLES "nobnc" "NoBNC IRC bouncer")
    set(CPACK_SOURCE_IGNORE_FILES "/.git;Makefile;CMakeFiles;CMakeCache.txt;CPackConfig.cmake;CPackSourceConfig.cmake;cmake_install.cmake;/*.log;/.travis*;/*.gz;make-tarball.sh")
    include(CPack)

    set(NO_TARBALL "${CPACK_OUTPUT_FILE_PREFIX}/${CPACK_SOURCE_PACKAGE_FILE_NAME}.tar.gz")
    add_custom_target(package_sign COMMAND gpg --detach-sign ${NO_TARBALL} COMMENT "Signing ${NO_TARBALL}...")
endif()

### SUMMARY

set(BUILD_TYPE ${CMAKE_BUILD_TYPE})
if(DEVELOPER)
    set(BUILD_TYPE "${BUILD_TYPE} (developer)")
endif()

message(STATUS "")
message(STATUS "${PROJECT_NAME} ${NO_VERSION} configuration:")
message(STATUS "")
if(NOT DEVELOPER)
    message(STATUS "Prefix ............... ${INSTALL_PREFIX}")
endif()
message(STATUS "Build ................ ${BUILD_TYPE}")
message(STATUS "IPv6 ................. ${HAVE_IPV6}")
message(STATUS "SSL .................. ${HAVE_LIBSSL}")
message(STATUS "ICU .................. ${HAVE_ICU}")
message(STATUS "Zlib ................. ${HAVE_ZLIB}")
message(STATUS "SASL ................. ${HAVE_SASL}")
message(STATUS "Threads .............. ${HAVE_THREADS}")
message(STATUS "")
