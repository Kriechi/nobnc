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

### SOURCES

list(APPEND NO_HEADERS include/znc/defines.h
                       include/znc/main.h
                       include/znc/noapp.h
                       include/znc/nobuffer.h
                       include/znc/nochannel.h
                       include/znc/noclient.h
                       include/znc/nodebug.h
                       include/znc/nodir.h
                       include/znc/noexecsock.h
                       include/znc/nofile.h
                       include/znc/nohttpsock.h
                       include/znc/noircsock.h
                       include/znc/nolistener.h
                       include/znc/nomd5.h
                       include/znc/nomessage.h
                       include/znc/nomodule.h
                       include/znc/nomodules.h
                       include/znc/nonetwork.h
                       include/znc/nonick.h
                       include/znc/noquery.h
                       include/znc/noserver.h
                       include/znc/nosettings.h
                       include/znc/nosha256.h
                       include/znc/nosocket.h
                       include/znc/nosslverifyhost.h
                       include/znc/nostring.h
                       include/znc/notemplate.h
                       include/znc/nothreads.h
                       include/znc/notimer.h
                       include/znc/nouser.h
                       include/znc/noutils.h
                       include/znc/nowebmodules.h
                       ${PROJECT_BINARY_DIR}/include/znc/Csocket.h
                       ${PROJECT_BINARY_DIR}/include/znc/noversion.h
)

list(APPEND NO_SOURCES src/noapp.cpp
                       src/nobuffer.cpp
                       src/nochannel.cpp
                       src/noclient.cpp
                       src/noclientcommand.cpp
                       src/nodebug.cpp
                       src/nodir.cpp
                       src/nofile.cpp
                       src/nohttpsock.cpp
                       src/noircsock.cpp
                       src/nolistener.cpp
                       src/nomd5.cpp
                       src/nomessage.cpp
                       src/nomodule.cpp
                       src/nomodules.cpp
                       src/nonetwork.cpp
                       src/nonick.cpp
                       src/noquery.cpp
                       src/noserver.cpp
                       src/nosettings.cpp
                       src/nosha256.cpp
                       src/nosocket.cpp
                       src/nosslverifyhost.cpp
                       src/nostring.cpp
                       src/notemplate.cpp
                       src/nothreads.cpp
                       src/notimer.cpp
                       src/nouser.cpp
                       src/noutils.cpp
                       src/nowebmodules.cpp
                       ${PROJECT_BINARY_DIR}/src/Csocket.cpp
                       ${PROJECT_BINARY_DIR}/src/noversion.cpp
)

### TARGETS

add_library(libno SHARED ${NO_SOURCES} ${NO_HEADERS})
include_directories(${NO_INCLUDEDIRS})
include_directories(${PROJECT_SOURCE_DIR}/include/znc) ### TODO: cleanup
include_directories(${PROJECT_BINARY_DIR}/include/znc) ### TODO: cleanup
target_link_libraries(libno ${NO_LIBRARIES})
set_target_properties(libno PROPERTIES OUTPUT_NAME no)
add_dependencies(libno version)

list(APPEND NO_LIBRARIES libno)

add_executable(nobnc src/main.cpp)
target_link_libraries(nobnc ${NO_LIBRARIES})

add_subdirectory(modules)
add_subdirectory(share)
add_subdirectory(test)

### INSTALLS

if(NOT DEVELOPER_BUILD)
    install(TARGETS nobnc RUNTIME DESTINATION ${INSTALL_BINDIR})
    install(TARGETS libno LIBRARY DESTINATION ${INSTALL_LIBDIR}
                          RUNTIME DESTINATION ${INSTALL_BINDIR}
                          ARCHIVE DESTINATION ${INSTALL_LIBDIR})
    install(DIRECTORY include/znc DESTINATION ${INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN *.h)
endif()

### GENERATED FILES

configure_file("${PROJECT_SOURCE_DIR}/include/znc/noconfig.h.in"
               "${PROJECT_BINARY_DIR}/include/znc/noconfig.h")
configure_file("${PROJECT_SOURCE_DIR}/include/znc/noversion.h.in"
               "${PROJECT_BINARY_DIR}/include/znc/noversion.h")
configure_file("${PROJECT_SOURCE_DIR}/src/noversion.cpp.in"
               "${PROJECT_BINARY_DIR}/src/noversion.cpp")
configure_file("${PROJECT_SOURCE_DIR}/third_party/Csocket/Csocket.cc"
               "${PROJECT_BINARY_DIR}/src/Csocket.cpp" COPYONLY)
configure_file("${PROJECT_SOURCE_DIR}/third_party/Csocket/Csocket.h"
               "${PROJECT_BINARY_DIR}/include/znc/Csocket.h" COPYONLY)

if(NOT DEVELOPER_BUILD)
    install(FILES "${PROJECT_BINARY_DIR}/include/znc/noconfig.h"
            DESTINATION ${INSTALL_INCLUDEDIR}/znc)
    install(FILES "${PROJECT_BINARY_DIR}/include/znc/noversion.h"
            DESTINATION ${INSTALL_INCLUDEDIR}/znc)
endif()

process_definitions("${NO_DEFINITIONS}" NO_DEFINITION_FLAGS)
process_includedirs("${NO_INCLUDEDIRS}" NO_INCLUDE_FLAGS)
process_link_libraries("${NO_LIBRARIES}" NO_LIBRARY_FLAGS)

if(NOT DEVELOPER_BUILD)
    set(NO_INCLUDE_FLAGS "-I${INSTALL_INCLUDEDIR} ${NO_INCLUDE_FLAGS}")
    set(NO_LIBRARY_FLAGS "-L${INSTALL_LIBDIR} ${NO_LIBRARY_FLAGS}")
else()
    set(NO_INCLUDE_FLAGS "-I${PROJECT_SOURCE_DIR}/include -I${PROJECT_BINARY_DIR}/include ${NO_INCLUDE_FLAGS}")
    set(NO_LIBRARY_FLAGS "-L${PROJECT_BINARY_DIR} ${NO_LIBRARY_FLAGS}")
endif()

set(NO_CXXFLAGS "${CMAKE_SHARED_MODULE_CXX_FLAGS} ${CMAKE_CXX_FLAGS} ${NO_DEFINITION_FLAGS} ${NO_INCLUDE_FLAGS}")
set(NO_LDFLAGS "${CMAKE_SHARED_MODULE_CREATE_CXX_FLAGS} ${NO_LIBRARY_FLAGS}")

configure_file("${PROJECT_SOURCE_DIR}/znc-buildmod.in"
               "${PROJECT_BINARY_DIR}/znc-buildmod" @ONLY)

configure_file("${PROJECT_SOURCE_DIR}/znc.pc.in"
               "${PROJECT_BINARY_DIR}/znc.pc" @ONLY)

if(NOT DEVELOPER_BUILD)
    install(FILES "${PROJECT_BINARY_DIR}/znc.pc" DESTINATION ${INSTALL_LIBDIR}/pkgconfig)
    install(PROGRAMS "${PROJECT_BINARY_DIR}/znc-buildmod" DESTINATION ${INSTALL_BINDIR})
endif()

### PACKAGE

if(NOT DEVELOPER_BUILD)
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
if(DEVELOPER_BUILD)
    set(BUILD_TYPE "${BUILD_TYPE} (developer)")
endif()

message(STATUS "")
message(STATUS "${PROJECT_NAME} ${NO_VERSION} configuration:")
message(STATUS "")
if(NOT DEVELOPER_BUILD)
    message(STATUS "Prefix ............... ${INSTALL_PREFIX}")
endif()
message(STATUS "Build ................ ${BUILD_TYPE}")
message(STATUS "IPv6 ................. ${HAVE_IPV6}")
message(STATUS "SSL .................. ${HAVE_LIBSSL}")
message(STATUS "ICU .................. ${HAVE_ICU}")
message(STATUS "Zlib ................. ${HAVE_ZLIB}")
message(STATUS "Cyrus ................ ${HAVE_CYRUS}")
message(STATUS "Threads .............. ${HAVE_THREADS}")
message(STATUS "")
