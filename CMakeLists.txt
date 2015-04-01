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

### SUBDIRS

add_subdirectory(src/lib)
list(APPEND NO_LIBRARIES libnobnc)
add_subdirectory(src/bnc)
add_subdirectory(src/modules)
add_subdirectory(share)
add_subdirectory(tests)

### FLAGS

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

### GENERATED FILES

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
