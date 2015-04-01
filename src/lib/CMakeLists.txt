### SOURCES

list(APPEND NO_HEADERS ${PROJECT_SOURCE_DIR}/include/nobnc/noapp.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/noapp_p.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/noauthenticator.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nobuffer.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nocachemap.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nochannel.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/noclient.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/noconditionvariable.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nodebug.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nodir.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/noescape.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/noexception.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nofile.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nohttpsocket.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/noircsocket.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nojob.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nolistener.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nonamespace.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nomessage.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nomessage_p.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nomodule.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nomodule_p.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nomodulecall.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nomodulecommand.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nomoduleinfo.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nomodulejob.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nomoduleloader.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nomodulesocket.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nomutex.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nomutexlocker.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nonetwork.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nonick.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/noprocess.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/noquery.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/noregistry.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/noserverinfo.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nosettings.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nosocket.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nosocketmanager.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nosslverifyhost.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nostring.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/notable.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/notemplate.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nothread.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nothread_p.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/notimer.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nouser.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/noutils.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nowebpage.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nowebsession.h
                       ${PROJECT_SOURCE_DIR}/include/nobnc/nowebsocket.h
                       ../3rdparty/defines.h
                       ../3rdparty/md5/md5.h
                       ../3rdparty/sha2/sha2.h
                       ../3rdparty/Csocket/Csocket.h
                       ${PROJECT_BINARY_DIR}/include/nobnc/noglobal.h
)

list(APPEND NO_SOURCES noapp.cpp
                       noauthenticator.cpp
                       nobuffer.cpp
                       nochannel.cpp
                       noclient.cpp
                       noclientcommand.cpp
                       nodebug.cpp
                       nodir.cpp
                       noescape.cpp
                       noexception.cpp
                       nofile.cpp
                       nohttpsocket.cpp
                       noircsocket.cpp
                       nolistener.cpp
                       nomessage.cpp
                       nomodule.cpp
                       nomodulecommand.cpp
                       nomoduleinfo.cpp
                       nomodulejob.cpp
                       nomoduleloader.cpp
                       nomodulesocket.cpp
                       nonetwork.cpp
                       nonick.cpp
                       noprocess.cpp
                       noquery.cpp
                       noregistry.cpp
                       noserverinfo.cpp
                       nosettings.cpp
                       nosocket.cpp
                       nosocketmanager.cpp
                       nosslverifyhost.cpp
                       nostring.cpp
                       notable.cpp
                       notemplate.cpp
                       nothread.cpp
                       notimer.cpp
                       nouser.cpp
                       noutils.cpp
                       nowebpage.cpp
                       nowebsession.cpp
                       ../3rdparty/md5/md5.cpp
                       ../3rdparty/sha2/sha2.c
                       ../3rdparty/Csocket/Csocket.cc
                       ${PROJECT_BINARY_DIR}/src/lib/noglobal.cpp
)

### TARGETS

add_library(libnobnc SHARED ${NO_SOURCES} ${NO_HEADERS})
include_directories(${NO_INCLUDEDIRS} ../3rdparty)
include_directories(${PROJECT_SOURCE_DIR}/include/nobnc) ### TODO: cleanup
include_directories(${PROJECT_BINARY_DIR}/include/nobnc) ### TODO: cleanup
target_link_libraries(libnobnc ${NO_LIBRARIES})
set_target_properties(libnobnc PROPERTIES OUTPUT_NAME nobnc
                                          LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
                                          DEFINE_SYMBOL EXPORT_NO)
add_dependencies(libnobnc version)

### INSTALLS

if(NOT DEVELOPER)
    install(TARGETS libnobnc LIBRARY DESTINATION ${INSTALL_LIBDIR}
                             RUNTIME DESTINATION ${INSTALL_BINDIR}
                             ARCHIVE DESTINATION ${INSTALL_LIBDIR})
    install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/nobnc DESTINATION ${INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN *.h)
endif()

### GENERATED FILES

configure_file("${PROJECT_SOURCE_DIR}/include/nobnc/noglobal.h.in"
               "${PROJECT_BINARY_DIR}/include/nobnc/noglobal.h")
configure_file("${PROJECT_SOURCE_DIR}/include/nobnc/noconfig.h.in"
               "${PROJECT_BINARY_DIR}/include/nobnc/noconfig.h")
configure_file("${PROJECT_SOURCE_DIR}/src/lib/noglobal.cpp.in"
               "${PROJECT_BINARY_DIR}/src/lib/noglobal.cpp")

if(NOT DEVELOPER)
    install(FILES "${PROJECT_BINARY_DIR}/include/nobnc/noconfig.h"
            DESTINATION ${INSTALL_INCLUDEDIR}/no)
    install(FILES "${PROJECT_BINARY_DIR}/include/nobnc/noglobal.h"
            DESTINATION ${INSTALL_INCLUDEDIR}/no)
endif()
