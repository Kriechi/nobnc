### SOURCES

set(NO_INCDIR ${PROJECT_SOURCE_DIR}/include/nobnc)

list(APPEND NO_HEADERS ${NO_INCDIR}/noapp.h
                       ${NO_INCDIR}/noapp_p.h
                       ${NO_INCDIR}/noauthenticator.h
                       ${NO_INCDIR}/nobuffer.h
                       ${NO_INCDIR}/nocachemap.h
                       ${NO_INCDIR}/nochannel.h
                       ${NO_INCDIR}/noclient.h
                       ${NO_INCDIR}/noconditionvariable_p.h
                       ${NO_INCDIR}/nodebug.h
                       ${NO_INCDIR}/nodir.h
                       ${NO_INCDIR}/noescape.h
                       ${NO_INCDIR}/noexception.h
                       ${NO_INCDIR}/nofile.h
                       ${NO_INCDIR}/nohostmask.h
                       ${NO_INCDIR}/nohttpsocket.h
                       ${NO_INCDIR}/noircsocket.h
                       ${NO_INCDIR}/nojob_p.h
                       ${NO_INCDIR}/nolistener.h
                       ${NO_INCDIR}/nonamespace.h
                       ${NO_INCDIR}/nomessage.h
                       ${NO_INCDIR}/nomessage_p.h
                       ${NO_INCDIR}/nomodule.h
                       ${NO_INCDIR}/nomodule_p.h
                       ${NO_INCDIR}/nomodulecommand.h
                       ${NO_INCDIR}/nomoduleinfo.h
                       ${NO_INCDIR}/nomoduleloader.h
                       ${NO_INCDIR}/nomodulesocket.h
                       ${NO_INCDIR}/nomutex_p.h
                       ${NO_INCDIR}/nomutexlocker_p.h
                       ${NO_INCDIR}/nonetwork.h
                       ${NO_INCDIR}/nonick.h
                       ${NO_INCDIR}/noprocess.h
                       ${NO_INCDIR}/noquery.h
                       ${NO_INCDIR}/noregistry.h
                       ${NO_INCDIR}/noserverinfo.h
                       ${NO_INCDIR}/nosettings.h
                       ${NO_INCDIR}/nosocket.h
                       ${NO_INCDIR}/nosocketmanager.h
                       ${NO_INCDIR}/nosslverifyhost.h
                       ${NO_INCDIR}/nostring.h
                       ${NO_INCDIR}/notable.h
                       ${NO_INCDIR}/notemplate.h
                       ${NO_INCDIR}/nothreadpool_p.h
                       ${NO_INCDIR}/notimer.h
                       ${NO_INCDIR}/nouser.h
                       ${NO_INCDIR}/nouser_p.h
                       ${NO_INCDIR}/noutils.h
                       ${NO_INCDIR}/nowebpage.h
                       ${NO_INCDIR}/nowebsession.h
                       ${NO_INCDIR}/nowebsocket.h
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
                       nohostmask.cpp
                       nohttpsocket.cpp
                       noircsocket.cpp
                       nolistener.cpp
                       nomessage.cpp
                       nomodule.cpp
                       nomodulecommand.cpp
                       nomoduleinfo.cpp
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
                       nothreadpool.cpp
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
