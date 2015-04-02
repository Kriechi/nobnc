list(APPEND BNC_HEADERS pidfile.h)
list(APPEND BNC_SOURCES main.cpp pidfile.cpp)

add_executable(nobnc ${BNC_SOURCES} ${BNC_HEADERS})
include_directories(${NO_INCLUDEDIRS})
target_link_libraries(nobnc ${NO_LIBRARIES})
set_target_properties(nobnc PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)

if(NOT DEVELOPER)
    install(TARGETS nobnc RUNTIME DESTINATION ${INSTALL_BINDIR})
endif()
