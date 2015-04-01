add_executable(nobnc main.cpp)
target_link_libraries(nobnc ${NO_LIBRARIES})
set_target_properties(nobnc PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)

if(NOT DEVELOPER)
    install(TARGETS nobnc RUNTIME DESTINATION ${INSTALL_BINDIR})
endif()
