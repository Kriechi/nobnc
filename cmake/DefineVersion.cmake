if(NOT DEFINED NO_VERSION_MAJOR OR NOT DEFINED NO_VERSION_MINOR OR NOT DEFINED NO_VERSION_PATCH OR NOT DEFINED NO_VERSION_STR)
    message(FATAL_ERROR "NO_VERSION_(MAJOR|MINOR|PATCH|STR) must be defined in the beginning of the root CMakeLists.txt.")
endif()

if(NOT DEFINED NO_VERSION_EXTRA)
    set(NO_VERSION_EXTRA $ENV{NO_VERSION_EXTRA})
    if(NOT NO_VERSION_EXTRA)
        if(GIT_EXECUTABLE)
            execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
                            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                            RESULT_VARIABLE GIT_RES
                            OUTPUT_VARIABLE GIT_SHA1
                            OUTPUT_STRIP_TRAILING_WHITESPACE)
            if(NOT GIT_RES)
                set(NO_VERSION_EXTRA "git-${GIT_SHA1}")
            endif()
        endif()
    endif()
endif()

if(NO_VERSION_EXTRA)
    set(NO_VERSION ${NO_VERSION_MAJOR}.${NO_VERSION_MINOR}-${NO_VERSION_EXTRA})
else()
    set(NO_VERSION ${NO_VERSION_MAJOR}.${NO_VERSION_MINOR}.${NO_VERSION_PATCH})
endif()

if(NO_VERSION_INPUT AND NO_VERSION_OUTPUT)
    configure_file(${NO_VERSION_INPUT} ${NO_VERSION_OUTPUT})
else()
    add_custom_target(version ${CMAKE_COMMAND}
                  -D GIT_EXECUTABLE=${GIT_EXECUTABLE}
                  -D PROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
                  -D NO_VERSION_MAJOR=${NO_VERSION_MAJOR}
                  -D NO_VERSION_MINOR=${NO_VERSION_MINOR}
                  -D NO_VERSION_PATCH=${NO_VERSION_PATCH}
                  -D NO_VERSION_STR=${NO_VERSION_STR}
                  -D NO_VERSION_INPUT=${PROJECT_SOURCE_DIR}/src/noversion.cpp.in
                  -D NO_VERSION_OUTPUT=${PROJECT_BINARY_DIR}/src/noversion.cpp
                  -P ${PROJECT_SOURCE_DIR}/cmake/DefineVersion.cmake)
endif()
