cmake_minimum_required(VERSION 3.05)

project(test LANGUAGES C CXX)

message(STATUS "Project: test")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
  message(STATUS "Build type not specified: Use Release by default")
endif(NOT CMAKE_BUILD_TYPE)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_FLAGS_DEBUG_INIT "-Wall")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-Wall")
#set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")
set(CMAKE_SKIP_RPATH ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out)

set(PATH_PRJ ${CMAKE_CURRENT_SOURCE_DIR})
set(PATH_COMMON_LOADERS ${PATH_PRJ}/../common/loaders)
set(PATH_COMMON_JSON ${PATH_PRJ}/../common/json)

include_directories(
    ${PATH_COMMON_LOADERS}
    ${PATH_COMMON_JSON}
)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../out)

add_executable (test
    test.cpp
    ${PATH_COMMON_LOADERS}/uapki-loader.cpp
    ${PATH_COMMON_JSON}/parson.c
    ${PATH_COMMON_JSON}/parson-helper.cpp
    ${PATH_COMMON_JSON}/strtod-no-locale.c
)

if(${UNIX})
    target_link_libraries(test PRIVATE dl)
endif()


add_custom_command(TARGET test POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:test> ../out/
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:test> ../../${OUT_DIR}/
)
