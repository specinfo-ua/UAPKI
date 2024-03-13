cmake_minimum_required(VERSION 3.17)

project(uapki LANGUAGES C CXX)
set(UAPKI_VERSION 2.0.12)
set(UAPKI_SOVERSION 2)
message(STATUS "Project: uapki, version: " ${UAPKI_VERSION})

option(UAPKI_DISABLE_COPY "Disable copying into out dir" OFF)
option(UAPKI_PUBLIC_INTERNAL_INCLUDES "Exposes uapki library internal include files" OFF)

if (DEFINED UAPKI_LIBS_TYPE)
    if (NOT UAPKI_LIBS_TYPE STREQUAL SHARED AND NOT UAPKI_LIBS_TYPE STREQUAL STATIC)
        message(FATAL_ERROR "Bad UAPKI_LIBS_TYPE")
    endif ()
else ()
    set(UAPKI_LIBS_TYPE SHARED)
endif ()

set(UAPKI_INTERNAL_INCLUDES_MODE PRIVATE)
if (UAPKI_PUBLIC_INTERNAL_INCLUDES)
    set(UAPKI_INTERNAL_INCLUDES_MODE PUBLIC)
endif ()

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
    message(STATUS "Build type not specified: Use Release by default")
endif (NOT CMAKE_BUILD_TYPE)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_DEBUG_INIT "-Wall")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-Wall")
set(CMAKE_SKIP_RPATH ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

if (${WIN32})
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif ()

find_package(CURL REQUIRED)

set(PATH_PRJ ${CMAKE_CURRENT_SOURCE_DIR})
set(PATH_UAPKIC ${PATH_PRJ}/../uapkic)
set(PATH_UAPKIF ${PATH_PRJ}/../uapkif)
set(PATH_COMMON_CMAPI ${PATH_PRJ}/../common/cm-api)
set(PATH_COMMON_JSON ${PATH_PRJ}/../common/json)
set(PATH_COMMON_LOADERS ${PATH_PRJ}/../common/loaders)
set(PATH_COMMON_MACROS ${PATH_PRJ}/../common/macros)
set(PATH_COMMON_PKIX ${PATH_PRJ}/../common/pkix)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../out)

aux_source_directory(${PATH_PRJ}/src/api UAPKI_API_SOURCES)
aux_source_directory(${PATH_PRJ}/src UAPKI_SOURCES)
aux_source_directory(${PATH_COMMON_PKIX} COMMON_SOURCES)
aux_source_directory(${PATH_COMMON_JSON} JSON_SOURCES)

add_library(uapki ${UAPKI_LIBS_TYPE}
        ${UAPKI_API_SOURCES}
        ${UAPKI_SOURCES}
        ${COMMON_SOURCES}
        ${PATH_COMMON_LOADERS}/cm-loader.cpp
        ${JSON_SOURCES}
)

target_include_directories(uapki ${UAPKI_INTERNAL_INCLUDES_MODE}
        ${PATH_COMMON_CMAPI}
        ${PATH_COMMON_JSON}
        ${PATH_COMMON_MACROS}
        ${PATH_COMMON_PKIX}
        ${PATH_PRJ}
        ${PATH_PRJ}/src
        ${PATH_PRJ}/src/api
        PUBLIC
        ${PATH_COMMON_LOADERS}
        ${PATH_PRJ}/include
)

set_target_properties(uapki PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(uapki PROPERTIES CXX_VISIBILITY_PRESET hidden)
set_target_properties(uapki PROPERTIES LINK_FLAGS_RELEASE -s)
set_target_properties(uapki PROPERTIES VERSION ${UAPKI_VERSION} SOVERSION ${UAPKI_SOVERSION})

target_compile_definitions(uapki PRIVATE UAPKI_LIBRARY)
target_link_libraries(uapki ${UAPKI_INTERNAL_INCLUDES_MODE} uapkic uapkif)
if (${UNIX})
    target_link_libraries(uapki PRIVATE dl curl)
endif ()
if (${APPLE})
    target_link_libraries(uapki PRIVATE iconv)
endif ()


if (NOT UAPKI_DISABLE_COPY)
    add_custom_command(TARGET uapki POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:uapki> ../out/
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:uapki> ../../${OUT_DIR}/
    )
endif ()
