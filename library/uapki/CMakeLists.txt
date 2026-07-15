cmake_minimum_required(VERSION 3.17)

project(uapki VERSION 2.0.16 LANGUAGES C CXX)

message(STATUS "Project: ${PROJECT_NAME} (version: ${PROJECT_VERSION})")

configure_file(
    "${CMAKE_SOURCE_DIR}/rc-version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/rc-version.h"
    @ONLY
)

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

if (NOT WIN32)
    set(CMAKE_SKIP_BUILD_RPATH OFF)
    set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH ON)
    
    if(APPLE)
        set(CMAKE_INSTALL_RPATH "@loader_path")
    else()
        set(CMAKE_INSTALL_RPATH "\${ORIGIN}")
    endif()
endif ()

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

if (WIN32)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif ()

if(NOT WIN32 AND NOT EMSCRIPTEN)
    find_package(CURL REQUIRED)
endif()

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
if(WIN32)
    set(RESOURCE_RC resource.rc)
else()
    set(RESOURCE_RC "")
endif()


add_library(uapki ${UAPKI_LIBS_TYPE}
    ${UAPKI_API_SOURCES}
    ${UAPKI_SOURCES}
    ${COMMON_SOURCES}
    ${PATH_COMMON_LOADERS}/cm-loader.cpp
    ${JSON_SOURCES}
    ${RESOURCE_RC}
)

if(WIN32)
    set(CURL_BASE_DIR "${CMAKE_SOURCE_DIR}/common/curl")
    set(CURL_INCLUDE_DIR "${CURL_BASE_DIR}/include")

    target_include_directories(${PROJECT_NAME} PRIVATE "${CURL_INCLUDE_DIR}")

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_libraries(${PROJECT_NAME} PRIVATE "${CURL_BASE_DIR}/builds/windows_x86-64/libcurl.lib")
    else()
        target_link_libraries(${PROJECT_NAME} PRIVATE "${CURL_BASE_DIR}/builds/windows_x86/libcurl.lib")
    endif()

    target_link_libraries(${PROJECT_NAME} PRIVATE Ws2_32 Wldap32 Crypt32 Normaliz)

    set(CURL_FOUND TRUE)
endif()

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
    ${CMAKE_CURRENT_BINARY_DIR}
)

set_target_properties(uapki PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(uapki PROPERTIES CXX_VISIBILITY_PRESET hidden)

if(NOT WIN32)
    if(APPLE)
        target_link_options(${PROJECT_NAME} PRIVATE "$<$<CONFIG:Release>:-Wl,-S>")
    elseif(NOT EMSCRIPTEN)
        set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS_RELEASE -s)
    endif()
else()
    target_compile_definitions(${PROJECT_NAME} PRIVATE HAVE_RC_VERSION_H)
    target_compile_definitions(${PROJECT_NAME} PRIVATE NOCRYPT)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION   "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}"
    SOVERSION "${PROJECT_VERSION_MAJOR}"
)

target_compile_definitions(uapki PRIVATE UAPKI_LIBRARY)
target_link_libraries(uapki ${UAPKI_INTERNAL_INCLUDES_MODE} uapkic uapkif)

if(UNIX AND NOT EMSCRIPTEN)
    target_link_libraries(uapki PRIVATE dl curl)
endif()

if (NOT UAPKI_DISABLE_COPY)
    add_custom_command(TARGET uapki POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:uapki> ../out/
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:uapki> ${CMAKE_SOURCE_DIR}/${OUT_DIR}/
    )
endif ()
