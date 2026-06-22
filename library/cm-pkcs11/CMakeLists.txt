cmake_minimum_required(VERSION 3.17)

project(cm-pkcs11 VERSION 1.0.12 LANGUAGES C CXX)

message(STATUS "Project: ${PROJECT_NAME} (version: ${PROJECT_VERSION})")

configure_file(
    "${CMAKE_SOURCE_DIR}/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/version.h"
    @ONLY
)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
  message(STATUS "Build type not specified: Use Release by default")
endif(NOT CMAKE_BUILD_TYPE)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_DEBUG_INIT "-Wall")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-Wall")

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

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

#set(CMAKE_SHARED_LINKER_FLAGS "-static-libgcc -static-libstdc++")

if(WIN32)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif()

set(PATH_PRJ ${CMAKE_CURRENT_SOURCE_DIR})

set(PATH_COMMON_CMAPI ${PATH_PRJ}/../common/cm-api)
set(PATH_COMMON_CRYPTOKI ${PATH_PRJ}/../common/cryptoki)
set(PATH_COMMON_JSON ${PATH_PRJ}/../common/json)
set(PATH_COMMON_MACROS ${PATH_PRJ}/../common/macros)
set(PATH_COMMON_PKIX ${PATH_PRJ}/../common/pkix)
set(PATH_UAPKIC ${PATH_PRJ}/../uapkic)
set(PATH_UAPKIF ${PATH_PRJ}/../uapkif)

include_directories(
    ${PATH_PRJ}/src
    ${PATH_PRJ}/src/storage
    ${PATH_COMMON_CRYPTOKI}
    ${PATH_UAPKIC}/include
    ${PATH_UAPKIF}/include
    ${PATH_COMMON_CMAPI}
    ${PATH_COMMON_JSON}
    ${PATH_COMMON_MACROS}
    ${PATH_COMMON_PKIX}
    ${CMAKE_CURRENT_BINARY_DIR}
)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../out)

aux_source_directory(${PATH_PRJ}/src TOKEN_SRC_SOURCES)
aux_source_directory(${PATH_PRJ}/src/storage TOKEN_STORAGE_SOURCES)
aux_source_directory(${PATH_COMMON_CRYPTOKI} TOKEN_CRYPTOKI_SOURCES)
aux_source_directory(${PATH_COMMON_JSON} COMMON_JSON_SOURCES)
set(COMMON_PKIX_SOURCES
    ${PATH_COMMON_PKIX}/ba-utils.c
    ${PATH_COMMON_PKIX}/certreq-builder.cpp
    ${PATH_COMMON_PKIX}/dstu-ns.cpp
    ${PATH_COMMON_PKIX}/dstu4145-params.c
    ${PATH_COMMON_PKIX}/ecdsa-params.c
    ${PATH_COMMON_PKIX}/extnreq-helper.cpp
    ${PATH_COMMON_PKIX}/iconv-utils.c
    ${PATH_COMMON_PKIX}/oids.c
    ${PATH_COMMON_PKIX}/oid-utils.c
    ${PATH_COMMON_PKIX}/uapki-ns-util.cpp
)

if(WIN32)
add_library(${PROJECT_NAME} SHARED
    ${TOKEN_CRYPTOKI_SOURCES}
    ${TOKEN_SRC_SOURCES}
    ${TOKEN_STORAGE_SOURCES}
    ${COMMON_JSON_SOURCES}
    ${COMMON_PKIX_SOURCES}
    resource.rc
)
else()
add_library(${PROJECT_NAME} SHARED
    ${TOKEN_CRYPTOKI_SOURCES}
    ${TOKEN_SRC_SOURCES}
    ${TOKEN_STORAGE_SOURCES}
    ${COMMON_JSON_SOURCES}
    ${COMMON_PKIX_SOURCES}
)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_VISIBILITY_PRESET hidden)
if(NOT WIN32)
    set_target_properties(uapkif PROPERTIES LINK_FLAGS_RELEASE -s)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION   "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}"
    SOVERSION "${PROJECT_VERSION_MAJOR}"
)

if(WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE NOCRYPT)
    target_compile_definitions(${PROJECT_NAME} PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

target_link_libraries(${PROJECT_NAME} PRIVATE uapkic uapkif)
if(UNIX)
    target_link_libraries(${PROJECT_NAME} PRIVATE dl)
endif()

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ../out/
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ../../${OUT_DIR}/
)
