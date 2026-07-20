cmake_minimum_required(VERSION 3.17)

project(cm-pkcs11 VERSION 1.0.12 LANGUAGES C CXX)

message(STATUS "Project: ${PROJECT_NAME} (version: ${PROJECT_VERSION})")

configure_file(
    "${CMAKE_SOURCE_DIR}/rc-version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/rc-version.h"
    @ONLY
)

option(UAPKI_DISABLE_COPY "Disable copying into out dir" OFF)

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
    set(RESOURCE_RC resource.rc)
else()
    set(RESOURCE_RC "")
endif()

add_library(${PROJECT_NAME} SHARED
    ${TOKEN_CRYPTOKI_SOURCES}
    ${TOKEN_SRC_SOURCES}
    ${TOKEN_STORAGE_SOURCES}
    ${COMMON_JSON_SOURCES}
    ${COMMON_PKIX_SOURCES}
    ${RESOURCE_RC}
)

set_target_properties(${PROJECT_NAME} PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_VISIBILITY_PRESET hidden)

if(NOT WIN32)
    if(APPLE)
        target_link_options(${PROJECT_NAME} PRIVATE "$<$<CONFIG:Release>:-Wl,-S>")
    else()
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

target_link_libraries(${PROJECT_NAME} PRIVATE uapkic uapkif)

if(UNIX)
    target_link_libraries(${PROJECT_NAME} PRIVATE dl)
endif()

if(NOT UAPKI_DISABLE_COPY AND (NOT CMAKE_SYSTEM_NAME STREQUAL "Android"))
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:cm-pkcs11> ../out/
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:cm-pkcs11> ${CMAKE_SOURCE_DIR}/${OUT_DIR}/
    )
endif()
