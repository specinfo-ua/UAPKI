cmake_minimum_required(VERSION 3.17)

project(cm-pkcs12 VERSION 1.0.24 LANGUAGES C CXX)

message(STATUS "Project: ${PROJECT_NAME} (version: ${PROJECT_VERSION})")

configure_file(
    "${CMAKE_SOURCE_DIR}/rc-version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/rc-version.h"
    @ONLY
)

option(UAPKI_DISABLE_COPY "Disable copying into out dir" OFF)

if (DEFINED UAPKI_CM_PKCS12_LIB_TYPE)
    if (NOT UAPKI_CM_PKCS12_LIB_TYPE STREQUAL SHARED AND NOT UAPKI_CM_PKCS12_LIB_TYPE STREQUAL STATIC)
    message(FATAL_ERROR "Bad UAPKI_CM_PKCS12_LIB_TYPE")
    endif ()
else ()
    set(UAPKI_CM_PKCS12_LIB_TYPE SHARED)
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

#set(CMAKE_SHARED_LINKER_FLAGS "-static-libgcc -static-libstdc++")

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

if (WIN32)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif ()

set(PATH_PRJ ${CMAKE_CURRENT_SOURCE_DIR})
set(PATH_UAPKIC ${PATH_PRJ}/../uapkic)
set(PATH_UAPKIF ${PATH_PRJ}/../uapkif)
set(PATH_COMMON_CMAPI ${PATH_PRJ}/../common/cm-api)
set(PATH_COMMON_JSON ${PATH_PRJ}/../common/json)
set(PATH_COMMON_MACROS ${PATH_PRJ}/../common/macros)
set(PATH_COMMON_PKIX ${PATH_PRJ}/../common/pkix)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../build)

aux_source_directory(${PATH_PRJ}/src CMP12_SRC_SOURCES)
aux_source_directory(${PATH_PRJ}/src/crypto CMP12_CRYPTO_SOURCES)
aux_source_directory(${PATH_PRJ}/src/storage CMP12_STORAGE_SOURCES)
aux_source_directory(${PATH_COMMON_JSON} JSON_SOURCES)
set(COMMON_SOURCES
    ${PATH_COMMON_PKIX}/aid.c
    ${PATH_COMMON_PKIX}/ba-utils.c
    ${PATH_COMMON_PKIX}/dstu4145-params.c
    ${PATH_COMMON_PKIX}/ecdsa-params.c
    ${PATH_COMMON_PKIX}/iconv-utils.c
    ${PATH_COMMON_PKIX}/iso15946.c
    ${PATH_COMMON_PKIX}/key-wrap.c
    ${PATH_COMMON_PKIX}/oids.c
    ${PATH_COMMON_PKIX}/oid-utils.c
    ${PATH_COMMON_PKIX}/private-key.c
    ${PATH_COMMON_PKIX}/uapki-ns-util.cpp
)
if(WIN32)
    set(RESOURCE_RC resource.rc)
else()
    set(RESOURCE_RC "")
endif()

add_library(${PROJECT_NAME} ${UAPKI_CM_PKCS12_LIB_TYPE}
    ${CMP12_CRYPTO_SOURCES}
    ${CMP12_SRC_SOURCES}
    ${CMP12_STORAGE_SOURCES}
    ${COMMON_SOURCES}
    ${JSON_SOURCES}
    ${RESOURCE_RC}
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ${PATH_COMMON_CMAPI}
    ${PATH_COMMON_JSON}
    ${PATH_COMMON_MACROS}
    ${PATH_COMMON_PKIX}
    ${PATH_PRJ}/src
    ${PATH_PRJ}/src/crypto
    ${PATH_PRJ}/src/storage
    ${CMAKE_CURRENT_BINARY_DIR}
)

set_target_properties(${PROJECT_NAME} PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_VISIBILITY_PRESET hidden)

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

target_compile_definitions(${PROJECT_NAME} PRIVATE CM_LIBRARY)

target_link_libraries(${PROJECT_NAME} PUBLIC uapkic uapkif)

if (NOT UAPKI_DISABLE_COPY)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:cm-pkcs12> ../out/
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:cm-pkcs12> ${CMAKE_SOURCE_DIR}/${OUT_DIR}/
    )
endif()
