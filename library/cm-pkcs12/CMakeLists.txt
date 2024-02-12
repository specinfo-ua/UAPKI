cmake_minimum_required(VERSION 3.05)

project(cm-pkcs12 LANGUAGES C CXX)
set(CM_PKCS12_VERSION 1.0.10)
set(CM_PKCS12_SOVERSION 1)
message(STATUS "Project: cm-pkcs12, version: " ${CM_PKCS12_VERSION})

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
set(CMAKE_SKIP_RPATH ON)

#set(CMAKE_SHARED_LINKER_FLAGS "-static-libgcc -static-libstdc++")

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

if (${WIN32})
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
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
        ${PATH_COMMON_PKIX}/iconv-utils.c
        ${PATH_COMMON_PKIX}/iso15946.c
        ${PATH_COMMON_PKIX}/key-wrap.c
        ${PATH_COMMON_PKIX}/oids.c
        ${PATH_COMMON_PKIX}/oid-utils.c
        ${PATH_COMMON_PKIX}/private-key.c
        ${PATH_COMMON_PKIX}/uapki-ns-util.cpp
)

add_library(cm-pkcs12 ${UAPKI_CM_PKCS12_LIB_TYPE}
        ${CMP12_CRYPTO_SOURCES}
        ${CMP12_SRC_SOURCES}
        ${CMP12_STORAGE_SOURCES}
        ${COMMON_SOURCES}
        ${JSON_SOURCES}
)

target_include_directories(cm-pkcs12 PUBLIC
        ${PATH_COMMON_CMAPI}
        ${PATH_COMMON_JSON}
        ${PATH_COMMON_MACROS}
        ${PATH_COMMON_PKIX}
        ${PATH_PRJ}/src
        ${PATH_PRJ}/src/crypto
        ${PATH_PRJ}/src/storage
)

set_target_properties(cm-pkcs12 PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(cm-pkcs12 PROPERTIES CXX_VISIBILITY_PRESET hidden)
set_target_properties(cm-pkcs12 PROPERTIES LINK_FLAGS_RELEASE -s)
set_target_properties(cm-pkcs12 PROPERTIES VERSION ${CM_PKCS12_VERSION} SOVERSION ${CM_PKCS12_SOVERSION})

target_compile_definitions(cm-pkcs12 PRIVATE CM_LIBRARY)
if (${WIN32})
    target_compile_definitions(cm-pkcs12 PRIVATE NOCRYPT)
    target_compile_definitions(cm-pkcs12 PRIVATE _CRT_SECURE_NO_WARNINGS)
endif ()

target_link_libraries(cm-pkcs12 PUBLIC uapkic uapkif)
if (${APPLE})
    target_link_libraries(cm-pkcs12 PRIVATE iconv)
endif ()


if (NOT UAPKI_DISABLE_COPY)
    add_custom_command(TARGET cm-pkcs12 POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:cm-pkcs12> ../out/
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:cm-pkcs12> ../../${OUT_DIR}/
    )
endif ()
