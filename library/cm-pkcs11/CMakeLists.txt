cmake_minimum_required(VERSION 3.05)

project(cm-pkcs11 LANGUAGES C CXX)
set(CM_PKCS11_VERSION 1.0.12)
set(CM_PKCS11_SOVERSION 1)
message(STATUS "Project: cm-pkcs11, version: " ${CM_PKCS11_VERSION})

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

set(CMAKE_SKIP_BUILD_RPATH OFF)
set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH ON)
set(CMAKE_INSTALL_RPATH "\$ORIGIN")

#set(CMAKE_SHARED_LINKER_FLAGS "-static-libgcc -static-libstdc++")

if(${WIN32})
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

add_library(cm-pkcs11 SHARED
    ${TOKEN_CRYPTOKI_SOURCES}
    ${TOKEN_SRC_SOURCES}
    ${TOKEN_STORAGE_SOURCES}
    ${COMMON_JSON_SOURCES}
    ${COMMON_PKIX_SOURCES}
)

set_target_properties(cm-pkcs11 PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(cm-pkcs11 PROPERTIES CXX_VISIBILITY_PRESET hidden)
set_target_properties(cm-pkcs11 PROPERTIES LINK_FLAGS_RELEASE -s)
set_target_properties(cm-pkcs11 PROPERTIES VERSION ${CM_PKCS11_VERSION} SOVERSION ${CM_PKCS11_SOVERSION})

if(${WIN32})
    target_compile_definitions(cm-pkcs11 PRIVATE NOCRYPT)
    target_compile_definitions(cm-pkcs11 PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

target_link_libraries(cm-pkcs11 PRIVATE uapkic uapkif)
if(${UNIX})
    target_link_libraries(cm-pkcs11 PRIVATE dl)
endif()


add_custom_command(TARGET cm-pkcs11 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:cm-pkcs11> ../out/
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:cm-pkcs11> ../../${OUT_DIR}/
)
