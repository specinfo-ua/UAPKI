cmake_minimum_required(VERSION 3.05)

project(uapkif LANGUAGES C)
set(UAPKIF_VERSION 2.0.1)
set(UAPKIF_SOVERSION 2)
message(STATUS "Project: uapkif, version: " ${UAPKIF_VERSION})

option(UAPKI_DISABLE_COPY "Disable copying into out dir" OFF)

if (DEFINED UAPKI_LIBS_TYPE)
    if (NOT UAPKI_LIBS_TYPE STREQUAL SHARED AND NOT UAPKI_LIBS_TYPE STREQUAL STATIC)
        message(FATAL_ERROR "Bad UAPKI_LIBS_TYPE")
    endif ()
else ()
    set(UAPKI_LIBS_TYPE SHARED)
endif ()

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
    message(STATUS "Build type not specified: Use Release by default")
endif (NOT CMAKE_BUILD_TYPE)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_FLAGS_DEBUG_INIT "-Wall")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-Wall")
set(CMAKE_SKIP_RPATH ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

if (${WIN32})
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif ()

set(PATH_PRJ ${CMAKE_CURRENT_SOURCE_DIR})
set(PATH_PRJ_SOURCES ${PATH_PRJ}/src)
set(PATH_UAPKIC ${PATH_PRJ}/../uapkic)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../out)

aux_source_directory(${PATH_PRJ_SOURCES}/asn1 UAPKIF_ASN1_SOURCES)
aux_source_directory(${PATH_PRJ_SOURCES}/struct UAPKIF_STRUCT_SOURCES)

add_library(uapkif ${UAPKI_LIBS_TYPE}
        ${UAPKIF_ASN1_SOURCES}
        ${UAPKIF_STRUCT_SOURCES}
)

target_include_directories(uapkif PUBLIC
        ${PATH_PRJ}
        ${PATH_PRJ}/asn1
        ${PATH_PRJ}/include
        ${PATH_PRJ_SOURCES}/asn1
)

set_target_properties(uapkif PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(uapkif PROPERTIES CXX_VISIBILITY_PRESET hidden)
set_target_properties(uapkif PROPERTIES LINK_FLAGS_RELEASE -s)
set_target_properties(uapkif PROPERTIES VERSION ${UAPKIF_VERSION} SOVERSION ${UAPKIF_SOVERSION})

target_compile_definitions(uapkif PRIVATE UAPKIF_LIBRARY)
if (${WIN32})
    target_compile_definitions(uapkif PRIVATE NOCRYPT)
    target_compile_definitions(uapkif PRIVATE _CRT_SECURE_NO_WARNINGS)
endif ()

target_link_libraries(uapkif PUBLIC uapkic)


if (NOT UAPKI_DISABLE_COPY)
    add_custom_command(TARGET uapkif POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:uapkif> ../out/
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:uapkif> ../../${OUT_DIR}/
    )
endif ()
