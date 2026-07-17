cmake_minimum_required(VERSION 3.17)

project(uapkif VERSION 2.0.2 LANGUAGES C)

message(STATUS "Project: ${PROJECT_NAME} (version: ${PROJECT_VERSION})")

configure_file(
    "${CMAKE_SOURCE_DIR}/rc-version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/rc-version.h"
    @ONLY
)

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

set(PATH_PRJ ${CMAKE_CURRENT_SOURCE_DIR})
set(PATH_PRJ_SOURCES ${PATH_PRJ}/src)
set(PATH_UAPKIC ${PATH_PRJ}/../uapkic)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/../out)

aux_source_directory(${PATH_PRJ_SOURCES}/asn1 UAPKIF_ASN1_SOURCES)
aux_source_directory(${PATH_PRJ_SOURCES}/struct UAPKIF_STRUCT_SOURCES)
if(WIN32)
    set(RESOURCE_RC resource.rc)
else()
    set(RESOURCE_RC "")
endif()

add_library(${PROJECT_NAME} ${UAPKI_LIBS_TYPE}
    ${UAPKIF_ASN1_SOURCES}
    ${UAPKIF_STRUCT_SOURCES}
    ${RESOURCE_RC}
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ${PATH_PRJ}
    ${PATH_PRJ}/asn1
    ${PATH_PRJ}/include
    ${PATH_PRJ_SOURCES}/asn1
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
    target_compile_definitions(${PROJECT_NAME} PRIVATE NOCRYPT)
    target_compile_definitions(${PROJECT_NAME} PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION   "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}"
    SOVERSION "${PROJECT_VERSION_MAJOR}"
)

target_compile_definitions(${PROJECT_NAME} PRIVATE UAPKIF_LIBRARY)

target_link_libraries(${PROJECT_NAME} PUBLIC uapkic)

if (NOT UAPKI_DISABLE_COPY)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:uapkif> ../out/
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:uapkif> ${CMAKE_SOURCE_DIR}/${OUT_DIR}/
    )
endif ()
