cmake_minimum_required(VERSION 3.17)

project(uapkic VERSION 2.0.2 LANGUAGES C)

message(STATUS "Project: ${PROJECT_NAME} (version: ${PROJECT_VERSION})")

configure_file(
    "${CMAKE_SOURCE_DIR}/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/version.h"
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
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif ()

set(PATH_PRJ ${CMAKE_CURRENT_SOURCE_DIR})

aux_source_directory(${PATH_PRJ}/src UAPKIC_SOURCES)

if(WIN32)
add_library(uapkic ${UAPKI_LIBS_TYPE}
    ${UAPKIC_SOURCES}
    resource.rc    
)
else()
add_library(uapkic ${UAPKI_LIBS_TYPE}
    ${UAPKIC_SOURCES}
)
endif()

target_include_directories(uapkic PUBLIC
    ${PATH_PRJ}
    ${PATH_PRJ}/include
    ${CMAKE_CURRENT_BINARY_DIR}
)

set_target_properties(uapkic PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(uapkic PROPERTIES CXX_VISIBILITY_PRESET hidden)
if(NOT WIN32)
    set_target_properties(uapkif PROPERTIES LINK_FLAGS_RELEASE -s)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION   "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}"
    SOVERSION "${PROJECT_VERSION_MAJOR}"
)

target_compile_definitions(uapkic PRIVATE UAPKIC_LIBRARY)
target_compile_definitions(uapkic PRIVATE UAPKIC_SELF_TEST)
if (WIN32)
    target_compile_definitions(uapkic PRIVATE NOCRYPT)
    target_compile_definitions(uapkic PRIVATE _CRT_SECURE_NO_WARNINGS)
else ()
    target_link_libraries(uapkic PRIVATE pthread)
endif ()


if (NOT UAPKI_DISABLE_COPY)
    add_custom_command(TARGET uapkic POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:uapkic> ../out/
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:uapkic> ../../${OUT_DIR}/
    )
endif ()
