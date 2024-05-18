cmake_minimum_required(VERSION 3.05)

project(uapkic LANGUAGES C)
set(UAPKIC_VERSION 2.0.1)
set(UAPKIC_SOVERSION 2)
message(STATUS "Project: uapkic, version: " ${UAPKIC_VERSION})

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

aux_source_directory(${PATH_PRJ}/src UAPKIC_SOURCES)

add_library(uapkic ${UAPKI_LIBS_TYPE}
        ${UAPKIC_SOURCES}
)

target_include_directories(uapkic PUBLIC
        ${PATH_PRJ}
        ${PATH_PRJ}/include
)

set_target_properties(uapkic PROPERTIES C_VISIBILITY_PRESET hidden)
set_target_properties(uapkic PROPERTIES CXX_VISIBILITY_PRESET hidden)
set_target_properties(uapkic PROPERTIES LINK_FLAGS_RELEASE -s)
set_target_properties(uapkic PROPERTIES VERSION ${UAPKIC_VERSION} SOVERSION ${UAPKIC_SOVERSION})

target_compile_definitions(uapkic PRIVATE UAPKIC_LIBRARY)
target_compile_definitions(uapkic PRIVATE UAPKIC_SELF_TEST)
if (${WIN32})
    target_compile_definitions(uapkic PRIVATE NOCRYPT)
    target_compile_definitions(uapkic PRIVATE _CRT_SECURE_NO_WARNINGS)
else ()
    target_link_libraries(uapkic PRIVATE pthread)
    if (${APPLE})
        target_link_libraries(uapkic PRIVATE iconv)
    endif ()
endif ()


if (NOT UAPKI_DISABLE_COPY)
    add_custom_command(TARGET uapkic POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:uapkic> ../out/
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:uapkic> ../../${OUT_DIR}/
    )
endif ()
