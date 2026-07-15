cmake_minimum_required(VERSION 3.17)

project(uapki-wasm LANGUAGES C)

if(NOT EMSCRIPTEN)
    message(STATUS "uapki-wasm: skipped (requires the Emscripten toolchain, use emcmake)")
    return()
endif()

message(STATUS "Project: ${PROJECT_NAME} (browser WASM bundle)")

add_executable(${PROJECT_NAME} main-wasm.c)

#  uapki carries the JSON API ('process'/'json_free'),
#  cm-pkcs12 is linked statically (see common/loaders/cm-loader.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE uapki cm-pkcs12)

set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "uapki"
    SUFFIX ".js"
)

target_link_options(${PROJECT_NAME} PRIVATE
    "-sMODULARIZE=1"
    "-sEXPORT_NAME=createUapkiModule"
    "-sEXPORTED_FUNCTIONS=_process,_json_free,_malloc,_free"
    "-sEXPORTED_RUNTIME_METHODS=cwrap,ccall,UTF8ToString,stringToNewUTF8,lengthBytesUTF8,FS"
    "-sALLOW_MEMORY_GROWTH=1"
    "-sINITIAL_MEMORY=67108864"
    "-sSTACK_SIZE=8388608"
    "-sENVIRONMENT=web,worker"
    #  HTTP goes through the browser's fetch() (see common/pkix/http-helper.cpp);
    #  Asyncify suspends the synchronous WASM call stack while fetch is pending.
    #  JS callers must invoke 'process' via ccall(..., {async: true}).
    "-sASYNCIFY=1"
    "-sASYNCIFY_STACK_SIZE=131072"
    "-sINVOKE_RUN=0"
    "--pre-js=${CMAKE_CURRENT_SOURCE_DIR}/pre.js"
)

set_property(TARGET ${PROJECT_NAME} APPEND PROPERTY LINK_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/pre.js
)

#  Platform output dir (library/out/wasm, see the root CMakeLists) and the
#  WebAssembly integration dir (JSON console) receive the built module.
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE_DIR:${PROJECT_NAME}>/uapki.js
        $<TARGET_FILE_DIR:${PROJECT_NAME}>/uapki.wasm
        ${CMAKE_SOURCE_DIR}/${OUT_DIR}/
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE_DIR:${PROJECT_NAME}>/uapki.js
        $<TARGET_FILE_DIR:${PROJECT_NAME}>/uapki.wasm
        ${CMAKE_SOURCE_DIR}/../integration/WebAssembly/
)
