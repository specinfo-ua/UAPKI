cmake_minimum_required(VERSION 3.17)

project("UAPKI Apps" VERSION 3.0.0 LANGUAGES C CXX)

#  Застосунки на базі UAPKI. Збираються окремо (uapkic і uapkif беруться з ../library)
#  або як частина іншого проєкту, де ці цілі вже є.

set(UAPKI_LIBRARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../library)
set(UAPKI_APPS_DIR ${CMAKE_CURRENT_SOURCE_DIR})

if(NOT DEFINED OUT_DIR)
    set(OUT_DIR "out")
endif()

if(NOT TARGET uapkic)
    #  Версія продукту в ресурсах бібліотек (rc-version.h.in)
    if(NOT DEFINED GLOBAL_PRODUCT_NAME)
        set(GLOBAL_PRODUCT_NAME "UAPKI")
        set(GLOBAL_PRODUCT_VERSION "${PROJECT_VERSION}")
        set(GLOBAL_PRODUCT_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
        set(GLOBAL_PRODUCT_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
        set(GLOBAL_PRODUCT_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
    endif()
    if(MSVC)
        add_compile_definitions(_CRT_NONSTDC_NO_DEPRECATE)
    endif()
    #  Бібліотеки копіюють себе в ../out відносно своїх каталогів збірки
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/out)
    file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/${OUT_DIR})
    add_subdirectory(${UAPKI_LIBRARY_DIR}/uapkic uapkic)
    add_subdirectory(${UAPKI_LIBRARY_DIR}/uapkif uapkif)
endif()

add_subdirectory(hasher)

if(NOT CMAKE_SYSTEM_NAME MATCHES "Android|iOS|Emscripten")
    add_subdirectory(common)
    add_subdirectory(tsp-checker)
    add_subdirectory(ocsp-checker)
endif()
