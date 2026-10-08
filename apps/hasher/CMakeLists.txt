project(hasher LANGUAGES C)

#  Один hasher.c — дві утиліти; алгоритм обирає макрос HASHER_<ІМ'Я>

include(${UAPKI_APPS_DIR}/app-install.cmake)

foreach(HASHER gost34311 kupyna256)
    string(TOUPPER ${HASHER} HASHER_UPPER)

    add_executable(${HASHER} hasher.c)
    target_compile_definitions(${HASHER} PRIVATE HASHER_${HASHER_UPPER})
    target_include_directories(${HASHER} PRIVATE ${UAPKI_LIBRARY_DIR}/uapkic/include)
    target_link_libraries(${HASHER} PRIVATE uapkic)
    set_target_properties(${HASHER} PROPERTIES C_STANDARD 99)
    if(MSVC)
        target_compile_definitions(${HASHER} PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()

    uapki_app_install(${HASHER})
endforeach()
