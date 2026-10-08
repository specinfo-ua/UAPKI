project(tsp-checker VERSION 0.6.0 LANGUAGES C CXX)

add_executable(tsp-checker
    src/oid-helper.cpp
    src/tsp-checker.cpp
    src/tsp-checker-options.cpp
    ${UAPKI_LIBRARY_DIR}/common/pkix/tsp-helper.cpp
)

set_target_properties(tsp-checker PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON)
target_compile_definitions(tsp-checker PRIVATE APP_VERSION="${PROJECT_VERSION}")
target_include_directories(tsp-checker PRIVATE src)
target_link_libraries(tsp-checker PRIVATE uapki-apps-common)

include(${UAPKI_APPS_DIR}/app-install.cmake)
uapki_app_install(tsp-checker)
