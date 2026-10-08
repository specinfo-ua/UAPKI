project(ocsp-checker VERSION 0.6.0 LANGUAGES C CXX)

add_executable(ocsp-checker
    src/ocsp-checker.cpp
    src/ocsp-checker-options.cpp
    ${UAPKI_LIBRARY_DIR}/common/pkix/ocsp-helper.cpp
    ${UAPKI_LIBRARY_DIR}/common/pkix/verify-status.cpp
)

set_target_properties(ocsp-checker PROPERTIES CXX_STANDARD 11 CXX_STANDARD_REQUIRED ON)
target_compile_definitions(ocsp-checker PRIVATE APP_VERSION="${PROJECT_VERSION}")
target_include_directories(ocsp-checker PRIVATE src)
target_link_libraries(ocsp-checker PRIVATE uapki-apps-common)

include(${UAPKI_APPS_DIR}/app-install.cmake)
uapki_app_install(ocsp-checker)
