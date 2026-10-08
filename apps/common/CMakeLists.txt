#  Спільний код tsp-checker і ocsp-checker: опції, звіт, HTTP, перевірка підпису відповіді

set(PATH_COMMON_PKIX ${UAPKI_LIBRARY_DIR}/common/pkix)

add_library(uapki-apps-common STATIC
    app-common.cpp
    getopt-helper.cpp
    pem-helper.cpp
    response-signature.cpp
    ${PATH_COMMON_PKIX}/attribute-helper.cpp
    ${PATH_COMMON_PKIX}/ba-utils.c
    ${PATH_COMMON_PKIX}/dstu4145-params.c
    ${PATH_COMMON_PKIX}/ecdsa-params.c
    ${PATH_COMMON_PKIX}/extension-helper.cpp
    ${PATH_COMMON_PKIX}/http-helper.cpp
    ${PATH_COMMON_PKIX}/iconv-utils.c
    ${PATH_COMMON_PKIX}/oids.c
    ${PATH_COMMON_PKIX}/oid-utils.c
    ${PATH_COMMON_PKIX}/signeddata-helper.cpp
    ${PATH_COMMON_PKIX}/time-util.cpp
    ${PATH_COMMON_PKIX}/uapki-errors.c
    ${PATH_COMMON_PKIX}/uapki-ns-util.cpp
    ${PATH_COMMON_PKIX}/uapki-ns-verify.cpp
)

set_target_properties(uapki-apps-common PROPERTIES
    C_STANDARD 99
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)

target_include_directories(uapki-apps-common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${UAPKI_LIBRARY_DIR}/uapkic/include
    ${UAPKI_LIBRARY_DIR}/uapkif/include
    ${UAPKI_LIBRARY_DIR}/common/macros
    ${PATH_COMMON_PKIX}
)

target_link_libraries(uapki-apps-common PUBLIC uapkic uapkif)

if(WIN32)
    set(CURL_BASE_DIR "${UAPKI_LIBRARY_DIR}/common/curl")
    target_include_directories(uapki-apps-common PRIVATE "${CURL_BASE_DIR}/include")
    if(CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64")
        target_link_libraries(uapki-apps-common PUBLIC "${CURL_BASE_DIR}/builds/windows_arm64/libcurl.lib")
    elseif(CMAKE_GENERATOR_PLATFORM STREQUAL "Win32" OR CMAKE_GENERATOR_PLATFORM STREQUAL "x86")
        target_link_libraries(uapki-apps-common PUBLIC "${CURL_BASE_DIR}/builds/windows_x86/libcurl.lib")
    else()
        target_link_libraries(uapki-apps-common PUBLIC "${CURL_BASE_DIR}/builds/windows_x86-64/libcurl.lib")
    endif()
    target_link_libraries(uapki-apps-common PUBLIC Ws2_32 Wldap32 Crypt32 Normaliz Bcrypt Iphlpapi)
    target_compile_definitions(uapki-apps-common PUBLIC _CRT_SECURE_NO_WARNINGS)
else()
    find_package(CURL REQUIRED)
    target_link_libraries(uapki-apps-common PUBLIC CURL::libcurl)
endif()
