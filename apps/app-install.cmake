#  Застосунки лінкуються з uapkic/uapkif як із DLL / .so і кладуться в OUT_DIR поруч із ними

include_guard(GLOBAL)

function(uapki_app_install TARGET)
    if(APPLE)
        set_target_properties(${TARGET} PROPERTIES BUILD_WITH_INSTALL_RPATH ON INSTALL_RPATH "@loader_path")
    elseif(NOT WIN32)
        set_target_properties(${TARGET} PROPERTIES BUILD_WITH_INSTALL_RPATH ON INSTALL_RPATH "\$ORIGIN")
    endif()

    if(NOT UAPKI_DISABLE_COPY)
        add_custom_command(TARGET ${TARGET} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${TARGET}> ${CMAKE_SOURCE_DIR}/${OUT_DIR}/
        )
    endif()
endfunction()
