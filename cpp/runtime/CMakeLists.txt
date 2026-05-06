set(RUNTIME_SOURCES
    registry_manager.cc
    utils.cc
    ../third-party/lzma/LzmaDecode.cc
    core.cc
    crypto.cc
    hook_manager.cc
    hwid.cc
    licensing_manager.cc
    loader.cc
    objects.cc
    precompiled.cc
    resource_manager.cc
    string_manager.cc
)

set(RUNTIME_HEADERS
    precommon.h
    registry_manager.h
    utils.h
    ../third-party/lzma/LzmaDecode.h
    core.h
    crypto.h
    common.h
    hook_manager.h
    hwid.h
    licensing_manager.h
    loader.h
    objects.h
    precompiled.h
    resource_manager.h
    string_manager.h
)

add_library(win_runtime SHARED ${RUNTIME_SOURCES} ${RUNTIME_HEADERS})

target_include_directories(win_runtime PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../third-party/lzma
)

target_compile_definitions(win_runtime PRIVATE
    _WINDOWS
    _USRDLL
    RUNTIME_EXPORTS
    _WIN32_WINNT=0x0600
)

if(MSVC)
    target_compile_options(win_runtime PRIVATE /Yu"precompiled.h" /FI"precompiled.h" /GR-)
    set_source_files_properties(precompiled.cc PROPERTIES COMPILE_FLAGS "/Yc\"precompiled.h\"")
    target_link_options(win_runtime PRIVATE /DEF:"${CMAKE_CURRENT_SOURCE_DIR}/runtime.def")
    set_target_properties(win_runtime PROPERTIES LINK_FLAGS "/DEF:\"${CMAKE_CURRENT_SOURCE_DIR}/runtime.def\"")
    target_link_libraries(win_runtime PUBLIC wtsapi32.lib)
endif()
