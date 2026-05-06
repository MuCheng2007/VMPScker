set(VMPCON_SOURCES
    console.cc
    precompiled.cc
    main.cc
)

set(VMPCON_HEADERS
    console.h
    main.h
    precompiled.h
)

add_executable(VMProtectCon ${VMPCON_SOURCES} ${VMPCON_HEADERS})

target_include_directories(VMProtectCon PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../core
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)

target_link_libraries(VMProtectCon PRIVATE
    core
    invariant_core
    VMProtectSDK
)

if(MSVC)
    target_compile_options(VMProtectCon PRIVATE /Yu"precompiled.h" /FI"precompiled.h")
    set_source_files_properties(precompiled.cc PROPERTIES COMPILE_FLAGS "/Yc\"precompiled.h\"")
    set_property(TARGET VMProtectCon PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_link_options(VMProtectCon PRIVATE /SUBSYSTEM:CONSOLE)
endif()
