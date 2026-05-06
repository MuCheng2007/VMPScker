set(SDK_SOURCES
    precompiled.cc
    sdk.cc
)

set(SDK_HEADERS
    precompiled.h
    sdk.h
)

add_library(VMProtectSDK SHARED ${SDK_SOURCES} ${SDK_HEADERS})

target_include_directories(VMProtectSDK PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../runtime
)

target_compile_definitions(VMProtectSDK PRIVATE
    _WINDOWS
    _USRDLL
    VMPROTECTSDK_EXPORTS
)

set_target_properties(VMProtectSDK PROPERTIES
    OUTPUT_NAME "VMProtectSDK$<TARGET_PROPERTY:VMProtectSDK,PLATFORM_ARCH>"
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_property(TARGET VMProtectSDK PROPERTY PLATFORM_ARCH "64")
else()
    set_property(TARGET VMProtectSDK PROPERTY PLATFORM_ARCH "32")
endif()

if(MSVC)
    target_compile_options(VMProtectSDK PRIVATE /Yu"precompiled.h" /FI"precompiled.h")
    set_source_files_properties(precompiled.cc PROPERTIES COMPILE_FLAGS "/Yc\"precompiled.h\"")
    target_link_options(VMProtectSDK PRIVATE /DEF:"${CMAKE_CURRENT_SOURCE_DIR}/sdk.def")
    set_target_properties(VMProtectSDK PROPERTIES LINK_FLAGS "/DEF:\"${CMAKE_CURRENT_SOURCE_DIR}/sdk.def\"")
endif()
