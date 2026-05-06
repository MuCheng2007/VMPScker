cmake_minimum_required(VERSION 3.20)
project(VMProtect LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/$<IF:$<EQUAL:${CMAKE_SIZEOF_VOID_P},8>,64,32>/${CMAKE_BUILD_TYPE})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/$<IF:$<EQUAL:${CMAKE_SIZEOF_VOID_P},8>,64,32>/${CMAKE_BUILD_TYPE})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin/$<IF:$<EQUAL:${CMAKE_SIZEOF_VOID_P},8>,64,32>/${CMAKE_BUILD_TYPE})

add_compile_definitions(
    SCI_NAMESPACE
    TIXML_USE_STL
    SCI_LEXER
    SPV_LIBRARY
    _7ZIP_ST
    FFI_BUILDING
    _CRT_SECURE_NO_WARNINGS
    UNICODE
    _UNICODE
)

if(MSVC)
    add_compile_options(/W3 /MP)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(/Od)
        add_compile_definitions(ULTIMATE _DEBUG)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDebugDLL")
    else()
        add_compile_options(/O2 /Oi /Gy)
        add_compile_definitions(NDEBUG)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
    endif()
endif()

add_subdirectory(core/invariant)
add_subdirectory(core)
add_subdirectory(sdk)
# add_subdirectory(runtime)
add_subdirectory(VMProtectCon)
