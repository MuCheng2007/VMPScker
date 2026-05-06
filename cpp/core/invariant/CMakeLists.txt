set(INVARIANT_CORE_CXX_SOURCES
    precompiled.cc
)

set(INVARIANT_CORE_C_SOURCES
    precompiled_c.c
    ../../third-party/demangle/cp-demangle.c
    ../../third-party/demangle/undname.c
    ../../third-party/demangle/unmangle.c
    ../../third-party/lzma/Alloc.c
    ../../third-party/lzma/LzFind.c
    ../../third-party/lzma/LzFindMt.c
    ../../third-party/lzma/LzmaEnc.c
    ../../third-party/lzma/Threads.c
)

set(INVARIANT_CORE_HEADERS
    precompiled.h
    precompiled_c.h
    ../../third-party/demangle/ansidecl.h
    ../../third-party/demangle/cp-demangle.h
    ../../third-party/demangle/demangle.h
    ../../third-party/demangle/libiberty.h
    ../../third-party/demangle/undname.h
    ../../third-party/demangle/unmangle.h
    ../../third-party/lzma/Alloc.h
    ../../third-party/lzma/LzFind.h
    ../../third-party/lzma/LzFindMt.h
    ../../third-party/lzma/LzmaEnc.h
    ../../third-party/lzma/Threads.h
)

add_library(invariant_core STATIC 
    ${INVARIANT_CORE_CXX_SOURCES} 
    ${INVARIANT_CORE_C_SOURCES} 
    ${INVARIANT_CORE_HEADERS}
)

target_include_directories(invariant_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/demangle
    ${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/lzma
    ${CMAKE_CURRENT_SOURCE_DIR}/../../runtime
)

if(MSVC)
    # C++ 文件使用 precompiled.h
    set_source_files_properties(precompiled.cc PROPERTIES COMPILE_FLAGS "/Yc\"precompiled.h\"")
    
    # C 文件使用 precompiled_c.h 作为预编译头
    # 首先创建 C 预编译头
    set_source_files_properties(precompiled_c.c PROPERTIES 
        LANGUAGE C
        COMPILE_FLAGS "/Yc\"precompiled_c.h\" /FI\"precompiled_c.h\""
    )
    
    # 其他 C 文件使用 C 预编译头
    set(OTHER_C_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/demangle/cp-demangle.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/demangle/undname.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/demangle/unmangle.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/lzma/Alloc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/lzma/LzFind.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/lzma/LzFindMt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/lzma/LzmaEnc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/lzma/Threads.c
    )
    foreach(src ${OTHER_C_SOURCES})
        set_source_files_properties(${src} PROPERTIES 
            LANGUAGE C
            COMPILE_FLAGS "/Yu\"precompiled_c.h\" /FI\"precompiled_c.h\""
        )
    endforeach()
endif()
