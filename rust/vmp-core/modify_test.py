import sys
import os

file_path = r'E:\Test_C++\ConsoleApplication1\examples\VMProtect_SDK_Example.cpp'

if not os.path.exists(file_path):
    print(f"Error: {file_path} not found")
    sys.exit(1)

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Modify Test_WinAPI
old_winapi = """void Test_WinAPI() {
    VMProtectBeginVirtualization("WinAPI");
    PrintLine(u8"\\n[Test 6] Windows API 外部调用");

    // GetTickCount64
    ULONGLONG t1 = GetTickCount64();
    PrintVal("GetTickCount64", (long long)t1);

    // GetCurrentProcessId
    DWORD pid = GetCurrentProcessId();
    PrintVal(u8"进程 PID", (long long)pid);

    // GetCurrentThreadId
    DWORD tid = GetCurrentThreadId();
    PrintVal(u8"线程 TID", (long long)tid);

    // QueryPerformanceCounter
    LARGE_INTEGER freq, cnt1, cnt2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt1);

    // 做点计算让时间流逝
    volatile long long work = 0;
    for (int i = 0; i < 1000000; i++) work += i;

    QueryPerformanceCounter(&cnt2);
    long long elapsed_us = (cnt2.QuadPart - cnt1.QuadPart) * 1000000 / freq.QuadPart;
    PrintVal(u8"计算耗时 (微秒)", elapsed_us);

    // VirtualAlloc / VirtualFree
    void* mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        memset(mem, 0xAB, 4096);
        unsigned char* p = (unsigned char*)mem;
        PrintHex(u8"VirtualAlloc 地址", (unsigned long long)mem);
        PrintVal(u8"首字节", p[0]);
        VirtualFree(mem, 0, MEM_RELEASE);
    }

    CountCall();
    VMProtectEnd();
}"""

new_winapi = """void Test_WinAPI() {
    VMProtectBeginVirtualization("WinAPI");
    PrintLine(u8"\\n[Test 6] Windows API 外部调用 (Deep Diagnostics)");

    // QueryPerformanceCounter
    LARGE_INTEGER freq;
    freq.QuadPart = 0xDEADBEEF; // Sentinel value
    PrintHex(u8"&freq Address", (unsigned long long)&freq);
    PrintHex(u8"freq.QuadPart (Before)", (unsigned long long)freq.QuadPart);
    
    BOOL resFreq = QueryPerformanceFrequency(&freq);
    
    PrintVal(u8"QueryPerformanceFrequency Result (BOOL)", (long long)resFreq);
    PrintHex(u8"freq.QuadPart (After)", (unsigned long long)freq.QuadPart);

    LARGE_INTEGER cnt1;
    cnt1.QuadPart = 0xCAFEBABE; // Sentinel value
    PrintHex(u8"&cnt1 Address", (unsigned long long)&cnt1);
    PrintHex(u8"cnt1.QuadPart (Before)", (unsigned long long)cnt1.QuadPart);
    
    BOOL resCnt1 = QueryPerformanceCounter(&cnt1);
    
    PrintVal(u8"QueryPerformanceCounter Result (BOOL)", (long long)resCnt1);
    PrintHex(u8"cnt1.QuadPart (After)", (unsigned long long)cnt1.QuadPart);

    LARGE_INTEGER cnt2;
    // 做点计算让时间流逝
    volatile long long work = 0;
    for (int i = 0; i < 1000000; i++) work += i;

    cnt2.QuadPart = 0xBAADF00D;
    PrintHex(u8"&cnt2 Address", (unsigned long long)&cnt2);
    PrintHex(u8"cnt2.QuadPart (Before)", (unsigned long long)cnt2.QuadPart);
    
    BOOL resCnt2 = QueryPerformanceCounter(&cnt2);
    
    PrintVal(u8"QueryPerformanceCounter 2 Result (BOOL)", (long long)resCnt2);
    PrintHex(u8"cnt2.QuadPart (After)", (unsigned long long)cnt2.QuadPart);

    if (freq.QuadPart != 0 && freq.QuadPart != 0xDEADBEEF) {
        long long elapsed_us = (cnt2.QuadPart - cnt1.QuadPart) * 1000000 / freq.QuadPart;
        PrintVal(u8"计算耗时 (微秒)", elapsed_us);
    } else {
        PrintLine(u8"ERROR: freq.QuadPart is invalid, cannot compute elapsed time.");
    }

    CountCall();
    VMProtectEnd();
}"""

# Replace main body
old_main = """    // ---- 执行所有测试 (每个测试有自己的 VM 保护区) ----
    Test_Fibonacci();
    Test_PrimeSieve();
    Test_Matrix();
    Test_Switch();
    Test_FuncPtr();
    Test_WinAPI();
    Test_BitOps();
    Test_Strings();
    Test_Conditionals();
    Test_Arithmetic();
    Test_CallChain();
    Test_TableLookup();
    Test_Float();
    Test_LargeImmediates();"""

new_main = """    // ---- 执行所有测试 (每个测试有自己的 VM 保护区) ----
    Test_WinAPI();"""

if old_winapi in content:
    content = content.replace(old_winapi, new_winapi)
    print("Replaced Test_WinAPI")
else:
    print("Could not find Test_WinAPI block")

if old_main in content:
    content = content.replace(old_main, new_main)
    print("Replaced main() calls")
else:
    print("Could not find main() calls block")

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
print("File updated.")
