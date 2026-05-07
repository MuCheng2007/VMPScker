// VMProtect SDK 增强测试程序
// 覆盖: 重计算、外部调用、递归、switch、函数指针、内存操作、字符串处理等
//
// 编译 (MSVC x64):
//   cl.exe /O2 /EHsc /Fe:test_enhanced.exe VMProtect_SDK_Example.cpp /I.. /link ..\lib\VMProtectSDK64.lib
//
// 编译 (MSVC x64, 无优化便于调试):
//   cl.exe /Od /Zi /EHsc /Fe:test_enhanced_d.exe VMProtect_SDK_Example.cpp /I.. /link ..\lib\VMProtectSDK64.lib

#include <iostream>
#include <windows.h>
#include <string>
#include <cstring>
#include <cmath>
#include "VMProtectSDK.h"


using namespace std;

// ============================================================
//  工具函数 (不在保护区域内, 测试外部跳转)
// ============================================================

void PrintLine(const char* s) { cout << s << endl; }
void PrintVal(const char* label, long long v) { cout << "  " << label << ": " << v << endl; }
void PrintHex(const char* label, unsigned long long v) {
    printf("  %s: 0x%016llX\n", label, v);
}

static int g_call_counter = 0;
void CountCall() { g_call_counter++; }

// ============================================================
//  测试 1: 重计算 — Fibonacci (递归 + 迭代)
// ============================================================

long long FibRecursive(int n) {
    if (n <= 1) return n;
    return FibRecursive(n - 1) + FibRecursive(n - 2);
}

long long FibIterative(int n) {
    long long a = 0, b = 1;
    for (int i = 2; i <= n; i++) {
        long long t = a + b;
        a = b;
        b = t;
    }
    return n > 0 ? b : a;
}

void Test_Fibonacci() {
    VMProtectBeginVirtualization("Fibonacci");
    PrintLine(u8"\n[Test 1] Fibonacci 计算");

    // 递归 (小规模, 测试栈帧)
    long long r1 = FibRecursive(30);
    PrintVal("FibRecursive(30)", r1);

    // 迭代 (大规模, 测试循环)
    long long r2 = FibIterative(90);
    PrintVal("FibIterative(90)", r2);

    // 验证
    bool ok = (r1 == 832040) && (r2 == 2880067194370816120LL);
    PrintVal(u8"验证结果", ok ? 1 : 0);

    CountCall();
    VMProtectEnd();
#pragma warning(pop)
}

// ============================================================
//  测试 2: 素数筛 (数组操作 + 嵌套循环)
// ============================================================

int PrimeSieve(int limit) {
    // 简单埃氏筛
    static bool sieve[100001];
    memset(sieve, 0, sizeof(sieve));
    int count = 0;
    for (int i = 2; i <= limit; i++) {
        if (!sieve[i]) {
            count++;
            for (long long j = (long long)i * i; j <= limit; j += i)
                sieve[j] = true;
        }
    }
    return count;
}

void Test_PrimeSieve() {
    VMProtectBeginVirtualization("PrimeSieve");
    PrintLine(u8"\n[Test 2] 素数筛");

    int count = PrimeSieve(100000);
    PrintVal(u8"100000以内素数个数", count);

    CountCall();
    VMProtectEnd();
}

// ============================================================
//  测试 3: 矩阵乘法 (二维数组 + 三重循环)
// ============================================================

#define MAT_N 64

static long long matA[MAT_N][MAT_N];
static long long matB[MAT_N][MAT_N];
static long long matC[MAT_N][MAT_N];

void MatMul() {
    for (int i = 0; i < MAT_N; i++)
        for (int j = 0; j < MAT_N; j++) {
            long long sum = 0;
            for (int k = 0; k < MAT_N; k++)
                sum += matA[i][k] * matB[k][j];
            matC[i][j] = sum;
        }
}

long long MatTrace() {
    long long trace = 0;
    for (int i = 0; i < MAT_N; i++)
        trace += matC[i][i];
    return trace;
}

void Test_Matrix() {
    VMProtectBeginVirtualization("MatrixMul");
    PrintLine(u8"\n[Test 3] 矩阵乘法 64x64");

    // 初始化
    for (int i = 0; i < MAT_N; i++)
        for (int j = 0; j < MAT_N; j++) {
            matA[i][j] = (i + 1) * (j + 1) % 1000;
            matB[i][j] = (i == j) ? 1 : 0; // 单位矩阵
        }

    MatMul();
    long long trace = MatTrace();
    PrintVal(u8"A * I 的迹", trace);

    CountCall();
    VMProtectEnd();
}

// ============================================================
//  测试 4: Switch/Case 分发 (大量分支)
// ============================================================

long long SwitchDispatch(int opcode, long long a, long long b) {
    switch (opcode) {
        case  0: return a + b;
        case  1: return a - b;
        case  2: return a * b;
        case  3: return b != 0 ? a / b : 0;
        case  4: return a ^ b;
        case  5: return a & b;
        case  6: return a | b;
        case  7: return ~a;
        case  8: return a << (b & 63);
        case  9: return (unsigned long long)a >> (b & 63);
        case 10: return (long long)a >> (b & 63);
        case 11: return a > b ? a : b;
        case 12: return a < b ? a : b;
        case 13: return a == b ? 1 : 0;
        case 14: return a != b ? 1 : 0;
        case 15: return a * a + b * b;
        default: return -1;
    }
}

void Test_Switch() {
    VMProtectBeginVirtualization("SwitchDispatch");
    PrintLine(u8"\n[Test 4] Switch/Case 分发 (16 分支)");

    long long acc = 0;
    for (int op = 0; op < 16; op++) {
        long long r = SwitchDispatch(op, 100, 7);
        acc += r;
    }
    PrintVal(u8"16分支累加结果", acc);

    CountCall();
    VMProtectEnd();
}

// ============================================================
//  测试 5: 函数指针 / 间接调用
// ============================================================

typedef long long (*BinOp)(long long, long long);

long long OpAdd(long long a, long long b) { return a + b; }
long long OpMul(long long a, long long b) { return a * b; }
long long OpXor(long long a, long long b) { return a ^ b; }
long long OpSub(long long a, long long b) { return a - b; }

void Test_FuncPtr() {
    VMProtectBeginVirtualization("FuncPtr");
    PrintLine(u8"\n[Test 5] 函数指针间接调用");

    BinOp ops[] = { OpAdd, OpMul, OpXor, OpSub };
    long long acc = 0;
    for (int i = 0; i < 1000; i++) {
        for (int j = 0; j < 4; j++) {
            acc = ops[j](acc, i + 1);
        }
    }
    PrintVal(u8"函数指针累加", acc);

    CountCall();
    VMProtectEnd();
}

// ============================================================
//  测试 6: Windows API 外部调用
// ============================================================

void Test_WinAPI() {
    VMProtectBeginVirtualization("WinAPI");
    PrintLine(u8"\n[Test 6] Windows API 外部调用 (Deep Diagnostics)");

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
}

// ============================================================
//  测试 7: 位操作密集 (加密/哈希模拟)
// ============================================================

unsigned long long HashBlock(const void* data, size_t len) {
    unsigned long long h = 0xcbf29ce484222325ULL; // FNV offset basis
    const unsigned char* p = (const unsigned char*)data;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL; // FNV prime
        // 额外混淆
        h = (h << 13) | (h >> 51);
        h ^= (h >> 7);
    }
    return h;
}

void Test_BitOps() {
    VMProtectBeginVirtualization("BitOps");
    PrintLine(u8"\n[Test 7] 位操作密集 (FNV-1a 哈希)");

    // 构造测试数据
    static char buf[4096];
    for (int i = 0; i < 4096; i++) buf[i] = (char)(i * 37 + 13);

    unsigned long long h = 0;
    for (int round = 0; round < 100; round++) {
        h ^= HashBlock(buf, sizeof(buf));
    }
    PrintHex(u8"哈希结果", h);

    CountCall();
    VMProtectEnd();
}

// ============================================================
//  测试 8: 字符串操作 (strcpy/strcmp/strlen + 手动操作)
// ============================================================

void Test_Strings() {
#pragma warning(push)
#pragma warning(disable: 4996)
    VMProtectBeginVirtualization("Strings");
    PrintLine(u8"\n[Test 8] 字符串操作");

    char dst[256];
    const char* src = "Hello VMProtect Virtualization Test!";
    strcpy(dst, src);
    PrintVal("strlen", (long long)strlen(dst));
    PrintVal("strcmp==0", strcmp(dst, src) == 0 ? 1 : 0);

    // 手动反转
    int len = (int)strlen(dst);
    for (int i = 0; i < len / 2; i++) {
        char t = dst[i]; dst[i] = dst[len - 1 - i]; dst[len - 1 - i] = t;
    }
    PrintVal(u8"反转后首字符", dst[0]);
    PrintVal(u8"反转后末字符", dst[len - 1]);

    CountCall();
    VMProtectEnd();
}

// ============================================================
//  测试 9: 条件嵌套 + 短路求值
// ============================================================

int ConditionalNest(int x) {
    int r = 0;
    if (x > 100) {
        if (x > 1000) {
            if (x > 10000) r = 4;
            else r = 3;
        } else {
            r = 2;
        }
    } else if (x > 10) {
        r = 1;
    } else {
        r = 0;
    }

    // 短路
    if (x > 0 && x < 50 && (x % 7 == 0)) r += 100;
    if (x <= 0 || x >= 50 || (x % 3 == 0)) r += 200;

    // 三目
    r += (x & 1) ? 1000 : 2000;

    return r;
}

void Test_Conditionals() {
    VMProtectBeginVirtualization("Conditionals");
    PrintLine(u8"\n[Test 9] 条件嵌套 + 短路求值");

    long long acc = 0;
    for (int i = -10; i <= 200; i++) {
        acc += ConditionalNest(i);
    }
    PrintVal(u8"条件累加", acc);

    CountCall();
    VMProtectEnd();
}

// ============================================================
//  测试 10: 位移 + 乘除 + 取模密集
// ============================================================

long long ArithmeticBench(int n) {
    long long acc = 0;
    for (int i = 1; i <= n; i++) {
        long long v = i;
        v = v * 31 + 17;
        v = v ^ (v >> 13);
        v = v * 1103515245 + 12345;
        v = v ^ (v << 7);
        v = v % 1000000007;
        if (v < 0) v = -v;
        acc += v;
    }
    return acc;
}

void Test_Arithmetic() {
    VMProtectBeginVirtualization("Arithmetic");
    PrintLine(u8"\n[Test 10] 算术密集 (类 LCG 随机数)");

    long long r = ArithmeticBench(1000000);
    PrintVal(u8"算术累加", r);

    CountCall();
    VMProtectEnd();
}

// ============================================================
//  测试 11: 多层函数调用链 (测试跨函数栈帧)
// ============================================================

int ChainA(int x);
int ChainB(int x);
int ChainC(int x);

int ChainA(int x) { CountCall(); return x <= 0 ? 1 : ChainB(x - 1) + x; }
int ChainB(int x) { CountCall(); return x <= 0 ? 2 : ChainC(x - 1) + x; }
int ChainC(int x) { CountCall(); return x <= 0 ? 3 : ChainA(x - 1) + x; }

void Test_CallChain() {
    VMProtectBeginVirtualization("CallChain");
    PrintLine(u8"\n[Test 11] 多层函数调用链 A->B->C->A");

    int r = ChainA(30);
    PrintVal("ChainA(30)", (long long)r);

    CountCall();
    VMProtectEnd();
}

// ============================================================
//  测试 12: 查表 + 跳转表
// ============================================================

static const unsigned long long LOOKUP_TABLE[256] = {
    0x72616E646F6D5F30ULL, 0x3A3A3A3A3A3A3A3AULL,
    0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL,
    // ... 填充更多
};

unsigned long long TableLookup(unsigned int idx) {
    // 多级索引
    unsigned int i0 = idx & 0xFF;
    unsigned int i1 = (idx >> 8) & 0xFF;
    unsigned int i2 = (idx >> 16) & 0xFF;
    return LOOKUP_TABLE[i0 % 4] ^ LOOKUP_TABLE[i1 % 4] ^ LOOKUP_TABLE[i2 % 4];
}

void Test_TableLookup() {
    VMProtectBeginVirtualization("TableLookup");
    PrintLine(u8"\n[Test 12] 查表 + 多级索引");

    unsigned long long acc = 0;
    for (unsigned int i = 0; i < 10000; i++) {
        acc ^= TableLookup(i * 2654435761u); // Knuth multiplicative hash
    }
    PrintHex(u8"查表结果", acc);

    CountCall();
    VMProtectEnd();
}

// ============================================================
//  测试 13: 浮点运算 (如果 VM 支持)
// ============================================================

double FloatBench(int n) {
    double acc = 0.0;
    for (int i = 1; i <= n; i++) {
        double x = (double)i / (double)n;
        acc += sin(x) * cos(x) + sqrt(x) * log(x + 1.0);
    }
    return acc;
}

void Test_Float() {
    // 浮点不在 VM 保护区域内, 测试外部调用
    PrintLine(u8"\n[Test 13] 浮点运算 (外部函数)");
    double r = FloatBench(100000);
    printf(u8"  浮点累加: %.6f\n", r);
}

// ============================================================
//  测试 14: 大立即数 / 64位常量
// ============================================================

void Test_LargeImmediates() {
    VMProtectBeginVirtualization("LargeImm");
    PrintLine(u8"\n[Test 14] 大立即数 / 64位常量");

    unsigned long long a = 0xDEADBEEFCAFEBABEULL;
    unsigned long long b = 0x0123456789ABCDEFULL;
    unsigned long long c = a ^ b;
    unsigned long long d = (c << 31) | (c >> 33);
    unsigned long long e = d * 0x9E3779B97F4A7C15ULL; // golden ratio hash

    PrintHex("a", a);
    PrintHex("b", b);
    PrintHex("a^b", c);
    PrintHex("rotated", d);
    PrintHex("hashed", e);

    CountCall();
    VMProtectEnd();
}

// ============================================================
//  主函数: 重计算入口 + 调度所有测试
// ============================================================

int main() {
    SetConsoleOutputCP(65001); // UTF-8

    // removed main begin

    PrintLine("************************************************************************");
    PrintLine("*                                                                      *");
    PrintLine("*          VMProtect VM Engine Enhanced Test Suite                      *");
    PrintLine("*                                                                      *");
    PrintLine("************************************************************************");

    cout << u8"\n测试项目:" << endl;
    cout << u8"  [1]  Fibonacci 递归+迭代" << endl;
    cout << u8"  [2]  素数筛 (数组+嵌套循环)" << endl;
    cout << u8"  [3]  矩阵乘法 64x64" << endl;
    cout << u8"  [4]  Switch/Case 16分支" << endl;
    cout << u8"  [5]  函数指针间接调用" << endl;
    cout << u8"  [6]  Windows API 外部调用" << endl;
    cout << u8"  [7]  位操作密集 (FNV-1a)" << endl;
    cout << u8"  [8]  字符串操作" << endl;
    cout << u8"  [9]  条件嵌套+短路求值" << endl;
    cout << u8"  [10] 算术密集 (LCG)" << endl;
    cout << u8"  [11] 多层调用链 A->B->C" << endl;
    cout << u8"  [12] 查表+多级索引" << endl;
    cout << u8"  [13] 浮点运算 (外部)" << endl;
    cout << u8"  [14] 大立即数/64位常量" << endl;

    // 主函数内的重计算: 累加验证
    long long main_sum = 0;
    for (int i = 0; i < 1000000; i++) {
        main_sum += (long long)i * i - (long long)i * 3 + 7;
    }
    PrintVal(u8"\n[main] 百万级累加", main_sum);

    // 主函数内的位操作
    unsigned long long hash = 0x811c9dc5ULL;
    for (int i = 0; i < 10000; i++) {
        hash ^= (unsigned long long)i;
        hash *= 0x01000193ULL;
        hash ^= (hash >> 13);
    }
    PrintHex(u8"[main] 哈希链", hash);

    // removed main end

    // ---- 执行所有测试 (每个测试有自己的 VM 保护区) ----
    Test_WinAPI();

    // ---- 汇总 ----
    PrintLine("\n========================================================================");
    PrintLine(u8"  测试完成");
    PrintVal(u8"总调用计数", (long long)g_call_counter);
    PrintLine("========================================================================");

    system("pause > nul");
    return 0;
}
