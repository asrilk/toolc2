/*
 * 内存DLL加载代码
 * 0.0.4 版本
 *
 * 版权所有 (c) 2004-2015 由 Joachim Bauch / mail@joachim-bauch.de
 * http://www.joachim-bauch.de
 *
 * 本文件内容以 Mozilla 公共许可证版本为准
 * 2.0（“许可证”）；除非符合以下规定，否则您不得使用此文件
 * 许可证。您可以在以下网址获得许可证的副本
 * http://www.mozilla.org/MPL/
 *
 * 根据许可分发的软件是按“原样”分发的，
 * 不提供任何形式的明示或暗示的保证。查看许可证
 * 用于管理权利和限制的特定语言
 * 执照。
 *
 * 原始代码为 Memory Module.h
 *
 * 原始代码的初始开发者是 Joachim Bauch。
 *
 * Joachim Bauch 创建的部分版权所有 (C) 2004-2015
 * 约阿希姆·鲍赫。版权所有。
 *
 */

#ifndef __MEMORY_MODULE_HEADER
#define __MEMORY_MODULE_HEADER

#include <windows.h>

typedef void* HMEMORYMODULE;

typedef void* HMEMORYRSRC;

typedef void* HCUSTOMMODULE;

#ifdef __cplusplus
extern "C" {
#endif

    typedef LPVOID(*CustomAllocFunc)(LPVOID, SIZE_T, DWORD, DWORD, void*);
    typedef BOOL(*CustomFreeFunc)(LPVOID, SIZE_T, DWORD, void*);
    typedef HCUSTOMMODULE(*CustomLoadLibraryFunc)(LPCSTR, void*);
    typedef FARPROC(*CustomGetProcAddressFunc)(HCUSTOMMODULE, LPCSTR, void*);
    typedef void (*CustomFreeLibraryFunc)(HCUSTOMMODULE, void*);

    /**
     * 从内存位置加载指定大小的 EXE/DLL。
     *
     * 使用默认加载库/获取过程地址解析所有依赖项
     * 通过 Windows API 调用。
     */
    HMEMORYMODULE MemoryLoadLibrary(const void*, size_t);

    /**
     * 使用自定义依赖项从给定大小的内存位置加载 EXE/DLL
     * 解析器。
     *
     * 依赖项将使用传递的回调方法解决。
     */
    HMEMORYMODULE MemoryLoadLibraryEx(const void*, size_t,
        CustomAllocFunc,
        CustomFreeFunc,
        CustomLoadLibraryFunc,
        CustomGetProcAddressFunc,
        CustomFreeLibraryFunc,
        void*);

    /**
     *获取导出方法的地址。支持按名称和按加载
     * 序数值.
     */
    FARPROC MemoryGetProcAddress(HMEMORYMODULE, LPCSTR);

    /**
     * 免费以前加载的 EXE/DLL。
     */
    void MemoryFreeLibrary(HMEMORYMODULE);

    /**
     * 执行入口点（仅限 EXE）。入口点只能被执行
     * 如果 EXE 已加载到正确的基地址，或者它可以
     * 被重定位（即重定位信息没有被
     * 链接器）。
     *
     * 重要：调用此函数不会返回，即一旦加载
     * EXE 运行完毕，进程将终止。
     *
     * 如果入口点无法执行，则返回负值。
     */
    int MemoryCallEntryPoint(HMEMORYMODULE);

    /**
     *查找具有指定类型和名称的资源的位置。
     */
    HMEMORYRSRC MemoryFindResource(HMEMORYMODULE, LPCTSTR, LPCTSTR);

    /**
     * 查找具有指定类型、名称和语言的资源的位置。
     */
    HMEMORYRSRC MemoryFindResourceEx(HMEMORYMODULE, LPCTSTR, LPCTSTR, WORD);

    /**
     * 以字节为单位获取资源的大小。
     */
    DWORD MemorySizeofResource(HMEMORYMODULE, HMEMORYRSRC);

    /**
     * 获取指向资源内容的指针。
     */
    LPVOID MemoryLoadResource(HMEMORYMODULE, HMEMORYRSRC);

    /**
     * 加载字符串资源。
     */
    int MemoryLoadString(HMEMORYMODULE, UINT, LPTSTR, int);

    /**
     * 加载指定语言的字符串资源。
     */
    int MemoryLoadStringEx(HMEMORYMODULE, UINT, LPTSTR, int, WORD);

    /**
    *调用 Virtual Alloc 的 Custom Alloc Func 的默认实现
    * 在内部为库分配内存
    *
    * 这是内存加载库使用的默认值。
    */
    LPVOID MemoryDefaultAlloc(LPVOID, SIZE_T, DWORD, DWORD, void*);

    /**
    *调用 Virtual Free 的 Custom Free Func 的默认实现
    * 在内部释放库使用的内存
    *
    * 这是内存加载库使用的默认值。
    */
    BOOL MemoryDefaultFree(LPVOID, SIZE_T, DWORD, void*);

    /**
     * 调用加载库 A 的自定义加载库函数的默认实现
     * 在内部加载额外的库。
     *
     * 这是内存加载库使用的默认值。
     */
    HCUSTOMMODULE MemoryDefaultLoadLibrary(LPCSTR, void*);

    /**
     * 调用 Get Proc Address 的 Custom Get Proc Address Func 的默认实现
     * 在内部获取导出函数的地址。
     *
     * 这是内存加载库使用的默认值。
     */
    FARPROC MemoryDefaultGetProcAddress(HCUSTOMMODULE, LPCSTR, void*);

    /**
     *调用 Free Library 的 Custom Free Library Func 的默认实现
     * 在内部释放额外的库。
     *
     * 这是内存加载库使用的默认值。
     */
    void MemoryDefaultFreeLibrary(HCUSTOMMODULE, void*);

#ifdef __cplusplus
}
#endif

#endif  // __MEMORY_MODULE_HEADER
