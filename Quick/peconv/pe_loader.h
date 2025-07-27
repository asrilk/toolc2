/**
* @file
* @brief   Loading PE from a file with the help of the custom loader.
*/

#pragma once

#include "pe_raw_to_virtual.h"
#include "function_resolver.h"

namespace peconv {
    /**
  将 PE 从给定缓冲区读入内存并将其映射为虚拟格式。
    （自动原始到虚拟转换）。
    如果可执行标志为真，则将 PE 文件加载到可执行内存中。
    如果重定位标志为真，则应用重定位。不加载导入。
    自动分配所需大小的缓冲区（大小在输出大小中返回）。缓冲区可以由函数 free pe buffer 释放。
    */
    BYTE* load_pe_module(BYTE* dllRawData, size_t r_size, OUT size_t &v_size, bool executable, bool relocate);

    /**
   将给定文件中的 PE 读入内存并将其映射为虚拟格式。
    （自动原始到虚拟转换）。
    如果可执行标志为真，则将 PE 文件加载到可执行内存中。
    如果重定位标志为真，则应用重定位。不加载导入。
    自动分配所需大小的缓冲区（大小在输出大小中返回）。缓冲区可以由函数 free pe buffer 释放。
    */
    BYTE* load_pe_module(const char *filename, OUT size_t &v_size, bool executable, bool relocate);

    /**
   以可以直接执行的方式从原始缓冲区加载完整的 PE：重新映射到虚拟格式，应用重定位，加载导入。
    允许提供自定义函数解析器。
    */
    BYTE* load_pe_executable(BYTE* dllRawData, size_t r_size, OUT size_t &v_size, t_function_resolver* import_resolver=NULL);

    /**
 以可以直接执行的方式从文件加载完整的 PE：重新映射到虚拟格式，应用重定位，加载导入。
    允许提供自定义函数解析器。
    */
    BYTE* load_pe_executable(const char *filename, OUT size_t &v_size, t_function_resolver* import_resolver=NULL);

};// namespace peconv
