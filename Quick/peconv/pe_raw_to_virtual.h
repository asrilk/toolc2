/**
* @file
* @brief   Converting PE from raw to virtual format.
*/

#pragma once

#include <windows.h>
#include <stdio.h>

#include "buffer_util.h"

namespace peconv {

    /**
 将缓冲区中提供的原始 PE 转换为虚拟格式。
    如果可执行标志为真（默认），PE 文件被加载到可执行内存中。
    不适用重定位。不加载导入。
    自动分配所需大小的缓冲区（大小在输出大小中返回）。缓冲区可以由函数 free pe 模块释放。
    如果定义了所需的基数（默认为 0），它将强制在特定基数进行分配。
    */
    BYTE* pe_raw_to_virtual(
        IN const BYTE* rawPeBuffer,
        IN size_t rawPeSize,
        OUT size_t &outputSize,
        IN OPTIONAL bool executable = true,
        IN OPTIONAL ULONGLONG desired_base = 0
    );

}; // namespace peconv
