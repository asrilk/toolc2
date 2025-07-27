/**
* @file
* @brief   Converting PE from virtual to raw format.
*/

#pragma once

#include <windows.h>

#include "buffer_util.h"

namespace peconv {

    /**
  将 PE 的虚拟图像映射到原始图像。自动应用重定位。
    自动分配所需大小的缓冲区（大小在输出大小中返回）。
    \param payload : 需要转换为 Raw 格式的 Virtual 格式的 PE
    \param in size : 输入缓冲区的大小（虚拟格式的 PE）
    \param load Base : 给定 PE 重定位到的基础
    \param output Size : 输出缓冲区的大小（原始格式的 PE）
    \param rebuffer ：如果设置（默认），输入缓冲区被重新缓冲，原始缓冲区不被修改。
    \返回一个输出大小的缓冲区，包含原始 PE。缓冲区可以由函数 free pe 模块释放。
    */
    BYTE* pe_virtual_to_raw(
        IN BYTE* payload,
        IN size_t in_size,
        IN ULONGLONG loadBase,
        OUT size_t &outputSize,
        IN OPTIONAL bool rebuffer=true
    );

    /*
 将 PE 的原始对齐方式修改为与虚拟对齐方式相同。
    \param payload : 需要重新对齐的虚拟格式的 PE
    \param in size : 输入缓冲区的大小
    \param load Base : 给定 PE 重定位到的基础
    \param output Size : 输出缓冲区的大小（原始格式的 PE）
    \返回一个输出大小的缓冲区，包含重新对齐的 PE。缓冲区可以由函数 free pe 模块释放。
    */
    BYTE* pe_realign_raw_to_virtual(
        IN const BYTE* payload,
        IN size_t in_size,
        IN ULONGLONG loadBase,
        OUT size_t &outputSize
    );

};//namespace peconv
