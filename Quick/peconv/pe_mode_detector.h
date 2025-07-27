/**
* @file
* @brief  检测提供的缓冲区（即原始、虚拟）中的 PE 处于哪种模式。分析特定模式的典型 PE 特征。
*/

#pragma once

#include <windows.h>

#include "pe_hdrs_helper.h"

namespace peconv {

    /**
  检查内存中的PE是否为原始格式
    */
    bool is_pe_raw(
        IN const BYTE* pe_buffer,
        IN size_t pe_size
    );

    /**
  检查虚拟部分地址是否与原始地址相同（即是否重新对齐 PE）
    */
    bool is_pe_raw_eq_virtual(
        IN const BYTE* pe_buffer,
        IN size_t pe_size
    );

    /**
  检查 PE 是否有在内存中解压/扩展的部分
    */
    bool is_pe_expanded(
        IN const BYTE* pe_buffer,
        IN size_t pe_size
    );

    /**
    检查给定部分是否在内存中解压
    */
    bool is_section_expanded(IN const BYTE* pe_buffer,
        IN size_t pe_size,
        IN const PIMAGE_SECTION_HEADER sec
    );

};// namespace peconv
