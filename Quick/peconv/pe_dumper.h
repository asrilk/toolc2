/**
* @file
* @brief  将 PE 从内存缓冲区转储到文件中。
*/

#pragma once

#include <windows.h>
#include "exports_mapper.h"

namespace peconv {

    /**
  一种丢弃 PE 填充物的模式。
    */
    typedef enum {
        PE_DUMP_AUTO = 0, /**< 自动检测最适合给定输入的转储模式 */
        PE_DUMP_VIRTUAL,/**<像在内存中一样转储（虚拟） */
        PE_DUMP_UNMAP, /**< 转换为原始格式：使用原始部分的标题 */
        PE_DUMP_REALIGN, /**< 转换为原始格式：通过将原始部分的标题重新对齐为与虚拟相同（如果 PE 在内存中解压缩，则很有用）*/
        PE_DUMP_MODES_COUNT /**<转储模式总数*/
    } t_pe_dump_mode;

    /**
  检测最适合给定输入的转储模式。
    \param buffer : 包含要转储的 PE 的缓冲区。
    \param 缓冲区大小：给定缓冲区的大小
    */
    t_pe_dump_mode detect_dump_mode(IN const BYTE* buffer, IN size_t buffer_size);

    /**
 将 PE 从 Fiven 缓冲区转储到文件中。它期望给出模块基数和大小。
    \param output File Path : 应该保存转储的文件的名称
    \param buffer : 包含要转储的 PE 的缓冲区。警告：缓冲区可能会在转储之前进行预处理。
    \param 缓冲区大小：给定缓冲区的大小
    \param module base : PE 缓冲区重定位到的基础
    \param dump mode : 指定 PE 应该以哪种格式被转储。如果模式设置为 PE DUMP AUTO，它会自动检测模式并返回检测到的模式。
    \param 导出地图：可选。如果提供了exports Map，它会根据提供的导出函数的map，尝试恢复PE的被破坏的导入表。
    */
    bool dump_pe(IN const char *outputFilePath,
        IN OUT BYTE* buffer,
        IN size_t buffer_size,
        IN const ULONGLONG module_base,
        IN OUT t_pe_dump_mode &dump_mode,
        IN OPTIONAL const peconv::ExportsMapper* exportsMap = nullptr
    );

};// namespace peconv
