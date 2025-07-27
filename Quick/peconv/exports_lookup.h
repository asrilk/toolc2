/**
* @file
* @brief  在 PE 的导出表中搜索特定函数。
*/

#pragma once
#include <windows.h>

#include "pe_hdrs_helper.h"
#include "function_resolver.h"
#include "exports_mapper.h"

#include <string>
#include <vector>
#include <map>

namespace peconv {

    /**
 通过名称获取函数地址。使用导出表查找。
    警告：不适用于转发功能。
    */
    FARPROC get_exported_func(PVOID modulePtr, LPSTR wanted_name);

    /**
   获取给定模块中按名称导出的所有函数的列表。
    */
    size_t get_exported_names(PVOID modulePtr, std::vector<std::string> &names_list);

    /**
  使用导出表查找的函数解析器。
    */
    class export_based_resolver : default_func_resolver {
        public:
        /**
       从给定的 DLL 中获取具有给定名称的函数的地址 (VA)。
        使用导出表查找作为查找导入的主要方法。失败时，它会退回到默认的函数解析器。
        \param func name : 函数名
        \param lib name : DLL 的名称
        \return 导出函数的虚拟地址
        */
        virtual FARPROC resolve_func(LPSTR lib_name, LPSTR func_name);
    };

    /**
   从导出表中读取 DLL 名称。
    */
    LPSTR read_dll_name(HMODULE modulePtr);

}; //namespace peconv
