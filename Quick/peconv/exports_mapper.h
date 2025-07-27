/**
* @file
* @brief  Exports Mapper 类的定义。从提供的 DLL 创建所有导出函数的查找。允许将地址与相应的功能相关联。
*/

#pragma once

#include <windows.h>

#include <string>
#include <map>
#include <set>
#include <sstream>

#include "pe_hdrs_helper.h"
#include "pe_raw_to_virtual.h"
#include "peconv/exported_func.h"
#include "peconv/file_util.h"

namespace peconv {

    struct DllInfo {
        DllInfo()
            : moduleBase(0), moduelSize(0), is64b(false)
        {
        }

        DllInfo(ULONGLONG _moduleBase, size_t _moduelSize, bool _is64b, std::string _moduleName)
        {
            moduleBase = _moduleBase;
            moduelSize = _moduelSize;
            moduleName = _moduleName;
            is64b = _is64b;
            shortName = get_dll_shortname(moduleName);
        }

        DllInfo(DllInfo &other)
        {
            moduleBase = other.moduleBase;
            moduelSize = other.moduelSize;
            moduleName = other.moduleName;
            shortName = other.shortName;
            is64b = other.is64b;
        }

        bool operator<(const DllInfo &other) const
        {
            return this->moduleBase < other.moduleBase;
        }

    protected:
        ULONGLONG moduleBase;
        size_t moduelSize;
        std::string moduleName;
        std::string shortName;
        bool is64b;

        friend class ExportsMapper;
    };

    class ExportsMapper {

    public:

        /**
       将给定的 DLL 附加到导出函数的查找表中。返回从此 DLL 导出的函数数（未转发）。
        \param 模块名称：DLL 的名称
        \param module Ptr : 包含虚拟格式 DLL 的缓冲区
        \param module Size : DLL 缓冲区的大小。如果模块大小 == 0，将使用来自 PE 标头的图像大小。
        \param module Base : 给定 DLL 重定位到的基地址
        */
        size_t add_to_lookup(std::string moduleName, HMODULE modulePtr, size_t moduleSize, ULONGLONG moduleBase);

        /**
      将给定的 DLL 附加到导出函数的查找表中。返回从此 DLL 导出的函数数（未转发）。
        \param 模块名称：DLL 的名称
        \param module Ptr : 包含虚拟格式 DLL 的缓冲区
        \param module Base : 给定 DLL 重定位到的基地址
        */
        size_t add_to_lookup(std::string moduleName, HMODULE modulePtr, ULONGLONG moduleBase)
        {
            return add_to_lookup(moduleName, modulePtr, 0, moduleBase);
        }

        /**
    将给定的 DLL 附加到导出函数的查找表中。返回从此 DLL 导出的函数数（未转发）。
        假设模块被重定位到与给定缓冲区（模块 Ptr）的地址相同的地址。
        （如果我们要添加在当前进程中加载​​的 DLL，则为这种情况的包装器。）
        \param 模块名称：DLL 的名称
        \param module Ptr : 包含虚拟格式的 DLL 的缓冲区。
        */
        size_t add_to_lookup(std::string moduleName, HMODULE modulePtr) 
        {
            return add_to_lookup(moduleName, modulePtr, reinterpret_cast<ULONGLONG>(modulePtr));
        }

        /**
      找到可以映射到给定 VA 的导出函数集。包括转发器和函数别名。
        */
        const std::set<ExportedFunc>* find_exports_by_va(ULONGLONG va) const
        {
            std::map<ULONGLONG, std::set<ExportedFunc>>::const_iterator itr = va_to_func.find(va);
            if (itr != va_to_func.end()) {
                const std::set<ExportedFunc> &fSet = itr->second;
                return &fSet;
            }
            return NULL;
        }

        /**
     检索包含给定函数的 DLL 的基础。如果未找到，则返回 0。
        */
        ULONGLONG find_dll_base_by_func_va(ULONGLONG func_rva) const
        {
            // the first element that is greater than the start address
            std::map<ULONGLONG, DllInfo>::const_iterator firstGreater = dll_base_to_info.upper_bound(func_rva);

            std::map<ULONGLONG, DllInfo>::const_iterator itr;
            for (itr = dll_base_to_info.begin(); itr != firstGreater; ++itr) {
                const DllInfo& module = itr->second;

                if (func_rva >= module.moduleBase && func_rva <= (module.moduleBase + module.moduelSize)) {
                    // Address found in module:
                    return module.moduleBase;
                }
            }
            return 0;
        }

        /**
      使用给定的模块库检索 DLL 的完整路径。
        */
        std::string get_dll_path(ULONGLONG base) const
        {
            std::map<ULONGLONG, DllInfo>::const_iterator found =  this->dll_base_to_info.find(base);
            if (found == this->dll_base_to_info.end()) { // no DLL found at this base
                return "";
            }
            const DllInfo& info = found->second;
            return info.moduleName;
        }

        /**
       使用给定的短名称检索 DLL 的路径。如果多个路径映射到同一个短名称，则检索第一个。
        */
        std::string get_dll_path(std::string short_name) const;

        /**
       使用给定的短名称检索 DLL 的路径。
        */
        size_t get_dll_paths(IN std::string short_name, OUT std::set<std::string>& paths) const;

        /**
     使用短名称（不带扩展名）检索 DLL 的全名（包括扩展名）。
        */
        std::string get_dll_fullname(std::string short_name) const
        {
            std::string dll_path = get_dll_path(short_name);
            if (dll_path.length() == 0) return "";

            return get_file_name(dll_path);
        }

        /**
      找到一个可以映射到给定 VA 的导出函数，
        */
        const ExportedFunc* find_export_by_va(ULONGLONG va) const
        {
            const std::set<ExportedFunc>* exp_set = find_exports_by_va(va);
            if (exp_set == NULL) return NULL;

            std::set<ExportedFunc>::iterator fItr = exp_set->begin();
            const ExportedFunc* func = &(*fItr);
            return func;
        }

        void print_va_to_func(std::stringstream &stream) const;
        void print_func_to_va(std::stringstream &stream) const;
        

    private:
        enum ADD_FUNC_RES { RES_INVALID = 0, RES_MAPPED = 1, RES_FORWARDED = 2 };
        ADD_FUNC_RES add_function_to_lookup(HMODULE modulePtr, ULONGLONG moduleBase, size_t moduleSize, ExportedFunc &currFunc, DWORD callRVA);

        bool add_forwarded(ExportedFunc &currFunc, DWORD callRVA, PBYTE modulePtr, size_t moduleSize);
        bool add_to_maps(ULONGLONG va, ExportedFunc &currFunc);

        size_t resolve_forwarders(const ULONGLONG va, ExportedFunc &currFunc);
        size_t make_ord_lookup_tables(PVOID modulePtr, size_t moduleSize, std::map<PDWORD, DWORD> &va_to_ord);

    protected:
        /**
        Add a function and a VA into a mutual mapping.
        */
        void associateVaAndFunc(ULONGLONG va, const ExportedFunc& func)
        {
            va_to_func[va].insert(func);
            func_to_va[func] = va;
        }

        /**
        A map associating VA of the function with the related exports.
        */
        std::map<ULONGLONG, std::set<ExportedFunc>> va_to_func;

        /**
        A map associating an exported functions with its forwarders.
        */
        std::map<ExportedFunc, std::set<ExportedFunc>> forwarders_lookup;

        /**
        A map associating an exported functions with its VA.
        */
        std::map<ExportedFunc, ULONGLONG> func_to_va;
        
        /**
        A map associating DLL shortname with the base(s) at which it was mapped
        */
        std::map<std::string, std::set<ULONGLONG>> dll_shortname_to_base;

        std::map<ULONGLONG, DllInfo> dll_base_to_info;
    };

}; //namespace peconv
