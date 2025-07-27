/**
* @file
* @brief  解析和填充导入表。
*/

#pragma once

#include <windows.h>
#include <set>

#include "pe_hdrs_helper.h"
#include "function_resolver.h"
#include "exports_mapper.h"

namespace peconv {

    /**
  定义一个回调的类，当找到下一个导入的函数时将执行该回调
    */
    class ImportThunksCallback
    {
    public:
        ImportThunksCallback(BYTE* _modulePtr, size_t _moduleSize)
            : modulePtr(_modulePtr), moduleSize(_moduleSize)
        {
            this->is64b = is64bit((BYTE*)modulePtr);
        }

        /**
    当找到下一个导入的函数时，进程导入表将执行的回调
        \param lib Name : 指向 DLL 名称的指针
        \param orig First Thunk Ptr : 指向原始 First Thunk 的指针
        \param first Thunk Ptr : 指向第一个 Thunk 的指针
        \return : 如果处理成功，则返回 true，否则返回 false
        */
        virtual bool processThunks(LPSTR libName, ULONG_PTR origFirstThunkPtr, ULONG_PTR firstThunkPtr) = 0;

    protected:
        BYTE* modulePtr;
        size_t moduleSize;
        bool is64b;
    };


    struct ImportsCollection
    {
    public:
        ImportsCollection() {};
        ~ImportsCollection()
        {
            std::map<DWORD, peconv::ExportedFunc*>::iterator itr;
            for (itr = thunkToFunc.begin(); itr != thunkToFunc.end(); ++itr) {
                peconv::ExportedFunc* exp = itr->second;
                if (!exp) continue;
                delete exp;
            }
            thunkToFunc.clear();
        }

        size_t size()
        {
            return thunkToFunc.size();
        }

        std::map<DWORD, peconv::ExportedFunc*> thunkToFunc;
    };

    /**
   每次找到新的导入函数时，处理给定 PE 的导入表并执行回调
    \param module Ptr : 指向被加载的 PE 的指针（虚拟格式）
    \param module Size : 提供的 PE 的大小
    \param callback : 一个回调，将被执行以处理每个导入的函数
    \return : 如果处理成功，则返回 true，否则返回 false
    */
    bool process_import_table(IN BYTE* modulePtr, IN SIZE_T moduleSize, IN ImportThunksCallback *callback);

    /**
    Fills imports of the given PE with the help of the defined functions resolver.
    \param modulePtr : a pointer to the loded PE (in virtual format)
    \param func_resolver : a resolver that will be used to fill the thunk of the import
    \return : true if loading all functions succeeded, false otherwise
    */
    bool load_imports(BYTE* modulePtr, t_function_resolver* func_resolver=nullptr);

    /**
    Checks if the given PE has a valid import table.
    */
    bool has_valid_import_table(const PBYTE modulePtr, size_t moduleSize);

    /**
    Checks if the given lib_name is a valid DLL name.
    A valid name must contain printable characters. Empty name is also acceptable (may have been erased).
    */
    bool is_valid_import_name(const PBYTE modulePtr, const size_t moduleSize, LPSTR lib_name);

    /**
    * Collects all the Import Thunks RVAs (via which Imports are called)
    */
    bool collect_thunks(IN BYTE* modulePtr, IN SIZE_T moduleSize, OUT std::set<DWORD>& thunk_rvas);

    bool collect_imports(IN BYTE* modulePtr, IN SIZE_T moduleSize, OUT ImportsCollection &collection);

}; // namespace peconv
