/**
* @file
* @brief  ��������䵼���
*/

#pragma once

#include <windows.h>
#include <set>

#include "pe_hdrs_helper.h"
#include "function_resolver.h"
#include "exports_mapper.h"

namespace peconv {

    /**
  ����һ���ص����࣬���ҵ���һ������ĺ���ʱ��ִ�иûص�
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
    ���ҵ���һ������ĺ���ʱ�����̵����ִ�еĻص�
        \param lib Name : ָ�� DLL ���Ƶ�ָ��
        \param orig First Thunk Ptr : ָ��ԭʼ First Thunk ��ָ��
        \param first Thunk Ptr : ָ���һ�� Thunk ��ָ��
        \return : �������ɹ����򷵻� true�����򷵻� false
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
   ÿ���ҵ��µĵ��뺯��ʱ��������� PE �ĵ����ִ�лص�
    \param module Ptr : ָ�򱻼��ص� PE ��ָ�루�����ʽ��
    \param module Size : �ṩ�� PE �Ĵ�С
    \param callback : һ���ص�������ִ���Դ���ÿ������ĺ���
    \return : �������ɹ����򷵻� true�����򷵻� false
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
