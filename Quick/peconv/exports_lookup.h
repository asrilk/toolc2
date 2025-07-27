/**
* @file
* @brief  �� PE �ĵ������������ض�������
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
 ͨ�����ƻ�ȡ������ַ��ʹ�õ�������ҡ�
    ���棺��������ת�����ܡ�
    */
    FARPROC get_exported_func(PVOID modulePtr, LPSTR wanted_name);

    /**
   ��ȡ����ģ���а����Ƶ��������к������б�
    */
    size_t get_exported_names(PVOID modulePtr, std::vector<std::string> &names_list);

    /**
  ʹ�õ�������ҵĺ�����������
    */
    class export_based_resolver : default_func_resolver {
        public:
        /**
       �Ӹ����� DLL �л�ȡ���и������Ƶĺ����ĵ�ַ (VA)��
        ʹ�õ����������Ϊ���ҵ������Ҫ������ʧ��ʱ�������˻ص�Ĭ�ϵĺ�����������
        \param func name : ������
        \param lib name : DLL ������
        \return ���������������ַ
        */
        virtual FARPROC resolve_func(LPSTR lib_name, LPSTR func_name);
    };

    /**
   �ӵ������ж�ȡ DLL ���ơ�
    */
    LPSTR read_dll_name(HMODULE modulePtr);

}; //namespace peconv
