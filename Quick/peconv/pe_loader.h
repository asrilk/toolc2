/**
* @file
* @brief   Loading PE from a file with the help of the custom loader.
*/

#pragma once

#include "pe_raw_to_virtual.h"
#include "function_resolver.h"

namespace peconv {
    /**
  �� PE �Ӹ��������������ڴ沢����ӳ��Ϊ�����ʽ��
    ���Զ�ԭʼ������ת������
    �����ִ�б�־Ϊ�棬�� PE �ļ����ص���ִ���ڴ��С�
    ����ض�λ��־Ϊ�棬��Ӧ���ض�λ�������ص��롣
    �Զ����������С�Ļ���������С�������С�з��أ��������������ɺ��� free pe buffer �ͷš�
    */
    BYTE* load_pe_module(BYTE* dllRawData, size_t r_size, OUT size_t &v_size, bool executable, bool relocate);

    /**
   �������ļ��е� PE �����ڴ沢����ӳ��Ϊ�����ʽ��
    ���Զ�ԭʼ������ת������
    �����ִ�б�־Ϊ�棬�� PE �ļ����ص���ִ���ڴ��С�
    ����ض�λ��־Ϊ�棬��Ӧ���ض�λ�������ص��롣
    �Զ����������С�Ļ���������С�������С�з��أ��������������ɺ��� free pe buffer �ͷš�
    */
    BYTE* load_pe_module(const char *filename, OUT size_t &v_size, bool executable, bool relocate);

    /**
   �Կ���ֱ��ִ�еķ�ʽ��ԭʼ���������������� PE������ӳ�䵽�����ʽ��Ӧ���ض�λ�����ص��롣
    �����ṩ�Զ��庯����������
    */
    BYTE* load_pe_executable(BYTE* dllRawData, size_t r_size, OUT size_t &v_size, t_function_resolver* import_resolver=NULL);

    /**
 �Կ���ֱ��ִ�еķ�ʽ���ļ����������� PE������ӳ�䵽�����ʽ��Ӧ���ض�λ�����ص��롣
    �����ṩ�Զ��庯����������
    */
    BYTE* load_pe_executable(const char *filename, OUT size_t &v_size, t_function_resolver* import_resolver=NULL);

};// namespace peconv
