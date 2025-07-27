/**
* @file
* @brief  ����ṩ�Ļ���������ԭʼ�����⣩�е� PE ��������ģʽ�������ض�ģʽ�ĵ��� PE ������
*/

#pragma once

#include <windows.h>

#include "pe_hdrs_helper.h"

namespace peconv {

    /**
  ����ڴ��е�PE�Ƿ�Ϊԭʼ��ʽ
    */
    bool is_pe_raw(
        IN const BYTE* pe_buffer,
        IN size_t pe_size
    );

    /**
  ������ⲿ�ֵ�ַ�Ƿ���ԭʼ��ַ��ͬ�����Ƿ����¶��� PE��
    */
    bool is_pe_raw_eq_virtual(
        IN const BYTE* pe_buffer,
        IN size_t pe_size
    );

    /**
  ��� PE �Ƿ������ڴ��н�ѹ/��չ�Ĳ���
    */
    bool is_pe_expanded(
        IN const BYTE* pe_buffer,
        IN size_t pe_size
    );

    /**
    �����������Ƿ����ڴ��н�ѹ
    */
    bool is_section_expanded(IN const BYTE* pe_buffer,
        IN size_t pe_size,
        IN const PIMAGE_SECTION_HEADER sec
    );

};// namespace peconv
