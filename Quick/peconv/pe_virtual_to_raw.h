/**
* @file
* @brief   Converting PE from virtual to raw format.
*/

#pragma once

#include <windows.h>

#include "buffer_util.h"

namespace peconv {

    /**
  �� PE ������ͼ��ӳ�䵽ԭʼͼ���Զ�Ӧ���ض�λ��
    �Զ����������С�Ļ���������С�������С�з��أ���
    \param payload : ��Ҫת��Ϊ Raw ��ʽ�� Virtual ��ʽ�� PE
    \param in size : ���뻺�����Ĵ�С�������ʽ�� PE��
    \param load Base : ���� PE �ض�λ���Ļ���
    \param output Size : ����������Ĵ�С��ԭʼ��ʽ�� PE��
    \param rebuffer ��������ã�Ĭ�ϣ������뻺���������»��壬ԭʼ�����������޸ġ�
    \����һ�������С�Ļ�����������ԭʼ PE�������������ɺ��� free pe ģ���ͷš�
    */
    BYTE* pe_virtual_to_raw(
        IN BYTE* payload,
        IN size_t in_size,
        IN ULONGLONG loadBase,
        OUT size_t &outputSize,
        IN OPTIONAL bool rebuffer=true
    );

    /*
 �� PE ��ԭʼ���뷽ʽ�޸�Ϊ��������뷽ʽ��ͬ��
    \param payload : ��Ҫ���¶���������ʽ�� PE
    \param in size : ���뻺�����Ĵ�С
    \param load Base : ���� PE �ض�λ���Ļ���
    \param output Size : ����������Ĵ�С��ԭʼ��ʽ�� PE��
    \����һ�������С�Ļ��������������¶���� PE�������������ɺ��� free pe ģ���ͷš�
    */
    BYTE* pe_realign_raw_to_virtual(
        IN const BYTE* payload,
        IN size_t in_size,
        IN ULONGLONG loadBase,
        OUT size_t &outputSize
    );

};//namespace peconv
