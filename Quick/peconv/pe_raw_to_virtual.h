/**
* @file
* @brief   Converting PE from raw to virtual format.
*/

#pragma once

#include <windows.h>
#include <stdio.h>

#include "buffer_util.h"

namespace peconv {

    /**
 �����������ṩ��ԭʼ PE ת��Ϊ�����ʽ��
    �����ִ�б�־Ϊ�棨Ĭ�ϣ���PE �ļ������ص���ִ���ڴ��С�
    �������ض�λ�������ص��롣
    �Զ����������С�Ļ���������С�������С�з��أ��������������ɺ��� free pe ģ���ͷš�
    �������������Ļ�����Ĭ��Ϊ 0��������ǿ�����ض��������з��䡣
    */
    BYTE* pe_raw_to_virtual(
        IN const BYTE* rawPeBuffer,
        IN size_t rawPeSize,
        OUT size_t &outputSize,
        IN OPTIONAL bool executable = true,
        IN OPTIONAL ULONGLONG desired_base = 0
    );

}; // namespace peconv
