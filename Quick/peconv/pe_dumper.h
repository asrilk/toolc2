/**
* @file
* @brief  �� PE ���ڴ滺����ת�����ļ��С�
*/

#pragma once

#include <windows.h>
#include "exports_mapper.h"

namespace peconv {

    /**
  һ�ֶ��� PE ������ģʽ��
    */
    typedef enum {
        PE_DUMP_AUTO = 0, /**< �Զ�������ʺϸ��������ת��ģʽ */
        PE_DUMP_VIRTUAL,/**<�����ڴ���һ��ת�������⣩ */
        PE_DUMP_UNMAP, /**< ת��Ϊԭʼ��ʽ��ʹ��ԭʼ���ֵı��� */
        PE_DUMP_REALIGN, /**< ת��Ϊԭʼ��ʽ��ͨ����ԭʼ���ֵı������¶���Ϊ��������ͬ����� PE ���ڴ��н�ѹ����������ã�*/
        PE_DUMP_MODES_COUNT /**<ת��ģʽ����*/
    } t_pe_dump_mode;

    /**
  ������ʺϸ��������ת��ģʽ��
    \param buffer : ����Ҫת���� PE �Ļ�������
    \param ��������С�������������Ĵ�С
    */
    t_pe_dump_mode detect_dump_mode(IN const BYTE* buffer, IN size_t buffer_size);

    /**
 �� PE �� Fiven ������ת�����ļ��С�����������ģ������ʹ�С��
    \param output File Path : Ӧ�ñ���ת�����ļ�������
    \param buffer : ����Ҫת���� PE �Ļ����������棺���������ܻ���ת��֮ǰ����Ԥ����
    \param ��������С�������������Ĵ�С
    \param module base : PE �������ض�λ���Ļ���
    \param dump mode : ָ�� PE Ӧ�������ָ�ʽ��ת�������ģʽ����Ϊ PE DUMP AUTO�������Զ����ģʽ�����ؼ�⵽��ģʽ��
    \param ������ͼ����ѡ������ṩ��exports Map����������ṩ�ĵ���������map�����Իָ�PE�ı��ƻ��ĵ����
    */
    bool dump_pe(IN const char *outputFilePath,
        IN OUT BYTE* buffer,
        IN size_t buffer_size,
        IN const ULONGLONG module_base,
        IN OUT t_pe_dump_mode &dump_mode,
        IN OPTIONAL const peconv::ExportsMapper* exportsMap = nullptr
    );

};// namespace peconv
