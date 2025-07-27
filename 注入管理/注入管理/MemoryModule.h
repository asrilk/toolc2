/*
 * �ڴ�DLL���ش���
 * 0.0.4 �汾
 *
 * ��Ȩ���� (c) 2004-2015 �� Joachim Bauch / mail@joachim-bauch.de
 * http://www.joachim-bauch.de
 *
 * ���ļ������� Mozilla �������֤�汾Ϊ׼
 * 2.0�������֤���������Ƿ������¹涨������������ʹ�ô��ļ�
 * ���֤����������������ַ������֤�ĸ���
 * http://www.mozilla.org/MPL/
 *
 * ������ɷַ�������ǰ���ԭ�����ַ��ģ�
 * ���ṩ�κ���ʽ����ʾ��ʾ�ı�֤���鿴���֤
 * ���ڹ���Ȩ�������Ƶ��ض�����
 * ִ�ա�
 *
 * ԭʼ����Ϊ Memory Module.h
 *
 * ԭʼ����ĳ�ʼ�������� Joachim Bauch��
 *
 * Joachim Bauch �����Ĳ��ְ�Ȩ���� (C) 2004-2015
 * Լ��ϣķ�����ա���Ȩ���С�
 *
 */

#ifndef __MEMORY_MODULE_HEADER
#define __MEMORY_MODULE_HEADER

#include <windows.h>

typedef void *HMEMORYMODULE;

typedef void *HMEMORYRSRC;

typedef void *HCUSTOMMODULE;

#ifdef __cplusplus
extern "C" {
#endif

typedef LPVOID (*CustomAllocFunc)(LPVOID, SIZE_T, DWORD, DWORD, void*);
typedef BOOL (*CustomFreeFunc)(LPVOID, SIZE_T, DWORD, void*);
typedef HCUSTOMMODULE (*CustomLoadLibraryFunc)(LPCSTR, void *);
typedef FARPROC (*CustomGetProcAddressFunc)(HCUSTOMMODULE, LPCSTR, void *);
typedef void (*CustomFreeLibraryFunc)(HCUSTOMMODULE, void *);

/**
 * ���ڴ�λ�ü���ָ����С�� EXE/DLL��
 *
 * ʹ��Ĭ�ϼ��ؿ�/��ȡ���̵�ַ��������������
 * ͨ�� Windows API ���á�
 */
HMEMORYMODULE MemoryLoadLibrary(const void *, size_t);

/**
 * ʹ���Զ���������Ӹ�����С���ڴ�λ�ü��� EXE/DLL
 * ��������
 *
 * �����ʹ�ô��ݵĻص����������
 */
HMEMORYMODULE MemoryLoadLibraryEx(const void *, size_t,
    CustomAllocFunc,
    CustomFreeFunc,
    CustomLoadLibraryFunc,
    CustomGetProcAddressFunc,
    CustomFreeLibraryFunc,
    void *);

/**
 *��ȡ���������ĵ�ַ��֧�ְ����ƺͰ�����
 * ����ֵ.
 */
FARPROC MemoryGetProcAddress(HMEMORYMODULE, LPCSTR);

/**
 * �����ǰ���ص� EXE/DLL��
 */
void MemoryFreeLibrary(HMEMORYMODULE);

/**
 * ִ����ڵ㣨���� EXE������ڵ�ֻ�ܱ�ִ��
 * ��� EXE �Ѽ��ص���ȷ�Ļ���ַ������������
 * ���ض�λ�����ض�λ��Ϣû�б�
 * ����������
 *
 * ��Ҫ�����ô˺������᷵�أ���һ������
 * EXE ������ϣ����̽���ֹ��
 *
 * �����ڵ��޷�ִ�У��򷵻ظ�ֵ��
 */
int MemoryCallEntryPoint(HMEMORYMODULE);

/**
 *���Ҿ���ָ�����ͺ����Ƶ���Դ��λ�á�
 */
HMEMORYRSRC MemoryFindResource(HMEMORYMODULE, LPCTSTR, LPCTSTR);

/**
 * ���Ҿ���ָ�����͡����ƺ����Ե���Դ��λ�á�
 */
HMEMORYRSRC MemoryFindResourceEx(HMEMORYMODULE, LPCTSTR, LPCTSTR, WORD);

/**
 * ���ֽ�Ϊ��λ��ȡ��Դ�Ĵ�С��
 */
DWORD MemorySizeofResource(HMEMORYMODULE, HMEMORYRSRC);

/**
 * ��ȡָ����Դ���ݵ�ָ�롣
 */
LPVOID MemoryLoadResource(HMEMORYMODULE, HMEMORYRSRC);

/**
 * �����ַ�����Դ��
 */
int MemoryLoadString(HMEMORYMODULE, UINT, LPTSTR, int);

/**
 * ����ָ�����Ե��ַ�����Դ��
 */
int MemoryLoadStringEx(HMEMORYMODULE, UINT, LPTSTR, int, WORD);

/**
*���� Virtual Alloc �� Custom Alloc Func ��Ĭ��ʵ��
* ���ڲ�Ϊ������ڴ�
*
* �����ڴ���ؿ�ʹ�õ�Ĭ��ֵ��
*/
LPVOID MemoryDefaultAlloc(LPVOID, SIZE_T, DWORD, DWORD, void *);

/**
*���� Virtual Free �� Custom Free Func ��Ĭ��ʵ��
* ���ڲ��ͷſ�ʹ�õ��ڴ�
*
* �����ڴ���ؿ�ʹ�õ�Ĭ��ֵ��
*/
BOOL MemoryDefaultFree(LPVOID, SIZE_T, DWORD, void *);

/**
 * ���ü��ؿ� A ���Զ�����ؿ⺯����Ĭ��ʵ��
 * ���ڲ����ض���Ŀ⡣
 *
 * �����ڴ���ؿ�ʹ�õ�Ĭ��ֵ��
 */
HCUSTOMMODULE MemoryDefaultLoadLibrary(LPCSTR, void *);

/**
 * ���� Get Proc Address �� Custom Get Proc Address Func ��Ĭ��ʵ��
 * ���ڲ���ȡ���������ĵ�ַ��
 *
 * �����ڴ���ؿ�ʹ�õ�Ĭ��ֵ��
 */
FARPROC MemoryDefaultGetProcAddress(HCUSTOMMODULE, LPCSTR, void *);

/**
 *���� Free Library �� Custom Free Library Func ��Ĭ��ʵ��
 * ���ڲ��ͷŶ���Ŀ⡣
 *
 * �����ڴ���ؿ�ʹ�õ�Ĭ��ֵ��
 */
void MemoryDefaultFreeLibrary(HCUSTOMMODULE, void *);

#ifdef __cplusplus
}
#endif

#endif  // __MEMORY_MODULE_HEADER
