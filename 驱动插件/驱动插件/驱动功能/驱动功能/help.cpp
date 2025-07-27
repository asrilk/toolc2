#include "help.h"

NTSTATUS readkey(LPWSTR strkeyname, WCHAR* keyvalue, ULONG len, WCHAR* Context)
{
	ULONG  POOL_TAG = 'rndf';
	UNICODE_STRING regpath;
	//RtlZeroMemory(keyvalue, len);
	RtlInitUnicodeString(&regpath, (WCHAR*)Context);
	OBJECT_ATTRIBUTES attribs = { 0 };
	InitializeObjectAttributes(&attribs, (PUNICODE_STRING)&regpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hKey;
	status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &attribs);
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WSK] [Client] ZwOpenKey ʧ�� failed: 0x%08X.\n", status);
	
		return status;
	}
	UNICODE_STRING KeyName;
	ULONG RetSize = 0;
	RtlInitUnicodeString(&KeyName, strkeyname);
	status = ZwQueryValueKey(hKey, &KeyName, KeyValuePartialInformation, NULL, 0, &RetSize);
	//������ȷ����������ص���STATUS_BUFFER_TOO_SMALL  ����ʹ��NT_SUCCESS���ж�
	if ((status == STATUS_OBJECT_NAME_NOT_FOUND) | (status == STATUS_INVALID_PARAMETER) | (RetSize == 0))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WSK] [Client] ��ѯ��ֵ����ʧ��\n");
		ZwClose(hKey);
	
		return status;
	}
	PKEY_VALUE_PARTIAL_INFORMATION pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, RetSize, POOL_TAG);
	if (!pvpi)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WSK] [Client] �ڴ����ʧ��\n");
		ZwClose(hKey);

		return status;
	}
	//��ѯ��Ϣ������ΪPKEY_VALUE_PARTIAL_INFORMATION
	status = ZwQueryValueKey(hKey, &KeyName, KeyValuePartialInformation, pvpi, RetSize, &RetSize);

	if (!NT_SUCCESS(status))
	{
		ZwClose(hKey);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[WSK] [Client] ��ѯ��ֵʧ��\n");
		return status;
	}
	else
	{
		switch (pvpi->Type)
		{
		case REG_SZ:
			if (pvpi->DataLength >= len * 2)
			{
				status = STATUS_OBJECT_NAME_NOT_FOUND;
			}
			else
				RtlCopyMemory(keyvalue, pvpi->Data, pvpi->DataLength);
			break;
			/*case REG_EXPAND_SZ:
				if (pvpi->DataLength >= len * 2)
				{
					status = STATUS_OBJECT_NAME_NOT_FOUND;
				}
				else
					RtlCopyMemory(keyvalue, pvpi->Data, pvpi->DataLength);
				break;
			case REG_BINARY:
				if (pvpi->DataLength >= len * 2)
				{
					status = STATUS_OBJECT_NAME_NOT_FOUND;
				}
				else
					RtlCopyMemory(keyvalue, pvpi->Data, pvpi->DataLength);
				break;*/
		case REG_DWORD:
			if (pvpi->DataLength >= len * 2)
			{
				status = STATUS_OBJECT_NAME_NOT_FOUND;
			}
			else
			{
				ULONG           msec;
				MyGetTickCount(&msec);
				swprintf_s(keyvalue, len, L"%d%d", (DWORD)(pvpi->Data), (DWORD)msec);
			}

			break;
			/*case REG_QWORD:
				if (pvpi->DataLength >= len * 2)
				{
					status = STATUS_OBJECT_NAME_NOT_FOUND;
				}
				else
					RtlCopyMemory(keyvalue, pvpi->Data, pvpi->DataLength);
				break;*/
		default:

			break;
		}
	}
	ZwClose(hKey);
	ExFreePoolWithTag(pvpi, POOL_TAG);
	return status;
}

NTSTATUS RegSetValueKey(LPWSTR REG_KEY_NAME, LPWSTR REG_VALUE_NAME, DWORD DataType, PVOID DataBuffer, DWORD DataLength)
{
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING usKeyName, usValueName;
	HANDLE hRegister;
	RtlInitUnicodeString(&usKeyName, REG_KEY_NAME);
	RtlInitUnicodeString(&usValueName, REG_VALUE_NAME);
	InitializeObjectAttributes(&objectAttributes, &usKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
	if (NT_SUCCESS(status))
	{
		status = ZwSetValueKey(hRegister, &usValueName, 0, DataType, DataBuffer, DataLength);
		ZwFlushKey(hRegister);
		ZwClose(hRegister);
	}
	return status;
}


// ��ȡϵͳ����һ����������ʱ�䣨���룩
void MyGetTickCount(PULONG msec)
{
	LARGE_INTEGER tick_count;
	ULONG myinc = KeQueryTimeIncrement();
	KeQueryTickCount(&tick_count);
	tick_count.QuadPart *= myinc;
	tick_count.QuadPart /= 10000;
	*msec = tick_count.LowPart;
}

PWCHAR MyCurTimeStr()
{
	LARGE_INTEGER snow, now;
	TIME_FIELDS now_fields;
	static WCHAR time_str[32] = { 0 };
	// ��ȡ��������ʱ��
	KeQuerySystemTime(&snow);
	// תΪ����ʱ��
	ExSystemTimeToLocalTime(&snow, &now);
	// תΪʱ��Ľṹ��
	RtlTimeToTimeFields(&now, &now_fields);
	// ���ṹ����Ϣƴ������
	RtlStringCchPrintfW(
		time_str,
		32,
		L"%4d-%02d-%02d %02d:%02d:%02d",
		now_fields.Year, now_fields.Month, now_fields.Day,
		now_fields.Hour, now_fields.Minute, now_fields.Second);

	return time_str;
}

NTSTATUS  Ksleep(int times)
{
	NTSTATUS Status = STATUS_SUCCESS;
	LARGE_INTEGER Interval = { 0 };
	Interval.QuadPart = (-10 * 1000);
	Interval.QuadPart *= times;
	Status = KeDelayExecutionThread(KernelMode, 0, &Interval);
	return Status;
}
