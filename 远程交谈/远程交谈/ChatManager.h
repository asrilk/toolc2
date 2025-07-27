#pragma once
#include "Manager.h"

//{{NO_DEPENDENCIES}}
// Microsoft Developer Studio generated include file.
// Used by Server.rc
//
#define IDI_ICON                        101
#define IDI_CHAT                        102
#define IDC_EDIT_CHATLOG                1000
#define IDC_EDIT_NEWMSG                 1001
#define IDC_BUTTON_SEND                 1002
#define IDC_BUTTON_END                  1003

// Next default values for new objects
// 
#ifdef APSTUDIO_INVOKED
#ifndef APSTUDIO_READONLY_SYMBOLS
#define _APS_NEXT_RESOURCE_VALUE        103
#define _APS_NEXT_COMMAND_VALUE         40001
#define _APS_NEXT_CONTROL_VALUE         1004
#define _APS_NEXT_SYMED_VALUE           101
#endif
#endif


enum
{
	COMMAND_NEXT_CChat,
	COMMAND_CHAT_CLOSE,
	COMMAND_CHAT_SCREEN_LOCK,
	COMMAND_CHAT_SCREEN_UNLOCK,

};
class CChatManager : public CManager
{
public:
	BOOL m_buser;
	CChatManager(ISocketBase* pClient);
	virtual ~CChatManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
private:
	HWND m_hWnd;
	static DWORD WINAPI MessageLoopProc(LPVOID lParam);
	static INT_PTR CALLBACK ChatDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	UINT nPreviousState;



};
