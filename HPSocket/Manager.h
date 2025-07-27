
#pragma once
#include "ISocketBase.h"
#ifdef _CONSOLE
#include <stdio.h>
#endif

struct SendErrorDate
{
	BYTE Btoken;
	TCHAR ErrorDate[255];

};


class CManager
{
	friend class ISocketBase;
	typedef int (*SENDPROC)(LPBYTE lpData, UINT nSize);

public:
	CManager(ISocketBase* pClient);
	 ~CManager();
	 virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
	//	virtual char* ReturnPath();
	int Send(LPBYTE lpData, UINT nSize);
	ISocketBase* m_pClient;
	BOOL IsConnect();
	void Disconnect();
	BOOL bStop;
	HANDLE		m_hEventDlgOpen;
	void WaitForDialogOpen();
	void NotifyDialogIsOpen();

	void SendLastError(int mode = 0, TCHAR* s_error_first = _T(""), TCHAR* s_error_next = _T("")); //0默认错误 1 自定义 2 

private:
	SENDPROC	m_pSendProc;
};

