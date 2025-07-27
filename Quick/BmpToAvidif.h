#pragma once
#include <vfw.h>


class CBmpToAvidif
{
public:
	CBmpToAvidif();
	virtual ~CBmpToAvidif();
	bool Open(HWND m_hWnd, LPCTSTR szFile, LPBITMAPINFO lpbmi, BOOL bIsWebCam = FALSE);
	bool Write(LPVOID lpBuffer);
	void Close();
private:
	PAVIFILE m_pfile;
	PAVISTREAM m_pavi;
	PAVISTREAM pCompressedStream;
	int m_nFrames;
	static AVISTREAMINFO m_si; // 这个参数需要是静态的
};
