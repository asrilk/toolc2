#pragma once

#include <windows.h>
#include <vfw.h>
#pragma comment(lib, "vfw32.lib")
class CBmpToAvi
{
public:
	CBmpToAvi();
	virtual ~CBmpToAvi();
	bool Open(LPCTSTR szFile, LPBITMAPINFO lpbmi);
	bool Write(LPVOID lpBuffer,int len);
	void Close();
private:
	BITMAPINFOHEADER m_bHeader;
	PAVIFILE m_pfile;
	PAVISTREAM m_pavi;
	int m_nFrames;
	static AVISTREAMINFO m_si; // 这个参数需要是静态的
};

