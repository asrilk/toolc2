#pragma once

#include "VideoCodec.h"
#include "BmpToAvi.h"
#include "MovieMaker.h"
#include "XvidDec.h"
#include <list>
#include <string>
#include <vector>

/////////////////////////////////////////////////////////////////////////////
// CWebCamDlg dialog



#define MY_TEST


enum
{
	COMMAND_NEXT_CWebCamDlg,
	COMMAND_WEBCAM_ENABLECOMPRESS,
	COMMAND_WEBCAM_DISABLECOMPRESS,
	COMMAND_WEBCAM_RESIZE,
	TOKEN_WEBCAM_DIB,
	COMMAND_WEBCAM_EXCEPTION,

};



class ResolutionInfo
{
public:
	int m_DeviceIndex;
	int m_iWidth;
	int m_iHeight;
};
class CWebCamDlg : public CDialog, public CXvidDecHandler
{
	// Construction
public:
	
	void OnReceiveComplete();
	void OnReceive();
	void PostDecHandler(unsigned char* image, int used_bytes);
	CWebCamDlg(CWnd* pParent = NULL, ISocketBase* pIOCPServer = NULL, ClientContext* pContext = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CWebCamDlg)
	enum { IDD = IDD_VEDIO };
	// NOTE: the ClassWizard will add data members here
//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CWebCamDlg)
public:
	virtual BOOL PreTranslateMessage(MSG* pMsg);
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual void PostNcDestroy();
	virtual void OnCancel();
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CWebCamDlg)
	//afx_msg void OnClose();
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	/*#ifdef NDEBUG*/
	afx_msg void OnPaint();
	/*#endif*/
	afx_msg void OnShowWindow(BOOL bShow, UINT nStatus);

	//afx_msg void OnDestroy();
	afx_msg void OnSize(UINT nType, int cx, int cy);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
private:
	std::vector<ResolutionInfo> m_resInfo;
	BITMAPINFOHEADER	m_fmtFrame;
	CXvidDec* m_dec;
	char* m_deviceList;
	int m_nWebcamSelected;
	int m_width;
	int m_height;
	int m_iResNum;
#if 0
	CBitmap m_bitmap;
	CDC m_cDc;
	HBITMAP m_hBmp;
#endif
	int	m_nOldWidth; // OnSize时判断是高或宽发生变化，宽优先
	int m_nDeviceNums;
	UINT m_nCount;
	HICON m_hIcon;
	//	CVideoCodec	*m_pVideoCodec;
	DWORD m_fccHandler;
	CString m_aviFile; // 如果文件名不为空就写入
	CString m_aviFile_MovieMaker; // 如果文件名不为空就写入
	BOOL m_bRecord;
	BOOL m_bReset;
	CBmpToAvi	m_aviStream;
	MovieMaker* m_avi;
	HDC			m_hDC;
	HDRAWDIB	m_hDD;
	void DrawDIB();

	void DoPaint();
	//	void InitCodec(DWORD fccHandler);
	bool SendResetScreen(int nWidth, int nHeight);
	void ResetScreen();
	bool SaveSnapshot();
	void SaveAvi();
	void SaveAvi_make();
	afx_msg void OnTimer(UINT nIDEvent);
	ClientContext* m_pContext;
	ISocketBase* m_iocpServer;
	CString m_IPAddress;
	LPVOID m_lpScreenDIB;
	//	LPBYTE m_lpCompressDIB;
	MINMAXINFO m_MMI;
	LPBITMAPINFO m_lpbmi;
	void InitMMI();
	LRESULT OnGetMiniMaxInfo(WPARAM, LPARAM);
	afx_msg LRESULT OnOut(WPARAM wParam, LPARAM lParam);
	void SendNext();
	void SendException();

	BOOL m_bOnClose;
};

