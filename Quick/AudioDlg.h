#pragma once
#include "WavePlayback.h"
#include "WaveRecord.h"



#include <mmsystem.h>
#pragma comment(lib, "Winmm.lib")





struct WAVE_INFO
{
	TCHAR str[1024];//  
	int nIndex;    // 下标
};

class CAudioDlg : public CDialog
{
public:
	CAudioDlg(CWnd* pParent = NULL, ISocketBase* pIOCPServer = NULL, ClientContext* pContext = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CAudioDlg)
	enum { IDD = IDD_AUDIO };

	void OnReceiveComplete();
	void OnReceive();
	void ShowLinesCombox(CString str, int nSelect);




	// Overrides
		// ClassWizard generated virtual function overrides
		//{{AFX_VIRTUAL(CAudioDlg)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual void PostNcDestroy();
	virtual void OnCancel();
	//}}AFX_VIRTUAL

// Implementation
protected:

	ClientContext* m_pContext;
	ISocketBase* m_iocpServer;
	HICON m_hIcon;
	UINT m_nTotalRecvBytes;
	UINT m_nTotalSendBytes;
	BOOL m_bOnClose;
	BOOL m_bCheckRec;
	int m_SelectedDevice, m_SelectedLines;

	CAudioCode			m_ACode;     //编解码
	CWavePlayback* m_pWavePlayback;  //播放音频
	CWaveRecord* m_pWaveRecord;  //获取并且发送

	CString csFileName;			//保存音频

	CProgressCtrl m_pro_re;
	CProgressCtrl m_pro_se;

	// Generated message map functions
	//{{AFX_MSG(CAudioDlg)
	virtual BOOL OnInitDialog();
	//afx_msg void OnClose();
	afx_msg LRESULT OnSendDate(WPARAM, LPARAM);	//下线删除
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
public:


	CComboBox m_combo_input_lines;
	CComboBox m_combo_input_drive;
	afx_msg void OnBnClickedButtonRe();
	afx_msg void OnBnClickedButtonReStop();
	afx_msg void OnBnClickedButtonSe();
	afx_msg void OnBnClickedButtonSeStop();
	afx_msg void OnBnClickedCheckRec();
	afx_msg void OnSelchangeComboDriveIn();
	afx_msg void OnSelchangeComboInputlines();
	
	afx_msg void OnHScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar);


	//音量控制
	
	CXTPScrollBar m_Scrollbar_r_in;
	CXTPScrollBar m_Scrollbar_r_out;
	CXTPScrollBar m_Scrollbar_l_in;
	CXTPScrollBar m_Scrollbar_l_out;
	CString str_CScrollBar;
};

