#pragma once




class CScreenMonitorDlg : public CXTPResizeFormView
{
	DECLARE_DYNCREATE(CScreenMonitorDlg)
public:

	CScreenMonitorDlg();
	virtual ~CScreenMonitorDlg();
#ifdef AFX_DESIGN_TIME
	enum {IDD = IDD_MONITOR};
#endif
#ifdef _DEBUG
	virtual void AssertValid() const;
#ifndef _WIN32_WCE
	virtual void Dump(CDumpContext& dc) const;
#endif
#endif
	virtual void OnInitialUpdate();

	void OnReceiveComplete(ClientContext* pContext);
	void HandlingRightClickMessages(int nitem); //主右键菜单消息处理

	void SendSelectCommand(PBYTE pData, UINT nSize);   //选中发送命令——主
	void SendDll(LPCTSTR lpDllName, SENDTASK sendtask = TASK_MAIN); //发送普通功能DLL
	void DelClient(ClientContext* pContext);
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL
	VOID AddClient(ClientContext* pContext);

// Implementation
protected:
	DECLARE_MESSAGE_MAP()


	afx_msg LRESULT OnAddClientData(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnDelClient(WPARAM wParam, LPARAM lParam)
	{	DelClient((ClientContext*)lParam);return 0;};
	afx_msg LRESULT OnChangeClient(WPARAM wParam, LPARAM lParam);
public:
	CMenu mListmeau;
	CMenu mListmeau_file;
	CMenu mListmeau_screen;
	CMenu mListmeau_Peripherals;
	CMenu mListmeau_ZJ;
	CMenu mListmeau_khd;
	CMenu mListmeau_hh;
	CMenu mListmeau_other;
	CMenu mListmeau_filter;
	int i_mListmeau_other_num;

	CLCS m_clcs;


	CListCtrl listCtrl;
	CImageList m_ImageList;

	int w, h,t;

	//CSliderCtrl m_slider_w;
	//CSliderCtrl m_slider_h;
	//CSliderCtrl m_slider_t;
	void ReShowPic(int mode,  int num);
	//afx_msg void OnHScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnRclickList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnclickList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnDclickList(NMHDR* pNMHDR, LRESULT* pResult);


	int mcx, mcy;
	RECT rect;
	CDC* pDC;
	CWnd* pWnd;
	CDC dcimage;
	HWND mHwndShow;
	
};



