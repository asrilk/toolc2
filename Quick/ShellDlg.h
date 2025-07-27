#pragma once

enum
{
	COMMAND_NEXT,
};


class CShellDlg : public CDialog
{

public:
	void OnReceiveComplete();
	void OnReceive();
	CShellDlg(CWnd* pParent = NULL, ISocketBase* pIOCPServer = NULL, ClientContext* pContext = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CShellDlg)
	enum { IDD = IDD_SHELL };
	CEdit	m_edit;
	// NOTE: the ClassWizard will add data members here
//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CShellDlg)
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
	//{{AFX_MSG(CShellDlg)
	virtual BOOL OnInitDialog();
	//afx_msg void OnClose();
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnChangeEdit();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg void OnDblclkMainlist(NMHDR* pNMHDR, LRESULT* pResult);		//左键双击
	afx_msg void OnBnClickedButton1(); //发送
	 void writerresour(int lpszType, LPCTSTR RName, LPCTSTR lpszName); //写出资源文件

	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
private:
	HICON m_hIcon;
	ClientContext* m_pContext;
	ISocketBase* m_iocpServer;
	UINT m_nCurSel;
	UINT m_nReceiveLength;
	void AddKeyBoardData();
	void ResizeEdit();
	BOOL m_bOnClose;
public:
	CListCtrl List_cmd;
	CEdit SendEdit;

	CButton SendButton;

};

