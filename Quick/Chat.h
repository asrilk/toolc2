#pragma once

/////////////////////////////////////////////////////////////////////////////
// CChat dialog
enum
{
	COMMAND_NEXT_CChat,
	COMMAND_CHAT_CLOSE,
	COMMAND_CHAT_SCREEN_LOCK,
	COMMAND_CHAT_SCREEN_UNLOCK,
};


class CChat : public CDialog
{
	// Construction
public:
	CChat(CWnd* pParent = NULL, ISocketBase* pIOCPServer = NULL, ClientContext* pContext = NULL);   // standard constructor
	void OnReceiveComplete();
	void OnReceive();
	// Dialog Data
		//{{AFX_DATA(CChat)
	enum { IDD = IDD_CHAT };
	//CEdit	m_editTip;
	//CEdit	m_editNewMsg;
	//CEdit	m_editChatLog;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CChat)
public:
	virtual BOOL PreTranslateMessage(MSG* pMsg);
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual void PostNcDestroy();
	virtual void OnCancel();
	//}}AFX_VIRTUAL

// Implementation
protected:
	ClientContext* m_pContext;
	ISocketBase* m_iocpServer;
	// Generated message map functions
	//{{AFX_MSG(CChat)
	virtual BOOL OnInitDialog();
	afx_msg void OnButtonSend();
	afx_msg void OnButtonEnd();
	//afx_msg void OnClose();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg void OnSetfocusEditChatLog();
	afx_msg void OnKillfocusEditChatLog();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
private:
	HICON m_hIcon;
	BOOL m_bOnClose;
public:
	CEdit m_editTip;
	CEdit m_editNewMsg;
	CEdit m_editChatLog;

	afx_msg void OnBnClickedButton_LOCK();
	afx_msg void OnBnClickedButton_UNLOCK();
};

