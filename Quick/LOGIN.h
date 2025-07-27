
#pragma once


/////////////////////////////////////////////////////////////////////////////
// LOGIN dialog

class LOGIN : public CDialog
{
	// Construction
public:
	char* MI(char* mi);
	char* GetJQM();
	LOGIN(CWnd* pParent = NULL);   // standard constructor
	DWORD dLogin;

	// Dialog Data
		//{{AFX_DATA(LOGIN)
	enum { IDD = IDD_LOGIN };
	CString	m_username;
	CString	m_userpass;
	CString	m_onlinepass;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(LOGIN)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(LOGIN)
	afx_msg void OnExit();
	afx_msg void OnLogin();
	virtual BOOL OnInitDialog();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
public:
	CString m_userip;
	CString m_userport;
};

