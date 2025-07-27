#pragma once
// RegeditTextDlg.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CRegeditTextDlg dialog

class CRegeditTextDlg : public CDialog
{
	// Construction
public:
	CRegeditTextDlg(CWnd* pParent = NULL);   // standard constructor
	void EnableKey();
	void EnablePath();


	bool EPath;
	bool EKey;
	bool isOK;
	bool isDWORD;             //ÊÇ·ñÎªDWORDÖµ
// Dialog Data
	//{{AFX_DATA(CRegeditTextDlg)
	enum { IDD = IDD_REGEDIT_TEXT };
	CString	m_strName;
	CString	m_strValue;
	//}}AFX_DATA

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CRegeditTextDlg)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CRegeditTextDlg)
	virtual void OnOK();
	virtual BOOL OnInitDialog();
	afx_msg void OnChangeEditDate();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

