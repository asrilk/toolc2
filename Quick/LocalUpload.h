
#pragma once

/////////////////////////////////////////////////////////////////////////////
// CLocalUpload dialog

class CLocalUpload : public CDialog
{
	// Construction
public:
	CLocalUpload(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CLocalUpload)
	enum { IDD = IDD_DIALOG_UPLOAD };
	CComboBox	m_combo_type;
	CString	m_edit_path;
	CString	m_edit_cmd_line;
	void Setview(CQuickView* pCQuickView);
	CQuickView* g_pCQuickView;
	//}}AFX_DATA

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CLocalUpload)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	UINT m_type;
	// Generated message map functions
	//{{AFX_MSG(CLocalUpload)
	virtual BOOL OnInitDialog();
	afx_msg void OnButtonPath();
	virtual void OnOK();
	afx_msg void OnSelchangeComboType();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

