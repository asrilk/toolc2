#pragma once

class CChangeGroupDlg : public CDialog
{
	// Construction
public:
	CChangeGroupDlg(CWnd* pParent = NULL);   // standard constructor
	CString strGroup;
	// Dialog Data
		//{{AFX_DATA(CGgfz)
	enum {
		IDD = IDD_CHANGEGROUP
	};
	CComboBox	m_combo_group;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CGgfz)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CGgfz)
	virtual BOOL OnInitDialog();
	virtual void OnOK();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};