#pragma once


// CCopyClientDlg 对话框




class CCopyClientDlg : public CDialog
{
	DECLARE_DYNAMIC(CCopyClientDlg)

public:
	CCopyClientDlg(CString title,CWnd* pParent = nullptr,bool bshow=false);   // 标准构造函数
	virtual ~CCopyClientDlg();
	COPYCLIENT m_COPYCLIENT;
	bool m_show;
	CString m_title;
	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum {
		IDD = IDD_COPYCLIENT
};
#endif

protected:
	virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	void Setfindinfo(CString& s, const TCHAR* f1, TCHAR* outstring, BOOL user);
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();

	CString m_edit_ip;
	CString m_edit_ip2;
	CString m_edit_ip3;
	CString m_edit_port;
	CString m_edit_port2;
	CString m_edit_port3;
	CComboBox h_combo_net;
	CComboBox h_combo_net2;
	CComboBox h_combo_net3;
};
