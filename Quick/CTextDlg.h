#pragma once


// CTextDlg �Ի���

class CTextDlg : public CDialog
{
	DECLARE_DYNAMIC(CTextDlg)

public:
	CTextDlg(CWnd* pParent = nullptr);   // ��׼���캯��
	virtual ~CTextDlg();
	CString	oldstr;
	CString nowstr;
	CString cmeline;
	// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TEXT };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();

};
