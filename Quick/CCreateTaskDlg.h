#pragma once


// CCreateTaskDlg �Ի���

class CCreateTaskDlg : public CDialog
{
	DECLARE_DYNAMIC(CCreateTaskDlg)

public:
	CCreateTaskDlg(CWnd* pParent = nullptr);   // ��׼���캯��
	virtual ~CCreateTaskDlg();

	// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CREATETASK };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonCREAT();
	CString m_TaskPath;
	CEdit m_TaskName;
	CString m_TaskNames;
	CString m_ExePath;
	CString m_ZhuoZhe;
	CString m_MiaoShu;
};
