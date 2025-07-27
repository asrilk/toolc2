#pragma once
#include "ProxyConnectServer.h"

/////////////////////////////////////////////////////////////////////////////
// CProxyMapDlg dialog
typedef struct
{
	BYTE Ver;      // Version Number
	BYTE CMD;      // 0x01==TCP CONNECT,0x02==TCP BIND,0x03==UDP ASSOCIATE
	BYTE RSV;
	BYTE ATYP;
	BYTE IP_LEN;
	BYTE szIP;
}Socks5Info;
class CProxyMapDlg : public CDialog
{
	// Construction
public:
	CProxyMapDlg(CWnd* pParent = NULL, ISocketBase* pIOCPServer = NULL, ClientContext* pContext = NULL);   // standard constructor
	
// Dialog Data
	//{{AFX_DATA(CProxyMapDlg)
	enum { IDD = IDD_PROXY };
	CEdit	m_edit;
	//}}AFX_DATA
	USHORT		nPort;
	static void CALLBACK NotifyProc( ClientContext* pContext, UINT nCode);
	void OnReceiveComplete();
	void OnReceive();
	void AddLog(TCHAR* lpText);
	void AddLog_other(TCHAR* lpText);
	// Overrides
		// ClassWizard generated virtual function overrides
		//{{AFX_VIRTUAL(CProxyMapDlg)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual void PostNcDestroy();
	virtual void OnCancel();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CProxyMapDlg)
	virtual BOOL OnInitDialog();
	//afx_msg void OnClose();
	afx_msg void OnSize(UINT nType, int cx, int cy);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
private:
	ClientContext* m_pContext;
	ISocketBase* m_iocpServer;
	CProxyConnectServer* m_iocpLocal;
	HICON m_hIcon;
	BOOL m_bOnClose;
	bool isclose;
public:
	CEdit m_edit_other;
};

//#pragma once
//#include "ProxyConnectServer.h"
//
///////////////////////////////////////////////////////////////////////////////
//// CProxyMapDlg dialog
//typedef struct
//{
//	BYTE Ver;      // Version Number
//	BYTE CMD;      // 0x01==TCP CONNECT,0x02==TCP BIND,0x03==UDP ASSOCIATE
//	BYTE RSV;
//	BYTE ATYP;
//	BYTE IP_LEN;
//	BYTE szIP;
//}Socks5Info;
//class CProxyMapDlg : public CDialog
//{
//	// Construction
//public:
//	CProxyMapDlg(CWnd* pParent = NULL, ISocketBase* pIOCPServer = NULL, ClientContext* pContext = NULL);   // standard constructor
//	virtual ~CProxyMapDlg();
//	// Dialog Data
//		//{{AFX_DATA(CProxyMapDlg)
//	enum { IDD = IDD_PROXY };
//	CEdit	m_edit;
//	//}}AFX_DATA
//	USHORT		nPort;
//	static void CALLBACK NotifyProc(ClientContext* pContext, UINT nCode);
//	ClientContext* pContexts[10000];
//	void OnReceiveComplete();
//	void AddLog(TCHAR* lpText);
//
//	// Overrides
//		// ClassWizard generated virtual function overrides
//		//{{AFX_VIRTUAL(CProxyMapDlg)
//protected:
//	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
//	virtual void PostNcDestroy();
//	virtual void OnCancel();
//	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
//	//}}AFX_VIRTUAL
//
//// Implementation
//protected:
//
//	// Generated message map functions
//	//{{AFX_MSG(CProxyMapDlg)
//	virtual BOOL OnInitDialog();
//	//afx_msg void OnClose();
//	afx_msg void OnSize(UINT nType, int cx, int cy);
//	//}}AFX_MSG
//	DECLARE_MESSAGE_MAP()
//private:
//	ClientContext* m_pContext;
//	ISocketBase* m_iocpServer;
//	CProxyIocpServer* m_iocpLocal;
//	CString m_IPAddress;
//	HICON m_hIcon;
//	BOOL m_bOnClose;
//	bool isclose;
//};