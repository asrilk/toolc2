// LOGIN.cpp : implementation file
//

#include "stdafx.h"
#include "Quick.h"
#include "LOGIN.h"
// #include "C_QQMusicCommon.h" 
// #include "C_system.h" 
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// LOGIN dialog

LOGIN::LOGIN(CWnd* pParent /*=NULL*/)
	: CDialog(LOGIN::IDD, pParent)


{
	//{{AFX_DATA_INIT(LOGIN)
	m_username = _T("123");
	m_userpass = _T("123");
	m_onlinepass = _T("123");
	m_userip=_T("127.0.0.1");
	m_userport = _T("888");
	//}}AFX_DATA_INIT
}


void LOGIN::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(LOGIN)
	DDX_Text(pDX, IDC_username, m_username);
	DDX_Text(pDX, IDC_userpass, m_userpass);
	//}}AFX_DATA_MAP
	DDX_Text(pDX, IDC_ip, m_userip);
	DDX_Text(pDX, IDC_ip2, m_userport);
}

BEGIN_MESSAGE_MAP(LOGIN, CDialog)
	//{{AFX_MSG_MAP(LOGIN)
	ON_BN_CLICKED(IDC_EXIT, OnExit)
	ON_BN_CLICKED(IDC_LOGIN, OnLogin)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// LOGIN message handlers

void LOGIN::OnLogin()
{

	UpdateData(TRUE);
	if (m_username.GetLength() == 0 || m_userpass.GetLength() == 0)
	{
		return;
	}
	//////////////////////////////////////////////////////////////////////////////////////////////////
	DWORD recvsize = 0;
	SOCKET sockInt;
	struct sockaddr_in serverAddr;
	//struct hostent *hp;
	WORD sockVersion;
	WSADATA wsaData;
	sockVersion = MAKEWORD(2, 2);
	WSAStartup(sockVersion, &wsaData);
	//创建SOCK
	sockInt = socket(AF_INET, SOCK_STREAM, 0);
	if (sockInt == INVALID_SOCKET)
	{
		::MessageBoxA(0,"socket error!",0,0);
		WSACleanup();
		return;
	}

	//获取服务器IP和端口
	serverAddr.sin_family = AF_INET;

	char tgtIP[30] = { 0 };
	struct hostent* hp = NULL;
	CStringA m_usernameA, m_userpassA, m_useripA, m_userportA;

	m_useripA = m_userip;
	if ((hp = gethostbyname(m_useripA.GetBuffer())) != NULL)

	{
		in_addr in;
		memcpy(&in, hp->h_addr, hp->h_length);
		strcpy_s(tgtIP, inet_ntoa(in));
	}

	serverAddr.sin_addr.s_addr = inet_addr(tgtIP);

	m_userportA = m_userport;

	serverAddr.sin_port = htons(atoi(m_userportA.GetBuffer()));

	//连接服务
	if (connect(sockInt, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
	{
		//////////////////////////////////////////////////////////
		char* RWgsb1 = "连接服务器失败", * PQyRw2 = "或是帐号过期.", * WrAIY3 = NULL;
		WrAIY3 = new char[strlen(RWgsb1) + strlen(PQyRw2) + 1];
		strcpy_s(WrAIY3, strlen(RWgsb1) + strlen(PQyRw2) + 1, RWgsb1);
		strcat_s(WrAIY3, strlen(RWgsb1) + strlen(PQyRw2) + 1, PQyRw2);
		//////////////////////////////////////////////////////////

		::MessageBoxA(0, WrAIY3, 0, 0);
		
		WSACleanup();
		return;
	}
	char USERIMFOR[256] = { 0 }, buff[256] = { 0 };

	m_usernameA = m_username;
	m_userpassA = m_userpass;

	sprintf_s(USERIMFOR, "Login:%s@%s", m_usernameA, m_userpassA);
	if (send(sockInt, USERIMFOR, sizeof(USERIMFOR), 0) == SOCKET_ERROR)
	{

		//////////////////////////////////////////////////////////
		char* pyvrJ1 = "连接服务器失败", * ffMII2 = "或是帐号过期.", * vLlAh3 = NULL;
		vLlAh3 = new char[strlen(pyvrJ1) + strlen(ffMII2) + 1];
		strcpy_s(vLlAh3, strlen(pyvrJ1) + strlen(ffMII2) + 1, pyvrJ1);
		strcat_s(vLlAh3, strlen(pyvrJ1) + strlen(ffMII2) + 1, ffMII2);
		//////////////////////////////////////////////////////////
		::MessageBoxA(0, vLlAh3, 0, 0);
		WSACleanup();
		return;
	}
	Sleep(50);
	int Ret = recv(sockInt, buff, sizeof(buff), NULL);
	if (Ret == 0 || Ret == SOCKET_ERROR)
	{

		//////////////////////////////////////////////////////////
		char* ZzxsL1 = "账号", * qbJrX2 = "错误", * KiHpV3 = NULL;
		KiHpV3 = new char[strlen(ZzxsL1) + strlen(qbJrX2) + 1];
		strcpy_s(KiHpV3, strlen(ZzxsL1) + strlen(qbJrX2) + 1, ZzxsL1);
		strcat_s(KiHpV3, strlen(ZzxsL1) + strlen(qbJrX2) + 1, qbJrX2);
		//////////////////////////////////////////////////////////
		//::MessageBoxA(0, KiHpV3, 0, 0);
		closesocket(sockInt);
		WSACleanup();
		return;
	}

	if (strstr(buff, "Pass") != NULL)//通过验证
	{
		closesocket(sockInt);
		WSACleanup();
	
		dLogin = GetTickCount();
		::MessageBoxA(0,buff + 6, "Vip信息", NULL);
		OnCancel();
	}
}

void LOGIN::OnExit()
{
	// TODO: Add your control notification handler code here
	ExitProcess(0);
}

BOOL LOGIN::OnInitDialog()
{
	CDialog::OnInitDialog();
	// TODO: Add extra initialization here

	UpdateData();
	UpdateData(FALSE);

	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}
