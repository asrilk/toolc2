// Quick.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "Quick.h"
#include "MainFrm.h"
#include "QuickDoc.h"
#include "TabView.h"
#include "QuickView.h"
#include "LOGIN.h"
LOGIN Login;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CQuickApp

BEGIN_MESSAGE_MAP(CQuickApp, CWinApp)
	ON_COMMAND(ID_APP_ABOUT, &CQuickApp::OnAppAbout)
	// Standard file based document commands
	ON_COMMAND(ID_FILE_NEW, &CWinApp::OnFileNew)
	ON_COMMAND(ID_FILE_OPEN, &CWinApp::OnFileOpen)
END_MESSAGE_MAP()



CQuickApp::CQuickApp()
{
		TCHAR ExePath[MAX_PATH] = { 0 };
		GetModuleFileName(NULL, ExePath, sizeof(ExePath));
		::PathStripPath(ExePath);
		g_Exename = ExePath;
		g_Exename.Replace(_T(".exe"), _T(" "));


		SHFILEINFO	sfi;
		memset(&sfi, 0, sizeof(sfi));
		HIMAGELIST hImageList;

	
		hImageList = (HIMAGELIST)SHGetFileInfo((LPCTSTR)_T(""), 0, &sfi, sizeof(SHFILEINFO), SHGFI_LARGEICON | SHGFI_SYSICONINDEX);
		m_pImageList_Large.Attach(hImageList);

	
		hImageList = (HIMAGELIST)SHGetFileInfo((LPCTSTR)_T(""), 0, &sfi, sizeof(SHFILEINFO), SHGFI_SMALLICON | SHGFI_SYSICONINDEX);
		m_pImageList_Small.Attach(hImageList);

}

CQuickApp::~CQuickApp()
{

}


// The one and only CQuickApp object

CQuickApp theApp;

void CQuickApp::ChangeOSnum(CString stros, bool isaddnum)
{
	if (isaddnum)
	{
		map_osnums::iterator it_map_osnums = m_map_osnums.find(stros);
		if (it_map_osnums != m_map_osnums.end())
		{
			int* i = it_map_osnums->second;
			(*i)++;
		}
		else
		{
			int* i = new int;
			*i = 1;
			m_map_osnums.insert(MAKE_PAIR(map_osnums, stros, i));
		}
	}
	else
	{
		map_osnums::iterator it_map_osnums = m_map_osnums.find(stros);
		if (it_map_osnums != m_map_osnums.end())
		{
			int* i = it_map_osnums->second;
			(*i)--;
			if ((*i)==0)
			{
				m_map_osnums.erase(it_map_osnums);
			}
		}

	}

}



// CQuickApp initialization

BOOL CQuickApp::InitInstance()
{
#ifdef OPEN_LOGIN
	Login.DoModal();
	if (Login.dLogin <= 10000)
	{
		return FALSE;
	}
#endif // OPEN_LOGIN


#ifdef ONLINE_TIME

	CString strSysTime, strDeadline, strSWCreateTime;
	CTime sysTime;//系统时间
	sysTime = CTime::GetCurrentTime();
	strSysTime = sysTime.Format(_T("%Y%m%d"));
	strSWCreateTime.Format(_T("20150629"));
	strDeadline = (_T("20150629"));
	if (strSysTime < strSWCreateTime)
	{
		return FALSE;
	}
	if (strSysTime > strDeadline)
	{
		return FALSE;
	}
#endif 
	// InitCommonControlsEx() is required on Windows XP if an application
	// manifest specifies use of ComCtl32.dll version 6 or later to enable
	// visual styles.  Otherwise, any window creation will fail.
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// Set this to include all the common control classes you want to use
	// in your application.
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	// of your final executable, you should remove from the following
	// the specific initialization routines you do not need
	// Change the registry key under which our settings are stored
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization
	SetRegistryKey(_T("Local AppWizard-Generated Applications"));
	LoadStdProfileSettings(4);  // Load standard INI file options (including MRU)
	// Register the application's document templates.  Document templates
	//  serve as the connection between documents, frame windows and views
	CSingleDocTemplate* pDocTemplate;
	pDocTemplate = new CSingleDocTemplate(
		IDR_MAINFRAME,
		RUNTIME_CLASS(CQuickDoc),
		RUNTIME_CLASS(CMainFrame),       // main SDI frame window
		RUNTIME_CLASS(CTabView));
	if (!pDocTemplate)
		return FALSE;
	AddDocTemplate(pDocTemplate);



	// Parse command line for standard shell commands, DDE, file open
	CCommandLineInfo cmdInfo;
	ParseCommandLine(cmdInfo);


	// Dispatch commands specified on the command line.  Will return FALSE if
	// app was launched with /RegServer, /Register, /Unregserver or /Unregister.
	if (!ProcessShellCommand(cmdInfo))
		return FALSE;

	// The one and only window has been initialized, so show and update it
	((CMainFrame*)m_pMainWnd)->Activate();
	m_pMainWnd->ShowWindow(SW_SHOW);
	m_pMainWnd->UpdateWindow();
	// call DragAcceptFiles only if there's a suffix
	//  In an SDI app, this should occur after ProcessShellCommand


	//old_locale = _strdup(setlocale(LC_ALL, NULL));
	//setlocale(LC_ALL, "chs");

	return TRUE;
}



// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

	// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()

// App command to run the dialog
void CQuickApp::OnAppAbout()
{
	CAboutDlg aboutDlg;
	aboutDlg.DoModal();
}


// CQuickApp message handlers

