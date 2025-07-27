

#include "stdafx.h"
#include "Quick.h"
#include "LockDlg.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CBrush m_bkbrush;

int user = 0;
CLockDlg* pDlg = NULL;
CString PASSWORD1;
CString	PASSWORD2;
CString PASSWORD3;


#define SE_DEBUG_PRIVILEGE 20

typedef LONG(__stdcall* RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
typedef LONG(__stdcall* SuspendOrResumeProcess)(HANDLE hProcess);
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

DWORD GetWinlogonPid() {
	HANDLE			snap;
	PROCESSENTRY32	pEntry;
	BOOL			rtn;

	snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pEntry.dwSize = sizeof(pEntry);
	rtn = Process32First(snap, &pEntry);
	while (rtn) {
		if (!_tcscmp(pEntry.szExeFile, _T("winlogon.exe"))) {
			CloseHandle(snap);
			return pEntry.th32ProcessID;
		}
		memset(pEntry.szExeFile, 0, 260);
		rtn = Process32Next(snap, &pEntry);
	}

	CloseHandle(snap);
	return 0;
}


BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
	PIDWNDINFO* pInfo = (PIDWNDINFO*)lParam;
	LONG lStyle = GetWindowLong(hWnd, GWL_STYLE);
	if (pInfo->dwProcessId == 0 && hWnd != pInfo->hWnd &&
		IsWindowVisible(hWnd) && GetParent(hWnd) == NULL && lStyle & WS_MINIMIZEBOX)
	{
		ShowWindow(hWnd, SW_MINIMIZE);
		return TRUE;
	}

	DWORD dwProcessId;
	GetWindowThreadProcessId(hWnd, &dwProcessId);
	if (dwProcessId == pInfo->dwProcessId && IsWindowVisible(hWnd) && GetParent(hWnd) == NULL)
	{
		pInfo->hWnd = hWnd;
		return FALSE;
	}
	return TRUE;
}


HHOOK g_hKeyBoard = NULL;
//底层键盘系统调用，过滤alt + tab和win键
LRESULT CALLBACK KeyBoardProc(int code, WPARAM wParam, LPARAM lParam)
{
	if (code == HC_ACTION)
	{
		PKBDLLHOOKSTRUCT p;

		switch (wParam)
		{
		case WM_KEYDOWN:
		case WM_SYSKEYDOWN:
		case WM_KEYUP:
		case WM_SYSKEYUP:
			p = (PKBDLLHOOKSTRUCT)lParam;

			if ((p->vkCode == VK_TAB && (p->flags & LLKHF_ALTDOWN) != 0) //ALT+TAB
				|| (p->vkCode == VK_F4 && (p->flags & LLKHF_ALTDOWN) != 0) //ALT+F4
				|| (p->vkCode == VK_ESCAPE && (p->flags & LLKHF_ALTDOWN) != 0) //Alt+Esc
				|| (p->vkCode == VK_ESCAPE && (GetKeyState(VK_CONTROL) & 0x8000) != 0) //Ctrl+Esc
				|| (p->vkCode == VK_LWIN)
				|| (p->vkCode == VK_RWIN)
				)
			{
				return 1;
			}
			if ((GetKeyState(VK_CAPITAL) & 1) != 0)
			{
				pDlg->m_sta_hint.SetWindowText(_T("！！！【大写锁定】！！！"));
			}
			else
			{
				pDlg->m_sta_hint.SetWindowText(_T("远程防误操作，输入密码亦可退出"));
			}

			break;
		}
	}

	return ::CallNextHookEx(g_hKeyBoard, code, wParam, lParam);
}
//注册全局hook
HANDLE hProcess;
SuspendOrResumeProcess lpfnNtResumeProcess;
void SetHook()
{
	g_hKeyBoard = SetWindowsHookEx(WH_KEYBOARD_LL, KeyBoardProc, GetModuleHandle(NULL), 0);
	HMODULE hMod = LoadLibrary(_T("ntdll"));

	RtlAdjustPrivilege lpfnRtlAdjustPrivilege = (RtlAdjustPrivilege)GetProcAddress(hMod, "RtlAdjustPrivilege");


	SuspendOrResumeProcess lpfnNtSuspendProcess = (SuspendOrResumeProcess)GetProcAddress(hMod, "NtSuspendProcess");


	lpfnNtResumeProcess = (SuspendOrResumeProcess)GetProcAddress(hMod, "NtResumeProcess");


	DWORD pid = GetWinlogonPid();


	BOOLEAN dummy = 0;
	lpfnRtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, true, false, &dummy);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

	lpfnNtSuspendProcess(hProcess);
	//MessageBox(NULL, "Now Ctrl+Alt+Del is disabled! Press OK to restore.", "Ha!", MB_OK | MB_ICONINFORMATION);

}
//注销全局hook
void UnSetHook()
{
	if (g_hKeyBoard)
		UnhookWindowsHookEx(g_hKeyBoard);

	lpfnNtResumeProcess(hProcess);
	g_hKeyBoard = NULL;
}


/////////////////////////////////////////////////////////////////////////////
// CLOCKDlg dialog
CLockDlg::CLockDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CLockDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CLockDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CLOCKDlg)
	//}}AFX_DATA_MAP
	DDX_Control(pDX, IDC_MESSAGE, m_sta_hint);
}

BEGIN_MESSAGE_MAP(CLockDlg, CDialog)
	//{{AFX_MSG_MAP(CLOCKDlg)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_CTLCOLOR()
	ON_WM_CLOSE()
	ON_WM_SYSCOMMAND()
	ON_BN_CLICKED(ID_SETLOCK, OnSetlock)
	ON_BN_CLICKED(ID_QUIT, OnQuit)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CLOCKDlg message handlers

BOOL CLockDlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	pDlg = this;
	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
/*	m_bkbrush.CreateSolidBrush(RGB(0,0,0));*/

	SendDlgItemMessage(IDC_UNLOCK, EM_SETREADONLY, 1);

	SetWindowPos(&wndTopMost, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
	return TRUE;  // return TRUE  unless you set the focus to a control
}

// 如果您在对话框中添加一个最小化按钮，您将需要下面的代码
// 绘制图标。对于使用文档/视图模型的 MFC 应用程序，
// 这是由框架自动为您完成的。

void CLockDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM)dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CLockDlg::OnQueryDragIcon()
{
	return (HCURSOR)m_hIcon;
}

void CLockDlg::OnSetlock()
{
	if (user == 0)
	{
		GetDlgItemText(IDC_SET, PASSWORD1);
		GetDlgItemText(IDC_SETAGAIN, PASSWORD2);
		if (PASSWORD1 != PASSWORD2)
		{
			SetDlgItemText(IDC_MESSAGE, _T("两次的密码不相同\n请重新输入"));
			SetDlgItemText(IDC_SET, _T(""));
			SetDlgItemText(IDC_SETAGAIN, _T(""));
			GetDlgItem(IDC_SET)->SetFocus();
			return;
		}
		if (PASSWORD1 == "")
		{
			SetDlgItemText(IDC_MESSAGE, _T("密码设为空\n这样不太安全!"));
			GetDlgItem(IDC_SET)->SetFocus();
			return;
		}
		SetDlgItemText(IDC_MESSAGE, _T("我先帮你看着\n快点回来."));

		SendDlgItemMessage(IDC_SET, EM_SETREADONLY, 1);
		SendDlgItemMessage(IDC_SETAGAIN, EM_SETREADONLY, 1);
		SendDlgItemMessage(IDC_UNLOCK, EM_SETREADONLY, 0);
		SetDlgItemText(ID_SETLOCK, _T("解锁"));
		SetDlgItemText(IDC_SET, _T(""));
		SetDlgItemText(IDC_SETAGAIN, _T(""));
		GetDlgItem(ID_QUIT)->EnableWindow(false);
		user = 1;

		CRect rct;
		PIDWNDINFO pwi;
		GetWindowRect(rct);
		ClipCursor(rct);
		SystemParametersInfo(SPI_SETSCREENSAVERRUNNING, true, 0, SPIF_UPDATEINIFILE);

		AfxGetApp()->m_pMainWnd->ShowWindow(SW_HIDE);
		pwi.dwProcessId = 0;
		pwi.hWnd = GetSafeHwnd();
		EnumWindows(EnumWindowsProc, (LPARAM)&pwi);
		::ShowWindow(::FindWindow(_T("Shell_TrayWnd"), NULL), SW_HIDE);
		::ShowWindow(::FindWindow(_T("Button"), _T("开始")), SW_HIDE);
		::ShowWindow(::FindWindow(_T("Progman"), NULL), SW_HIDE);
		GetDlgItem(IDC_UNLOCK)->SetFocus();
		SetHook();
		return;
	}
	if (user == 1)
	{
		UnSetHook();
		GetDlgItemText(IDC_UNLOCK, PASSWORD3);
		if (PASSWORD1 != PASSWORD3)
		{
			SetDlgItemText(IDC_MESSAGE, _T("密码输入错误\n你无权解锁!"));
			SetDlgItemText(IDC_UNLOCK, _T(""));
			GetDlgItem(IDC_UNLOCK)->SetFocus();
			return;
		}
		SetDlgItemText(IDC_MESSAGE, _T("不用我帮忙了?"));

		SendDlgItemMessage(IDC_SET, EM_SETREADONLY, 0);
		SendDlgItemMessage(IDC_SETAGAIN, EM_SETREADONLY, 0);
		SendDlgItemMessage(IDC_UNLOCK, EM_SETREADONLY, 1);
		SetDlgItemText(ID_SETLOCK, _T("加锁"));
		SetDlgItemText(IDC_UNLOCK, _T(""));
		GetDlgItem(ID_QUIT)->EnableWindow(true);
		user = 0;

		ClipCursor(NULL);
		SystemParametersInfo(SPI_SETSCREENSAVERRUNNING, false, 0, SPIF_UPDATEINIFILE);
		::ShowWindow(::FindWindow(_T("Shell_TrayWnd"), NULL), SW_SHOW);
		::ShowWindow(::FindWindow(_T("Button"), _T("开始")), SW_SHOW);
		::ShowWindow(::FindWindow(_T("Progman"), NULL), SW_SHOW);
		AfxGetApp()->m_pMainWnd->ShowWindow(SW_SHOW);
	}
}

void CLockDlg::OnQuit()
{
	OnOK();
}

void CLockDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if (nID == SC_MINIMIZE)
		return;

	CDialog::OnSysCommand(nID, lParam);
}

BOOL CLockDlg::PreTranslateMessage(MSG* pMsg)
{
	if (pMsg->message == WM_KEYDOWN)
	{
		if (pMsg->wParam == VK_ESCAPE)
			return TRUE;
	}
	return CDialog::PreTranslateMessage(pMsg);
}

void CLockDlg::OnClose()
{

	CDialog::OnClose();
}

