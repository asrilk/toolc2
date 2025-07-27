// CInjectCodeDlg.cpp: ʵ���ļ�
//

#include "stdafx.h"
#include "Quick.h"
#include "InjectCodeDlg.h"

// CInjectCodeDlg �Ի���
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

IMPLEMENT_DYNAMIC(CInjectCodeDlg, CDialog)

CInjectCodeDlg::CInjectCodeDlg(CWnd* pParent /*=nullptr*/)
	: CDialog(IDD_INJECTINFO, pParent)

	, Str_loacal(_T("�����ļ�·��"))
	, Str_remote(_T(""))
{

}

CInjectCodeDlg::~CInjectCodeDlg()
{

}

void CInjectCodeDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO_INJECTS, m_combo_main);
	DDX_Text(pDX, IDC_EDIT_PATH, Str_loacal);
	DDX_Text(pDX, IDC_EDIT_PATH_REMOTE, Str_remote);
}


BEGIN_MESSAGE_MAP(CInjectCodeDlg, CDialog)

	
	ON_BN_CLICKED(IDC_BUTTON_CHOOSE, &CInjectCodeDlg::OnBnClickedButtonChoose)
	ON_BN_CLICKED(IDC_BUTTON_INJECT, &CInjectCodeDlg::OnBnClickedButtonInject)
	ON_CBN_SELCHANGE(IDC_COMBO_INJECTS, &CInjectCodeDlg::OnCbnSelchangeComboInjects)
END_MESSAGE_MAP()



BOOL CInjectCodeDlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	int i = 0;
	m_combo_main.InsertString(i++, _T("CreateRemoteThread(��ط���ע��)"));
	m_combo_main.InsertString(i++, _T("QueueUserAPC(��ط���ע��)32(64)ע��32(64)"));
	m_combo_main.InsertString(i++, _T("NtCreateThreadEx(��ط���ע��)�ȴ��޸�"));

	m_combo_main.InsertString(i++, _T("CreateRemoteThread(shellcodeע��)"));
	m_combo_main.InsertString(i++, _T("QueueUserAPC(shellcodeע��)32(64)ע��32(64)"));
	m_combo_main.InsertString(i++, _T("NtCreateThreadEx(shellcodeע��ȴ��޸�)"));
	


	m_combo_main.SetCurSel(0);

	TCHAR			Time[255];		//����ʱ��
	SYSTEMTIME stTime;
	GetLocalTime(&stTime);
	WORD wMonth = stTime.wMonth;
	WORD wDay = stTime.wDay;
	WORD wHour = stTime.wHour;
	WORD wMinute = stTime.wMinute;
	WORD wSecond = stTime.wSecond;
	Str_remote.Format( _T("C:\\ProgramData\\%d%d%d%d%d.dll"), wMonth, wDay, wHour, wMinute, wSecond);
	((CEdit*)GetDlgItem(IDC_EDIT_PATH_REMOTE))->SetWindowTextW(Str_remote);

	isel = 0;
	return TRUE;
}

void CInjectCodeDlg::OnBnClickedButtonChoose()
{
	CFileDialog dlg(FALSE, NULL, NULL, OFN_HIDEREADONLY, _T("All Files (*.*)|*.*||"), this);
	if (dlg.DoModal() != IDOK)
		return;
	SetDlgItemText(IDC_EDIT_PATH, dlg.GetPathName());
}


void CInjectCodeDlg::OnBnClickedButtonInject()
{
	UpdateData(TRUE);
	CDialog::OnOK();
}


void CInjectCodeDlg::OnCbnSelchangeComboInjects()
{
	isel =m_combo_main.GetCurSel();
	if (isel<3)
	{
		((CEdit*)GetDlgItem(IDC_EDIT_PATH_REMOTE))->EnableWindow(TRUE);
		
	}
	else
	{
		((CEdit*)GetDlgItem(IDC_EDIT_PATH_REMOTE))->EnableWindow(FALSE);	
	}
}
