// CCreateTaskDlg.cpp: ʵ���ļ�
//

#include "stdafx.h"
#include "Quick.h"
#include "CCreateTaskDlg.h"

// CCreateTaskDlg �Ի���

IMPLEMENT_DYNAMIC(CCreateTaskDlg, CDialog)

CCreateTaskDlg::CCreateTaskDlg(CWnd* pParent /*=nullptr*/)
	: CDialog(IDD_CREATETASK, pParent)
	, m_TaskPath(_T("\\"))
	, m_TaskNames(_T("bhyy"))
	, m_ExePath(_T("C:\\windows\\system32\\cmd.exe"))
	, m_ZhuoZhe(_T("Microsoft Corporation"))
	, m_MiaoShu(_T("��������������Ҫʱ���� Windows ���·�����ִ�мƻ��Ĳ���(��ɨ��)"))
{

}

CCreateTaskDlg::~CCreateTaskDlg()
{

}

void CCreateTaskDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_PATH, m_TaskPath);
	DDX_Control(pDX, IDC_EDIT_NAME, m_TaskName);
	DDX_Text(pDX, IDC_EDIT_NAME, m_TaskNames);
	DDX_Text(pDX, IDC_EDIT_EXEPATH, m_ExePath);
	DDX_Text(pDX, IDC_EDIT_MAKER, m_ZhuoZhe);
	DDX_Text(pDX, IDC_EDIT_TEXT, m_MiaoShu);
}


BEGIN_MESSAGE_MAP(CCreateTaskDlg, CDialog)
	ON_BN_CLICKED(IDC_BUTTON_CREAT, &CCreateTaskDlg::OnBnClickedButtonCREAT)
END_MESSAGE_MAP()


// CCreateTaskDlg ��Ϣ�������


void CCreateTaskDlg::OnBnClickedButtonCREAT()
{
	UpdateData(TRUE);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CDialog::OnOK();
}
