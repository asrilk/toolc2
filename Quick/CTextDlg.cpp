// CTextDlg.cpp: ʵ���ļ�
//

#include "stdafx.h"
#include "Quick.h"
#include "CTextDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// CTextDlg �Ի���

IMPLEMENT_DYNAMIC(CTextDlg, CDialog)

CTextDlg::CTextDlg(CWnd* pParent /*=nullptr*/)
	: CDialog(IDD_TEXT, pParent)
	, nowstr(_T(""))
	, cmeline(_T(""))
	, oldstr(_T(""))
{

}

CTextDlg::~CTextDlg()
{
}

void CTextDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT1, oldstr);
	DDX_Text(pDX, IDC_EDIT2, nowstr);
	DDX_Text(pDX, IDC_EDIT3, cmeline);
}


BEGIN_MESSAGE_MAP(CTextDlg, CDialog)
	ON_BN_CLICKED(IDOK, &CTextDlg::OnBnClickedOk)

END_MESSAGE_MAP()


// CTextDlg ��Ϣ�������


void CTextDlg::OnBnClickedOk()
{
	UpdateData(TRUE);
	CDialog::OnOK();
}
