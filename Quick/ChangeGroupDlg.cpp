#include "stdafx.h"
#include "Quick.h"
#include "ChangeGroupDlg.h"
#include "afxdialogex.h"
#include "TabView.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

extern CTabView* g_pTabView;
/////////////////////////////////////////////////////////////////////////////
// CChangeGroupDlg dialog


CChangeGroupDlg::CChangeGroupDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CChangeGroupDlg::IDD, pParent)
{

}


void CChangeGroupDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO_GROUP, m_combo_group);
}


BEGIN_MESSAGE_MAP(CChangeGroupDlg, CDialog)
	//{{AFX_MSG_MAP(CChangeGroupDlg)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CChangeGroupDlg message handlers

BOOL CChangeGroupDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// TODO: Add extra initialization here
	CString strGroupName, strTemp;
	int nTabs = g_pTabView->m_wndTabControl.GetItemCount();
	for (int i = 0; i < nTabs; i++)
	{
		strTemp = g_pTabView->m_wndTabControl.GetItem(i)->GetCaption();
		int n = strTemp.ReverseFind(_T('('));
		if (n > 0)
		{
			strGroupName = strTemp.Left(n);
		}
		else
		{
			strGroupName = strTemp;
		}
		m_combo_group.AddString(strGroupName);
	}
	m_combo_group.SetCurSel(0);
	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

void CChangeGroupDlg::OnOK()
{
	// TODO: Add extra validation here
	((CEdit*)GetDlgItem(IDC_COMBO_GROUP))->GetWindowText(strGroup);
	if (strGroup == _T(""))
	{
		AfxMessageBox(_T("输入不能为空!"));
		return;
	}
	CString strTemp, Temp;
	strTemp = g_pTabView->m_wndTabControl.GetSelectedItem()->GetCaption();

	int n = strTemp.ReverseFind(_T('('));
	if (n > 0)
	{
		Temp = strTemp.Left(n);
	}
	else
	{
		Temp = strTemp;
	}
	if (strGroup == Temp)
	{
		AfxMessageBox(_T("分组没有改变!"));
		return;
	}
	CDialog::OnOK();
}
