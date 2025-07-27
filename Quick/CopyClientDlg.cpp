// CCopyClientDlg.cpp: ʵ���ļ�
//

#include "stdafx.h"
#include "Quick.h"
#include "CopyClientDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// CCopyClientDlg �Ի���

IMPLEMENT_DYNAMIC(CCopyClientDlg, CDialog)

CCopyClientDlg::CCopyClientDlg(CString title, CWnd* pParent, bool bshow)
	: CDialog(IDD_COPYCLIENT, pParent)

	, m_edit_ip(_T("127.0.0.1"))
	, m_edit_ip2(_T("127.0.0.1"))
	, m_edit_ip3(_T("127.0.0.1"))
	, m_edit_port(_T("1111"))
	, m_edit_port2(_T("2222"))
	, m_edit_port3(_T("3333"))
{
	m_show = bshow;
	m_title = title;

}

CCopyClientDlg::~CCopyClientDlg()
{
}

void CCopyClientDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);

	DDX_Text(pDX, IDC_EDIT_IP, m_edit_ip);
	DDX_Text(pDX, IDC_EDIT_IP2, m_edit_ip2);
	DDX_Text(pDX, IDC_EDIT_IP3, m_edit_ip3);
	DDX_Text(pDX, IDC_EDIT_PORT, m_edit_port);
	DDX_Text(pDX, IDC_EDIT_PORT2, m_edit_port2);
	DDX_Text(pDX, IDC_EDIT_PORT3, m_edit_port3);
	DDX_Control(pDX, IDC_COMBO_NET, h_combo_net);
	DDX_Control(pDX, IDC_COMBO_NET2, h_combo_net2);
	DDX_Control(pDX, IDC_COMBO_NET3, h_combo_net3);
}


BEGIN_MESSAGE_MAP(CCopyClientDlg, CDialog)
	ON_BN_CLICKED(IDOK, &CCopyClientDlg::OnBnClickedOk)

END_MESSAGE_MAP()


// CCopyClientDlg ��Ϣ�������
BOOL CCopyClientDlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	SetWindowText(m_title);
	if (!m_show)
	{
		GetDlgItem(IDC_EDIT_IP2)->EnableWindow(FALSE);
		GetDlgItem(IDC_EDIT_PORT2)->EnableWindow(FALSE);
		GetDlgItem(IDC_COMBO_NET2)->EnableWindow(FALSE);
		GetDlgItem(IDC_EDIT_IP3)->EnableWindow(FALSE);
		GetDlgItem(IDC_EDIT_PORT3)->EnableWindow(FALSE);
		GetDlgItem(IDC_COMBO_NET3)->EnableWindow(FALSE);		
		h_combo_net.SetCurSel(0);
		return TRUE;
	}
	h_combo_net.SetCurSel(0);
	h_combo_net2.SetCurSel(0);
	h_combo_net3.SetCurSel(0);
	return TRUE; 
}

void CCopyClientDlg::OnBnClickedOk()
{
	UpdateData(TRUE);

	if (m_show)
	{
		CString s = _T("|p1:��ַ1|o1:�˿�1|t1:ͨ��1|p2:��ַ2|o2:�˿�2|t2:ͨ��2|p3:��ַ3|o3:�˿�3|t3:ͨ��3|");
		Setfindinfo(s, _T("��ַ1"), m_edit_ip.GetBuffer(), NULL);
		Setfindinfo(s, _T("�˿�1"), m_edit_port.GetBuffer(), NULL);
		Setfindinfo(s, _T("ͨ��1"), NULL, h_combo_net.GetCurSel() ? false : true);

		Setfindinfo(s, _T("��ַ2"), m_edit_ip2.GetBuffer(), NULL);
		Setfindinfo(s, _T("�˿�2"), m_edit_port2.GetBuffer(), NULL);
		Setfindinfo(s, _T("ͨ��2"), NULL, h_combo_net2.GetCurSel() ? false : true);

		Setfindinfo(s, _T("��ַ3"), m_edit_ip3.GetBuffer(), NULL);
		Setfindinfo(s, _T("�˿�3"), m_edit_port3.GetBuffer(), NULL);
		Setfindinfo(s, _T("ͨ��3"), NULL, h_combo_net3.GetCurSel() ? false : true);
		m_COPYCLIENT.token = COMMAND_CHANGEINFO;
		memcpy(m_COPYCLIENT.confimodel, s.GetBuffer(), s.GetLength() * 2 + 2);
	}
	else
	{
		CString s = _T("|p1:��ַ1|o1:�˿�1|t1:ͨ��1|");
		Setfindinfo(s, _T("��ַ1"), m_edit_ip.GetBuffer(), NULL);
		Setfindinfo(s, _T("�˿�1"), m_edit_port.GetBuffer(), NULL);
		Setfindinfo(s, _T("ͨ��1"), NULL, h_combo_net.GetCurSel() ? false : true);
		m_COPYCLIENT.token = COMMAND_ADDCLIENT;
		memcpy(m_COPYCLIENT.confimodel, s.GetBuffer(), s.GetLength() * 2 + 2);
	}



	CDialog::OnOK();
}


void CCopyClientDlg::Setfindinfo(CString& s, const TCHAR* f1, TCHAR* outstring, BOOL user)
{
	if (outstring)
		s.Replace(f1, outstring);
	else
	{
		user ? s.Replace(f1, _T("1")) : s.Replace(f1, _T("0"));
	}
}